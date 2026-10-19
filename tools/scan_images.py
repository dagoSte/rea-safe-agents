#!/usr/bin/env python3
"""Inventory and report vulnerabilities in both built images without running them.

Only Docker and Python's standard library are required on the host. Trivy runs
in a restricted container and receives docker-save archives, never the Docker
socket. Database downloads run separately, without access to target archives.
Reports include all severities and unfixed vulnerabilities. Exit 0 means the
reports were produced; it does not mean there are no vulnerabilities. Operational
errors, invalid/empty reports and stale databases return 1 and preserve evidence.
Downloaded JDKs and arbitrary native binaries have no generic CVE coverage here.
"""

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import uuid

from check_versions import ROOT, read_pins

SCANNER_VERSION = "0.76.0"
SCANNER_IMAGE = "ghcr.io/aquasecurity/trivy:0.76.0@sha256:2416d1f74045b57274df1a340eee6b510cacd73c66a6ccb8da092b117eb7d222"
DB_REPOSITORIES = {"db": "ghcr.io/aquasecurity/trivy-db:2", "java-db": "ghcr.io/aquasecurity/trivy-java-db:1"}
SEVERITIES = ("UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL")
LIMITATIONS = [
    "Known-vulnerability matching is not an exploitability assessment or a guarantee of safety.",
    "Offline scanning can miss dependencies that require remote Maven resolution.",
    "Downloaded JDKs and arbitrary native executables (including Ghidra, Codex and Claude binaries) may lack supported package metadata; their vulnerability coverage is not guaranteed.",
    "The SBOM contains components recognized by this scanner, not every file or statically linked library.",
]


class ScanError(RuntimeError):
    pass


def utc_now():
    return datetime.now(timezone.utc)


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ScanError(f"Invalid JSON evidence: {path.name} ({type(exc).__name__})") from None


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return "sha256:" + digest.hexdigest()


def run(command, output, log, timeout=1200, cleanup=None):
    """Keep partial output and stderr on failure; never interpret it as a report."""
    try:
        with output.open("wb") as stdout, log.open("wb") as stderr:
            result = subprocess.run(command, stdout=stdout, stderr=stderr, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        # Killing the Docker CLI alone can leave its daemon-side container alive.
        if cleanup:
            try:
                with log.open("ab") as stderr:
                    subprocess.run(cleanup, stdout=subprocess.DEVNULL, stderr=stderr, timeout=30, check=True)
            except (OSError, subprocess.SubprocessError):
                raise ScanError(f"Command timed out; container cleanup failed; see {log.name}") from None
        raise ScanError(f"Command failed (TimeoutExpired); see {log.name}") from None
    except OSError as exc:
        raise ScanError(f"Command failed ({type(exc).__name__}); see {log.name}") from None
    if result.returncode:
        raise ScanError(f"Command exited {result.returncode}; see {log.name}")


def inspect(docker, reference, output):
    run([*docker, "image", "inspect", reference], output, output.with_suffix(".stderr.log"), timeout=60)
    value = load_json(output)
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        raise ScanError("Docker image inspection returned an invalid object")
    image = value[0]
    if not isinstance(image.get("Id"), str) or not image["Id"].startswith("sha256:"):
        raise ScanError("Docker image inspection has no image ID")
    return {key: image.get(key) for key in ("Id", "RepoDigests", "Architecture", "Os", "Created")}


def container(docker, mounts=(), network=False, scratch=None, name=None):
    command = [*docker, "run", "--rm", "--name", name or "rea-image-scan-" + uuid.uuid4().hex,
               "--pull", "never", "--read-only", "--network", "bridge" if network else "none",
               "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "256",
               "--cpus", "2", "--memory", "3g", "--memory-swap", "3g",
               "--user", f"{os.getuid() if hasattr(os, 'getuid') else 1000}:{os.getgid() if hasattr(os, 'getgid') else 1000}",
               "--env", "HOME=/tmp", "--env", "TMPDIR=/tmp"]
    if scratch is None:
        command += ["--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=2g"]
    else:
        mounts = [*mounts, (scratch, "/tmp", False)]
    for source, target, readonly in mounts:
        if "," in str(source):
            raise ScanError("Docker bind paths cannot contain commas")
        command += ["--mount", f"type=bind,source={source},target={target}" + (",readonly" if readonly else "")]
    return [*command, "--entrypoint", "trivy", SCANNER_IMAGE]


def run_scanner(docker, arguments, output, log, mounts=(), network=False):
    name = "rea-image-scan-" + uuid.uuid4().hex
    cleanup = [*docker, "rm", "--force", name]
    if not network:
        # Offline target parsing keeps both temporary storage and memory bounded.
        run([*container(docker, mounts, name=name), *arguments], output, log, cleanup=cleanup)
        return
    # Java DB downloads exceed a small tmpfs. This directory starts empty and
    # contains no host credentials or source; removing it cannot affect users.
    with tempfile.TemporaryDirectory(prefix="scanner-scratch-", dir=output.parent) as temporary:
        run([*container(docker, mounts, network, Path(temporary), name=name), *arguments], output, log, cleanup=cleanup)


def database_metadata(cache, now):
    result = {}
    for name, max_age_hours in (("db", 48), ("java-db", 96)):
        path = cache / name / "metadata.json"
        value = load_json(path)
        try:
            updated = datetime.fromisoformat(value["UpdatedAt"].replace("Z", "+00:00"))
            if updated.tzinfo is None:
                raise ValueError("Timestamp lacks timezone")
            age = (now - updated).total_seconds() / 3600
            if age < -1 or age > max_age_hours:
                raise ValueError("Database is stale or from the future")
        except (TypeError, KeyError, AttributeError, ValueError):
            raise ScanError(f"{name} database timestamp is invalid or exceeds {max_age_hours} hours") from None
        result[name] = {"repository": DB_REPOSITORIES[name], "metadata": value, "age_hours": round(age, 3),
                        "max_age_hours": max_age_hours, "metadata_sha256": sha256(path),
                        "database_sha256": sha256(cache / name / ("trivy.db" if name == "db" else "trivy-java.db"))}
    return result


def prepare_cache(cache):
    """Only a dedicated scanner cache may be exposed to the download container."""
    cache.mkdir(parents=True, exist_ok=True)
    if not stat.S_ISDIR(cache.lstat().st_mode):
        raise ScanError("Database cache must be a real directory")
    directories = {Path("db"), Path("java-db")}
    allowed = {Path(name) for name in ("db", "java-db", "db/metadata.json", "db/trivy.db", "java-db/metadata.json", "java-db/trivy-java.db")}
    for path in cache.rglob("*"):
        relative, info = path.relative_to(cache), path.lstat()
        if (relative not in allowed
                or relative in directories and not stat.S_ISDIR(info.st_mode)
                or relative not in directories and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1)):
            raise ScanError("Database cache contains unexpected files, links or special files; use a dedicated scanner cache")


def summarize_report(report, image_id):
    if not isinstance(report, dict) or report.get("SchemaVersion") != 2 or report.get("ArtifactType") != "container_image":
        raise ScanError("Trivy JSON is not a schema-2 container-image report")
    if not isinstance(report.get("Metadata"), dict) or report["Metadata"].get("ImageID") != image_id:
        raise ScanError("Trivy report image ID does not match the inspected image")
    results = report.get("Results")
    if not isinstance(results, list) or not results:
        raise ScanError("Trivy report has no result inventory")
    counts, unfixed, package_types = Counter(), Counter(), Counter()
    for result in results:
        if not isinstance(result, dict) or not isinstance(result.get("Target"), str) or not isinstance(result.get("Type"), str):
            raise ScanError("Trivy result has invalid target/type")
        packages, findings = result.get("Packages", []), result.get("Vulnerabilities", [])
        if not isinstance(packages, list) or not isinstance(findings, list):
            raise ScanError("Trivy result has invalid package/vulnerability lists")
        for package in packages:
            if not isinstance(package, dict) or not isinstance(package.get("Name"), str) or not isinstance(package.get("Version"), str):
                raise ScanError("Trivy inventory contains an invalid package")
        package_types[result["Type"]] += len(packages)
        for finding in findings:
            if (not isinstance(finding, dict) or finding.get("Severity") not in SEVERITIES
                    or not all(isinstance(finding.get(key), str) and finding[key] for key in ("VulnerabilityID", "PkgName", "InstalledVersion"))
                    or not isinstance(finding.get("FixedVersion", ""), str)):
                raise ScanError("Trivy report contains an invalid vulnerability")
            counts[finding["Severity"]] += 1
            if not finding.get("FixedVersion"):
                unfixed[finding["Severity"]] += 1
    if not sum(package_types.values()) or not any(result.get("Class") == "os-pkgs" and result.get("Packages") for result in results):
        raise ScanError("Trivy inventory is empty or lacks OS packages")
    return {"package_occurrences_by_type": dict(sorted(package_types.items())),
            "vulnerability_occurrences_by_severity": {key: counts[key] for key in SEVERITIES},
            "unfixed_occurrences_by_severity": {key: unfixed[key] for key in SEVERITIES}}


def validate_sbom(value):
    if (not isinstance(value, dict) or value.get("bomFormat") != "CycloneDX"
            or not isinstance(value.get("components"), list) or not value["components"]
            or not all(isinstance(item, dict) and isinstance(item.get("name"), str) and item["name"] for item in value["components"])):
        raise ScanError("CycloneDX SBOM is malformed or empty")


def scan(docker, output, cache=None):
    pins = read_pins(ROOT)
    images = {"rea": f"rea-local:{pins['rea-agents']}-ghidra-{pins['ghidra']}-locked",
              "agent": f"rea-agent-local:codex-{pins['codex']}-claude-{pins['claude-code']}-locked"}
    provenance = {"status": "incomplete", "started_at": utc_now().isoformat(), "scanner": {"image": SCANNER_IMAGE, "version": SCANNER_VERSION},
                  "policy": "report-only: all severities and unfixed findings included; errors fail", "declared_build_pins": pins,
                  "limitations": LIMITATIONS, "images": {}}
    try:
        provenance["scanner"]["inspection"] = inspect(docker, SCANNER_IMAGE, output / "scanner.inspect.json")
        version = output / "scanner.version.json"
        run_scanner(docker, ["--version", "--format", "json"], version, output / "scanner.version.stderr.log")
        version_value = load_json(version)
        if not isinstance(version_value, dict) or version_value.get("Version") != SCANNER_VERSION:
            raise ScanError("The scanner binary version does not match the reviewed pin")
        cache = cache or output / "cache"
        prepare_cache(cache)
        for name, flag in (("db", "--download-db-only"), ("java-db", "--download-java-db-only")):
            run_scanner(docker, ["image", "--cache-dir", "/cache", "--no-progress",
                 "--disable-telemetry", flag, "--db-repository", DB_REPOSITORIES["db"], "--java-db-repository", DB_REPOSITORIES["java-db"]],
                output / f"{name}.download.stdout.log", output / f"{name}.download.stderr.log", [(cache, "/cache", False)], network=True)
        prepare_cache(cache)
        provenance["databases"] = database_metadata(cache, utc_now())
        for name, reference in images.items():
            evidence = {"reference": reference, "status": "incomplete", "inspection": inspect(docker, reference, output / f"{name}.inspect.json")}
            provenance["images"][name] = evidence
            with tempfile.TemporaryDirectory(prefix=f"{name}-archive-", dir=output) as temporary:
                archive = Path(temporary) / "image.tar"
                run([*docker, "image", "save", "--output", str(archive), evidence["inspection"]["Id"]],
                    output / f"{name}.save.stdout.log", output / f"{name}.save.stderr.log")
                evidence["archive_sha256"] = sha256(archive)
                report = output / f"{name}.trivy.json"
                arguments = ["image", "--input", "/input/image.tar", "--cache-dir", "/cache", "--cache-backend", "memory",
                             "--skip-db-update", "--skip-java-db-update", "--offline-scan", "--disable-telemetry", "--no-progress",
                             "--scanners", "vuln", "--pkg-types", "os,library", "--detection-priority", "comprehensive",
                             "--severity", ",".join(SEVERITIES), "--ignore-unfixed=false", "--ignorefile", "/dev/null",
                             "--list-all-pkgs", "--exit-code", "0", "--parallel", "2", "--timeout", "15m", "--format", "json"]
                run_scanner(docker, arguments, report, output / f"{name}.scan.stderr.log", [(archive, "/input/image.tar", True), (cache, "/cache", True)])
                evidence["summary"] = summarize_report(load_json(report), evidence["inspection"]["Id"])
                sbom = output / f"{name}.cyclonedx.json"
                run_scanner(docker, ["convert", "--format", "cyclonedx", "/input/report.json"], sbom, output / f"{name}.sbom.stderr.log", [(report, "/input/report.json", True)])
                validate_sbom(load_json(sbom))
                evidence.update(status="complete", report=report.name, report_sha256=sha256(report), sbom=sbom.name, sbom_sha256=sha256(sbom))
        provenance["status"] = "complete"
    except (ScanError, OSError, ValueError) as exc:
        provenance["error"] = str(exc)
        raise ScanError(str(exc)) from None
    finally:
        provenance["finished_at"] = utc_now().isoformat()
        write_json(output / "provenance.json", provenance)
    return provenance


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", help="Docker context used to build both images")
    parser.add_argument("--output-dir", type=Path, required=True, help="New directory outside this repository; contains reports, logs and database cache")
    parser.add_argument("--cache-dir", type=Path, help="Reuse a scanner database cache outside this repository; dates and hashes are still checked")
    args = parser.parse_args(argv)
    output = args.output_dir.resolve()
    if output == ROOT or ROOT in output.parents:
        parser.error("--output-dir must be outside the repository")
    cache = args.cache_dir.resolve() if args.cache_dir else None
    if cache is not None and (cache == ROOT or ROOT in cache.parents):
        parser.error("--cache-dir must be outside the repository")
    docker = ["docker"] + (["--context", args.context] if args.context else [])
    try:
        output.mkdir(mode=0o700, parents=True, exist_ok=False)
        provenance = scan(docker, output, cache)
    except (OSError, ScanError) as exc:
        print(f"Image scan failed: {exc}; evidence: {output}", file=sys.stderr)
        return 1
    for name, image in provenance["images"].items():
        print(f"{name}: {json.dumps(image['summary'], sort_keys=True)}")
    print(f"Report-only scan complete; review findings and limitations in {output / 'provenance.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
