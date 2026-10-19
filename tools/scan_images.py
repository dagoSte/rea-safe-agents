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
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import uuid

from check_versions import ROOT, read_pins

SCANNER_VERSION = "0.76.0"
SCANNER_IMAGE = "ghcr.io/aquasecurity/trivy:0.76.0@sha256:2416d1f74045b57274df1a340eee6b510cacd73c66a6ccb8da092b117eb7d222"
DB_REPOSITORIES = {"db": "ghcr.io/aquasecurity/trivy-db:2", "java-db": "ghcr.io/aquasecurity/trivy-java-db:1"}
SEVERITIES = ("UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL")
IMAGE_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
MAX_ARCHIVE_MEMBERS = 4096
MAX_IMAGE_JSON = 1024 * 1024
MAX_IDENTITY_JSON = 8 * MAX_IMAGE_JSON
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
    if not isinstance(image.get("Id"), str) or IMAGE_DIGEST.fullmatch(image["Id"]) is None:
        raise ScanError("Docker image inspection has no image ID")
    return {key: image.get(key) for key in ("Id", "RepoDigests", "Architecture", "Os", "Created", "RootFS", "Descriptor")}


def archive_identity(path, inspection):
    """Bind a plain docker-save tar to its inspected config/manifest/index digest.

    Support plain Docker-save archives with canonical USTAR outer headers only.
    Read fixed-size headers and bounded JSON; never extract files or decompress
    layers. Other TAR dialects/extensions and case-insensitive duplicate JSON
    keys (including data maps) fail closed to avoid Python/Go parser differences.
    The OCI index -> manifest -> config chain and exact stored layers are hashed;
    legacy uncompressed layers are checked against the config's DiffIDs.
    """
    index_types = {"application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json"}
    manifest_types = {"application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json"}
    try:
        if not stat.S_ISREG(path.lstat().st_mode):
            raise ScanError("Image archive must be a regular file")
        with path.open("rb") as stream:
            size, members = path.stat().st_size, {}
            for _ in range(MAX_ARCHIVE_MEMBERS + 1):
                header = stream.read(512)
                if header == bytes(512):
                    if stream.read(512) != bytes(512) or any(stream.read(10240)) or stream.tell() != size:
                        raise ScanError("Invalid image archive terminator")
                    break
                if len(header) != 512 or len(members) >= MAX_ARCHIVE_MEMBERS:
                    raise ScanError("Image archive is truncated or exceeds the member limit")
                # Python and Go interpret GNU header prefix/atime bytes differently.
                if header[257:265] != b"ustar\x0000":
                    raise ScanError("Image archive requires canonical USTAR headers")
                info = tarfile.TarInfo.frombuf(header, "utf-8", "strict")
                name = info.name.rstrip("/") if info.type == tarfile.DIRTYPE else info.name
                if (info.type not in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE)
                        or not name or str(PurePosixPath(name)) != name or PurePosixPath(name).is_absolute()
                        or ".." in PurePosixPath(name).parts or "\\" in name or name in members
                        or info.size < 0 or info.type == tarfile.DIRTYPE and info.size != 0):
                    raise ScanError("Image archive contains ambiguous paths, links or unsupported TAR extensions")
                offset = stream.tell()
                end = offset + (info.size + 511) // 512 * 512
                if end > size:
                    raise ScanError("Image archive member is truncated")
                members[name] = (offset, info.size, info.type)
                stream.seek(end)
            else:
                raise ScanError("Image archive exceeds the member limit")

            remaining_json = MAX_IDENTITY_JSON

            def member(name):
                if not isinstance(name, str) or name not in members or members[name][2] == tarfile.DIRTYPE:
                    raise ScanError("Image archive is missing a referenced regular file")
                offset, length, _ = members[name]
                stream.seek(offset)
                return length

            def document(name):
                nonlocal remaining_json
                length = member(name)
                if length > MAX_IMAGE_JSON or length > remaining_json:
                    raise ScanError("Image identity JSON exceeds the byte budget")
                remaining_json -= length
                raw = stream.read(length)
                if len(raw) != length:
                    raise ScanError("Image identity JSON is truncated")
                def unique(pairs):
                    value, folded = {}, set()
                    for key, item in pairs:
                        if key.casefold() in folded:
                            raise ScanError("Duplicate image identity JSON key (case-insensitive)")
                        folded.add(key.casefold())
                        value[key] = item
                    return value
                value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique,
                                   parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Non-finite JSON")))
                return value, "sha256:" + hashlib.sha256(raw).hexdigest()

            def digest_member(name):
                remaining = member(name)
                digest = hashlib.sha256()
                while remaining:
                    block = stream.read(min(remaining, 1024 * 1024))
                    if not block:
                        raise ScanError("Image archive member is truncated")
                    remaining -= len(block)
                    digest.update(block)
                return "sha256:" + digest.hexdigest()

            def blob(descriptor):
                if (not isinstance(descriptor, dict) or not isinstance(descriptor.get("digest"), str)
                        or IMAGE_DIGEST.fullmatch(descriptor["digest"]) is None
                        or type(descriptor.get("size")) is not int or descriptor["size"] <= 0):
                    raise ScanError("Invalid image identity descriptor")
                name = "blobs/sha256/" + descriptor["digest"][7:]
                if member(name) != descriptor["size"]:
                    raise ScanError("Image descriptor size does not match its archive member")
                return name

            def verified_document(descriptor):
                value, digest = document(blob(descriptor))
                if digest != descriptor["digest"] or not isinstance(value, dict) or value.get("schemaVersion") != 2:
                    raise ScanError("Image manifest/index digest or schema does not match")
                return value

            compatible, _ = document("manifest.json")
            if not isinstance(compatible, list) or len(compatible) != 1 or not isinstance(compatible[0], dict):
                raise ScanError("Image archive must select exactly one Docker image")
            selected = compatible[0]
            config, config_id = document(selected.get("Config"))
            if (not isinstance(config, dict) or not isinstance(config.get("rootfs"), dict)
                    or config["rootfs"].get("type") != "layers" or not isinstance(config["rootfs"].get("diff_ids"), list)):
                raise ScanError("Invalid image configuration/rootfs")
            diff_ids, layers = config["rootfs"]["diff_ids"], selected.get("Layers")
            if (not diff_ids or not all(isinstance(item, str) and IMAGE_DIGEST.fullmatch(item) for item in diff_ids)
                    or not isinstance(layers, list) or len(layers) != len(diff_ids)
                    or config.get("architecture") != inspection.get("Architecture") or config.get("os") != inspection.get("Os")
                    or inspection.get("RootFS") != {"Type": "layers", "Layers": diff_ids}):
                raise ScanError("Exported image platform/rootfs does not match inspection")
            inspected_id = inspection.get("Id")
            manifest_id, expected_layers = None, diff_ids
            if config_id != inspected_id:
                root = inspection.get("Descriptor")
                if not isinstance(root, dict) or root.get("digest") != inspected_id:
                    raise ScanError("No descriptor binds the inspected image to the archive config")
                value = verified_document(root)
                if root.get("mediaType") in index_types:
                    candidates = value.get("manifests")
                    if not isinstance(candidates, list) or not all(isinstance(item, dict) for item in candidates):
                        raise ScanError("Invalid image index")
                    candidates = [item for item in candidates if isinstance(item.get("platform"), dict)
                                  and item["platform"].get("architecture") == inspection["Architecture"]
                                  and item["platform"].get("os") == inspection["Os"]]
                    if len(candidates) != 1:
                        raise ScanError("Image index does not select one unambiguous inspected platform")
                    root = candidates[0]
                    value = verified_document(root)
                if root.get("mediaType") not in manifest_types:
                    raise ScanError("Unsupported image manifest descriptor")
                manifest_id = root["digest"]
                if blob(value.get("config")) != selected["Config"] or value["config"]["digest"] != config_id:
                    raise ScanError("Image manifest does not bind the selected config")
                descriptors = value.get("layers")
                if not isinstance(descriptors, list) or [blob(item) for item in descriptors] != layers:
                    raise ScanError("Image manifest does not bind the selected layers")
                expected_layers = [item["digest"] for item in descriptors]
            layer_hashes = {name: digest_member(name) for name in dict.fromkeys(layers)}
            if [layer_hashes[name] for name in layers] != expected_layers:
                raise ScanError("Image layer bytes do not match the verified image identity")
            return {"inspected_id": inspected_id, "config_id": config_id, "manifest_id": manifest_id,
                    "layer_digests": expected_layers, "binding": "config" if manifest_id is None else "manifest/index -> manifest -> config"}
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, RecursionError, tarfile.HeaderError) as exc:
        raise ScanError(f"Invalid image archive identity ({type(exc).__name__})") from None


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
        raise ScanError("Trivy report image ID does not match the verified archive config")
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
                evidence["archive_identity"] = archive_identity(archive, evidence["inspection"])
                report = output / f"{name}.trivy.json"
                arguments = ["image", "--input", "/input/image.tar", "--cache-dir", "/cache", "--cache-backend", "memory",
                             "--skip-db-update", "--skip-java-db-update", "--offline-scan", "--disable-telemetry", "--no-progress",
                             "--scanners", "vuln", "--pkg-types", "os,library", "--detection-priority", "comprehensive",
                             "--severity", ",".join(SEVERITIES), "--ignore-unfixed=false", "--ignorefile", "/dev/null",
                             "--list-all-pkgs", "--exit-code", "0", "--parallel", "2", "--timeout", "15m", "--format", "json"]
                run_scanner(docker, arguments, report, output / f"{name}.scan.stderr.log", [(archive, "/input/image.tar", True), (cache, "/cache", True)])
                evidence["summary"] = summarize_report(load_json(report), evidence["archive_identity"]["config_id"])
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
