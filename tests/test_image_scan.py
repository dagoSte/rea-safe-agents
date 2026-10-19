"""Offline image scanner fixtures: isolation, report policy and failure evidence."""

from datetime import datetime, timedelta, timezone
import gzip
import hashlib
import json
import io
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import scan_images as scan

IMAGE_ID = "sha256:" + "a" * 64
NOW = datetime(2026, 10, 19, 12, tzinfo=timezone.utc)


def report_fixture(image_id=IMAGE_ID):
    return {"SchemaVersion": 2, "ArtifactType": "container_image", "Metadata": {"ImageID": image_id}, "Results": [
        {"Target": "debian", "Class": "os-pkgs", "Type": "debian", "Packages": [{"Name": "libc6", "Version": "2.36"}],
         "Vulnerabilities": [{"VulnerabilityID": "CVE-2099-0001", "PkgName": "libc6", "InstalledVersion": "2.36", "Severity": "HIGH"}]},
        {"Target": "app.jar", "Class": "lang-pkgs", "Type": "jar", "Packages": [{"Name": "example:dependency", "Version": "1.0"}],
         "Vulnerabilities": [{"VulnerabilityID": "CVE-2099-0002", "PkgName": "example:dependency", "InstalledVersion": "1.0", "Severity": "LOW", "FixedVersion": "1.1"}]},
        {"Target": "app/node_modules", "Class": "lang-pkgs", "Type": "node-pkg", "Packages": [{"Name": "example", "Version": "1.0"}]},
    ]}


def write_archive(path, files):
    with tarfile.open(path, "w", format=tarfile.USTAR_FORMAT) as archive:
        for name, raw in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            archive.addfile(info, io.BytesIO(raw))


def image_archive_fixture(path, mode="index", label="rea"):
    """Independent Docker-save metadata with distinct config/manifest/index IDs."""
    def encoded(value):
        return json.dumps(value, separators=(",", ":")).encode()
    def digest(raw):
        return "sha256:" + hashlib.sha256(raw).hexdigest()
    def blob(raw, media_type):
        value = {"mediaType": media_type, "digest": digest(raw), "size": len(raw)}
        files["blobs/sha256/" + value["digest"][7:]] = raw
        return value
    files = {}
    layer = b"uncompressed fixture layer for " + label.encode()
    diff_id = digest(layer)
    config = encoded({"architecture": "amd64", "os": "linux", "rootfs": {"type": "layers", "diff_ids": [diff_id]}, "config": {"User": label}})
    config_id = digest(config)
    inspection = {"Id": config_id, "Architecture": "amd64", "Os": "linux", "RootFS": {"Type": "layers", "Layers": [diff_id]}}
    manifest_id = None
    if mode == "legacy":
        config_path, layer_paths = config_id[7:] + ".json", ["layer/layer.tar"]
        files.update({config_path: config, layer_paths[0]: layer})
    else:
        config_descriptor = blob(config, "application/vnd.oci.image.config.v1+json")
        layer_descriptor = blob(gzip.compress(layer, mtime=0), "application/vnd.oci.image.layer.v1.tar+gzip")
        manifest = {"schemaVersion": 2, "config": config_descriptor, "layers": [layer_descriptor]}
        descriptor = blob(encoded(manifest), "application/vnd.oci.image.manifest.v1+json")
        manifest_id = descriptor["digest"]
        config_path, layer_paths = "blobs/sha256/" + config_id[7:], ["blobs/sha256/" + layer_descriptor["digest"][7:]]
        if mode == "index":
            descriptor["platform"] = {"architecture": "amd64", "os": "linux", "variant": "fixture"}
            index = {"schemaVersion": 2, "manifests": [descriptor,
                     {"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": "sha256:" + "f" * 64,
                      "size": 123, "platform": {"architecture": "unknown", "os": "unknown"}}]}
            descriptor = blob(encoded(index), "application/vnd.oci.image.index.v1+json")
        inspection.update(Id=descriptor["digest"], Descriptor=descriptor)
    files["manifest.json"] = encoded([{"Config": config_path, "Layers": layer_paths, "RepoTags": []}])
    write_archive(path, files)
    return {"inspection": inspection, "config_id": config_id, "manifest_id": manifest_id, "files": files,
            "config_path": config_path, "layer_path": layer_paths[0]}


class ImageScanTests(unittest.TestCase):
    def test_full_pipeline_uses_immutable_images_and_separates_network_access(self):
        with tempfile.TemporaryDirectory() as temporary:
            output, commands = Path(temporary), []
            fixtures = {name: image_archive_fixture(output / (name + "-fixture.tar"), mode, name)
                        for name, mode in (("rea", "index"), ("agent", "legacy"))}
            def fake_run(command, stdout, log, **kwargs):
                commands.append(command)
                log.write_text("")
                if "inspect" in command:
                    reference = command[-1]
                    value = {"Id": IMAGE_ID} if reference == scan.SCANNER_IMAGE else fixtures["agent" if reference.startswith("rea-agent-") else "rea"]["inspection"]
                    scan.write_json(stdout, [value])
                elif "--version" in command:
                    scan.write_json(stdout, {"Version": scan.SCANNER_VERSION})
                elif "--download-db-only" in command or "--download-java-db-only" in command:
                    name = "db" if "--download-db-only" in command else "java-db"
                    cache = output / "cache" / name
                    cache.mkdir()
                    scan.write_json(cache / "metadata.json", {"UpdatedAt": NOW.isoformat()})
                    (cache / ("trivy.db" if name == "db" else "trivy-java.db")).write_bytes(b"fixture")
                    stdout.write_bytes(b"")
                elif "save" in command:
                    fixture = next(value for value in fixtures.values() if value["inspection"]["Id"] == command[-1])
                    write_archive(Path(command[command.index("--output") + 1]), fixture["files"])
                    stdout.write_bytes(b"")
                elif "convert" in command:
                    scan.write_json(stdout, {"bomFormat": "CycloneDX", "components": [{"name": "example"}]})
                else:
                    scan.write_json(stdout, report_fixture(fixtures[stdout.name.split(".")[0]]["config_id"]))
            with patch.object(scan, "run", side_effect=fake_run), patch.object(scan, "utc_now", return_value=NOW):
                provenance = scan.scan(["docker"], output)
            self.assertEqual(provenance["status"], "complete")
            self.assertEqual(set(provenance["images"]), {"rea", "agent"})
            self.assertFalse(list(output.glob("*-archive-*")))
            for command in commands:
                if "save" in command:
                    self.assertIn(command[-1], {value["inspection"]["Id"] for value in fixtures.values()})
                if "--network" in command:
                    network = command[command.index("--network") + 1]
                    if network == "bridge":
                        self.assertNotIn("/input/", " ".join(command))
                    if "--input" in command:
                        self.assertEqual(network, "none")
                        self.assertIn("--ignore-unfixed=false", command)
                        self.assertEqual(command[command.index("--ignorefile") + 1], "/dev/null")
                        self.assertEqual(command[command.index("--severity") + 1], ",".join(scan.SEVERITIES))
            for name in ("rea", "agent"):
                self.assertEqual(provenance["images"][name]["status"], "complete")
                self.assertEqual(provenance["images"][name]["archive_identity"]["config_id"], fixtures[name]["config_id"])
                self.assertTrue((output / f"{name}.cyclonedx.json").exists())

    def test_legacy_manifest_and_containerd_index_bind_report_to_config(self):
        for mode in ("legacy", "manifest", "index"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "image.tar"
                fixture = image_archive_fixture(path, mode)
                identity = scan.archive_identity(path, fixture["inspection"])
                self.assertEqual(identity["config_id"], fixture["config_id"])
                self.assertEqual(identity["manifest_id"], fixture["manifest_id"])
                scan.summarize_report(report_fixture(fixture["config_id"]), identity["config_id"])
                if mode != "legacy":
                    self.assertNotEqual(fixture["inspection"]["Id"], fixture["config_id"])
                    with self.assertRaises(scan.ScanError):
                        scan.summarize_report(report_fixture(fixture["inspection"]["Id"]), identity["config_id"])

    def test_archive_rejects_tampered_config_manifest_index_or_layer(self):
        for mode in ("legacy", "index"):
            with tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "image.tar"
                fixture = image_archive_fixture(path, mode)
                for name, original in fixture["files"].items():
                    if name == "manifest.json":
                        continue
                    tampered = dict(fixture["files"])
                    tampered[name] = bytes([original[0] ^ 1]) + original[1:]
                    write_archive(path, tampered)
                    with self.subTest(mode=mode, member=name), self.assertRaises(scan.ScanError):
                        scan.archive_identity(path, fixture["inspection"])

    def test_archive_rejects_unrelated_compatibility_config_and_layers(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "image.tar"
            fixture = image_archive_fixture(path)
            for key, replacement in (("Config", "foreign.json"), ("Layers", ["foreign.tar"])):
                files = dict(fixture["files"])
                compatible = json.loads(files["manifest.json"])
                compatible[0][key] = replacement
                files["foreign.json"] = files[fixture["config_path"]].replace(b'"User":"rea"', b'"User":"foreign"')
                files["foreign.tar"] = b"foreign layer"
                files["manifest.json"] = json.dumps(compatible).encode()
                write_archive(path, files)
                with self.subTest(key=key), self.assertRaises(scan.ScanError):
                    scan.archive_identity(path, fixture["inspection"])

    def test_archive_rejects_missing_blobs_and_wrong_inspection(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "image.tar"
            fixture = image_archive_fixture(path)
            for name in fixture["files"]:
                files = dict(fixture["files"])
                del files[name]
                write_archive(path, files)
                with self.subTest(missing=name), self.assertRaises(scan.ScanError):
                    scan.archive_identity(path, fixture["inspection"])
            write_archive(path, fixture["files"])
            for change in ({"Id": IMAGE_ID}, {"RootFS": {"Type": "layers", "Layers": [IMAGE_ID]}}, {"Architecture": "arm64"}):
                with self.subTest(change=change), self.assertRaises(scan.ScanError):
                    scan.archive_identity(path, fixture["inspection"] | change)

    def test_archive_rejects_ambiguous_platform_and_multiple_docker_images(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "image.tar"
            fixture = image_archive_fixture(path)
            root_path = "blobs/sha256/" + fixture["inspection"]["Id"][7:]
            files = dict(fixture["files"])
            index = json.loads(files[root_path])
            index["manifests"].append(index["manifests"][0])
            raw = json.dumps(index).encode()
            root_id = "sha256:" + hashlib.sha256(raw).hexdigest()
            files["blobs/sha256/" + root_id[7:]] = raw
            write_archive(path, files)
            inspection = fixture["inspection"] | {"Id": root_id, "Descriptor": fixture["inspection"]["Descriptor"] | {"digest": root_id, "size": len(raw)}}
            with self.assertRaisesRegex(scan.ScanError, "unambiguous"):
                scan.archive_identity(path, inspection)
            files = dict(fixture["files"])
            compatible = json.loads(files["manifest.json"])
            files["manifest.json"] = json.dumps(compatible * 2).encode()
            write_archive(path, files)
            with self.assertRaisesRegex(scan.ScanError, "exactly one"):
                scan.archive_identity(path, fixture["inspection"])

    def test_archive_metadata_is_bounded_and_duplicate_members_fail(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "image.tar"
            fixture = image_archive_fixture(path)
            files = dict(fixture["files"])
            files["manifest.json"] = b" " * (scan.MAX_IMAGE_JSON + 1)
            write_archive(path, files)
            with self.assertRaisesRegex(scan.ScanError, "byte budget"):
                scan.archive_identity(path, fixture["inspection"])
            write_archive(path, fixture["files"])
            with patch.object(scan, "MAX_ARCHIVE_MEMBERS", 1), self.assertRaisesRegex(scan.ScanError, "member limit"):
                scan.archive_identity(path, fixture["inspection"])
            with tarfile.open(path, "w", format=tarfile.USTAR_FORMAT) as archive:
                for _ in range(2):
                    info = tarfile.TarInfo("manifest.json")
                    info.size = 2
                    archive.addfile(info, io.BytesIO(b"[]"))
            with self.assertRaisesRegex(scan.ScanError, "ambiguous paths"):
                scan.archive_identity(path, fixture["inspection"])

    def test_archive_rejects_extensions_links_truncation_and_duplicate_json_keys(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "image.tar"
            fixture = image_archive_fixture(path)
            for kind in (tarfile.XHDTYPE, tarfile.GNUTYPE_LONGNAME, tarfile.SYMTYPE, tarfile.LNKTYPE):
                info = tarfile.TarInfo("unsupported")
                info.type, info.size = kind, 2 ** 32
                path.write_bytes(info.tobuf(format=tarfile.USTAR_FORMAT) + bytes(1024))
                with self.subTest(kind=kind), self.assertRaisesRegex(scan.ScanError, "unsupported TAR"):
                    scan.archive_identity(path, fixture["inspection"])
            write_archive(path, fixture["files"])
            path.write_bytes(path.read_bytes()[:515])
            with self.assertRaises(scan.ScanError):
                scan.archive_identity(path, fixture["inspection"])
            files = dict(fixture["files"])
            files["manifest.json"] = b'[{"Config":"a","Config":"b","Layers":[]}]'
            write_archive(path, files)
            with self.assertRaisesRegex(scan.ScanError, "Duplicate image identity JSON key"):
                scan.archive_identity(path, fixture["inspection"])

    def test_archive_rejects_gnu_header_shadowing_the_docker_manifest(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "image.tar"
            fixture = image_archive_fixture(path, "legacy")
            files = dict(fixture["files"])
            files["foreign/layer.tar"] = b"foreign layer"
            write_archive(path, files)
            genuine = path.read_bytes()
            shadow = json.dumps([{"Config": fixture["config_path"], "Layers": ["foreign/layer.tar"]}]).encode()
            info = tarfile.TarInfo("manifest.json")
            info.size = len(shadow)
            header = bytearray(info.tobuf(format=tarfile.GNU_FORMAT))
            header[345:357] = b"00000000123\0"  # GNU atime; Python reads this as a USTAR prefix.
            header[148:156] = b"        "
            header[148:156] = f"{sum(header):06o}\0 ".encode()
            self.assertEqual(tarfile.TarInfo.frombuf(header, "utf-8", "strict").name, "00000000123/manifest.json")
            path.write_bytes(header + shadow + bytes(-len(shadow) % 512) + genuine)
            with self.assertRaisesRegex(scan.ScanError, "canonical USTAR"):
                scan.archive_identity(path, fixture["inspection"])

    def test_archive_rejects_case_aliases_that_override_go_manifest_fields(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "image.tar"
            fixture = image_archive_fixture(path, "legacy")
            for field, alias_name, foreign in (("Layers", "layers", ["foreign/layer.tar"]),
                                               ("Layers", "Layerſ", ["foreign/layer.tar"]),
                                               ("Config", "config", "foreign/config.json"),
                                               ("RepoTags", "repotags", ["foreign:tag"]),
                                               ("LayerSources", "layersources", {}),
                                               ("Key", "Key", "foreign")):
                for alias_last in (True, False):
                    files = dict(fixture["files"])
                    selected = json.loads(files["manifest.json"])[0]
                    selected.setdefault("LayerSources", {})
                    selected.setdefault(field, "canonical")
                    files["manifest.json"] = json.dumps([selected]).encode()
                    write_archive(path, files)
                    self.assertEqual(scan.archive_identity(path, fixture["inspection"])["config_id"], fixture["config_id"])
                    alias = {alias_name: foreign}
                    selected = selected | alias if alias_last else alias | selected
                    files["manifest.json"] = json.dumps([selected]).encode()
                    files["foreign/layer.tar"] = b"foreign layer"
                    files["foreign/config.json"] = files[fixture["config_path"]]
                    write_archive(path, files)
                    with self.subTest(alias=alias_name, alias_last=alias_last), self.assertRaisesRegex(scan.ScanError, "case-insensitive"):
                        scan.archive_identity(path, fixture["inspection"])

    def test_full_report_keeps_unfixed_and_every_severity(self):
        summary = scan.summarize_report(report_fixture(), IMAGE_ID)
        self.assertEqual(summary["package_occurrences_by_type"], {"debian": 1, "jar": 1, "node-pkg": 1})
        self.assertEqual(summary["vulnerability_occurrences_by_severity"], {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 0, "HIGH": 1, "CRITICAL": 0})
        self.assertEqual(summary["unfixed_occurrences_by_severity"]["HIGH"], 1)
        self.assertEqual(summary["unfixed_occurrences_by_severity"]["LOW"], 0)

    def test_valid_zero_report_still_requires_package_inventory(self):
        report = report_fixture()
        for result in report["Results"]:
            result.pop("Vulnerabilities", None)
        self.assertFalse(any(scan.summarize_report(report, IMAGE_ID)["vulnerability_occurrences_by_severity"].values()))

    def test_malformed_or_wrong_target_reports_never_count_as_zero(self):
        mutations = [lambda r: r.update(SchemaVersion=1), lambda r: r.update(ArtifactType="filesystem"),
                     lambda r: r.update(Metadata=None), lambda r: r["Metadata"].update(ImageID="different"),
                     lambda r: r.update(Results=[]), lambda r: r.update(Results=None),
                     lambda r: r["Results"][0].update(Packages=None), lambda r: r["Results"][0].update(Vulnerabilities=None),
                     lambda r: r["Results"][0]["Packages"][0].pop("Version"),
                     lambda r: r["Results"][0]["Vulnerabilities"][0].update(Severity="invalid"),
                     lambda r: r["Results"][0]["Vulnerabilities"][0].update(FixedVersion=[]),
                     lambda r: r["Results"][0]["Vulnerabilities"][0].pop("PkgName"),
                     lambda r: r["Results"][0].update(Class="lang-pkgs")]
        for mutation in mutations:
            report = report_fixture()
            mutation(report)
            with self.subTest(mutation=mutation), self.assertRaises(scan.ScanError):
                scan.summarize_report(report, IMAGE_ID)

    def test_sbom_must_have_components(self):
        scan.validate_sbom({"bomFormat": "CycloneDX", "components": [{"name": "example"}]})
        for value in ({}, {"bomFormat": "CycloneDX", "components": []}, {"bomFormat": "CycloneDX", "components": [None]}):
            with self.subTest(value=value), self.assertRaises(scan.ScanError):
                scan.validate_sbom(value)

    def test_scan_container_has_no_socket_or_target_entrypoint(self):
        archive, cache = Path("/safe/image.tar"), Path("/safe/cache")
        command = scan.container(["docker", "--context", "review"], [(archive, "/input/image.tar", True), (cache, "/cache", True)])
        self.assertEqual(command[:3], ["docker", "--context", "review"])
        self.assertIn("ghcr.io/aquasecurity/trivy:0.76.0@sha256:", command[-1])
        for option, value in (("--network", "none"), ("--entrypoint", "trivy"), ("--cap-drop", "ALL"), ("--pull", "never"), ("--memory", "3g")):
            self.assertEqual(command[command.index(option) + 1], value)
        self.assertIn("--read-only", command)
        self.assertNotIn("docker.sock", " ".join(command))
        self.assertEqual([command[index + 1] for index, item in enumerate(command) if item == "--mount"],
                         [f"type=bind,source={archive},target=/input/image.tar,readonly", f"type=bind,source={cache},target=/cache,readonly"])

    def test_comma_in_bind_path_is_rejected(self):
        with self.assertRaises(scan.ScanError):
            scan.container(["docker"], [(Path("/unsafe,readonly=false"), "/cache", True)])

    def test_database_dates_age_and_hashes_are_recorded(self):
        with tempfile.TemporaryDirectory() as temporary:
            cache = Path(temporary)
            for name in scan.DB_REPOSITORIES:
                (cache / name).mkdir()
                scan.write_json(cache / name / "metadata.json", {"UpdatedAt": (NOW - timedelta(hours=3)).isoformat()})
                (cache / name / ("trivy.db" if name == "db" else "trivy-java.db")).write_bytes(b"offline fixture")
            metadata = scan.database_metadata(cache, NOW)
            self.assertEqual(metadata["java-db"]["age_hours"], 3)
            self.assertTrue(metadata["db"]["database_sha256"].startswith("sha256:"))
            for timestamp in ((NOW - timedelta(hours=49)).isoformat(), (NOW + timedelta(hours=2)).isoformat(), "2026-10-19", None):
                scan.write_json(cache / "db/metadata.json", {"UpdatedAt": timestamp})
                with self.subTest(timestamp=timestamp), self.assertRaises(scan.ScanError):
                    scan.database_metadata(cache, NOW)

    def test_reused_cache_cannot_expose_unrelated_host_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            cache = Path(temporary) / "cache"
            scan.prepare_cache(cache)
            (cache / "db").mkdir()
            (cache / "db/metadata.json").write_text("{}")
            scan.prepare_cache(cache)
            (cache / "private-key").write_text("synthetic")
            with self.assertRaisesRegex(scan.ScanError, "dedicated scanner cache"):
                scan.prepare_cache(cache)

    @unittest.skipIf(sys.platform == "win32", "Creating symlinks can require privileges on Windows")
    def test_reused_cache_rejects_symbolic_links(self):
        with tempfile.TemporaryDirectory() as temporary:
            cache = Path(temporary) / "cache"
            cache.mkdir()
            (cache / "db").symlink_to(Path(temporary), target_is_directory=True)
            with self.assertRaisesRegex(scan.ScanError, "links"):
                scan.prepare_cache(cache)

    @unittest.skipIf(sys.platform == "win32", "Hard-link fixture needs a local compatible filesystem")
    def test_reused_cache_rejects_hard_links_to_host_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            cache = Path(temporary) / "cache"
            (cache / "db").mkdir(parents=True)
            source = Path(temporary) / "synthetic-secret"
            source.write_text("synthetic")
            (cache / "db/trivy.db").hardlink_to(source)
            with self.assertRaisesRegex(scan.ScanError, "links"):
                scan.prepare_cache(cache)

    @unittest.skipIf(sys.platform == "win32", "FIFOs are a Unix filesystem feature")
    def test_reused_cache_rejects_fifos_before_reading_them(self):
        with tempfile.TemporaryDirectory() as temporary:
            cache = Path(temporary) / "cache"
            (cache / "db").mkdir(parents=True)
            scan.os.mkfifo(cache / "db/metadata.json")
            with self.assertRaisesRegex(scan.ScanError, "special files"):
                scan.prepare_cache(cache)

    def test_command_failure_preserves_partial_output_and_stderr(self):
        with tempfile.TemporaryDirectory() as temporary:
            output, log = Path(temporary) / "partial.json", Path(temporary) / "stderr.log"
            def failed(command, **kwargs):
                kwargs["stdout"].write(b"{partial")
                kwargs["stderr"].write(b"scanner failed")
                return subprocess.CompletedProcess(command, 7)
            with patch.object(scan.subprocess, "run", side_effect=failed), self.assertRaisesRegex(scan.ScanError, "exited 7"):
                scan.run(["fixture"], output, log)
            self.assertEqual(output.read_text(), "{partial")
            self.assertEqual(log.read_text(), "scanner failed")

    def test_timeout_fails_instead_of_producing_a_summary(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(scan.subprocess, "run", side_effect=subprocess.TimeoutExpired("fixture", 1)):
            with self.assertRaisesRegex(scan.ScanError, "TimeoutExpired"):
                scan.run(["fixture"], Path(temporary) / "partial", Path(temporary) / "stderr")

    def test_timeout_removes_only_its_own_named_container(self):
        for context in ("review", "run"):
            with self.subTest(context=context), tempfile.TemporaryDirectory() as temporary, patch.object(scan.subprocess, "run", side_effect=[
                    subprocess.TimeoutExpired("fixture", 1), subprocess.CompletedProcess([], 0)]) as runner:
                with self.assertRaisesRegex(scan.ScanError, "TimeoutExpired"):
                    scan.run_scanner(["docker", "--context", context], ["--version"], Path(temporary) / "partial", Path(temporary) / "stderr")
            command = runner.call_args_list[0].args[0]
            name = command[command.index("--name") + 1]
            self.assertEqual(runner.call_args_list[1].args[0], ["docker", "--context", context, "rm", "--force", name])

    def test_malformed_json_is_a_scan_error(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "broken.json"
            path.write_text("{partial")
            with self.assertRaises(scan.ScanError):
                scan.load_json(path)

    def test_operational_failure_writes_incomplete_provenance(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(scan, "inspect", side_effect=scan.ScanError("unavailable")):
            output = Path(temporary)
            with self.assertRaises(scan.ScanError):
                scan.scan(["docker"], output)
            provenance = scan.load_json(output / "provenance.json")
            self.assertEqual(provenance["status"], "incomplete")
            self.assertEqual(provenance["error"], "unavailable")
            self.assertEqual(provenance["images"], {})
            self.assertIn("report-only", provenance["policy"])

    def test_malformed_version_object_is_a_controlled_scan_error(self):
        for value in ([], None, "0.76.0"):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary)
                def malformed_version(docker, arguments, path, log):
                    scan.write_json(path, value)
                with patch.object(scan, "inspect", return_value={"Id": IMAGE_ID}), patch.object(scan, "run_scanner", side_effect=malformed_version):
                    with self.assertRaisesRegex(scan.ScanError, "binary version"):
                        scan.scan(["docker"], output)
                provenance = scan.load_json(output / "provenance.json")
                self.assertEqual(provenance["status"], "incomplete")
                self.assertIn("binary version", provenance["error"])

    def test_output_inside_repository_is_refused_before_docker(self):
        with patch.object(scan, "scan") as scanner, patch.object(sys, "stderr", io.StringIO()), self.assertRaises(SystemExit):
            scan.main(["--output-dir", str(ROOT / "do-not-create-scan-output")])
        scanner.assert_not_called()

    def test_database_cache_inside_repository_is_refused(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(scan, "scan") as scanner, patch.object(sys, "stderr", io.StringIO()), self.assertRaises(SystemExit):
            scan.main(["--output-dir", str(Path(temporary) / "new-output"), "--cache-dir", str(ROOT / "cache")])
        scanner.assert_not_called()

    def test_explicit_database_cache_is_forwarded_without_copying(self):
        with tempfile.TemporaryDirectory() as temporary:
            output, cache = Path(temporary) / "reports", Path(temporary) / "db-cache"
            with patch.object(scan, "scan", return_value={"images": {}}) as scanner, patch.object(sys, "stdout", io.StringIO()):
                self.assertEqual(scan.main(["--output-dir", str(output), "--cache-dir", str(cache)]), 0)
            scanner.assert_called_once_with(["docker"], output.resolve(), cache.resolve())


if __name__ == "__main__":
    unittest.main()
