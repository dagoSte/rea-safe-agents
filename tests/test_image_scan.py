"""Offline image scanner fixtures: isolation, report policy and failure evidence."""

from datetime import datetime, timedelta, timezone
import json
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import scan_images as scan

IMAGE_ID = "sha256:" + "a" * 64
NOW = datetime(2026, 10, 19, 12, tzinfo=timezone.utc)


def report_fixture():
    return {"SchemaVersion": 2, "ArtifactType": "container_image", "Metadata": {"ImageID": IMAGE_ID}, "Results": [
        {"Target": "debian", "Class": "os-pkgs", "Type": "debian", "Packages": [{"Name": "libc6", "Version": "2.36"}],
         "Vulnerabilities": [{"VulnerabilityID": "CVE-2099-0001", "PkgName": "libc6", "InstalledVersion": "2.36", "Severity": "HIGH"}]},
        {"Target": "app.jar", "Class": "lang-pkgs", "Type": "jar", "Packages": [{"Name": "example:dependency", "Version": "1.0"}],
         "Vulnerabilities": [{"VulnerabilityID": "CVE-2099-0002", "PkgName": "example:dependency", "InstalledVersion": "1.0", "Severity": "LOW", "FixedVersion": "1.1"}]},
        {"Target": "app/node_modules", "Class": "lang-pkgs", "Type": "node-pkg", "Packages": [{"Name": "example", "Version": "1.0"}]},
    ]}


class ImageScanTests(unittest.TestCase):
    def test_full_pipeline_uses_immutable_images_and_separates_network_access(self):
        with tempfile.TemporaryDirectory() as temporary:
            output, commands = Path(temporary), []
            def fake_run(command, stdout, log, **kwargs):
                commands.append(command)
                log.write_text("")
                if "inspect" in command:
                    scan.write_json(stdout, [{"Id": IMAGE_ID, "Os": "linux", "Architecture": "arm64"}])
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
                    Path(command[command.index("--output") + 1]).write_bytes(b"archive fixture")
                    stdout.write_bytes(b"")
                elif "convert" in command:
                    scan.write_json(stdout, {"bomFormat": "CycloneDX", "components": [{"name": "example"}]})
                else:
                    scan.write_json(stdout, report_fixture())
            with patch.object(scan, "run", side_effect=fake_run), patch.object(scan, "utc_now", return_value=NOW):
                provenance = scan.scan(["docker"], output)
            self.assertEqual(provenance["status"], "complete")
            self.assertEqual(set(provenance["images"]), {"rea", "agent"})
            self.assertFalse(list(output.glob("*-archive-*")))
            for command in commands:
                if "save" in command:
                    self.assertEqual(command[-1], IMAGE_ID)  # changing a tag after inspect cannot change the scanned bytes
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
                self.assertTrue((output / f"{name}.cyclonedx.json").exists())

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
