"""Saved Desktop policy is a narrow configuration check, not VM attestation."""

import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / "skills/rea-isolated/scripts"
sys.path.insert(0, str(SCRIPTS))
import container as boundary
import desktop_policy
import input_snapshot
import agent_container as pair


class DesktopPolicyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.home = Path(temporary.name).resolve()
        self.staging = self.home / "staging"
        self.staging.mkdir(mode=0o700)
        self.folder = self.home / "Library/Group Containers/group.com.docker"
        self.folder.mkdir(parents=True)

    def settings(self, shares, *, legacy=False, **extra):
        data = {"FilesharingDirectories": shares, "EnhancedContainerIsolation": False, "unrelatedSecret": "never-print-this", **extra}
        path = self.folder / ("settings.json" if legacy else "settings-store.json")
        path.write_text(json.dumps(data))
        return path

    def inspect(self, **kwargs):
        return desktop_policy.inspect(str(self.staging), home=self.home, host_os="darwin", **kwargs)

    def test_only_dedicated_saved_shares_satisfy_the_policy(self):
        self.settings([str(self.staging)])
        result = self.inspect()
        self.assertEqual(result["status"], "saved-share-policy-satisfied")
        self.assertIs(result["effective_vm_verified"], False)
        self.assertIs(result["eci"], False)  # ECI is a separate optional feature.
        self.assertNotIn("never-print-this", json.dumps(result))

    def test_broad_extra_empty_and_unrecognized_shares_are_not_accepted(self):
        for shares in ([str(self.home)], [str(self.staging), str(self.home)], ["/"], [], [7], "wrong", None):
            with self.subTest(shares=shares):
                self.settings(shares)
                self.assertNotEqual(self.inspect()["status"], "saved-share-policy-satisfied")

    def test_missing_malformed_duplicate_or_conflicting_settings_are_unknown(self):
        self.assertEqual(self.inspect()["status"], "unknown-saved-sharing")
        path = self.settings([str(self.staging)])
        for value in ("[]", "{", '{"FilesharingDirectories":[],"FilesharingDirectories":["/"]}'):
            with self.subTest(value=value):
                path.write_text(value)
                self.assertEqual(self.inspect()["status"], "unknown-saved-sharing")
        self.settings([str(self.staging)])
        self.settings([str(self.home)], legacy=True)
        self.assertEqual(self.inspect()["status"], "unknown-saved-sharing")

    def test_legacy_spelling_and_equal_projections_are_supported(self):
        self.settings([str(self.staging)])
        legacy = self.folder / "settings.json"
        legacy.write_text(json.dumps({"filesharingDirectories": [str(self.staging)], "enhancedContainerIsolation": False}))
        self.assertEqual(self.inspect()["status"], "saved-share-policy-satisfied")

    def test_windows_and_linux_desktop_do_not_inherit_macos_assurance(self):
        for host in ("win32", "linux"):
            with self.subTest(host=host):
                result = desktop_policy.inspect(str(self.staging), home=self.home, host_os=host)
                self.assertEqual(result["status"], "unsupported-desktop-host")
                with patch.object(desktop_policy, "inspect", return_value=result), self.assertRaises(ValueError):
                    desktop_policy.check({"desktop_share_policy": "strict", "staging_root": str(self.staging)}, desktop=True)
        self.assertEqual(self.inspect(desktop=False)["status"], "not-applicable-to-engine")

    def test_a_later_settings_change_cannot_reuse_a_clean_result(self):
        self.settings([str(self.staging)])
        config = {"desktop_share_policy": "strict", "staging_root": str(self.staging)}
        original = desktop_policy.inspect
        with patch.object(desktop_policy, "inspect", wraps=lambda root, **kwargs: original(root, home=self.home, host_os="darwin")):
            self.assertEqual(desktop_policy.check(config, desktop=True)["status"], "saved-share-policy-satisfied")
            self.settings([str(self.home)])
            with self.assertRaises(ValueError):
                desktop_policy.check(config, desktop=True)

    def test_snapshots_use_the_dedicated_root_and_are_removed(self):
        source = self.home / "inputs"
        source.mkdir()
        (source / "inert.bin").write_bytes(b"inert")
        temporary, snapshot = input_snapshot.stage(source, input_snapshot.manifest(source), staging_root=self.staging)
        try:
            self.assertEqual(snapshot.parent.parent, self.staging)
            self.assertEqual((snapshot / "inert.bin").read_bytes(), b"inert")
        finally:
            temporary.cleanup()
        self.assertEqual(list(self.staging.iterdir()), [])

    @unittest.skipIf(os.name == "nt", "POSIX ownership and mode check")
    def test_staging_root_is_private_real_and_not_an_account_directory(self):
        self.assertEqual(boundary.staging_directory(str(self.staging)), str(self.staging.resolve()))
        self.staging.chmod(0o755)
        with self.assertRaises(boundary.BoundaryError):
            boundary.staging_directory(str(self.staging))
        self.staging.chmod(0o700)
        alias = self.home / "alias"
        alias.symlink_to(self.staging, target_is_directory=True)
        with self.assertRaises(boundary.BoundaryError):
            boundary.staging_directory(str(alias))
        with patch.object(boundary, "account_homes", return_value=[self.staging]), self.assertRaises(boundary.BoundaryError):
            boundary.staging_directory(str(self.staging))

    @unittest.skipIf(os.name == "nt", "POSIX ownership and mode check")
    def test_staging_cannot_cover_account_homes_or_credential_directories(self):
        home = self.home / "account"
        home.mkdir(mode=0o700)
        with patch.object(boundary, "account_homes", return_value=[home]):
            for name in boundary.PROTECTED_HOME_DIRS:
                directory = home / name
                directory.mkdir(mode=0o700)
                with self.subTest(name=name), self.assertRaises(boundary.BoundaryError):
                    boundary.staging_directory(str(directory))
            with self.assertRaises(boundary.BoundaryError):
                boundary.staging_directory(str(self.home))

    def test_nonexistent_control_and_login_paths_stay_outside_staging(self):
        config = {"staging_root": str(self.staging)}
        for path in (self.staging / "rea.json", self.staging / "new" / "private" / "login.json", self.staging):
            with self.subTest(path=path), self.assertRaises(boundary.BoundaryError):
                boundary.keep_outside_staging(config, path)
        boundary.keep_outside_staging(config, self.home / "private" / "login.json")

    def test_future_paths_under_filesystem_aliases_stay_outside_staging(self):
        aliases = [self.staging.with_name(self.staging.name.upper())]
        if sys.platform == "darwin":
            aliases.append(Path("/System/Volumes/Data") / str(self.staging).lstrip("/"))
        tested = 0
        for alias in aliases:
            if alias.is_dir() and os.path.samefile(alias, self.staging):
                tested += 1
                with self.subTest(alias=alias), self.assertRaises(boundary.BoundaryError):
                    boundary.keep_outside_staging({"staging_root": str(self.staging)}, alias / "new" / "login.json")
        if not tested:
            self.skipTest("No case-insensitive or macOS firmlink alias on this filesystem")

    def test_a_strict_saved_share_failure_happens_before_container_creation(self):
        self.settings([str(self.home)])
        original = desktop_policy.inspect
        config = {"context": "fixture", "staging_root": str(self.staging), "desktop_share_policy": "strict"}
        version = {"Server": {"Os": "linux", "Version": "29.8.2", "Platform": {"Name": "Docker Desktop 4.95.0"}}}
        context = [{"Endpoints": {"docker": {"Host": "unix:///fixture/docker.sock"}}}]
        with patch.object(boundary, "docker_json", side_effect=[context, version]), patch.object(boundary, "docker") as docker, \
                patch.object(desktop_policy, "inspect", wraps=lambda root, **kwargs: original(root, home=self.home, host_os="darwin")):
            with self.assertRaises(ValueError):
                boundary._run_checked(config, "probe")
        docker.assert_not_called()

    def test_empty_diagnostics_use_only_dedicated_staging_and_cleanup(self):
        def checked(config, mode):
            empty = Path(config["input_dir"])
            self.assertEqual(empty.parent.parent, self.staging)
            self.assertEqual(list(empty.iterdir()), [])
            return 0
        with patch.object(boundary, "validate_config"), patch.object(boundary, "_run_checked", side_effect=checked):
            self.assertEqual(boundary.run_container({"staging_root": str(self.staging)}, "probe"), 0)
        self.assertEqual(list(self.staging.iterdir()), [])

    def test_device_login_refuses_output_in_shared_staging_before_docker(self):
        from types import SimpleNamespace
        with patch.object(pair, "load_config", return_value=(None, {"client": "codex"}, {"staging_root": str(self.staging)})), \
                patch.object(pair.boundary, "preflight") as preflight, patch.object(pair.subprocess, "Popen") as popen:
            with self.assertRaises(boundary.BoundaryError):
                pair.codex_login(SimpleNamespace(config="unused", output=str(self.staging / "login.json")))
        preflight.assert_not_called()
        popen.assert_not_called()


if __name__ == "__main__":
    unittest.main()
