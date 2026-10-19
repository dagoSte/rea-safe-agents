import csv
import importlib.util
from pathlib import Path
import os
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "skills/rea-isolated/scripts/container.py"
spec = importlib.util.spec_from_file_location("rea_container", SCRIPT)
boundary = importlib.util.module_from_spec(spec)
spec.loader.exec_module(boundary)
ACCOUNT_HOMES = boundary.account_homes
IMAGE ="sha256:" + "a" * 64
CID = "b" * 64
ENV = ["PATH=/usr/local/bin:/usr/bin:/bin", "NODE_VERSION=24.22.0"]


def approved(config):
    return {
        "Id": CID, "Image": IMAGE, "State": {"Running": False},
        "Config": {
            "User": boundary.USER, "WorkingDir": "/input", "Volumes": None,
            "Entrypoint": ["/usr/local/bin/rea"], "Cmd": ["mcp"],
            "Env": [*ENV, "HOME=/home/node"], "Tty": False, "OpenStdin": True,
        },
        "HostConfig": {
            "NetworkMode": "none", "ReadonlyRootfs": True, "Privileged": False,
            "Init": True, "AutoRemove": True, "CapDrop": ["ALL"], "CapAdd": None,
            "LogConfig": {"Type": "none", "Config": {}},
            "SecurityOpt": ["no-new-privileges:true"], "Memory": boundary.MEMORY,
            "MemorySwap": boundary.MEMORY, "NanoCpus": boundary.CPUS,
            "PidsLimit": boundary.PIDS, "Tmpfs": dict(boundary.TMPFS),
            "IpcMode": "private", "CgroupnsMode": "private",
        },
        "Mounts": [{"Type": "bind", "Source": config["input_dir"], "Destination": "/input", "RW": False}],
    }


class ContainerPolicyTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name)
        # A separate fixture home keeps these tests independent of the runner's
        # account and outside the directories that other tests select.
        homes_directory = tempfile.TemporaryDirectory()
        self.addCleanup(homes_directory.cleanup)
        self.home = (Path(homes_directory.name) / "account home").resolve()
        for name in (".ssh", ".docker"):
            (self.home / name).mkdir(parents=True)
        homes = patch.object(boundary, "account_homes", return_value=[self.home])
        homes.start()
        self.addCleanup(homes.stop)
        self.binary = root / "docker"
        self.binary.touch()
        self.inputs = root / "input files, selected"
        self.inputs.mkdir()
        control = root / "docker-control"
        control.mkdir()
        self.config = {"schema": 1, "docker": str(self.binary.resolve()), "docker_config": str(control.resolve()), "context": "desktop-linux", "image_id": IMAGE, "input_dir": str(self.inputs.resolve())}

    def test_approved_inspection_is_accepted(self):
        boundary.validate_config(self.config)
        evidence = boundary.verify_container(self.config, approved(self.config), "mcp", ENV)
        self.assertEqual(evidence["network"], "none")

    def test_dangerous_runtime_settings_are_rejected(self):
        overrides = {
            "NetworkMode": "host", "ReadonlyRootfs": False, "Privileged": True,
            "Init": False, "AutoRemove": False, "CapDrop": [], "CapAdd": ["SYS_ADMIN"],
            "LogConfig": {"Type": "json-file"},
            "SecurityOpt": ["seccomp=unconfined"], "Memory": 0, "MemorySwap": -1,
            "NanoCpus": 0, "PidsLimit": 0, "Tmpfs": {"/home": "rw"},
            "Binds": ["/:/host:rw"], "VolumesFrom": ["another-container"],
            "Devices": [{"PathOnHost": "/dev/kvm"}], "DeviceRequests": [{"Count": -1}],
            "DeviceCgroupRules": ["a *:* rwm"], "PidMode": "host", "IpcMode": "host",
            "UTSMode": "host", "CgroupnsMode": "host", "UsernsMode": "host",
            "GroupAdd": ["0"], "PublishAllPorts": True, "PortBindings": {"80/tcp": [{}]},
        }
        for key, value in overrides.items():
            with self.subTest(setting=key):
                data = approved(self.config)
                data["HostConfig"][key] = value
                with self.assertRaises(boundary.BoundaryError):
                    boundary.verify_container(self.config, data, "mcp", ENV)

    def test_unexpected_mounts_and_environment_are_rejected(self):
        for mutate in [
            lambda d: d["Mounts"].append({"Type": "bind", "Source": "/var/run/docker.sock", "Destination": "/var/run/docker.sock", "RW": True}),
            lambda d: d["Mounts"][0].update(RW=True),
            lambda d: d["Mounts"][0].update(Source="/unapproved"),
            lambda d: d["Config"]["Env"].append("HTTPS_PROXY=http://user:secret@proxy"),
            lambda d: d["Config"].update(User="0:0"),
            lambda d: d["Config"].update(Entrypoint=["sh"]),
            lambda d: d["Config"].update(Cmd=["-c", "host-command"]),
            lambda d: d["Config"].update(Volumes={"/data": {}}),
            lambda d: d["Config"].update(Tty=True),
            lambda d: d["Config"].update(OpenStdin=False),
            lambda d: d.update(Image="sha256:" + "c" * 64),
            lambda d: d["State"].update(Running=True),
        ]:
            data = approved(self.config)
            mutate(data)
            with self.assertRaises(boundary.BoundaryError):
                boundary.verify_container(self.config, data, "mcp", ENV)

    def test_failed_inspection_never_starts_container_and_cleans_up(self):
        data = approved(self.config)
        data["HostConfig"]["NetworkMode"] = "bridge"
        calls = []
        def fake_docker(config, args, **kwargs):
            calls.append(args)
            return subprocess.CompletedProcess(args, 0, stdout=CID, stderr="")
        with patch.object(boundary, "preflight", return_value={}), patch.object(boundary, "docker", side_effect=fake_docker), patch.object(boundary, "docker_json", side_effect=[[{"Id": IMAGE, "Config": {"Env": ENV}}], [data]]):
            with self.assertRaises(boundary.BoundaryError):
                boundary._run_checked(self.config, "mcp")
        self.assertFalse(any(args[0] == "start" for args in calls))
        self.assertIn(["rm", "--force", CID], calls)

    def test_interrupted_attach_still_removes_its_exact_container(self):
        calls = []
        def fake_docker(config, args, **kwargs):
            calls.append(args)
            if args[0] == "start":
                raise KeyboardInterrupt
            return subprocess.CompletedProcess(args, 0, stdout=CID, stderr="")
        with patch.object(boundary, "preflight", return_value={}), patch.object(boundary, "docker", side_effect=fake_docker), patch.object(boundary, "docker_json", side_effect=[[{"Id": IMAGE, "Config": {"Env": ENV}}], [approved(self.config)]]):
            with self.assertRaises(KeyboardInterrupt):
                boundary._run_checked(self.config, "mcp")
        self.assertEqual(calls[-1], ["rm", "--force", CID])

    def test_public_launcher_refuses_host_mcp_and_diagnostics_mount_only_empty_copies(self):
        with patch.object(boundary, "_run_checked") as checked:
            with self.assertRaises(boundary.BoundaryError):
                boundary.run_container(self.config, "mcp")
            checked.assert_not_called()
        (self.inputs / "must-not-be-mounted.txt").write_bytes(b"original bytes")
        def inspect(config, mode):
            self.assertEqual(mode, "version")
            mounted = Path(config["input_dir"])
            self.assertNotEqual(mounted, self.inputs)
            self.assertEqual(list(mounted.iterdir()), [])
            return 0
        with patch.object(boundary, "_run_checked", side_effect=inspect):
            self.assertEqual(boundary.run_container(self.config, "version"), 0)

    def test_invalid_config_cannot_add_flags_or_mutable_image(self):
        for extra in [{"extra_args": ["--privileged"]}, {"image_id": "rea-local:latest"}, {"context": "--host=tcp://host"}]:
            config = {**self.config, **extra}
            with self.assertRaises(boundary.BoundaryError):
                boundary.validate_config(config)

    def test_home_roots_and_symlinks_are_rejected(self):
        for path in [self.home, self.home.parent, self.home / ".ssh", Path(self.home.anchor)]:
            with self.assertRaises(boundary.BoundaryError):
                boundary.input_directory(str(path))
        with patch.object(boundary.os.path, "ismount", return_value=True):
            with self.assertRaises(boundary.BoundaryError):
                boundary.input_directory(str(self.inputs))
        link = Path(self.directory.name) / "linked-input"
        try:
            link.symlink_to(self.inputs, target_is_directory=True)
        except (OSError, NotImplementedError):
            return  # Native Windows may deny symlink creation without developer mode.
        with self.assertRaises(boundary.BoundaryError):
            boundary.input_directory(str(link))

    def test_alternate_spellings_of_protected_directories_are_rejected(self):
        if not Path(str(self.home).swapcase()).exists():
            self.skipTest("Case-sensitive filesystem has no alternate spelling")
        for path in [self.home, self.home.parent, self.home / ".ssh", self.home / ".docker"]:
            with self.subTest(path=path), self.assertRaises(boundary.BoundaryError):
                boundary.input_directory(str(path).swapcase())
        config = {**self.config, "input_dir": self.config["docker_config"].swapcase()}
        with self.assertRaises(boundary.BoundaryError):
            boundary.validate_config(config)

    def test_another_path_to_the_same_volume_cannot_expose_the_home(self):
        # Simulate a macOS firmlink or bind mount: a second directory whose
        # subtree holds the same home without being one of its spelled parents.
        alias = Path(self.directory.name) / "data volume"
        alias.mkdir()
        alias = alias.resolve()
        tail = Path(*self.home.parts[1:])
        real = boundary.same_directory
        def same_directory(first, second):
            if Path(first) == alias / tail:
                first = self.home
            return real(first, second)
        with patch.object(boundary, "same_directory", side_effect=same_directory):
            with self.assertRaises(boundary.BoundaryError):
                boundary.input_directory(str(alias))
            boundary.input_directory(str(self.inputs))

    @unittest.skipIf(boundary.pwd is None, "No account database module on Windows")
    def test_redirected_home_does_not_unprotect_the_account_home(self):
        account = SimpleNamespace(pw_dir=str(self.home))
        with patch.dict(os.environ, {"HOME": str(self.inputs)}), patch.object(boundary.pwd, "getpwuid", return_value=account), \
                patch.object(boundary, "account_homes", ACCOUNT_HOMES):
            self.assertIn(self.home, boundary.account_homes())
            with self.assertRaises(boundary.BoundaryError):
                boundary.input_directory(str(self.home))
        with patch.object(boundary.pwd, "getpwuid", side_effect=KeyError(0)):
            with self.assertRaises(boundary.BoundaryError):
                ACCOUNT_HOMES()

    @unittest.skipUnless(os.name == "nt", "Native Windows profile lookup")
    def test_redirected_userprofile_does_not_unprotect_the_windows_profile(self):
        profile = Path.home().resolve()
        with patch.dict(os.environ, {"USERPROFILE": str(self.inputs), "HOME": str(self.inputs)}):
            homes = ACCOUNT_HOMES()
        self.assertTrue(any(boundary.same_directory(home, profile) for home in homes))

    def test_paths_remain_data_in_csv_and_subprocess_arguments(self):
        for path in ["/input files/a,b", "C:\\Input files\\a,b", "/literal/$(touch unexpected)"]:
            fields = next(csv.reader([boundary.mount_spec(path)]))
            self.assertEqual(fields, ["type=bind", "source=" + path, "target=/input", "readonly"])
        args = boundary.create_args(self.config, "mcp")
        with patch.object(boundary.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, stdout="", stderr="")) as run:
            boundary.docker(self.config, args)
            self.assertIs(run.call_args.kwargs["shell"], False)
            self.assertEqual(run.call_args.kwargs["stdin"], subprocess.DEVNULL)
            self.assertEqual(run.call_args.kwargs["encoding"], "utf-8")
            self.assertEqual(run.call_args.args[0][:5], [self.config["docker"], "--config", self.config["docker_config"], "--context", "desktop-linux"])

    def test_docker_control_metadata_cannot_be_mounted_as_input(self):
        for source in [self.config["docker_config"], str(Path(self.config["docker_config"]).parent)]:
            config = {**self.config, "input_dir": source}
            with self.assertRaises(boundary.BoundaryError):
                boundary.validate_config(config)

    def test_no_arbitrary_operation_or_host_fallback(self):
        for mode in ["shell", "bash", "npm install", "--privileged"]:
            with self.assertRaises(boundary.BoundaryError):
                boundary.create_args(self.config, mode)
        with patch.object(boundary.subprocess, "run", side_effect=FileNotFoundError), patch.object(boundary.shutil, "which") as fallback:
            with self.assertRaises(boundary.BoundaryError):
                boundary.docker(self.config, ["version"])
            fallback.assert_not_called()

    def test_windows_drive_translation_preserves_the_exact_approved_directory(self):
        approved_path = r"C:\REA Input\selected, files"
        self.assertTrue(boundary.same_path(approved_path, approved_path, host_os="nt"))
        self.assertTrue(boundary.same_path("/run/desktop/mnt/host/c/REA Input/selected, files", approved_path, host_os="nt"))
        for source in [
            "/run/desktop/mnt/host/c/REA Input", "/run/desktop/mnt/host/d/REA Input/selected, files",
            "/run/desktop/mnt/host/c/REA Input/selected, files/../other",
            "/run/desktop/mnt/host/c/Other/selected, files", "/host_mnt/c/REA Input/selected, files",
        ]:
            self.assertFalse(boundary.same_path(source, approved_path, host_os="nt"))
        self.assertFalse(boundary.same_path("/run/desktop/mnt/host/c/REA Input", r"\\remote\share\REA Input", host_os="nt"))
        self.assertFalse(boundary.same_path("/run/desktop/mnt/host/c/REA Input", "C:/REA Input", host_os="posix"))

    def test_preflight_refuses_old_versions_remote_daemons_and_windows_containers(self):
        valid_server = {"Os": "linux", "Version": "29.8.2", "Platform": {"Name": "Docker Desktop 4.95.0 (test)"}}
        cases = [
            ("tcp://remote:2375", valid_server),
            ("ssh://remote", valid_server),
            ("npipe:////remote/pipe/docker_engine", valid_server),
            ("unix:///docker.sock", {**valid_server, "Os": "windows"}),
            ("unix:///docker.sock", {**valid_server, "Version": "28.1.1"}),
            ("unix:///docker.sock", {**valid_server, "Platform": {"Name": "Docker Desktop 4.41.2"}}),
            ("unix:///docker.sock", {**valid_server, "Platform": {"Name": "Podman 29.8.2"}}),
            ("unix:///docker.sock", {**valid_server, "Platform": {"Name": ""}}),
            ("unix:///docker.sock", {}),
        ]
        for endpoint, server in cases:
            with self.subTest(endpoint=endpoint, server=server):
                with patch.object(boundary, "docker_json", side_effect=[[{"Endpoints": {"docker": {"Host": endpoint}}}], {"Server": server}]):
                    with self.assertRaises(boundary.BoundaryError):
                        boundary.preflight(self.config)
        for endpoint in ["unix:///docker.sock", "npipe:////./pipe/dockerDesktopLinuxEngine"]:
            with patch.object(boundary, "docker_json", side_effect=[[{"Endpoints": {"docker": {"Host": endpoint}}}], {"Server": valid_server}]):
                self.assertEqual(boundary.preflight(self.config)["container_os"], "linux")


if __name__ == "__main__":
    unittest.main()
