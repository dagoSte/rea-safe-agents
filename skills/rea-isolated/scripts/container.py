#!/usr/bin/env python3
"""Create, inspect, then start REA under a fixed Docker policy. Python 3.11+."""

import argparse
import csv
import io
import json
import os
from pathlib import Path, PureWindowsPath
import re
import shutil
import signal
import subprocess
import sys
import tempfile

try:
    import pwd
except ImportError:  # Windows has no account database module.
    pwd = None


MIN_DESKTOP = (4, 95, 0)
MIN_ENGINE = (29, 8, 2)
MEMORY = 2 * 1024**3
CPUS = 2 * 10**9
PIDS = 128
USER = "1000:1000"
TMPFS = {
    "/tmp": "rw,nosuid,nodev,noexec,mode=1777,size=256m",
    "/home/node": "rw,nosuid,nodev,noexec,uid=1000,gid=1000,mode=0700,size=128m",
}
MODES = {
    "mcp": ["mcp"],
    "version": ["--version"],
    "setup-plan": ["setup", "--client", "codex", "--skill=false", "--dry-run", "--json"],
}


class BoundaryError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise BoundaryError(message)


def clean_environment():
    # Docker credentials stay with the trusted Docker client. No host variables
    # are passed to the container through -e or --env-file.
    return {k: v for k, v in os.environ.items() if not k.upper().startswith("DOCKER_")}


def docker(config, args, *, capture=True, check=True):
    command = [config["docker"], "--config", config["docker_config"], "--context", config["context"], *args]
    try:
        result = subprocess.run(
            command, env=clean_environment(), capture_output=capture,
            text=capture, encoding="utf-8" if capture else None,
            stdin=subprocess.DEVNULL if capture else None,
            timeout=45 if capture else None, shell=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise BoundaryError("Docker is unavailable; host execution is forbidden") from exc
    if check and result.returncode:
        raise BoundaryError((result.stderr or "Docker command failed").strip())
    return result


def docker_json(config, args):
    try:
        return json.loads(docker(config, args).stdout)
    except json.JSONDecodeError as exc:
        raise BoundaryError("Docker returned invalid inspection data") from exc


def semver(value):
    match = re.search(r"(?<!\d)(\d+)\.(\d+)\.(\d+)(?!\d)", str(value))
    require(match is not None, "Cannot establish the runtime version")
    return tuple(int(v) for v in match.groups())


def preflight(config):
    contexts = docker_json(config, ["context", "inspect", config["context"]])
    require(isinstance(contexts, list) and len(contexts) == 1, "Unexpected Docker context")
    endpoint = contexts[0].get("Endpoints", {}).get("docker", {}).get("Host", "")
    local_endpoint = endpoint.replace("\\", "/")
    require(local_endpoint.startswith("unix:///") or local_endpoint.startswith("npipe:////./pipe/"), "Only a local Docker socket/pipe is supported")
    version = docker_json(config, ["version", "--format", "{{json .}}"])
    server = version.get("Server") or {}
    require(server.get("Os") == "linux", "Linux containers are required on every host OS")
    require(semver(server.get("Version", "")) >= MIN_ENGINE, "Docker Engine is below the reviewed baseline")
    platform = server.get("Platform", {}).get("Name", "")
    require(platform.startswith(("Docker Desktop ", "Docker Engine")), "Only the reviewed official Docker runtime family is supported")
    desktop = None
    if "Docker Desktop" in platform:
        desktop = semver(platform)
        require(desktop >= MIN_DESKTOP, "Docker Desktop is below the reviewed baseline; update it first")
    return {"engine": server["Version"], "desktop": desktop, "container_os": "linux"}


def same_directory(first, second):
    try:
        return os.path.samefile(first, second)
    except OSError:
        return False


def contains(outer, inner):
    # Compare filesystem identity, not spelling: case-insensitive volumes,
    # macOS firmlinks (/System/Volumes/Data) give one directory several paths.
    # Renamed bind mounts cannot be established portably with this test. This
    # filter is defense in depth; original input trees are never mounted.
    return any(same_directory(outer.joinpath(*inner.parts[i:]), inner) for i in range(1, len(inner.parts) + 1))


def windows_profile():
    # The profile Windows records for this process token, unlike USERPROFILE.
    import ctypes
    from ctypes import wintypes
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    userenv = ctypes.WinDLL("userenv", use_last_error=True)
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    userenv.GetUserProfileDirectoryW.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    userenv.GetUserProfileDirectoryW.restype = wintypes.BOOL
    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), 0x0008, ctypes.byref(token)):  # TOKEN_QUERY
        raise OSError(ctypes.get_last_error(), "Cannot open the process token")
    try:
        size = wintypes.DWORD(32768)
        buffer = ctypes.create_unicode_buffer(size.value)
        if not userenv.GetUserProfileDirectoryW(token, buffer, ctypes.byref(size)):
            raise OSError(ctypes.get_last_error(), "Cannot read the account profile directory")
    finally:
        kernel32.CloseHandle(token)
    return Path(buffer.value)


def account_homes():
    # HOME and USERPROFILE are caller-controlled (the receiving agent runs with
    # a separate one), so also protect the home the operating system records.
    homes = [Path.home()]
    try:
        if pwd is not None:
            homes.append(Path(pwd.getpwuid(os.getuid()).pw_dir))
        elif os.name == "nt":
            homes.append(windows_profile())
    except (KeyError, OSError) as exc:
        raise BoundaryError("Cannot establish the account home directory") from exc
    return [home.resolve() for home in homes]


def input_directory(raw):
    path = Path(raw).expanduser()
    require(path.is_absolute(), "The input directory must be an absolute path")
    require(path.is_dir() and not path.is_symlink(), "Use a real dedicated input directory")
    resolved = path.resolve(strict=True)
    if os.name == "nt":
        require(bool(re.fullmatch(r"[A-Za-z]:", resolved.drive)), "Use a local Windows drive path, not a UNC/WSL network path")
    require(resolved != Path(resolved.anchor) and not os.path.ismount(resolved), "A drive/filesystem root cannot be shared")
    homes = account_homes()
    require(not any(contains(resolved, home) for home in homes), "The home directory or its parents cannot be shared")
    for home in homes:
        for name in (".ssh", ".aws", ".azure", ".gnupg", ".kube", ".config", ".codex", ".claude", ".docker", "AppData", "Library"):
            require(not contains(home / name, resolved), "Do not share a host credential or application-state directory")
    require(not any(c in str(resolved) for c in "\r\n\x00"), "Unsupported control character in input path")
    return str(resolved)


def validate_config(config):
    require(set(config) == {"schema", "docker", "docker_config", "context", "image_id", "input_dir"}, "Unexpected configuration fields")
    require(config["schema"] == 1, "Unsupported configuration schema")
    binary = Path(config["docker"])
    require(binary.is_absolute() and binary.is_file(), "Docker must be a trusted absolute executable path")
    require(binary.name.lower() in ("docker", "docker.exe"), "Expected the Docker CLI executable")
    control = Path(config["docker_config"])
    require(control.is_absolute() and control.is_dir(), "Pin the host Docker CLI configuration directory")
    require(bool(re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]*", config["context"])), "Invalid Docker context name")
    require(bool(re.fullmatch(r"sha256:[0-9a-f]{64}", config["image_id"])), "Use a pinned local image ID, not a mutable tag")
    require(input_directory(config["input_dir"]) == config["input_dir"], "The input directory changed identity")
    source = Path(config["input_dir"])
    require(not contains(source, control) and not contains(control, source), "Docker control metadata cannot be shared with REA")


def mount_spec(source):
    # --mount is CSV; quote a source containing commas without shell escaping.
    out = io.StringIO(newline="")
    csv.writer(out, lineterminator="").writerow(["type=bind", "source=" + source, "target=/input", "readonly"])
    return out.getvalue()


def create_args(config, mode):
    require(mode in {*MODES, "probe"}, "Unknown operation; arbitrary commands are forbidden")
    args = [
        "create", "--rm", "--interactive", "--init", "--pull=never",
        "--read-only", "--network=none", "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true", "--user=" + USER,
        "--memory=2g", "--memory-swap=2g", "--cpus=2", "--pids-limit=128",
        "--log-driver=none",
        "--workdir=/input", "--env=HOME=/home/node",
        "--label=org.rea-isolated.managed=true",
        "--mount", mount_spec(config["input_dir"]),
    ]
    for path, options in TMPFS.items():
        args.extend(["--tmpfs", path + ":" + options])
    if mode == "probe":
        source = Path(__file__).with_name("probe.js").read_text(encoding="utf-8")
        args.extend(["--entrypoint=/usr/local/bin/node", config["image_id"], "-e", source])
    else:
        args.extend(["--entrypoint=/usr/local/bin/rea", config["image_id"], *MODES[mode]])
    return args


def same_path(first, second, host_os=None):
    if (host_os or os.name) == "nt":
        approved = PureWindowsPath(second)
        if not approved.is_absolute() or not re.fullmatch(r"[A-Za-z]:", approved.drive):
            return False
        actual = str(first).replace("\\", "/")
        native = approved.drive[0].lower() + approved.as_posix()[1:]
        if len(actual) > 1 and actual[1] == ":":
            return actual[0].lower() + actual[1:] == native
        # Docker Desktop reports native Windows drive mounts using this VM
        # prefix. Accept only the exact approved drive and remaining path.
        translated = "/run/desktop/mnt/host/" + approved.drive[0].lower() + "/" + "/".join(approved.parts[1:])
        return actual == translated
    return os.path.normcase(os.path.normpath(str(first))) == os.path.normcase(os.path.normpath(str(second)))


def verify_container(config, data, mode, image_env):
    host = data.get("HostConfig", {})
    inner = data.get("Config", {})
    require(data.get("Image") == config["image_id"], "Image identity mismatch")
    require(not data.get("State", {}).get("Running"), "Inspect the container before any code starts")
    require(inner.get("User") == USER, "Unexpected container user")
    require(inner.get("Tty") is False and inner.get("OpenStdin") is True, "MCP requires interactive stdin without a TTY")
    require(inner.get("WorkingDir") == "/input", "Unexpected working directory")
    expected_env = dict(item.split("=", 1) for item in image_env)
    expected_env["HOME"] = "/home/node"
    actual_env = inner.get("Env") or []
    require(len(actual_env) == len(expected_env) and dict(item.split("=", 1) for item in actual_env) == expected_env, "Unexpected environment injection, such as host proxy credentials")
    require(not inner.get("Volumes"), "Image-declared volumes are forbidden")
    expected_entrypoint = ["/usr/local/bin/node"] if mode == "probe" else ["/usr/local/bin/rea"]
    require(inner.get("Entrypoint") == expected_entrypoint, "Unexpected entrypoint")
    expected_cmd = ["-e", Path(__file__).with_name("probe.js").read_text(encoding="utf-8")] if mode == "probe" else MODES[mode]
    require(inner.get("Cmd") == expected_cmd, "Unexpected command")
    require(host.get("NetworkMode") == "none", "Runtime networking must be disabled")
    require(host.get("ReadonlyRootfs") is True, "The root filesystem must be read-only")
    require(host.get("Privileged") is False, "Privileged containers are forbidden")
    require(host.get("Init") is True, "A process reaper is required")
    require(host.get("AutoRemove") is True, "Automatic container removal is required")
    require(host.get("LogConfig", {}).get("Type") == "none", "Persistent Docker container logging is forbidden")
    require(set(host.get("CapDrop") or []) == {"ALL"} and not host.get("CapAdd"), "All Linux capabilities must be dropped")
    options = set(host.get("SecurityOpt") or [])
    require(options in ({"no-new-privileges"}, {"no-new-privileges:true"}), "Unexpected security options")
    require(host.get("Memory") == MEMORY and host.get("MemorySwap") == MEMORY, "Unexpected memory limits")
    require(host.get("NanoCpus") == CPUS and host.get("PidsLimit") == PIDS, "Unexpected process/CPU limits")
    require(host.get("Tmpfs") == TMPFS, "Unexpected temporary filesystems")
    require(not host.get("Binds") and not host.get("VolumesFrom"), "Unmanaged mounts are forbidden")
    require(not host.get("Devices") and not host.get("DeviceRequests") and not host.get("DeviceCgroupRules"), "Device access is forbidden")
    require(not host.get("PidMode") and host.get("IpcMode") in ("private", ""), "Host process/IPC namespaces are forbidden")
    require(not host.get("GroupAdd") and host.get("UsernsMode") != "host", "Extra groups or the host user namespace are forbidden")
    require(not host.get("UTSMode") and host.get("CgroupnsMode") in ("private", ""), "Shared host namespaces are forbidden")
    require(not host.get("PublishAllPorts") and not host.get("PortBindings"), "Port publishing is forbidden")
    mounts = data.get("Mounts", [])
    require(len(mounts) == 1, "Exactly one approved input mount is required")
    mount = mounts[0]
    require(mount.get("Type") == "bind" and mount.get("Destination") == "/input" and mount.get("RW") is False, "Input must be a read-only bind mount")
    # Only the exact source or the narrow native-Windows drive translation is
    # accepted; unknown WSL, UNC and alternate aliases remain refused.
    require(same_path(mount.get("Source"), config["input_dir"]), "Input mount source does not match the approved path")
    return {"image_id": data["Image"], "network": "none", "user": USER, "read_only": True, "input_read_only": True}


def run_container(config, mode):
    require(mode != "mcp", "Direct host MCP sessions are retired; use agent_container.py with both clients contained")
    validate_config(config)
    # Diagnostics need no user data. A renamed bind mount can defeat portable
    # credential-path filters, so never expose the original tree here either.
    with tempfile.TemporaryDirectory(prefix="rea-diagnostic-") as scratch:
        empty = Path(scratch) / "input"
        empty.mkdir(mode=0o755)
        return _run_checked({**config, "input_dir": str(empty)}, mode)


def _run_checked(config, mode):
    runtime = preflight(config)
    images = docker_json(config, ["image", "inspect", config["image_id"]])
    require(isinstance(images, list) and len(images) == 1 and images[0].get("Id") == config["image_id"], "Pinned image inspection failed")
    image_env = images[0].get("Config", {}).get("Env") or []
    created = docker(config, create_args(config, mode)).stdout.strip()
    require(bool(re.fullmatch(r"[0-9a-f]{64}", created)), "Invalid created-container identity")
    try:
        inspected = docker_json(config, ["inspect", created])
        require(isinstance(inspected, list) and len(inspected) == 1 and inspected[0].get("Id") == created, "Container inspection identity mismatch")
        evidence = verify_container(config, inspected[0], mode, image_env)
        print(json.dumps({"boundary": evidence, "runtime": runtime}), file=sys.stderr)
        return docker(config, ["start", "--attach", "--interactive", created], capture=False, check=False).returncode
    finally:
        docker(config, ["rm", "--force", created], check=False)


def configure(args):
    executable = shutil.which("docker")
    require(executable is not None, "Install a supported Docker runtime first")
    config = {
        "schema": 1, "docker": str(Path(executable).resolve()),
        "docker_config": str(Path(os.environ.get("DOCKER_CONFIG", str(Path.home() / ".docker"))).expanduser().resolve(strict=True)),
        "context": args.context, "image_id": "sha256:" + "0" * 64,
        "input_dir": input_directory(args.input_dir),
    }
    validate_config(config)
    preflight(config)
    images = docker_json(config, ["image", "inspect", args.image])
    require(isinstance(images, list) and len(images) == 1, "Expected one local image")
    image = images[0]
    require(image.get("Os") == "linux", "The REA image must use Linux")
    require(image.get("Config", {}).get("User") in ("node", USER), "Unexpected image user")
    config["image_id"] = image["Id"]
    validate_config(config)
    output = Path(args.output).expanduser()
    require(not output.exists(), "Refusing to overwrite an existing approved deployment configuration")
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8") as handle:
        json.dump(config, handle, indent=2)
        handle.write("\n")
    if os.name != "nt":
        output.chmod(0o600)
    print(json.dumps({"configuration": str(output.resolve()), "image_id": config["image_id"]}))


def interrupt_cleanup(signum, frame):
    # Exit through run_container's finally block so this launcher's exact
    # container is removed; never leave REA behind after an MCP cancellation.
    raise KeyboardInterrupt


def main():
    signal.signal(signal.SIGTERM, interrupt_cleanup)
    if hasattr(signal, "SIGBREAK"):
        signal.signal(signal.SIGBREAK, interrupt_cleanup)
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="operation", required=True)
    setup = sub.add_parser("configure", help="Pin a reviewed local image and a dedicated input directory")
    setup.add_argument("--image", required=True)
    setup.add_argument("--input-dir", required=True)
    setup.add_argument("--context", required=True)
    setup.add_argument("--output", required=True)
    for operation in [*MODES, "probe"]:
        p = sub.add_parser(operation)
        p.add_argument("--config", required=True)
    args = parser.parse_args()
    try:
        if args.operation == "configure":
            configure(args)
            return 0
        with Path(args.config).open(encoding="utf-8") as handle:
            config = json.load(handle)
        return run_container(config, args.operation)
    except KeyboardInterrupt:
        print("REA launcher interrupted; container cleanup requested", file=sys.stderr)
        return 130
    except (BoundaryError, OSError, ValueError, KeyError, TypeError) as exc:
        print("REA isolation refused: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
