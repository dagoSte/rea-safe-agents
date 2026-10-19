#!/usr/bin/env python3
"""Run REA and its receiving client in separate inspected Docker containers."""

import argparse
import base64
import contextlib
from datetime import datetime, timezone
import hashlib
import hmac
import http.client
import http.server
import json
import os
from pathlib import Path
import queue
import re
import signal
import ssl
import subprocess
import sys
import threading
import time
from urllib.parse import urlsplit
import uuid

import agent_session as profile
import container as boundary
import input_snapshot
from offline_model import OfflineHandler
from model_policy import validate_body
from tunnel import MAX_BODY, MAX_RESPONSE, MAX_TOOL_TEXT, MAX_TRANSCRIPT, STATIC_TOOLS, ProtocolError, Wire, decode_json, digest, pack, read_frame, require, unpack

HERE = Path(__file__).resolve()
HELPERS = ("agent_container.py", "agent_worker.py", "agent_session.py", "container.py", "input_snapshot.py", "model_policy.py", "offline_model.py", "tunnel.py", "probe.js")
WORKER_FILES = ("agent_worker.py", "agent_session.py", "tunnel.py")
TOOLS = STATIC_TOOLS
PROBE_KEYS = {"non_root", "no_new_privileges", "no_effective_capabilities", "seccomp_filter_active",
              "no_active_non_loopback_interface", "no_docker_cli", "no_docker_socket", "no_host_input_mount",
              "no_model_credentials", "root_write_denied", "outbound_connection_denied"}
AGENT_TMPFS = {"/tmp": "rw,nosuid,nodev,noexec,mode=1777,size=256m",
               "/home/node": "rw,nosuid,nodev,noexec,uid=1000,gid=1000,mode=0700,size=256m"}
AGENT_ENTRY = ["python3", "/opt/rea-sandbox/agent_worker.py"]
MAX_REQUESTS = 32
MAX_OUTPUT_TOKENS = 32000
# One streamed model answer: long enough for MAX_OUTPUT_TOKENS, still inside the session budget.
RESPONSE_TIMEOUT = 900
# REA may answer with up to 10 MiB (its own budget); results are cut before relay.
MAX_REA_LINE, REA_ITEM_LIMIT = 12 * 1024 * 1024, 2_000_000
MAX_REFRESHES = 3
CODEX_LOGIN_OUTPUT = 1024 * 1024
HEADER_TOKEN = re.compile(r"[\x21-\x7e]{1,16384}")
RECEIPT_SUFFIX = ".verification.json"
RESPONSE_HEADER = re.compile(r"retry-after|x-should-retry|anthropic-ratelimit-unified-[a-z0-9-]{1,64}")
OAUTH_BETA = "oauth-2025-04-20"
CODEX_VERSION = "0.163.0"
CODEX_HOST, CODEX_PATH = "chatgpt.com", "/backend-api/codex/responses"
CODEX_AUTH_HOST, CODEX_CLIENT_ID = "auth.openai.com", "app_EMoamEEZ73f0CkXaXp7hrann"
CODEX_REFRESH_MARGIN = 300
MAX_FRAMES = 4096
PIPE_TIMEOUT = 5


def helper_identity():
    return {name: digest(HERE.with_name(name)) for name in HELPERS}


def private_output(raw):
    path = Path(raw).expanduser().resolve()
    protected = {HERE.parents[1].resolve()}
    # Installed skills sit under .agents/skills or .claude/skills. A fixed
    # parent index is not the project's repository root, especially in worktrees.
    for location in (HERE, path):
        for parent in location.parents:
            marker = parent / ".git"
            if marker.is_dir() or marker.is_file():
                protected.add(parent.resolve())
    ancestor = path
    while not ancestor.exists():
        ancestor = ancestor.parent
    require(all(path != repo and repo not in path.parents and not boundary.contains(repo, ancestor) for repo in protected),
            "Keep private control state outside the published repository")
    return path


def agent_args(image):
    args = ["create", "--rm", "--interactive", "--init", "--pull=never", "--read-only", "--network=none",
            "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--user=1000:1000",
            "--memory=2g", "--memory-swap=2g", "--cpus=2", "--pids-limit=128", "--log-driver=none",
            "--workdir=/tmp", "--env=HOME=/home/node", "--label=org.rea-isolated.managed=true",
            "--label=org.rea-isolated.role=agent"]
    for path, options in AGENT_TMPFS.items():
        args += ["--tmpfs", path + ":" + options]
    return [*args, "--entrypoint=python3", image, "/opt/rea-sandbox/agent_worker.py"]


def verify_agent(image, data, image_env):
    host, inner = data.get("HostConfig", {}), data.get("Config", {})
    require(data.get("Image") == image and data.get("State", {}).get("Running") is False, "Inspect the pinned agent before startup")
    require(inner.get("User") == "1000:1000" and inner.get("WorkingDir") == "/tmp", "Unexpected agent user/workdir")
    require(inner.get("Entrypoint") == AGENT_ENTRY[:1] and inner.get("Cmd") == AGENT_ENTRY[1:], "Unexpected agent command")
    require(inner.get("Tty") is False and inner.get("OpenStdin") is True and not inner.get("Volumes"), "Unexpected agent I/O or volumes")
    expected = dict(item.split("=", 1) for item in image_env)
    expected["HOME"] = "/home/node"
    actual = inner.get("Env") or []
    require(len(actual) == len(expected) and dict(item.split("=", 1) for item in actual) == expected, "Agent environment injection refused")
    require(data.get("Mounts") == [] and not host.get("Binds") and not host.get("VolumesFrom"), "The agent must have zero mounts")
    require(host.get("NetworkMode") == "none" and not host.get("PortBindings") and not host.get("PublishAllPorts"), "Agent networking must be disabled")
    require(host.get("ReadonlyRootfs") is True and host.get("Privileged") is False, "Unsafe agent root filesystem or privilege")
    require(host.get("Init") is True and host.get("AutoRemove") is True and host.get("LogConfig", {}).get("Type") == "none", "Unexpected agent lifecycle/logging")
    require(set(host.get("CapDrop") or []) == {"ALL"} and not host.get("CapAdd"), "Agent capabilities must be dropped")
    require(set(host.get("SecurityOpt") or []) in ({"no-new-privileges"}, {"no-new-privileges:true"}), "Unexpected agent security options")
    require(host.get("Memory") == boundary.MEMORY and host.get("MemorySwap") == boundary.MEMORY
            and host.get("NanoCpus") == boundary.CPUS and host.get("PidsLimit") == boundary.PIDS, "Unexpected agent resource limits")
    require(host.get("Tmpfs") == AGENT_TMPFS, "Unexpected agent temporary storage")
    for key in ("Devices", "DeviceRequests", "DeviceCgroupRules", "PidMode", "UTSMode", "GroupAdd"):
        require(not host.get(key), "Agent devices/shared namespaces/groups are forbidden")
    require(host.get("IpcMode") in ("", "private") and host.get("CgroupnsMode") in ("", "private")
            and host.get("UsernsMode") != "host", "Unexpected agent namespace")


def config_name(path):
    # One receipt per configuration: <name>.json maps to <name>.verification.json.
    require(path.name.endswith(".json") and not path.name.lower().endswith(RECEIPT_SUFFIX),
            "Name configurations <name>.json; names ending in " + RECEIPT_SUFFIX + " are reserved for receipts")


def configure(args):
    config_name(Path(args.output))
    rea_path = Path(args.rea_config).expanduser().resolve(strict=True)
    rea = decode_json(rea_path.read_bytes())
    boundary.validate_config(rea)
    boundary.preflight(rea)
    images = boundary.docker_json(rea, ["image", "inspect", args.image])
    require(isinstance(images, list) and len(images) == 1 and images[0].get("Os") == "linux", "Expected one local Linux agent image")
    image = images[0]
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", image.get("Id", "")) is not None, "Invalid immutable agent image")
    require(image.get("Config", {}).get("Entrypoint") == AGENT_ENTRY and image.get("Config", {}).get("User") == "node", "Review the bundled agent image first")
    selected = input_snapshot.manifest(Path(rea["input_dir"]))
    output = private_output(args.output)
    config_name(output)
    require(not output.exists(), "Refusing to overwrite an approved paired deployment")
    require(Path(rea["input_dir"]) not in output.parents, "Control state must stay outside the selected input")
    output.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    value = {"schema": 1, "rea_config": str(rea_path), "rea_sha256": digest(rea_path), "agent_image_id": image["Id"],
             "client": args.client, "helpers": helper_identity(), "inputs": selected}
    with output.open("x", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2)
        handle.write("\n")
    if os.name != "nt":
        output.chmod(0o600)
    return {"configuration": str(output), "client": args.client, "agent_image_id": image["Id"],
            "selected_files": len(selected), "selected_bytes": sum(item["size"] for item in selected),
            "status": "requires-paired-verification"}


def load_config(raw):
    config_name(Path(raw))
    path = private_output(raw).resolve(strict=True)
    config_name(path)
    value = decode_json(path.read_bytes())
    require(isinstance(value, dict) and set(value) == {"schema", "rea_config", "rea_sha256", "agent_image_id", "client", "helpers", "inputs"}, "Unexpected paired configuration")
    require(value["schema"] == 1 and value["client"] in profile.REVIEWED, "Unsupported paired profile")
    require(value["helpers"] == helper_identity(), "Helpers changed; rebuild/reconfigure and verify again")
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", value["agent_image_id"]) is not None, "Pin the agent image ID")
    require(digest(value["rea_config"]) == value["rea_sha256"], "REA deployment changed; review and configure again")
    rea = decode_json(Path(value["rea_config"]).read_bytes())
    boundary.validate_config(rea)
    return path, value, rea


def identity(path, config):
    return {"config_sha256": digest(path), "helpers": config["helpers"], "agent_image_id": config["agent_image_id"],
            "client": config["client"], "host_os": sys.platform}


def receipt_path(config_path):
    return config_path.with_name(config_path.stem + RECEIPT_SUFFIX)


def clear_receipt(report):
    """Invalidate an earlier receipt; never delete a file that is not one."""
    require(not report.is_symlink(), "Refusing " + report.name + ": a link is not a verification receipt; remove it yourself")
    if report.exists():
        try:
            value = decode_json(report.read_bytes())
        except ProtocolError:
            value = None
        require(isinstance(value, dict) and value.get("status") == "verified-contained-offline" and isinstance(value.get("identity"), dict),
                "Refusing to replace " + report.name + ": it is not a verification receipt")
        report.unlink()


class PipeSink:
    """A contained process that stops reading must not block the controller."""
    def __init__(self, stream):
        self.stream = stream

    def write(self, raw):
        completed, failures = threading.Event(), []
        def send():
            try:
                if self.stream.write(raw) != len(raw):
                    raise OSError("Incomplete container write")
                self.stream.flush()
            except (OSError, ValueError) as exc:
                failures.append(exc)
            finally:
                completed.set()
        threading.Thread(target=send, daemon=True).start()
        require(completed.wait(PIPE_TIMEOUT), "Container stdin stalled; terminate the contained session")
        require(not failures, "Container stdin closed")

    def flush(self):
        pass  # write waits for the actual flush.


class Containers:
    def __init__(self, rea):
        self.rea, self.identifiers, self.processes = rea, [], []

    def create(self, role, image, snapshot):
        images = boundary.docker_json(self.rea, ["image", "inspect", image])
        require(isinstance(images, list) and len(images) == 1 and images[0].get("Id") == image, "Pinned image unavailable")
        settings = {**self.rea, "input_dir": str(snapshot)}
        args = agent_args(image) if role == "agent" else boundary.create_args(settings, "probe" if role == "probe" else "mcp")
        identifier = boundary.docker(self.rea, args).stdout.strip()
        require(re.fullmatch(r"[0-9a-f]{64}", identifier) is not None, "Invalid created container identity")
        self.identifiers.append(identifier)
        inspected = boundary.docker_json(self.rea, ["inspect", identifier])
        require(isinstance(inspected, list) and len(inspected) == 1 and inspected[0].get("Id") == identifier, "Container identity changed")
        env = images[0].get("Config", {}).get("Env") or []
        if role == "agent":
            verify_agent(image, inspected[0], env)
        else:
            boundary.verify_container(settings, inspected[0], "probe" if role == "probe" else "mcp", env)
        return identifier

    def start(self, identifier):
        args = [self.rea["docker"], "--config", self.rea["docker_config"], "--context", self.rea["context"],
                "start", "--attach", "--interactive", identifier]
        # Native Docker endpoint/config are explicit. Provider keys, SSH agent
        # forwarding and host proxy/runtime overrides do not enter the CLI.
        allowed = {"PATH", "SystemRoot", "WINDIR", "PATHEXT", "TEMP", "TMP", "TMPDIR", "LANG"}
        env = {key: value for key, value in os.environ.items() if key in allowed}
        process = subprocess.Popen(args, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
        self.processes.append(process)
        return process

    def close(self):
        failures = []
        uncertain = []
        for identifier in reversed(self.identifiers):
            try:
                result = boundary.docker(self.rea, ["rm", "--force", identifier], check=False)
                # --rm may already have removed a normally completed container.
                if result.returncode and "No such container" not in (result.stderr or ""):
                    uncertain.append(identifier)
            except (boundary.BoundaryError, OSError) as exc:
                failures.append(type(exc).__name__ + " during container removal")
        for process in self.processes:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    process.terminate()
                    process.wait(timeout=5)
                except (OSError, subprocess.TimeoutExpired):
                    with contextlib.suppress(OSError):
                        process.kill()
                    try:
                        process.wait(timeout=5)
                    except (OSError, subprocess.TimeoutExpired):
                        failures.append("Docker attach process did not exit")
            # Remove/stop first: flushing stdin before stopping a malicious
            # non-reader can block forever on the buffered pipe's lock.
            for stream in (process.stdin, process.stdout, process.stderr):
                with contextlib.suppress(OSError):
                    stream.close()
        for identifier in uncertain:
            try:
                # AutoRemove can race rm --force while attached processes exit.
                # Accept the race only after Docker confirms this exact ID absent.
                remaining = boundary.docker(self.rea, ["ps", "--all", "--quiet", "--no-trunc", "--filter", "id=" + identifier])
                if remaining.stdout.strip():
                    failures.append("container removal failed")
            except (boundary.BoundaryError, OSError):
                failures.append("container absence could not be verified")
        require(not failures, "Cleanup incomplete: " + "; ".join(failures))


def bounded_text(text):
    raw = text.encode("utf-8", errors="replace")
    if len(raw) <= MAX_TOOL_TEXT:
        return text
    note = ("\n\n[The controller omitted the middle of this REA result: it was " + str(len(raw)) + " bytes and at most "
            + str(MAX_TOOL_TEXT) + " are relayed. Request a narrower view, for example detail=summary, "
            "inspect_analysis_view with offset and limit, or one address, procedure or search pattern.]\n\n")
    keep = MAX_TOOL_TEXT - len(note.encode())
    return raw[:keep * 3 // 4].decode("utf-8", errors="ignore") + note + raw[len(raw) - keep // 4:].decode("utf-8", errors="ignore")


def bound_result(result):
    """Relay a tool result as one text copy of at most MAX_TOOL_TEXT bytes, cut visibly."""
    result.pop("structuredContent", None)
    content = result.get("content")
    if not isinstance(content, list):
        return
    # Model requests carry text only, so other block types become a short note.
    parts = []
    for block in content:
        if isinstance(block, dict) and block.get("type") == "text" and isinstance(block.get("text"), str):
            parts.append(block["text"])
        else:
            kind = block.get("type") if isinstance(block, dict) and isinstance(block.get("type"), str) else "unknown"
            parts.append("[The controller omitted a non-text MCP content block of type " + json.dumps(kind[:40]) + ".]")
    result["content"] = [{"type": "text", "text": bounded_text("\n".join(parts))}]


def bound_error(item):
    error = item.get("error")
    if isinstance(error, dict):
        error.pop("data", None)
        if isinstance(error.get("message"), str):
            error["message"] = bounded_text(error["message"])


class MCPPolicy:
    def __init__(self):
        self.pending = {}
        self.discovered = set()
        self.server_version = None
        self.local_response = None
        self.requested_tools = {}
        self.completed_tools = []

    def request(self, raw):
        item = decode_json(raw)
        require(isinstance(item, dict) and item.get("jsonrpc") == "2.0" and isinstance(item.get("method"), str), "Invalid MCP request")
        method = item["method"]
        self.local_response = None
        require(re.fullmatch(r"[A-Za-z0-9_./-]{1,80}", method) is not None, "Invalid MCP method name")
        if method == "server/discover":
            identifier = item.get("id")
            require(type(identifier) in (str, int) and len(str(identifier)) <= 128, "Invalid discovery request ID")
            self.local_response = json.dumps({"jsonrpc": "2.0", "id": identifier,
                                              "error": {"code": -32601, "message": "Discovery extension is not supported"}}).encode() + b"\n"
            return None
        require(method in {"initialize", "notifications/initialized", "ping", "tools/list", "tools/call"}, "MCP method outside the approved profile: " + method)
        if method == "initialize":
            require(isinstance(item.get("params"), dict), "Invalid MCP initialization")
            item["params"]["capabilities"] = {}  # No sampling, roots, elicitation or reverse host callbacks.
        if method == "tools/call":
            params = item.get("params", {})
            require(params.get("name") in TOOLS and isinstance(params.get("arguments", {}), dict), "MCP tool outside the approved static profile")
            args = params.get("arguments", {})
            name = params["name"]
            if name == "close_binary":
                require(not args, "Snapshot exports are outside the initial paired profile")
            if name == "open_binary":
                require("snapshot_path" not in args, "Snapshot imports are outside the paired profile")
                require(args.get("provider_id", "auto") in {"auto", "ghidra"}, "Only the Ghidra provider is in the paired profile")
            elif name != "analyze_javascript_application":
                require(not any("path" in key.lower() for key in args), "Only the target tools accept filesystem paths")
            if name in {"open_binary", "analyze_javascript_application"}:
                key = "path" if name == "open_binary" else "input_path"
                path = args.get(key)
                require(isinstance(path, str) and path.startswith("/input/") and ".." not in path.split("/")
                        and "\\" not in path and not any(c in path for c in "\x00\r\n"), "Targets must use the frozen /input snapshot")
        if "id" in item:
            identifier = item["id"]
            require(type(identifier) in (str, int) and len(str(identifier)) <= 128
                    and identifier not in self.pending and len(self.pending) < 64, "Invalid or duplicate MCP request ID")
            self.pending[identifier] = method
            if method == "tools/call":
                self.requested_tools[identifier] = item["params"]["name"]
        else:
            require(method == "notifications/initialized", "Unexpected MCP notification")
        return json.dumps(item, separators=(",", ":")).encode() + b"\n"

    def response(self, raw):
        item = decode_json(raw, item_limit=REA_ITEM_LIMIT)
        require(isinstance(item, dict) and item.get("jsonrpc") == "2.0", "Invalid REA response")
        if "method" in item:
            require("id" not in item, "Reverse MCP requests are forbidden")
            require(item["method"] in {"notifications/message", "notifications/progress", "notifications/tools/list_changed"}, "Unexpected REA notification")
        else:
            identifier = item.get("id")
            require(type(identifier) in (str, int) and identifier in self.pending, "Unsolicited REA response")
            method = self.pending.pop(identifier)
            bound_error(item)
            result = item.get("result")
            if method == "tools/call":
                name = self.requested_tools.pop(identifier)
                if "error" not in item and isinstance(result, dict) and not result.get("isError"):
                    self.completed_tools.append(name)
                if isinstance(result, dict):
                    bound_result(result)
            if method == "initialize" and isinstance(result, dict):
                result["capabilities"] = {"tools": {}}
                self.server_version = result.get("serverInfo", {}).get("version")
            if method == "tools/list" and isinstance(result, dict):
                tools = result.get("tools")
                require(isinstance(tools, list), "Invalid REA catalog")
                result["tools"] = [tool for tool in tools if isinstance(tool, dict) and tool.get("name") in TOOLS]
                for tool in result["tools"]:
                    # Results reach the model as one bounded text copy, so the
                    # clients must not expect structured output. Claude keeps
                    # annotated results inline up to the announced size.
                    tool.pop("outputSchema", None)
                    tool["_meta"] = {"anthropic/maxResultSizeChars": MAX_TOOL_TEXT}
                self.discovered.update(tool["name"] for tool in result["tools"])
        return json.dumps(item, separators=(",", ":")).encode() + b"\n"


def catalog_names(client, catalogs, *, require_mcp=True):
    require(bool(catalogs), "The contained client made no model request")
    observations = []
    allowed = {"mcp__rea__" + name for name in TOOLS}
    if client == "codex":
        allowed |= profile.CODEX_PASSIVE
    for tools in catalogs:
        require(isinstance(tools, list), "Unexpected model tool catalog")
        names = set()
        for tool in tools:
            require(isinstance(tool, dict), "Invalid model tool declaration")
            require(tool.get("type") in ({"function", "namespace"} if client == "codex" else {None, "custom"}), "Hosted model tools are forbidden")
            if client == "codex" and tool.get("type") == "namespace":
                require(tool.get("name") == "mcp__rea", "Unapproved model tool namespace")
                children = tool.get("tools")
                require(isinstance(children, list) and all(isinstance(item, dict) and item.get("type", "function") == "function"
                        and isinstance(item.get("name"), str) for item in children), "Invalid namespace tools")
                names.update("mcp__rea__" + item["name"] for item in children)
            else:
                name = tool.get("name")
                require(isinstance(name, str), "Invalid model tool name")
                names.add(name)
        require(names <= allowed and (not require_mcp or "mcp__rea__binary_session" in names), "Unexpected or missing tools in contained client")
        observations.append(sorted(names))
    return observations


def send(connection, method, path, **request):
    try:
        connection.request(method, path, **request)
    except ValueError:
        # http.client quotes a rejected header, which may hold a credential.
        raise ProtocolError("Refused an invalid request header") from None


def jwt_claims(token):
    """Unverified claims, read only to schedule a refresh before expiry."""
    try:
        payload = token.split(".")[1]
        value = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except (AttributeError, IndexError, ValueError, TypeError):
        return {}
    return value if isinstance(value, dict) else {}


def write_private(path, value):
    temporary = path.with_name(path.name + ".tmp")
    temporary.unlink(missing_ok=True)
    with os.fdopen(os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    try:
        os.replace(temporary, path)
    except OSError as exc:
        # A rotated refresh token exists only in the new file; never delete it.
        raise ProtocolError("Could not replace " + str(path) + "; the current login is saved in " + str(temporary)) from exc
    if os.name != "nt":
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)


def codex_account(data):
    tokens = data.get("tokens") if isinstance(data, dict) else None
    # Visible ASCII only: a token that cannot be a header value is refused here,
    # with a fixed message, before any library can quote it in an error.
    if not isinstance(tokens, dict) or not all(isinstance(tokens.get(key), str) and HEADER_TOKEN.fullmatch(tokens[key])
                                               for key in ("access_token", "refresh_token")):
        return None
    claims = jwt_claims(tokens.get("id_token", "")).get("https://api.openai.com/auth", {})
    account = tokens.get("account_id") or (claims.get("chatgpt_account_id") if isinstance(claims, dict) else None)
    return account if isinstance(account, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", account) else None


class CodexLogin:
    """A ChatGPT login used only by this controller, never by a host Codex.

    Refresh tokens are single-use, so one run holds the file at a time and each
    refresh is written back atomically before the new access token is used.
    """

    def __init__(self, raw):
        self.path = private_output(raw).resolve(strict=True)
        if os.name != "nt":
            require(self.path.stat().st_mode & 0o077 == 0, "Keep the ChatGPT login file private to your account (mode 0600)")
        self.lock = self.path.with_name(self.path.name + ".lock")
        self.data, self.refreshes = None, 0

    def __enter__(self):
        try:
            os.close(os.open(self.lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
        except FileExistsError:
            raise ProtocolError("Another run holds this ChatGPT login; if none is running, delete " + str(self.lock)) from None
        try:
            self.data = decode_json(self.path.read_bytes())
            require(codex_account(self.data) is not None, "Use a ChatGPT login created by agent_container.py codex-login")
        except BaseException:
            self.lock.unlink(missing_ok=True)
            raise
        return self

    def __exit__(self, *exc):
        self.lock.unlink(missing_ok=True)

    def headers(self):
        expiry = jwt_claims(self.data["tokens"]["access_token"]).get("exp")
        if type(expiry) in (int, float) and expiry - time.time() < CODEX_REFRESH_MARGIN:
            self.refresh()
        return {"Authorization": "Bearer " + self.data["tokens"]["access_token"], "ChatGPT-Account-ID": codex_account(self.data)}

    def refresh(self):
        # Every refresh rotates the single-use token; a run that keeps getting
        # 401 stops instead of burning through rotations.
        self.refreshes += 1
        require(self.refreshes <= MAX_REFRESHES, "The ChatGPT login keeps failing; run codex-login again")
        body = json.dumps({"client_id": CODEX_CLIENT_ID, "grant_type": "refresh_token",
                           "refresh_token": self.data["tokens"]["refresh_token"]}).encode()
        connection = http.client.HTTPSConnection(CODEX_AUTH_HOST, 443, context=ssl.create_default_context(), timeout=60)
        try:
            send(connection, "POST", "/oauth/token", body=body, headers={"Content-Type": "application/json", "Accept": "application/json"})
            response = connection.getresponse()
            raw = response.read(MAX_BODY + 1)
        finally:
            connection.close()
        require(response.status == 200 and len(raw) <= MAX_BODY, "The ChatGPT login could not be refreshed; run codex-login again")
        value = decode_json(raw)
        require(isinstance(value, dict) and isinstance(value.get("access_token"), str) and value["access_token"], "Unexpected ChatGPT token response")
        tokens = dict(self.data["tokens"])
        tokens.update({key: value[key] for key in ("access_token", "refresh_token", "id_token") if isinstance(value.get(key), str) and value[key]})
        data = dict(self.data, tokens=tokens, last_refresh=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"))
        require(codex_account(data) is not None, "Unexpected ChatGPT token response")
        write_private(self.path, data)
        self.data = data


class ModelGateway:
    def __init__(self, client, *, model=None, fixture_port=None, login=None):
        self.client, self.model, self.fixture_port, self.login, self.requests = client, model, fixture_port, login, 0
        self.catalogs = []
        self.session = str(uuid.uuid4())
        if client == "claude":
            # Claude passes its own subscription login through; the gateway only
            # checks that requests carry exactly the login the user exported.
            require(isinstance(login, str) and profile.CLAUDE_LOGIN.fullmatch(login) is not None, "Claude needs the user's own setup-token login")
        if fixture_port is None:
            require(isinstance(model, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", model) is not None, "Select an explicit model ID")
            require(client == "claude" or isinstance(login, CodexLogin), "Codex needs the dedicated ChatGPT login")

    def exchange(self, frame, wire):
        deadline = min(getattr(self, "deadline", float("inf")), time.monotonic() + RESPONSE_TIMEOUT)
        require(set(frame) == {"type", "id", "path", "beta", "auth", "body"} and frame["type"] == "model"
                and type(frame["id"]) is int and 0 < frame["id"] <= MAX_REQUESTS, "Invalid model envelope")
        self.requests += 1
        require(self.requests <= MAX_REQUESTS, "Model request budget exceeded")
        parsed = urlsplit(frame["path"])
        endpoints = {"/v1/responses"} if self.client == "codex" else {"/v1/messages", "/v1/messages/count_tokens"}
        require(not parsed.scheme and not parsed.netloc and not parsed.fragment and parsed.path in endpoints
                and parsed.query in (("",) if self.client == "codex" else ("", "beta=true")), "Model endpoint outside the approved profile")
        endpoint = parsed.path
        require(isinstance(frame["beta"], str) and len(frame["beta"]) <= 2048
                and re.fullmatch(r"[A-Za-z0-9,._ -]*", frame["beta"]) is not None, "Invalid model beta header")
        betas = [item for item in frame["beta"].split(",") if item]
        require(isinstance(frame["auth"], str) and len(frame["auth"]) <= 600, "Invalid client authorization")
        if self.client == "claude":
            # The genuine client signs in with the user's own subscription. The
            # gateway forwards that login unchanged and never stores or replaces it.
            require(hmac.compare_digest(frame["auth"].encode(), ("Bearer " + self.login).encode()),
                    "Claude must use the subscription login the user exported for this run")
            require(endpoint != "/v1/messages" or OAUTH_BETA in betas, "Claude subscription requests must carry the OAuth capability")
        else:
            require(frame["auth"] == "", "The contained Codex client must not hold a credential")
        raw = unpack(frame["body"])
        body = decode_json(raw)
        require(isinstance(body, dict), "Invalid model request body")
        validate_body(self.client, body, frame["beta"])
        counting = endpoint == "/v1/messages/count_tokens"
        names = catalog_names(self.client, [body.get("tools", [])], require_mcp=not counting)[0]
        if not counting:
            self.catalogs.append([{"type": "function", "name": name} if self.client == "codex" else {"name": name} for name in names])
        headers = {"Content-Type": "application/json", "Accept-Encoding": "identity"}
        path = endpoint + ("?beta=true" if parsed.query else "")
        if self.fixture_port is None:
            body["model"] = self.model
            if self.client == "codex":
                # The ChatGPT backend serves streamed, unstored responses only and
                # rejects output caps; byte and time budgets still bound them.
                require(body.get("stream") is True, "Codex must stream its responses")
                body["store"] = False
                body.pop("max_output_tokens", None)
                body.pop("background", None)
                headers.update({"Accept": "text/event-stream", "originator": "codex_exec", "version": CODEX_VERSION,
                                "User-Agent": "codex_exec/" + CODEX_VERSION, "session-id": self.session})
                hostname, path = CODEX_HOST, CODEX_PATH
            else:
                if endpoint == "/v1/messages":
                    maximum = body.get("max_tokens", MAX_OUTPUT_TOKENS)
                    require(type(maximum) is int and maximum > 0, "Invalid output token limit")
                    body["max_tokens"] = min(maximum, MAX_OUTPUT_TOKENS)
                    thinking = body.get("thinking", {})
                    if isinstance(thinking, dict) and thinking.get("type") == "enabled":
                        require(type(thinking.get("budget_tokens")) is int and 0 < thinking["budget_tokens"] < body["max_tokens"], "Thinking budget exceeds the gateway limit")
                headers.update({"Authorization": frame["auth"], "anthropic-version": "2023-06-01",
                                "anthropic-beta": ",".join(betas + [OAUTH_BETA] * (OAUTH_BETA not in betas))})
                hostname = "api.anthropic.com"
            raw = json.dumps(body, separators=(",", ":")).encode()
        for attempt in range(2):
            if self.fixture_port is not None:
                connection = http.client.HTTPConnection("127.0.0.1", self.fixture_port, timeout=60)
            else:
                if isinstance(self.login, CodexLogin):
                    headers.update(self.login.headers())
                connection = http.client.HTTPSConnection(hostname, 443, context=ssl.create_default_context(), timeout=60)
            try:
                send(connection, "POST", path, body=raw, headers=headers)
                response = connection.getresponse()
                if response.status == 401 and isinstance(self.login, CodexLogin) and attempt == 0:
                    # Renew an expired ChatGPT login once, before anything reaches the client.
                    self.login.refresh()
                    continue
                require(not 300 <= response.status < 400, "Model redirects are refused")
                content_type = response.getheader("Content-Type", "application/json").split(";", 1)[0]
                require(content_type in {"application/json", "text/event-stream"}, "Unexpected model response type")
                # Retry advice and plan-usage limits, so the client can tell a limit from an outage.
                limits = {name.lower(): value for name, value in response.getheaders()
                          if RESPONSE_HEADER.fullmatch(name.lower()) and re.fullmatch(r"[ -~]{0,200}", value)}
                wire.send({"type": "model-start", "id": frame["id"], "status": response.status, "content_type": content_type,
                           "headers": dict(sorted(limits.items())[:32])})
                total = 0
                while chunk := response.read1(16384):
                    require(time.monotonic() < deadline, "Model response exceeded time limit")
                    total += len(chunk)
                    require(total <= MAX_RESPONSE, "Model response exceeds byte limit")
                    wire.send({"type": "model-data", "id": frame["id"], "body": pack(chunk)})
                wire.send({"type": "model-end", "id": frame["id"]})
                return
            finally:
                connection.close()


@contextlib.contextmanager
def fixture(client, *, steps=None, test_refusals=True):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), OfflineHandler)
    server.client, server.requests, server.refused = client, 0, set()
    server.steps = steps if steps is not None else [("binary_session", {})]
    server.test_refusals = test_refusals
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def exercise(config, rea, *, prompt, gateway, timeout, login=None, diagnostics=None):
    boundary.preflight(rea)
    temporary, snapshot = input_snapshot.stage(rea["input_dir"], config["inputs"])
    managed = Containers(rea)
    incoming = queue.Queue(maxsize=16)
    transcripts = {"stdout": bytearray(), "stderr": bytearray()}
    container_errors = bytearray()
    policy, done = MCPPolicy(), None
    def queue_item(actor, item):
        incoming.put((actor, item), timeout=5)
    def read_agent(process):
        try:
            while (item := read_frame(process.stdout)) is not None:
                queue_item("agent", item)
            queue_item("agent", None)
        except (OSError, ProtocolError, queue.Full) as exc:
            queue_item("failure", str(exc))
    def read_rea(process):
        try:
            for raw in iter(lambda: process.stdout.readline(MAX_REA_LINE + 1), b""):
                require(len(raw) <= MAX_REA_LINE and raw.endswith(b"\n"), "REA response exceeds tunnel limit")
                queue_item("rea", raw)
            queue_item("rea", None)
        except (OSError, ProtocolError, queue.Full) as exc:
            queue_item("failure", str(exc))
    def drain_errors(process):
        total = 0
        for raw in iter(lambda: process.stderr.read1(16384), b""):
            total += len(raw)
            if total > MAX_TRANSCRIPT:
                queue_item("failure", "Container stderr exceeded byte limit")
                return
            container_errors.extend(raw)
    try:
        rea_id = managed.create("rea", rea["image_id"], snapshot)
        agent_id = managed.create("agent", config["agent_image_id"], snapshot)
        rea_process, agent_process = managed.start(rea_id), managed.start(agent_id)
        wire = Wire(PipeSink(agent_process.stdin))
        rea_sink = PipeSink(rea_process.stdin)
        for target, process in ((read_agent, agent_process), (read_rea, rea_process),
                                (drain_errors, agent_process), (drain_errors, rea_process)):
            threading.Thread(target=target, args=(process,), daemon=True).start()
        wire.send({"type": "start", "client": config["client"], "prompt": prompt, "login": login})
        deadline, frames = time.monotonic() + timeout, 0
        gateway.deadline = deadline
        while done is None:
            require(time.monotonic() < deadline, "Contained session exceeded time limit")
            try:
                actor, item = incoming.get(timeout=1)
            except queue.Empty:
                continue
            frames += 1
            require(frames <= MAX_FRAMES, "Tunnel frame budget exceeded")
            require(actor != "failure" and item is not None, "Contained transport closed before completion")
            if actor == "rea":
                wire.send({"type": "mcp", "body": pack(policy.response(item))})
            elif item["type"] == "mcp":
                require(set(item) == {"type", "body"}, "Unexpected MCP envelope")
                request = policy.request(unpack(item["body"]))
                if request is None:
                    wire.send({"type": "mcp", "body": pack(policy.local_response)})
                else:
                    rea_sink.write(request)
            elif item["type"] == "model":
                gateway.exchange(item, wire)
            elif item["type"] == "output":
                require(set(item) == {"type", "channel", "body"} and item["channel"] in transcripts, "Unexpected output channel")
                transcripts[item["channel"]].extend(unpack(item["body"]))
                require(sum(map(len, transcripts.values())) <= MAX_TRANSCRIPT, "Client transcript exceeded byte limit")
            elif item["type"] == "done":
                done = item
            else:
                raise ProtocolError("Unexpected worker frame")
        require(set(done) == {"type", "returncode", "version", "checks", "marker_absent", "bundle"}, "Unexpected worker result")
        require(done["returncode"] == 0 and done["version"] == profile.REVIEWED[config["client"]], "Contained client failed or changed version")
        require(done["bundle"] == {name: config["helpers"][name] for name in WORKER_FILES}, "Image helpers differ from reviewed local helpers; rebuild the agent image")
        require(isinstance(done["checks"], dict) and set(done["checks"]) == PROBE_KEYS
                and all(value is True for value in done["checks"].values()) and done["marker_absent"] is True, "Contained worker isolation check failed")
        require(policy.discovered == TOOLS and policy.server_version == "6.7.0", "Real REA catalog or version did not match")
        observations = catalog_names(config["client"], gateway.catalogs)
        stdout = bytes(transcripts["stdout"]).decode("utf-8", errors="replace")
        if config["client"] == "claude":
            initializations = []
            for line in stdout.splitlines():
                try:
                    item = json.loads(line)
                except ValueError:
                    continue
                if item.get("type") == "system" and item.get("subtype") == "init":
                    initializations.append(item)
            require(len(initializations) == 1 and set(initializations[0].get("tools", [])) == {"mcp__rea__" + name for name in TOOLS}
                    and initializations[0].get("skills") == [], "Contained Claude initialization catalog changed")
        return {"client_version": done["version"], "agent_probe": done["checks"], "rea_version": policy.server_version,
                "exposed_rea_tools": sorted(policy.discovered), "model_catalogs": observations,
                "completed_rea_calls": policy.completed_tools,
                "model_requests": gateway.requests, "host_write_marker_absent": True,
                "original_input_directory_mounted": False, "agent_mount_count": 0,
                "both_containers_network": "none",
                # The worker environment holds no credential; the Claude process holds its own login.
                "client_holds_subscription_login": config["client"] == "claude"}, transcripts
    except BaseException:
        if diagnostics is not None:
            for channel, data in {**transcripts, "container-stderr": container_errors}.items():
                target = diagnostics.with_name(diagnostics.stem + "." + channel + ".local.log")
                target.write_bytes(data)
                if os.name != "nt":
                    target.chmod(0o600)
        raise
    finally:
        original_error = sys.exc_info()[1]
        try:
            try:
                managed.close()
            except (ProtocolError, boundary.BoundaryError, OSError) as cleanup_error:
                if original_error is not None:
                    raise ProtocolError(str(original_error) + "; " + str(cleanup_error)) from original_error
                raise
        finally:
            temporary.cleanup()


def verify(args):
    path, config, rea = load_config(args.config)
    report = receipt_path(path)
    clear_receipt(report)
    with fixture(config["client"]) as server:
        # Claude runs its real subscription profile with an inert login, which the
        # gateway checks and the localhost fixture never receives.
        login = profile.OFFLINE_CLAUDE_LOGIN if config["client"] == "claude" else None
        gateway = ModelGateway(config["client"], fixture_port=server.server_port, login=login)
        result, _ = exercise(config, rea, prompt="Reply with a short acknowledgement after the offline boundary check.", gateway=gateway,
                             timeout=120, login=login, diagnostics=path)
        expected = {"exec_command", "apply_patch"} if config["client"] == "codex" else {"Bash", "Write"}
        require(expected <= server.refused, "Contained client did not reject undeclared host tools")
        require(result["completed_rea_calls"] == ["binary_session"], "The client did not complete a real REA tool call")
        result["undeclared_tools_rejected"] = sorted(server.refused)
    result.update(status="verified-contained-offline", identity=identity(path, config), real_provider_requests=0)
    write_private(report, result)  # replaces, never writes through, whatever is at the path
    return result


def run(args):
    path, config, rea = load_config(args.config)
    report = decode_json(receipt_path(path).read_bytes())
    require(report.get("status") == "verified-contained-offline" and report.get("identity") == identity(path, config), "A matching native paired verification is required")
    prompt = Path(args.prompt_file).read_text(encoding="utf-8")
    require(bool(prompt.strip()) and len(prompt.encode()) <= 128 * 1024, "Provide a bounded analysis prompt")
    output = private_output(args.output)
    require(not output.exists(), "Use a new private output directory for every fresh contained session")
    if config["client"] == "claude":
        # The user's own `claude setup-token` login, held in memory for this run:
        # it goes to the contained Claude Code, and the gateway checks that each
        # request carries exactly it. It is never written to disk.
        login = os.environ.get("CLAUDE_CODE_OAUTH_TOKEN", "")
        require(profile.CLAUDE_LOGIN.fullmatch(login) is not None, "Run `claude setup-token` and set CLAUDE_CODE_OAUTH_TOKEN for this command")
        account = contextlib.nullcontext(login)
    else:
        require(bool(args.codex_login), "Create a dedicated ChatGPT login with codex-login and pass it as --codex-login")
        login, account = None, CodexLogin(args.codex_login)
    with account as credential:
        gateway = ModelGateway(config["client"], model=args.model, login=credential)
        output.mkdir(mode=0o700, parents=True)
        profile.write_json(output / "started.json", {"identity": identity(path, config), "model": args.model})
        # A failed run still leaves its transcripts in the private output directory.
        result, transcripts = exercise(config, rea, prompt=prompt, gateway=gateway, timeout=1800, login=login,
                                       diagnostics=output / "failed")
    for channel, data in transcripts.items():
        target = output / ("agent." + channel + ".jsonl")
        target.write_bytes(data)
        if os.name != "nt":
            target.chmod(0o600)
    result.update(status="completed-contained-analysis", model=args.model, output_directory=str(output))
    try:
        result["report_file"] = str(write_report(output, result))
    except ProtocolError:
        result["report_file"] = None  # the transcripts stay available for diagnosis
    profile.write_json(output / "result.json", result)
    return result


# Terminal control characters and bidirectional overrides: model text written
# from an untrusted file must not drive a terminal or disguise what it says.
UNSAFE_TEXT = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f\u200e\u200f\u202a-\u202e\u2066-\u2069]")


def final_report(output):
    """The model's final answer from a run's transcript (Claude Code or Codex)."""
    text = None
    for line in (output / "agent.stdout.jsonl").read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if not isinstance(item, dict):
            continue
        if item.get("type") == "result" and isinstance(item.get("result"), str):  # Claude Code
            text = item["result"]
        event = item.get("item")
        if item.get("type") == "item.completed" and isinstance(event, dict) and event.get("type") == "agent_message" \
                and isinstance(event.get("text"), str):  # Codex
            text = event["text"]
    require(text is not None and text.strip() != "", "This run's transcript has no final report")
    return UNSAFE_TEXT.sub("", text)


def write_report(output, result):
    probes = result.get("agent_probe", {})
    checks = "all {} passed".format(len(probes)) if probes and all(value is True for value in probes.values()) else "NOT all passed"
    lines = ["# REA Safe Agent analysis report", "",
             "- Model: " + str(result.get("model", "?")),
             "- Client: " + str(result.get("client_version", "?")) + ", REA " + str(result.get("rea_version", "?")),
             "- REA calls: " + ", ".join(result.get("completed_rea_calls", [])),
             "- Isolation checks: " + checks + "; container network " + str(result.get("both_containers_network", "?"))
             + "; agent host mounts " + str(result.get("agent_mount_count", "?")), "",
             "> Written by the model from REA's output about a file you do not trust.",
             "> Treat it as untrusted text and verify any claim that matters.", "", "---", "", final_report(output)]
    path = output / "report.md"
    with os.fdopen(os.open(path, os.O_CREAT | os.O_TRUNC | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600), "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines).rstrip("\n") + "\n")
    if os.name != "nt":
        path.chmod(0o600)  # also when an older report.md had wider permissions
    return path


def report(args):
    output = private_output(args.output).resolve(strict=True)
    result = decode_json((output / "result.json").read_bytes())
    require(isinstance(result, dict) and result.get("status") == "completed-contained-analysis", "Not a completed analysis folder")
    return write_report(output, result).read_text(encoding="utf-8")


def codex_login(args):
    _, config, rea = load_config(args.config)
    require(config["client"] == "codex", "Use the Codex paired configuration")
    output = private_output(args.output)
    require(not output.exists() and output.parent.is_dir(), "Use a new file in an existing private control directory")
    boundary.preflight(rea)
    # The only network-enabled container: the pinned official client signs in
    # through OpenAI's device flow with an empty tmpfs home. It gets no input,
    # REA, host mount or Docker socket; the login returns on stdout only.
    script = ('mkdir -p "$CODEX_HOME" && /opt/agent-bin/codex login --device-auth >&2 '
              '&& printf "%s\\n" REA-CODEX-LOGIN && base64 -w0 "$CODEX_HOME/auth.json"')
    name = "rea-codex-login-" + uuid.uuid4().hex[:12]
    base = [rea["docker"], "--config", rea["docker_config"], "--context", rea["context"]]
    argv = [*base, "run", "--rm", "--pull=never", "--name=" + name, "--label=org.rea-isolated.managed=true",
            "--label=org.rea-isolated.role=codex-login", "--read-only", "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true", "--user=1000:1000", "--memory=1g", "--memory-swap=1g", "--cpus=1",
            "--pids-limit=64", "--log-driver=none",
            "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,mode=1777,size=64m",
            "--tmpfs", "/home/node:rw,nosuid,nodev,noexec,uid=1000,gid=1000,mode=0700,size=64m",
            "--env=HOME=/home/node", "--env=CODEX_HOME=/home/node/codex",
            "--entrypoint=/bin/sh", config["agent_image_id"], "-c", script]
    allowed = {"PATH", "SystemRoot", "WINDIR", "PATHEXT", "TEMP", "TMP", "TMPDIR", "LANG"}
    env = {key: value for key, value in os.environ.items() if key in allowed}
    process = subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, shell=False)
    try:
        output_box = []
        reader = threading.Thread(target=lambda: output_box.append(process.stdout.read(CODEX_LOGIN_OUTPUT + 1)), daemon=True)
        reader.start()
        reader.join(timeout=1200)
        require(not reader.is_alive(), "The ChatGPT device login timed out")
        process.wait(timeout=30)
    finally:
        if process.poll() is None:
            # The CLI alone would leave the container running.
            subprocess.run([*base, "rm", "--force", name], env=env, capture_output=True, timeout=60, shell=False)
            process.kill()
            process.wait(timeout=10)
    stdout = output_box[0] if output_box else b""
    marker = b"REA-CODEX-LOGIN\n"
    require(process.returncode == 0 and len(stdout) <= CODEX_LOGIN_OUTPUT and stdout.count(marker) == 1,
            "The ChatGPT device login did not complete")
    data = decode_json(base64.b64decode(stdout.split(marker, 1)[1].strip(), validate=True))
    require(codex_account(data) is not None, "The device login did not return a ChatGPT account")
    write_private(output, data)
    return {"codex_login": str(output), "status": "dedicated-chatgpt-login-saved"}


def codex_models(args):
    """List the model IDs the dedicated ChatGPT login may use with Codex."""
    with CodexLogin(args.codex_login) as login:
        headers = dict(login.headers(), **{"Accept": "application/json", "originator": "codex_exec", "version": CODEX_VERSION,
                                           "User-Agent": "codex_exec/" + CODEX_VERSION})
        connection = http.client.HTTPSConnection(CODEX_HOST, 443, context=ssl.create_default_context(), timeout=60)
        try:
            send(connection, "GET", "/backend-api/codex/models?client_version=" + CODEX_VERSION, headers=headers)
            response = connection.getresponse()
            raw = response.read(MAX_BODY + 1)
        finally:
            connection.close()
    require(response.status == 200 and len(raw) <= MAX_BODY, "ChatGPT did not return the model list")
    value = decode_json(raw)
    models = value.get("models") if isinstance(value, dict) else None
    require(isinstance(models, list), "Unexpected ChatGPT model list")
    return {"models": [item["slug"] for item in models if isinstance(item, dict) and isinstance(item.get("slug"), str)
                       and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", item["slug"]) and item.get("visibility") == "list"]}


def main():
    signal.signal(signal.SIGTERM, boundary.interrupt_cleanup)
    if hasattr(signal, "SIGBREAK"):
        signal.signal(signal.SIGBREAK, boundary.interrupt_cleanup)
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="operation", required=True)
    p = sub.add_parser("configure")
    p.add_argument("--rea-config", required=True)
    p.add_argument("--image", required=True)
    p.add_argument("--client", choices=sorted(profile.REVIEWED), required=True)
    p.add_argument("--output", required=True)
    p = sub.add_parser("codex-models")
    p.add_argument("--codex-login", required=True)
    p = sub.add_parser("report", help="Print and save the final report of a completed analysis")
    p.add_argument("--output", required=True, help="The analysis output folder given to run")
    for operation in ("verify", "run", "codex-login"):
        p = sub.add_parser(operation)
        p.add_argument("--config", required=True)
        if operation == "run":
            p.add_argument("--model", required=True)
            p.add_argument("--prompt-file", required=True)
            p.add_argument("--output", required=True)
            p.add_argument("--codex-login", help="Dedicated ChatGPT login file created by codex-login (Codex only)")
        if operation == "codex-login":
            p.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        function = {"configure": configure, "verify": verify, "run": run, "codex-login": codex_login,
                    "codex-models": codex_models, "report": report}[args.operation]
        value = function(args)
        print(value if isinstance(value, str) else json.dumps(value, indent=2))
        return 0
    except KeyboardInterrupt:
        print("Contained session interrupted; exact-container cleanup requested", file=sys.stderr)
        return 130
    except (ProtocolError, boundary.BoundaryError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        print("REA contained-session refused: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
