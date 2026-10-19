#!/usr/bin/env python3
"""Prepare and verify a fresh REA-only tool session. Python 3.11+, no dependencies."""

import argparse
import hashlib
import http.server
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import threading
from urllib.parse import urlsplit


CODEX_PASSIVE = {"list_mcp_resources", "list_mcp_resource_templates", "read_mcp_resource", "request_user_input"}
CODEX_OFF = (
    "shell_tool", "shell_snapshot", "goals", "sleep_tool", "apps", "browser_use",
    "browser_use_external", "computer_use", "image_generation", "multi_agent",
    "multi_agent_v2", "plugins", "hooks", "code_mode", "code_mode_host", "view_image",
)
REVIEWED = {"codex": "codex-cli 0.163.0", "claude": "2.1.302 (Claude Code)"}
# Seconds one REA call may run; the first native query starts Ghidra.
TOOL_TIMEOUT = 900
MAX_TURNS = 100  # upper bound for Claude's agentic turns; the controller sets the actual value
# Claude signs in with the user's own `claude setup-token` login. Offline checks
# use this inert value, which the localhost fixture never forwards anywhere.
CLAUDE_LOGIN = re.compile(r"sk-ant-oat[0-9A-Za-z_-]{8,512}")
OFFLINE_CLAUDE_LOGIN = "sk-ant-oat01-offline-fixture-not-a-credential"
HERE = Path(__file__).resolve()
CONTAINER = HERE.with_name("container.py")
PROMPT = "Reply with a short acknowledgement. This is an offline tool catalog check."


class BoundaryError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise BoundaryError(message)


def digest(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    if os.name != "nt":
        Path(path).chmod(0o600)


def executable_path(client, raw=None):
    value = raw or shutil.which(client)
    require(value is not None, "Install the selected client separately; this helper never installs clients")
    path = Path(value).expanduser().absolute()
    require(path.is_file(), "Client executable does not exist")
    require(path.suffix.lower() not in (".bat", ".cmd", ".ps1"), "Use the native executable; shell wrappers are unsupported")
    return str(path)


def environment(root, client):
    # No credentials, proxy configuration, provider overrides, plugin paths,
    # global configuration paths, NODE_OPTIONS or PYTHONPATH are inherited.
    allowed = {"PATH", "SystemRoot", "WINDIR", "PATHEXT", "TEMP", "TMP", "TMPDIR", "LANG"}
    env = {k: v for k, v in os.environ.items() if k in allowed}
    home = Path(root) / "home"
    home.mkdir(exist_ok=True)
    env.update(HOME=str(home), USERPROFILE=str(home), XDG_CONFIG_HOME=str(home / "config"),
               XDG_DATA_HOME=str(home / "data"), XDG_CACHE_HOME=str(home / "cache"))
    if client == "codex":
        config = home / "codex"
        env["CODEX_HOME"] = str(config)
    else:
        config = home / "claude"
        env.update(CLAUDE_CONFIG_DIR=str(config), CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1",
                   DISABLE_AUTOUPDATER="1", DISABLE_TELEMETRY="1", DISABLE_ERROR_REPORTING="1")
    config.mkdir(exist_ok=True)
    return env, config


def client_version(executable, root, client):
    env, _ = environment(root, client)
    result = subprocess.run([executable, "--version"], env=env, cwd=root,
                            capture_output=True, text=True, timeout=15, shell=False)
    require(result.returncode == 0, "Client version check failed")
    return result.stdout.strip()


def identity(session):
    return {"client": session["client"], "version": session["version"],
            "executable_sha256": digest(session["executable"]), "helper_sha256": digest(HERE),
            "container_helper_sha256": digest(CONTAINER), "deployment_sha256": digest(session["deployment"])}


def prepare(args):
    root = Path(args.output).expanduser().absolute()
    require(not root.exists(), "Use a new session directory; existing state is never reused")
    deployment = Path(args.deployment).expanduser().resolve(strict=True)
    require(deployment.is_file(), "Expected the approved container deployment JSON")
    # Parse the strict deployment schema without starting Docker or REA.
    data = json.loads(deployment.read_text(encoding="utf-8"))
    require(set(data) == {"schema", "docker", "docker_config", "context", "image_id", "input_dir"} and data["schema"] == 1,
            "Unexpected container deployment schema")
    root.mkdir(parents=True, mode=0o700)
    (root / "work").mkdir(mode=0o700)
    client = args.client
    executable = executable_path(client, args.executable)
    version = client_version(executable, root, client)
    require(version == REVIEWED[client], "Client version has not been reviewed; stop and update the profile with behavioral evidence")
    session = {"schema": 1, "client": client, "executable": executable, "version": version,
               "deployment": str(deployment)}
    session["identity"] = identity(session)
    write_json(root / "session.json", session)
    return {"session": str(root), "client": client, "version": version, "status": "requires-offline-verification"}


def load_session(raw):
    root = Path(raw).expanduser().resolve(strict=True)
    session = json.loads((root / "session.json").read_text(encoding="utf-8"))
    require(set(session) == {"schema", "client", "executable", "version", "deployment", "identity"}, "Unexpected session schema")
    require(session["schema"] == 1 and session["client"] in REVIEWED, "Unsupported client session")
    require(session["version"] == REVIEWED[session["client"]], "Unreviewed client version")
    require(identity(session) == session["identity"], "Executable, helpers or deployment changed; prepare a new session")
    require(client_version(session["executable"], root, session["client"]) == session["version"], "Client version changed")
    require((root / "work").is_dir() and not (root / "work").is_symlink(), "Unexpected working directory")
    return root, session


def mcp_command(deployment):
    return [str(Path(sys.executable).resolve()), str(CONTAINER), "mcp", "--config", str(deployment)]


def check_mock_url(value):
    parsed = urlsplit(value)
    require(parsed.scheme == "http" and parsed.hostname == "127.0.0.1" and parsed.port
            and not parsed.username and not parsed.password and parsed.path == ""
            and not parsed.query and not parsed.fragment, "Offline provider must be localhost")


def command(root, session, mcp, *, mock_url=None, prompt=PROMPT, login=None, max_turns=20):
    require(type(max_turns) is int and 0 < max_turns <= MAX_TURNS, "Invalid turn budget")
    client = session["client"]
    env, config_dir = environment(root, client)
    # "--" ends option parsing, so a prompt starting with "-" stays a prompt.
    if client == "codex":
        lines = ["sandbox_mode = \"read-only\"", "approval_policy = \"never\"", "web_search = \"disabled\""]
        if mock_url:
            check_mock_url(mock_url)
            lines += ["model = \"offline-probe\"", "model_provider = \"offline\"", "[model_providers.offline]",
                      "name = \"Offline probe\"", "base_url = " + json.dumps(mock_url + "/v1"),
                      "wire_api = \"responses\"", "requires_openai_auth = false", "request_max_retries = 0", "stream_max_retries = 0"]
        lines += ["[features]"] + [name + " = false" for name in CODEX_OFF]
        lines += ["[mcp_servers.rea]", "command = " + json.dumps(mcp[0]), "args = " + json.dumps(mcp[1:]), "required = true"]
        (config_dir / "config.toml").write_text("\n".join(lines) + "\n", encoding="utf-8")
        args = [session["executable"], "exec", "--skip-git-repo-check", "--ephemeral", "--ignore-rules", "--strict-config", "--json", "--", prompt]
    else:
        mcp_path = Path(root) / "mcp.json"
        write_json(mcp_path, {"mcpServers": {"rea": {"command": mcp[0], "args": mcp[1:], "timeout": TOOL_TIMEOUT * 1000}}})
        # Bare mode ignores subscription logins. The explicit flags keep the
        # same minimal profile: no built-in tools, settings, hooks or commands.
        args = [session["executable"], "--tools", "", "--strict-mcp-config", "--mcp-config", str(mcp_path),
                "--setting-sources", "", "--permission-mode", "dontAsk", "--allowedTools", "mcp__rea__*", "--no-chrome",
                "--disable-slash-commands", "--no-session-persistence", "--settings", '{"disableAllHooks":true}',
                "--max-turns", str(max_turns), "--verbose", "--output-format", "stream-json", "-p", "--", prompt]
        if mock_url:
            check_mock_url(mock_url)
            require(isinstance(login, str) and CLAUDE_LOGIN.fullmatch(login) is not None, "Claude needs the user's own setup-token login")
            env.update(CLAUDE_CODE_OAUTH_TOKEN=login, ANTHROPIC_BASE_URL=mock_url)
    return args, env


def fixture_mcp():
    """Inert MCP server used only by offline verification, never a REA substitute."""
    for line in sys.stdin:
        request = json.loads(line)
        method = request.get("method")
        result = {}
        if method == "initialize":
            result = {"protocolVersion": request["params"]["protocolVersion"], "capabilities": {"tools": {}},
                      "serverInfo": {"name": "inert-rea-fixture", "version": "1"}}
        elif method == "tools/list":
            result = {"tools": [{"name": "catalog_probe", "description": "Inert fixture; no host data or actions",
                                  "inputSchema": {"type": "object", "properties": {}}}]}
        elif method == "tools/call":
            result = {"content": [{"type": "text", "text": "inert fixture"}]}
        if "id" in request:
            print(json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}), flush=True)


def refusal_evidence(body):
    refused = set()
    for item in body.get("input", []):
        if isinstance(item, dict) and item.get("type") == "function_call_output":
            value = str(item.get("output", ""))
            for name in ("exec_command", "apply_patch"):
                if "unsupported call: " + name in value:
                    refused.add(name)
    for message in body.get("messages", []):
        for item in message.get("content", []) if isinstance(message.get("content"), list) else []:
            if item.get("type") == "tool_result" and item.get("is_error"):
                value = str(item.get("content", ""))
                for name in ("Bash", "Write"):
                    if "No such tool available: " + name in value:
                        refused.add(name)
    return refused


class MockHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        # Store schemas only. Never log request headers or the conversation.
        require(self.headers.get("content-encoding", "identity") == "identity", "Unexpected compressed request")
        length = int(self.headers.get("content-length", "0"))
        require(0 < length < 4 * 1024 * 1024, "Unexpected request size")
        body = json.loads(self.rfile.read(length))
        self.server.refused.update(refusal_evidence(body))
        if self.path.startswith("/v1/messages"):
            self.server.catalogs.append(body.get("tools", []))
            result = {"id": "msg_offline", "type": "message", "role": "assistant", "model": body.get("model", "offline"),
                      "content": [{"type": "text", "text": "Offline catalog captured."}], "stop_reason": "end_turn",
                      "stop_sequence": None, "usage": {"input_tokens": 1, "output_tokens": 1}}
            if not {"Bash", "Write"} <= self.server.refused:
                result["content"] = [
                    {"type": "tool_use", "id": "deny_bash", "name": "Bash", "input": {"command": "echo REA_OFFLINE_HOST_EXEC_PROBE"}},
                    {"type": "tool_use", "id": "deny_write", "name": "Write", "input": {"file_path": str(self.server.marker), "content": "must not exist"}},
                ]
                result["stop_reason"] = "tool_use"
            payload, content_type = json.dumps(result).encode(), "application/json"
        elif self.path == "/v1/responses":
            self.server.catalogs.append(body.get("tools", []))
            result = {"id": "resp_offline", "object": "response", "created_at": 0, "status": "completed",
                      "output": [], "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2}}
            if not {"exec_command", "apply_patch"} <= self.server.refused:
                patch_text = "*** Begin Patch\n*** Add File: " + str(self.server.marker) + "\n+must not exist\n*** End Patch"
                result["output"] = [
                    {"id": "fc_exec", "type": "function_call", "call_id": "deny_exec", "name": "exec_command", "arguments": json.dumps({"cmd": "echo REA_OFFLINE_HOST_EXEC_PROBE"})},
                    {"id": "fc_patch", "type": "function_call", "call_id": "deny_patch", "name": "apply_patch", "arguments": json.dumps({"patch": patch_text})},
                ]
            events = [("response.created", {"type": "response.created", "response": dict(result, status="in_progress", output=[])}),
                      *[(event, {"type": event, "output_index": i, "item": item}) for i, item in enumerate(result["output"])
                        for event in ("response.output_item.added", "response.output_item.done")],
                      ("response.completed", {"type": "response.completed", "response": result})]
            payload = "".join("event: " + name + "\ndata: " + json.dumps(value) + "\n\n" for name, value in events).encode()
            content_type = "text/event-stream"
        else:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def catalog_evidence(client, catalogs, stdout):
    require(bool(catalogs), "No model request was captured; tool boundary is unverified")
    names = []
    for catalog in catalogs:
        require(isinstance(catalog, list), "Unexpected tool schema")
        current = set()
        for tool in catalog:
            name = tool.get("name", tool.get("type", ""))
            if client == "codex" and tool.get("type") == "namespace":
                require(name == "mcp__rea", "Unexpected tool namespace")
                require({item.get("name") for item in tool.get("tools", [])} == {"catalog_probe"}, "Unexpected fixture tools")
                current.add("mcp__rea__catalog_probe")
            else:
                current.add(name)
        allowed = CODEX_PASSIVE | {"mcp__rea__catalog_probe"} if client == "codex" else {"mcp__rea__catalog_probe"}
        require("mcp__rea__catalog_probe" in current, "REA fixture is missing; this is not a valid receiving-agent test")
        require(current <= allowed, "Unexpected actionable tools: " + ", ".join(sorted(current - allowed)))
        names.append(sorted(current))
    metadata = {}
    if client == "claude":
        inits = []
        for line in stdout.splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if item.get("type") == "system" and item.get("subtype") == "init":
                inits.append(item)
        require(len(inits) == 1, "Claude did not report a unique initialization catalog")
        require(set(inits[0].get("tools", [])) == {"mcp__rea__catalog_probe"}, "Claude initialization tool catalog changed")
        require(inits[0].get("skills") == [], "Unexpected skills in the fresh Claude session")
        require(inits[0].get("mcp_servers") == [{"name": "rea", "status": "connected", "source": "dynamic"}], "Unexpected connected MCP servers")
        metadata = {"client_agent_type_metadata": inits[0].get("agents", []),
                    "client_plugin_metadata": [item.get("name") for item in inits[0].get("plugins", [])]}
    return {"request_catalogs": names, **metadata, "host_shell_file_browser_tools_advertised": False,
            "scope": "offline mock-provider tool advertisement and undeclared-tool rejection; not OS containment or real-model certification"}


def verify(args):
    root, session = load_session(args.session)
    report = root / "verification.json"
    report.unlink(missing_ok=True)  # A failed retry must not leave a passing certificate.
    with tempfile.TemporaryDirectory(prefix="rea-client-offline-") as temporary:
        probe = Path(temporary)
        (probe / "work").mkdir()
        try:
            server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), MockHandler)
        except OSError as exc:
            raise BoundaryError("Cannot bind the localhost mock provider; client boundary remains unverified") from exc
        server.catalogs = []
        server.refused = set()
        server.marker = probe / "work" / "UNEXPECTED-HOST-WRITE"
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = "http://127.0.0.1:" + str(server.server_port)
            argv, env = command(probe, session, [str(Path(sys.executable).resolve()), str(HERE), "fixture-mcp"], mock_url=url,
                                login=OFFLINE_CLAUDE_LOGIN)
            result = subprocess.run(argv, env=env, cwd=probe / "work", stdin=subprocess.DEVNULL,
                                    capture_output=True, text=True, timeout=45, shell=False)
            require(result.returncode == 0, "Offline client check failed; no live-provider fallback is allowed")
            evidence = catalog_evidence(session["client"], server.catalogs, result.stdout)
            expected_refusals = {"Bash", "Write"} if session["client"] == "claude" else {"exec_command", "apply_patch"}
            require(expected_refusals <= server.refused, "Client did not prove rejection of undeclared host tools")
            require(not server.marker.exists(), "A disabled host file tool created the marker; do not use this profile")
            evidence["undeclared_host_tool_calls_rejected"] = sorted(server.refused)
            evidence["host_write_marker_absent"] = True
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
    value = {"schema": 1, "status": "verified-offline-catalog", "identity": session["identity"], "evidence": evidence,
             "host_os": sys.platform, "python": sys.version.split()[0]}
    write_json(report, value)
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="operation", required=True)
    p = sub.add_parser("prepare", help="Create separate client state without changing global settings")
    p.add_argument("--client", required=True, choices=sorted(REVIEWED))
    p.add_argument("--deployment", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--executable", help="Absolute native Codex or Claude executable")
    p = sub.add_parser("verify")
    p.add_argument("--session", required=True)
    sub.add_parser("fixture-mcp", help=argparse.SUPPRESS)
    args = parser.parse_args()
    try:
        if args.operation == "fixture-mcp":
            fixture_mcp()
            return 0
        raise BoundaryError("Host receiving sessions are retired; use agent_container.py configure, verify and run")
    except (BoundaryError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        print("REA receiving-agent isolation refused: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
