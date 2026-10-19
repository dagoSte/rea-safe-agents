#!/usr/bin/env python3
"""Image-owned worker. All client execution stays inside the agent container."""

import http.server
import errno
import fcntl
import json
import os
from pathlib import Path
import queue
import re
import shutil
import socket
import subprocess
import struct
import sys
import threading

import agent_session as profile
from tunnel import MAX_BODY, MAX_RESPONSE, MAX_TRANSCRIPT, STATIC_TOOLS, ProtocolError, Wire, digest, pack, read_frame, require, unpack

SOCKET = "/tmp/rea-mcp.sock"
# Longest silence between two pieces of one model answer, e.g. during reasoning.
STREAM_GAP = 300
RESPONSE_HEADER = re.compile(r"retry-after|x-should-retry|anthropic-ratelimit-unified-[a-z0-9-]{1,64}")
MARKER = "/tmp/rea-unexpected-write"
HERE = Path(__file__).resolve()


def relay():
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.connect(SOCKET)
        def incoming():
            try:
                while True:
                    raw = connection.recv(65536)
                    if not raw:
                        return
                    sys.stdout.buffer.write(raw)
                    sys.stdout.buffer.flush()
            except OSError:
                return
        thread = threading.Thread(target=incoming, daemon=True)
        thread.start()
        for raw in iter(lambda: sys.stdin.buffer.readline(MAX_BODY + 1), b""):
            require(len(raw) <= MAX_BODY and raw.endswith(b"\n"), "Invalid MCP relay line")
            connection.sendall(raw)
        connection.shutdown(socket.SHUT_WR)
        thread.join(timeout=5)


def no_active_external_interface():
    # Linux creates DOWN fallback tunnel devices even for network=none.
    # Query flags in this process's namespace; names alone are insufficient.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
        for _, name in socket.if_nameindex():
            flags = fcntl.ioctl(connection.fileno(), 0x8913, struct.pack("256s", name.encode()))
            if name != "lo" and struct.unpack("H", flags[16:18])[0] & 1:  # IFF_UP
                return False
    return True


def probe():
    status = Path("/proc/self/status").read_text()
    fields = dict(line.split(":", 1) for line in status.splitlines() if ":" in line)
    checks = {
        "non_root": os.getuid() == 1000,
        "no_new_privileges": fields.get("NoNewPrivs", "").strip() == "1",
        "no_effective_capabilities": int(fields.get("CapEff", "1").strip(), 16) == 0,
        "seccomp_filter_active": fields.get("Seccomp", "").strip() == "2",
        "no_active_non_loopback_interface": no_active_external_interface(),
        "no_docker_cli": shutil.which("docker") is None,
        "no_docker_socket": not any(Path(path).exists() for path in ("/var/run/docker.sock", "/run/docker.sock")),
        "no_host_input_mount": not Path("/input").exists(),
        "no_model_credentials": not any(os.environ.get(key) for key in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN",
                                                                        "CLAUDE_CODE_OAUTH_TOKEN", "CODEX_API_KEY", "CODEX_ACCESS_TOKEN", "SSH_AUTH_SOCK")),
    }
    target = Path("/rea-write-must-fail")
    try:
        with target.open("x") as handle:
            handle.write("probe")
        checks["root_write_denied"] = False
        target.unlink()
    except OSError as exc:
        checks["root_write_denied"] = exc.errno in (errno.EROFS, errno.EACCES, errno.EPERM)
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connection.settimeout(1)
    try:
        connection.connect(("1.1.1.1", 443))
        checks["outbound_connection_denied"] = False
    except OSError as exc:
        checks["outbound_connection_denied"] = exc.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH, errno.EACCES, errno.EPERM)
    finally:
        connection.close()
    return checks


class Gateway(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_GET(self):
        self.send_error(404)

    def do_POST(self):
        pending = queue.Queue(maxsize=8)
        registered = False
        try:
            require(self.headers.get("Transfer-Encoding") is None, "Chunked requests are unsupported")
            require(self.headers.get("Content-Encoding", "identity") == "identity", "Compressed requests are unsupported")
            length = int(self.headers.get("Content-Length", "0"))
            require(0 < length <= MAX_BODY, "Invalid request size")
            with self.server.pending_lock:
                require(not self.server.pending, "Concurrent model requests are refused")
                self.server.sequence += 1
                identifier = self.server.sequence
                self.server.pending[identifier] = pending
                registered = True
            body = self.rfile.read(length)
            require(len(body) == length, "Incomplete model request")
            # The client's own login header is passed to the host gateway, which
            # forwards it only to the fixed provider endpoint.
            self.server.wire.send({"type": "model", "id": identifier, "path": self.path,
                                   "beta": self.headers.get("anthropic-beta", ""),
                                   "auth": self.headers.get("Authorization", ""), "body": pack(body)})
            first = pending.get(timeout=STREAM_GAP)
            require(first.get("type") == "model-start", "Missing model response headers")
            self.send_response(first["status"])
            self.send_header("Content-Type", first["content_type"])
            headers = first.get("headers", {})
            require(isinstance(headers, dict) and len(headers) <= 32, "Invalid model response headers")
            for name, value in headers.items():
                require(isinstance(name, str) and isinstance(value, str) and RESPONSE_HEADER.fullmatch(name) is not None
                        and re.fullmatch(r"[ -~]{0,200}", value) is not None, "Invalid model response header")
                self.send_header(name, value)
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True
            total = 0
            while True:
                item = pending.get(timeout=STREAM_GAP)
                if item["type"] == "model-end":
                    break
                require(item["type"] == "model-data", "Unexpected model response")
                raw = unpack(item["body"])
                total += len(raw)
                require(total <= MAX_RESPONSE, "Model response exceeds byte limit")
                self.wfile.write(raw)
                self.wfile.flush()
        except (ProtocolError, ValueError, OSError, queue.Empty):
            self.close_connection = True
        finally:
            if registered:
                with self.server.pending_lock:
                    self.server.pending.pop(identifier, None)


def run():
    start = read_frame(sys.stdin.buffer)
    require(start is not None and set(start) == {"type", "client", "prompt", "login", "turns", "tool_timeout"} and start["type"] == "start",
            "Invalid worker start")
    client, prompt, login, turns, tool_timeout = start["client"], start["prompt"], start["login"], start["turns"], start["tool_timeout"]
    require(client in profile.REVIEWED and isinstance(prompt, str) and 0 < len(prompt.encode()) <= 128 * 1024, "Invalid client or prompt")
    # Claude receives the user's own login in its process environment only;
    # Codex never holds one, because the host gateway authenticates it.
    require(login is None if client == "codex" else isinstance(login, str) and profile.CLAUDE_LOGIN.fullmatch(login) is not None,
            "Invalid client login")
    checks = probe()
    require(all(checks.values()), "Agent container probe failed: " + ", ".join(key for key, value in checks.items() if not value))
    root = Path("/home/node/session")
    root.mkdir(mode=0o700)
    (root / "work").mkdir()
    executable = "/opt/agent-bin/" + client
    version = profile.client_version(executable, root, client)
    require(version == profile.REVIEWED[client], "Unreviewed contained client version")
    wire = Wire(sys.stdout.buffer)
    stopped = threading.Event()
    failure = []
    peer = []
    pending_mcp = queue.Queue(maxsize=8)
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Gateway)
    server.daemon_threads = True
    server.wire, server.pending, server.pending_lock, server.sequence = wire, {}, threading.Lock(), 0
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(SOCKET)
    os.chmod(SOCKET, 0o600)
    listener.listen(1)

    def receive():
        try:
            while not stopped.is_set():
                item = read_frame(sys.stdin.buffer)
                require(item is not None, "Host tunnel closed")
                if item["type"] == "mcp":
                    require(set(item) == {"type", "body"}, "Unexpected MCP envelope")
                    pending_mcp.put(unpack(item["body"]), timeout=5)
                else:
                    require(item["type"] in {"model-start", "model-data", "model-end"}, "Unexpected host frame")
                    with server.pending_lock:
                        target = server.pending.get(item.get("id"))
                    require(target is not None, "Unknown model request")
                    target.put(item, timeout=5)
        except (OSError, ProtocolError, queue.Full) as exc:
            if not stopped.is_set():
                failure.append(str(exc))
                stopped.set()

    def bridge():
        try:
            connection, _ = listener.accept()
            peer.append(connection)
            def output():
                while not stopped.is_set():
                    try:
                        raw = pending_mcp.get(timeout=1)
                    except queue.Empty:
                        continue
                    connection.sendall(raw)
            threading.Thread(target=output, daemon=True).start()
            with connection.makefile("rb") as stream:
                for raw in iter(lambda: stream.readline(MAX_BODY + 1), b""):
                    require(len(raw) <= MAX_BODY and raw.endswith(b"\n"), "Invalid MCP request")
                    wire.send({"type": "mcp", "body": pack(raw)})
        except (OSError, ProtocolError) as exc:
            if not stopped.is_set():
                failure.append(str(exc))
                stopped.set()

    for function in (receive, bridge, server.serve_forever):
        threading.Thread(target=function, daemon=True).start()
    session = {"client": client, "executable": executable}
    argv, env = profile.command(root, session, [sys.executable, str(HERE), "mcp-relay"],
                                mock_url="http://127.0.0.1:" + str(server.server_port),
                                prompt="Analysis task:\n" + prompt, login=login, max_turns=turns, tool_timeout=tool_timeout)
    if client == "codex":
        config_path = Path(env["CODEX_HOME"]) / "config.toml"
        # Pre-approve only the contained static tools admitted by the separate
        # broker. Global approval_policy=never and disabled host tools stay set.
        # The first native query starts Ghidra; results arrive already bounded
        # by the broker, so the token budget only prevents a second, silent cut.
        additions = ["enabled_tools = " + json.dumps(sorted(STATIC_TOOLS)), "tool_timeout_sec = " + str(tool_timeout)]
        for name in sorted(STATIC_TOOLS):
            additions += ["[mcp_servers.rea.tools." + name + "]", 'approval_mode = "approve"', "output_token_limit = 60000"]
        with config_path.open("a", encoding="utf-8") as handle:
            handle.write("\n".join(additions) + "\n")
    process = subprocess.Popen(argv, cwd=root / "work", env=env, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
    budget = {"bytes": 0}
    budget_lock = threading.Lock()
    def capture(stream, channel):
        try:
            for raw in iter(lambda: stream.read1(16384), b""):
                with budget_lock:
                    budget["bytes"] += len(raw)
                    require(budget["bytes"] <= MAX_TRANSCRIPT, "Client output exceeds byte limit")
                wire.send({"type": "output", "channel": channel, "body": pack(raw)})
        except (OSError, ProtocolError) as exc:
            failure.append(str(exc))
            stopped.set()
    readers = [threading.Thread(target=capture, args=(stream, channel), daemon=True)
               for stream, channel in ((process.stdout, "stdout"), (process.stderr, "stderr"))]
    for thread in readers:
        thread.start()
    try:
        while process.poll() is None:
            if stopped.wait(0.1):
                process.terminate()
                process.wait(timeout=5)
        for thread in readers:
            thread.join(timeout=5)
        require(not failure, "Contained transport failed")
        require(not any(thread.is_alive() for thread in readers), "Client output did not close")
        wire.send({"type": "done", "returncode": process.returncode, "version": version,
                   "checks": checks, "marker_absent": not Path(MARKER).exists(),
                   "bundle": {name: digest(HERE.with_name(name)) for name in ("agent_worker.py", "agent_session.py", "tunnel.py")}})
    finally:
        stopped.set()
        server.shutdown()
        server.server_close()
        listener.close()
        for connection in peer:
            connection.close()
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)


if __name__ == "__main__":
    try:
        if sys.argv[1:] == ["mcp-relay"]:
            relay()
        else:
            require(not sys.argv[1:], "Unexpected worker arguments")
            run()
    except (ProtocolError, OSError, ValueError, subprocess.SubprocessError) as exc:
        print("Contained worker refused: " + str(exc), file=sys.stderr)
        sys.exit(1)
