#!/usr/bin/env python3
"""Verify REA MCP discovery through the guarded launcher, without model calls."""

import argparse
import json
import os
from pathlib import Path
import queue
import re
import signal
import subprocess
import sys
import threading
import time


# Match the MCP TypeScript SDK's default receive-buffer budget. REA's real
# tools/list response exceeds 2 MiB; this remains a bounded byte count.
MAX_MESSAGE_BYTES = 10 * 1024 * 1024
RESPONSE_TIMEOUT = 60
SHUTDOWN_TIMEOUT = 15


def verify(config):
    launcher = Path(__file__).with_name("container.py")
    process = subprocess.Popen(
        [sys.executable, str(launcher), "mcp", "--config", str(Path(config).resolve())],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, shell=False,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0,
    )
    messages = queue.Queue(maxsize=4)
    largest_message = 0

    def read():
        nonlocal largest_message
        failed = False
        while True:
            line = process.stdout.readline(MAX_MESSAGE_BYTES + 1)
            if failed:
                # Keep consuming bounded chunks after the first error so a
                # full stdout pipe cannot prevent server EOF/launcher cleanup.
                if not line:
                    return
                continue
            if not line:
                message = RuntimeError("MCP connection closed before discovery completed")
            else:
                largest_message = max(largest_message, len(line))
                try:
                    if len(line) > MAX_MESSAGE_BYTES or not line.endswith(b"\n"):
                        raise ValueError("MCP discovery message exceeded the probe limit")
                    message = json.loads(line)
                    if not isinstance(message, dict):
                        raise ValueError("Unexpected MCP message shape")
                except ValueError as exc:
                    message = exc
            try:
                messages.put_nowait(message)
            except queue.Full:
                messages.get_nowait()
                messages.put_nowait(RuntimeError("Too many pending MCP messages"))
                failed = True
            failed = failed or isinstance(message, Exception)
            if not line:
                return

    reader = threading.Thread(target=read, daemon=True)
    reader.start()

    def send(value):
        process.stdin.write((json.dumps({"jsonrpc": "2.0", **value}) + "\n").encode("utf-8"))
        process.stdin.flush()

    def response(identifier):
        deadline = time.monotonic() + RESPONSE_TIMEOUT
        for _ in range(100):
            try:
                message = messages.get(timeout=max(0.001, deadline - time.monotonic()))
            except queue.Empty as exc:
                raise RuntimeError("MCP response " + str(identifier) + " timed out") from exc
            if isinstance(message, Exception):
                raise message
            if message.get("id") == identifier:
                if "error" in message:
                    raise RuntimeError("MCP request returned an error")
                return message["result"]
        raise RuntimeError("Too many unrelated MCP messages")

    primary_error = None
    evidence = None
    try:
        send({"id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "rea-isolation-smoke", "version": "1"},
        }})
        initialized = response(1)
        send({"method": "notifications/initialized"})
        tools = []
        cursor = None
        for page in range(100):
            send({"id": page + 2, "method": "tools/list", "params": {} if cursor is None else {"cursor": cursor}})
            result = response(page + 2)
            tools.extend(result.get("tools", []))
            cursor = result.get("nextCursor")
            if not cursor:
                break
        else:
            raise RuntimeError("Too many discovery pages")
        names = [tool.get("name", "") for tool in tools]
        if not names or any(not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", name) for name in names):
            raise RuntimeError("Unexpected or empty MCP tool catalog")
        server = initialized.get("serverInfo", {})
        # Do not display untrusted tool descriptions, prompts, or result text.
        version = str(server.get("version", ""))
        if not re.fullmatch(r"[0-9A-Za-z.+_-]{1,80}", version):
            raise RuntimeError("Unexpected MCP server version")
        evidence = {"mcp_discovery": "passed", "server_version": version, "tool_count": len(names),
                    "tool_names": names, "largest_message_bytes": largest_message}
    except BaseException as exc:
        primary_error = exc
    finally:
        cleanup_error = None
        try:
            process.stdin.close()
            try:
                process.wait(timeout=SHUTDOWN_TIMEOUT)
            except subprocess.TimeoutExpired:
                # Let the launcher run its finally block and remove its exact
                # container. A hard terminate is only a reported last resort.
                interrupt = signal.CTRL_BREAK_EVENT if os.name == "nt" else signal.SIGINT
                try:
                    process.send_signal(interrupt)
                    process.wait(timeout=SHUTDOWN_TIMEOUT)
                except (OSError, subprocess.TimeoutExpired):
                    process.terminate()
                    process.wait(timeout=10)
                    raise RuntimeError("MCP launcher required forced termination; container cleanup is unverified")
                raise RuntimeError("MCP required an interrupt after EOF; launcher cleanup completed")
            if process.returncode:
                raise RuntimeError("MCP launcher exited with status " + str(process.returncode))
        except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
            cleanup_error = exc
        finally:
            reader.join(timeout=2)
            if not reader.is_alive():
                process.stdout.close()
        if primary_error is not None:
            if cleanup_error is not None:
                raise RuntimeError(str(primary_error) + "; cleanup also failed: " + str(cleanup_error)) from primary_error
            raise primary_error
        if cleanup_error is not None:
            raise cleanup_error
    return evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(verify(args.config), indent=2))
    except (RuntimeError, ValueError, OSError, KeyError, TypeError) as exc:
        print("MCP verification failed: " + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
