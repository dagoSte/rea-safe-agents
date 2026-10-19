"""Security invariants for file snapshots, the agent container and the broker."""

import base64
import io
import json
import os
from pathlib import Path
import stat
import sys
import tarfile
import tempfile
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / "skills/rea-isolated/scripts"
sys.path.insert(0, str(SCRIPTS))
import agent_container as pair
import input_snapshot as snapshot
import tunnel

IMAGE = "sha256:" + "a" * 64
ENV = ["PATH=/opt/agent-bin:/usr/bin:/bin"]


def agent_data():
    return {"Image": IMAGE, "State": {"Running": False}, "Mounts": [],
            "Config": {"User": "1000:1000", "WorkingDir": "/tmp", "Entrypoint": ["python3"],
                       "Cmd": ["/opt/rea-sandbox/agent_worker.py"], "Tty": False, "OpenStdin": True,
                       "Env": [*ENV, "HOME=/home/node"]},
            "HostConfig": {"NetworkMode": "none", "ReadonlyRootfs": True, "Privileged": False,
                           "Init": True, "AutoRemove": True, "LogConfig": {"Type": "none"}, "CapDrop": ["ALL"],
                           "SecurityOpt": ["no-new-privileges:true"], "Memory": pair.boundary.MEMORY,
                           "MemorySwap": pair.boundary.MEMORY, "NanoCpus": pair.boundary.CPUS,
                           "PidsLimit": pair.boundary.PIDS, "Tmpfs": dict(pair.AGENT_TMPFS),
                           "IpcMode": "private", "CgroupnsMode": "private"}}


def catalog(client):
    if client == "codex":
        return [{"type": "namespace", "name": "mcp__rea", "tools": [{"name": name} for name in sorted(pair.TOOLS)]}]
    return [{"name": "mcp__rea__" + name, "input_schema": {"type": "object", "properties": {}}} for name in sorted(pair.TOOLS)]


LOGIN = "sk-ant-oat01-" + "f" * 40


def frame(client="codex", **changes):
    value = {"type": "model", "id": 1, "path": "/v1/responses" if client == "codex" else "/v1/messages?beta=true",
             "beta": "" if client == "codex" else pair.OAUTH_BETA, "auth": "" if client == "codex" else "Bearer " + LOGIN,
             "body": tunnel.pack(json.dumps({"model": "untrusted", "tools": catalog(client)}).encode())}
    value.update(changes)
    return value


def jwt(claims):
    encode = lambda value: base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")
    return encode({"alg": "none"}) + "." + encode(claims) + ".signature"


def codex_login_file(directory, expiry):
    path = Path(directory) / "codex-login.json"
    pair.write_private(path, {"auth_mode": "chatgpt", "tokens": {"access_token": jwt({"exp": expiry}), "refresh_token": "refresh-1",
                                                               "account_id": "account-1", "id_token": jwt({})}})
    return path


class Response:
    def __init__(self, status=200, body=b"", headers=()):
        self.status, self.body, self.headers = status, body, list(headers)

    def getheader(self, name, default=None):
        return "application/json"

    def getheaders(self):
        return self.headers

    def read1(self, size):
        body, self.body = self.body, b""
        return body

    def read(self, size=-1):
        return self.read1(size)


class RecordingWire:
    def __init__(self):
        self.frames = []

    def send(self, item):
        self.frames.append(item)


class FramingTests(unittest.TestCase):
    def test_round_trip_preserves_unicode_and_bytes(self):
        out = io.BytesIO()
        tunnel.Wire(out).send({"type": "mcp", "body": tunnel.pack("✓\n\x00".encode())})
        out.seek(0)
        item = tunnel.read_frame(out)
        self.assertEqual(tunnel.unpack(item["body"]), "✓\n\x00".encode())

    def test_bad_or_oversized_frames_are_rejected(self):
        for raw in (b'{"type":"a","type":"b"}\n', b'{"type":"a","x":NaN}\n', b'{"type":"a","x":1e400}\n',
                    b'{"type":"a","x":' + b'[' * 10 + b']' * 10 + b'}\n',
                    b'{"type":"a","x":[' + b'0,' * 128 + b'0]}\n', b'[]\n', b'{"type":"a"}', b'\xff\n'):
            with self.subTest(raw=raw), self.assertRaises(tunnel.ProtocolError):
                tunnel.read_frame(io.BytesIO(raw))
        with patch.object(tunnel, "MAX_FRAME", 8), self.assertRaises(tunnel.ProtocolError):
            tunnel.read_frame(io.BytesIO(b'{"type":"a"}\n'))
        for raw in ("!!!!", "a", 4):
            with self.assertRaises(tunnel.ProtocolError):
                tunnel.unpack(raw)

    def test_utf16_cannot_bypass_the_utf8_allocation_budget(self):
        value = {"type": "mcp", 'a"': [[[[[[[[[[0]]]]]]]]]], 'b"': 0}
        for encoding in ("utf-16-be", "utf-16-le", "utf-32-be", "utf-32-le"):
            raw = json.dumps(value).encode(encoding) + b"\n"
            with self.subTest(encoding=encoding), self.assertRaises(tunnel.ProtocolError):
                tunnel.read_frame(io.BytesIO(raw))


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "selected").mkdir()
        (self.root / "selected" / "file.txt").write_bytes(b"approved bytes only")

    def test_only_approved_bytes_are_frozen_with_non_executable_permissions(self):
        approved = snapshot.manifest(self.root)
        (self.root / "later-secret.txt").write_bytes(b"must never enter the snapshot")
        with snapshot.archive(self.root, approved) as frozen, tarfile.open(fileobj=frozen) as archive:
            files = [entry for entry in archive if entry.isfile()]
            self.assertEqual([entry.name for entry in files], ["selected/file.txt"])
            self.assertEqual(archive.extractfile(files[0]).read(), b"approved bytes only")
            self.assertEqual(files[0].mode, 0o444)
        staged, root = snapshot.stage(self.root, approved)
        try:
            self.assertEqual((root / "selected/file.txt").read_bytes(), b"approved bytes only")
            self.assertFalse((root / "later-secret.txt").exists())
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o555)
        finally:
            staged.cleanup()

    def test_changed_input_is_refused_before_returning_any_archive(self):
        approved = snapshot.manifest(self.root)
        (self.root / "selected/file.txt").write_bytes(b"unapproved bytes")
        with self.assertRaises(tunnel.ProtocolError):
            snapshot.archive(self.root, approved)

    def test_stale_path_metadata_does_not_reject_an_unchanged_file(self):
        # Windows can report stale directory-entry times and sizes for a path.
        real = snapshot.regular_stat
        def stale(path, *, directory=False):
            value = real(path, directory=directory)
            if directory:
                return value
            return SimpleNamespace(st_dev=value.st_dev, st_ino=value.st_ino, st_mode=value.st_mode, st_nlink=value.st_nlink,
                                   st_size=value.st_size + 7, st_mtime_ns=0, st_ctime_ns=0)
        with patch.object(snapshot, "regular_stat", side_effect=stale):
            self.assertEqual(snapshot.manifest(self.root)[0]["path"], "selected/file.txt")

    def test_a_file_changed_during_the_read_or_swapped_before_opening_is_refused(self):
        real_fstat, calls = os.fstat, []
        def changing(descriptor):
            value = real_fstat(descriptor)
            calls.append(descriptor)
            if len(calls) == 2:  # the second handle stat, taken after the read
                fields = {name: getattr(value, name) for name in ("st_mode", "st_nlink", "st_dev", "st_ino", "st_size", "st_ctime_ns")}
                return SimpleNamespace(**fields, st_mtime_ns=value.st_mtime_ns + 1)
            return value
        with patch.object(snapshot.os, "fstat", side_effect=changing), self.assertRaises(tunnel.ProtocolError):
            snapshot.manifest(self.root)
        real = snapshot.regular_stat
        def swapped(path, *, directory=False):
            value = real(path, directory=directory)
            if directory:
                return value
            return SimpleNamespace(st_dev=value.st_dev, st_ino=value.st_ino + 1, st_mode=value.st_mode, st_nlink=1,
                                   st_size=value.st_size, st_mtime_ns=value.st_mtime_ns, st_ctime_ns=value.st_ctime_ns)
        with patch.object(snapshot, "regular_stat", side_effect=swapped), self.assertRaises(tunnel.ProtocolError):
            snapshot.manifest(self.root)

    def test_traversal_and_duplicate_manifest_entries_are_rejected(self):
        for name in ("../key", "/absolute", "a/../key", "a\\key", "a:key", "./file", "a//key", "a\nkey"):
            with self.subTest(name=name), self.assertRaises(tunnel.ProtocolError):
                snapshot.relative_name(name)
        approved = snapshot.manifest(self.root)
        with self.assertRaises(tunnel.ProtocolError):
            snapshot.archive(self.root, approved + approved)

    def test_symlinks_hardlinks_and_special_files_are_not_copied(self):
        source = self.root / "selected/file.txt"
        link = self.root / "hardlink"
        try:
            os.link(source, link)
        except OSError:
            self.skipTest("Fixture filesystem cannot create hard links")
        with self.assertRaises(tunnel.ProtocolError):
            snapshot.manifest(self.root)
        link.unlink()
        alias = self.root / "alias"
        try:
            alias.symlink_to(source)
        except OSError:
            return  # Windows reparse handling is checked separately without this privilege.
        with self.assertRaises(tunnel.ProtocolError):
            snapshot.manifest(self.root)

    def test_windows_reparse_attribute_and_size_budgets_are_enforced(self):
        fake = type("Stat", (), {"st_mode": stat.S_IFREG | 0o644, "st_file_attributes": 0x400})()
        with patch.object(Path, "lstat", return_value=fake), self.assertRaises(tunnel.ProtocolError):
            snapshot.regular_stat(self.root / "junction")
        with patch.object(snapshot, "MAX_TOTAL_BYTES", 1), self.assertRaises(tunnel.ProtocolError):
            snapshot.manifest(self.root)


class AgentContainerTests(unittest.TestCase):
    def test_nonreading_container_pipe_cannot_stall_the_controller(self):
        reader, writer = os.pipe()
        stream = os.fdopen(writer, "wb")
        try:
            with patch.object(pair, "PIPE_TIMEOUT", 0.05), self.assertRaises(tunnel.ProtocolError):
                pair.PipeSink(stream).write(b"x" * (1024 * 1024))
        finally:
            # The controller removes the receiver before closing its own pipe.
            os.close(reader)
            try:
                stream.close()
            except (OSError, ValueError):
                pass

    def test_exact_agent_profile_is_accepted(self):
        pair.verify_agent(IMAGE, agent_data(), ENV)
        args = pair.agent_args(IMAGE)
        self.assertNotIn("--mount", args)
        self.assertNotIn("--volume", args)
        self.assertIn("--network=none", args)

    def test_unsafe_agent_configuration_is_rejected(self):
        changes = [
            ("NetworkMode", "bridge"), ("NetworkMode", "host"), ("ReadonlyRootfs", False),
            ("Privileged", True), ("Init", False), ("AutoRemove", False), ("CapDrop", []),
            ("CapAdd", ["SYS_ADMIN"]), ("SecurityOpt", ["seccomp=unconfined"]),
            ("Memory", 0), ("MemorySwap", -1), ("PidsLimit", 0), ("NanoCpus", 0),
            ("Tmpfs", {}), ("Binds", ["/:/host:rw"]), ("VolumesFrom", ["elsewhere"]),
            ("Devices", ["/dev/kvm"]), ("DeviceRequests", [{"Count": -1}]),
            ("DeviceCgroupRules", ["a *:* rwm"]), ("PidMode", "host"), ("UTSMode", "host"),
            ("UsernsMode", "host"), ("IpcMode", "host"), ("CgroupnsMode", "host"),
            ("GroupAdd", ["0"]), ("PortBindings", {"80/tcp": [{}]}),
            ("PublishAllPorts", True), ("LogConfig", {"Type": "json-file"}),
        ]
        for key, value in changes:
            data = agent_data()
            data["HostConfig"][key] = value
            with self.subTest(setting=key), self.assertRaises(tunnel.ProtocolError):
                pair.verify_agent(IMAGE, data, ENV)
        for change in (lambda d: d.update(Mounts=[{"Source": "/host"}]),
                       lambda d: d["Config"]["Env"].append("OPENAI_API_KEY=forbidden"),
                       lambda d: d["Config"].update(User="root"),
                       lambda d: d["Config"].update(Cmd=["-c", "unapproved"]),
                       lambda d: d["State"].update(Running=True)):
            data = agent_data()
            change(data)
            with self.assertRaises(tunnel.ProtocolError):
                pair.verify_agent(IMAGE, data, ENV)

    def test_failed_agent_inspection_cannot_start_code(self):
        manager = pair.Containers({})
        data = agent_data()
        data.update(Id="b" * 64, Mounts=[{"Source": "/host"}])
        response = type("Response", (), {"stdout": "b" * 64})()
        with patch.object(pair.boundary, "docker_json", side_effect=[[{"Id": IMAGE, "Config": {"Env": ENV}}], [data]]), \
                patch.object(pair.boundary, "docker", return_value=response) as docker, \
                patch.object(pair.subprocess, "Popen") as popen:
            with self.assertRaises(tunnel.ProtocolError):
                manager.create("agent", IMAGE, "/unused")
            self.assertEqual(docker.call_args.args[1][0], "create")
            popen.assert_not_called()
        self.assertEqual(manager.identifiers, ["b" * 64])

    def test_cleanup_attempts_every_container_and_process_after_a_removal_timeout(self):
        manager = pair.Containers({})
        manager.identifiers = ["a" * 64, "b" * 64]
        from unittest.mock import MagicMock
        process = MagicMock()
        process.stdin.closed = False
        process.wait.side_effect = [subprocess.TimeoutExpired("docker", 5), None]
        manager.processes = [process]
        with patch.object(pair.boundary, "docker", side_effect=[pair.boundary.BoundaryError("timeout"),
                                                              SimpleNamespace(returncode=0, stderr="")]) as docker:
            with self.assertRaises(tunnel.ProtocolError):
                manager.close()
            self.assertEqual([call.args[1][-1] for call in docker.call_args_list], ["b" * 64, "a" * 64])
            process.terminate.assert_called_once()
            process.stdout.close.assert_called_once()
            process.stderr.close.assert_called_once()

    def test_receipt_names_are_reserved_and_only_receipts_are_replaced(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.object(pair.boundary, "preflight") as preflight, self.assertRaises(tunnel.ProtocolError):
                pair.configure(SimpleNamespace(rea_config=str(root / "rea.json"), image=IMAGE, client="claude",
                                               output=str(root / "pair.verification.json")))
            preflight.assert_not_called()
            other = root / "pair.verification.json"
            other.write_text(json.dumps({"schema": 1, "client": "codex"}))
            with self.assertRaises(tunnel.ProtocolError):
                pair.clear_receipt(other)
            self.assertTrue(other.exists())  # an unrelated file survives a failed verification
            other.write_text(json.dumps({"status": "verified-contained-offline", "identity": {}}))
            pair.clear_receipt(other)
            self.assertFalse(other.exists())
            pair.clear_receipt(other)  # absent receipt: nothing to do

    def test_output_paths_cannot_enter_the_repository_through_aliases(self):
        repo = pair.HERE.parents[3]
        for path in (repo / "new-private-dir" / "output", repo / "skills/../output"):
            with self.assertRaises(tunnel.ProtocolError):
                pair.private_output(path)
        alias_spelling = Path(str(repo).swapcase())
        if alias_spelling.exists():
            with self.assertRaises(tunnel.ProtocolError):
                pair.private_output(alias_spelling / "new-private-dir" / "output")

    def test_auto_remove_race_requires_confirmation_of_exact_container_absence(self):
        identifier = "b" * 64
        for remaining in ("", identifier):
            manager = pair.Containers({})
            manager.identifiers = [identifier]
            replies = [SimpleNamespace(returncode=1, stderr="removal already in progress"),
                       SimpleNamespace(returncode=0, stdout=remaining)]
            with patch.object(pair.boundary, "docker", side_effect=replies) as docker:
                if remaining:
                    with self.assertRaises(tunnel.ProtocolError):
                        manager.close()
                else:
                    manager.close()
                self.assertEqual(docker.call_args_list[1].args[1], ["ps", "--all", "--quiet", "--no-trunc", "--filter", "id=" + identifier])

    def test_installed_skill_and_worktree_layouts_cannot_store_control_in_git(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for layout in (".agents", ".claude"):
                project = root / layout.removeprefix(".")
                project.mkdir()
                (project / ".git").write_text("gitdir: /unused/worktree-metadata\n")
                helper = project / layout / "skills/rea-isolated/scripts/agent_container.py"
                with patch.object(pair, "HERE", helper):
                    with self.assertRaises(tunnel.ProtocolError):
                        pair.private_output(project / "private-output")
                    self.assertEqual(pair.private_output(root / "outside"), (root / "outside").resolve())


class ControlRecordTests(unittest.TestCase):
    def test_configuration_names_map_to_exactly_one_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ("pair.verification.json", "pair.Verification.json", "pair.Verification.JSON", "pair.cfg", "pair.JSON", "pair"):
                with self.subTest(name=name), patch.object(pair.boundary, "preflight") as preflight, self.assertRaises(tunnel.ProtocolError):
                    pair.configure(SimpleNamespace(rea_config=str(root / "rea.json"), image=IMAGE, client="claude", output=str(root / name)))
                preflight.assert_not_called()
            for name in ("x.verification.json", "x.Verification.json", "x.Verification.JSON"):
                (root / name).write_text("{}")
                with self.subTest(load=name), self.assertRaises(tunnel.ProtocolError):
                    pair.load_config(str(root / name))

    def test_failed_verification_never_deletes_another_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config, other = root / "pair.json", root / "pair.verification.json"
            config.write_text("{}")
            other.write_text(json.dumps({"schema": 1, "client": "codex"}))
            def attempt():
                with patch.object(pair, "load_config", return_value=(config, {"client": "codex"}, {})), \
                        patch.object(pair, "exercise", side_effect=tunnel.ProtocolError("contained client failed")), \
                        self.assertRaises(tunnel.ProtocolError):
                    pair.verify(SimpleNamespace(config=str(config)))
            attempt()
            self.assertTrue(other.exists())  # not a receipt: kept although verification failed
            other.write_text(json.dumps({"status": "verified-contained-offline", "identity": {}}))
            attempt()
            self.assertFalse(other.exists())  # an earlier receipt is invalidated even when verification then fails

    @unittest.skipIf(os.name == "nt", "POSIX symlink fixture")
    def test_a_link_at_the_receipt_path_is_refused_and_never_written_through(self):
        with tempfile.TemporaryDirectory() as temporary, tempfile.TemporaryDirectory() as outside:
            link, target = Path(temporary) / "pair.verification.json", Path(outside) / "created-through-link"
            link.symlink_to(target)
            with self.assertRaises(tunnel.ProtocolError):
                pair.clear_receipt(link)
            self.assertTrue(link.is_symlink())
            self.assertFalse(target.exists())
            pair.write_private(link, {"status": "verified-contained-offline"})
            self.assertFalse(link.is_symlink())
            self.assertFalse(target.exists())


class MCPPolicyTests(unittest.TestCase):
    def test_only_successful_actual_rea_results_count_as_completed_calls(self):
        policy = pair.MCPPolicy()
        for identifier, result in ((1, {"error": {"code": -1}}), (2, {"result": {"isError": True}}),
                                   (3, {"result": {"content": []}})):
            request = {"jsonrpc": "2.0", "id": identifier, "method": "tools/call", "params": {"name": "binary_session", "arguments": {}}}
            policy.request(json.dumps(request).encode())
            policy.response(json.dumps({"jsonrpc": "2.0", "id": identifier, **result}).encode())
        self.assertEqual(policy.completed_tools, ["binary_session"])

    def test_optional_discovery_gets_a_local_method_not_found_without_callbacks(self):
        policy = pair.MCPPolicy()
        request = {"jsonrpc": "2.0", "id": "discover-1", "method": "server/discover", "params": {"capabilities": {"elicitation": {}}}}
        self.assertIsNone(policy.request(json.dumps(request).encode()))
        self.assertEqual(json.loads(policy.local_response)["error"]["code"], -32601)
        self.assertEqual(policy.pending, {})

    def test_catalog_is_filtered_and_reverse_capabilities_removed(self):
        policy = pair.MCPPolicy()
        request = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"capabilities": {"sampling": {}}}}
        value = json.loads(policy.request(json.dumps(request).encode()))
        self.assertEqual(value["params"]["capabilities"], {})
        response = {"jsonrpc": "2.0", "id": 1, "result": {"capabilities": {"resources": {}, "prompts": {}, "tools": {}}, "serverInfo": {"version": "6.7.0"}}}
        value = json.loads(policy.response(json.dumps(response).encode()))
        self.assertEqual(value["result"]["capabilities"], {"tools": {}})
        policy.request(b'{"jsonrpc":"2.0","id":2,"method":"tools/list"}')
        response = {"jsonrpc": "2.0", "id": 2, "result": {"tools": [{"name": "binary_session", "outputSchema": {"type": "object"}},
                                                                   {"name": "gdb_console"}]}}
        value = json.loads(policy.response(json.dumps(response).encode()))
        # Claude keeps annotated results inline; no client may expect structured output.
        self.assertEqual(value["result"]["tools"], [{"name": "binary_session", "_meta": {"anthropic/maxResultSizeChars": tunnel.MAX_TOOL_TEXT}}])

    def test_results_are_one_visibly_bounded_text_copy(self):
        policy = pair.MCPPolicy()
        for identifier, text in ((1, "small"), (2, "head-" + "\u00e9" * tunnel.MAX_TOOL_TEXT + "-tail")):
            policy.request(json.dumps({"jsonrpc": "2.0", "id": identifier, "method": "tools/call",
                                       "params": {"name": "list_strings", "arguments": {}}}).encode())
            response = {"jsonrpc": "2.0", "id": identifier, "result": {"content": [{"type": "text", "text": text}],
                                                                      "structuredContent": {"text": text}}}
            value = json.loads(policy.response(json.dumps(response).encode()))["result"]
            self.assertNotIn("structuredContent", value)
            sent = value["content"][0]["text"]
            self.assertLessEqual(len(sent.encode()), tunnel.MAX_TOOL_TEXT)
            if identifier == 1:
                self.assertEqual(sent, "small")
            else:
                self.assertTrue(sent.startswith("head-") and sent.endswith("-tail"))
                self.assertIn("The controller omitted the middle of this REA result", sent)
        self.assertEqual(policy.completed_tools, ["list_strings", "list_strings"])

    def test_non_text_blocks_and_errors_are_bounded_too(self):
        policy = pair.MCPPolicy()
        for identifier in (1, 2):
            policy.request(json.dumps({"jsonrpc": "2.0", "id": identifier, "method": "tools/call",
                                       "params": {"name": "list_strings", "arguments": {}}}).encode())
        big = "x" * (tunnel.MAX_TOOL_TEXT + 10)
        content = [{"type": "text", "text": "first"}, {"type": "resource", "resource": {"text": big}}, {"type": "text", "text": big}]
        value = json.loads(policy.response(json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"content": content}}).encode()))["result"]
        self.assertEqual(len(value["content"]), 1)
        sent = value["content"][0]["text"]
        self.assertTrue(sent.startswith("first\n[The controller omitted a non-text MCP content block") and len(sent.encode()) <= tunnel.MAX_TOOL_TEXT)
        error = json.loads(policy.response(json.dumps({"jsonrpc": "2.0", "id": 2, "error": {"code": -1, "message": big, "data": big}}).encode()))["error"]
        self.assertNotIn("data", error)
        self.assertLessEqual(len(error["message"].encode()), tunnel.MAX_TOOL_TEXT)

    def test_native_queries_are_admitted_without_filesystem_arguments(self):
        for name, arguments in (("list_strings", {}), ("search_strings", {"pattern": "marker"}),
                                ("procedure_pseudo_code", {"procedure": "_start"}), ("read_bytes", {"address": "0x400078", "length": 16})):
            request = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": arguments}}
            with self.subTest(name=name):
                self.assertIsNotNone(pair.MCPPolicy().request(json.dumps(request).encode()))

    def test_unadvertised_tools_and_host_callbacks_are_refused(self):
        for method, params in (("tools/call", {"name": "gdb_console", "arguments": {}}),
                               ("tools/call", {"name": "open_binary", "arguments": {"path": "/etc/passwd"}}),
                               ("tools/call", {"name": "open_binary", "arguments": {"path": "/input/../etc/passwd"}}),
                               ("tools/call", {"name": "close_binary", "arguments": {"snapshot_path": "/tmp/export"}}),
                               ("tools/call", {"name": "open_binary", "arguments": {"path": "/input/a", "snapshot_path": "/tmp/import"}}),
                               ("tools/call", {"name": "open_binary", "arguments": {"path": "/input/a", "provider_id": "ida"}}),
                               ("tools/call", {"name": "list_strings", "arguments": {"Snapshot_Path": "/tmp/x"}}),
                               ("tools/call", {"name": "annotate_native_function", "arguments": {"procedure": "main", "name": "x"}}),
                               ("tools/call", {"name": "set_address_name", "arguments": {"address": "0x1", "name": "x"}}),
                               ("resources/read", {"uri": "file:///host"})):
            request = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
            with self.subTest(method=method, params=params), self.assertRaises(tunnel.ProtocolError):
                pair.MCPPolicy().request(json.dumps(request).encode())
        with self.assertRaises(tunnel.ProtocolError):
            pair.MCPPolicy().response(b'{"jsonrpc":"2.0","id":1,"method":"sampling/createMessage"}')


class GatewayTests(unittest.TestCase):
    def test_cloud_connectors_media_files_state_and_unknown_betas_never_connect(self):
        cases = []
        for path in ("/v1/messages", "/v1/messages/count_tokens"):
            for extra in ({"mcp_servers": [{"type": "url", "url": "https://unapproved.invalid/sse", "name": "unapproved", "tool_configuration": {"enabled": True}}]},
                          {"container": {"skills": [{"type": "anthropic", "skill_id": "unapproved"}]}},
                          {"messages": [{"role": "user", "content": [{"type": "image", "source": {"type": "url", "url": "https://unapproved.invalid/image"}}]}]}):
                cases.append(("claude", frame("claude", path=path, body=tunnel.pack(json.dumps({"tools": catalog("claude"), **extra}).encode()))))
        for extra in ({"previous_response_id": "resp_unapproved"}, {"conversation": "conv_unapproved"},
                      {"input": [{"type": "message", "role": "user", "content": [{"type": "input_file", "file_id": "file_unapproved"}]}]}):
            cases.append(("codex", frame(body=tunnel.pack(json.dumps({"tools": catalog("codex"), **extra}).encode()))))
        cases.append(("claude", frame("claude", beta=pair.OAUTH_BETA + ",mcp-client-2025-11-20")))
        for client, item in cases:
            with self.subTest(client=client, path=item["path"]), \
                    patch.object(pair.http.client, "HTTPConnection") as connect, self.assertRaises(tunnel.ProtocolError):
                pair.ModelGateway(client, fixture_port=1, login=LOGIN if client == "claude" else None).exchange(item, RecordingWire())
            connect.assert_not_called()

    def test_claude_forwards_only_its_own_subscription_login_to_the_fixed_endpoint(self):
        with patch.object(pair.http.client, "HTTPSConnection") as connect:
            connect.return_value.getresponse.return_value = Response(headers=[("Retry-After", "7"), ("anthropic-ratelimit-unified-status", "allowed"),
                                                                              ("Set-Cookie", "private"), ("x-should-retry", "true\r\nx: y")])
            gateway = pair.ModelGateway("claude", model="explicit-model", login=LOGIN)
            wire = RecordingWire()
            body = {"model": "attacker-model", "messages": [{"role": "user", "content": "test"}]}
            # Token counting may omit the OAuth capability; the gateway forwards it.
            gateway.exchange(frame("claude", path="/v1/messages/count_tokens?beta=true", beta="token-counting-2024-11-01",
                                   body=tunnel.pack(json.dumps(body).encode())), wire)
            self.assertEqual(connect.call_args.args[:2], ("api.anthropic.com", 443))
            args = connect.return_value.request.call_args
            self.assertEqual(args.args, ("POST", "/v1/messages/count_tokens?beta=true"))
            self.assertEqual(json.loads(args.kwargs["body"]), {**body, "model": "explicit-model"})
            self.assertEqual(args.kwargs["headers"]["Authorization"], "Bearer " + LOGIN)
            self.assertNotIn("x-api-key", args.kwargs["headers"])
            self.assertEqual(args.kwargs["headers"]["anthropic-beta"], "token-counting-2024-11-01," + pair.OAUTH_BETA)
            self.assertEqual(gateway.catalogs, [])
            # Only retry and plan-limit headers return to the client, and only printable values.
            self.assertEqual(wire.frames[0]["headers"], {"anthropic-ratelimit-unified-status": "allowed", "retry-after": "7"})

    def test_claude_without_a_subscription_login_never_connects(self):
        other = "sk-ant-oat01-" + "a" * 40  # well formed, but not the login exported for this run
        for changes in ({"auth": ""}, {"auth": "Bearer sk-ant-api03-" + "k" * 40}, {"auth": LOGIN}, {"auth": "Bearer " + other},
                        {"auth": "Bearer " + LOGIN + "\r\nx-api-key: injected"}, {"beta": ""}):
            with self.subTest(changes=changes), patch.object(pair.http.client, "HTTPSConnection") as connect, \
                    self.assertRaises(tunnel.ProtocolError):
                pair.ModelGateway("claude", model="explicit-model", login=LOGIN).exchange(frame("claude", **changes), RecordingWire())
            connect.assert_not_called()
        for login in (None, "", "sk-ant-api03-" + "k" * 40):
            with self.assertRaises(tunnel.ProtocolError):
                pair.ModelGateway("claude", model="explicit-model", login=login)

    def test_codex_history_may_carry_a_message_phase_label_only(self):
        message = {"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "Opening it."}]}
        pair.validate_body("codex", {"input": [dict(message, phase="commentary")]}, "")
        logged = dict(message, content=[{"type": "output_text", "text": "Opening it.", "annotations": [], "logprobs": []}])
        pair.validate_body("codex", {"input": [logged]}, "")
        for phase in ("x" * 33, "Commentary", "a b", 7):
            with self.assertRaises(tunnel.ProtocolError):
                pair.validate_body("codex", {"input": [dict(message, phase=phase)]}, "")

    def test_unexpected_urls_queries_headers_and_tools_never_connect(self):
        gateway = pair.ModelGateway("codex", fixture_port=1)
        candidates = [frame(path=path) for path in ("https://evil.invalid/v1/responses", "//evil.invalid/v1/responses", "/v1/responses?next=evil", "/v1/responses#fragment", "/v1/files")]
        candidates.append(frame(beta="x\r\nAuthorization: forbidden"))
        candidates.append(frame(body=tunnel.pack(json.dumps({"tools": catalog("codex") + [{"type": "web_search"}]}).encode())))
        candidates.append(frame(body=tunnel.pack(json.dumps({"tools": catalog("codex") + [{"type": "web_search", "name": "mcp__rea__binary_session"}]}).encode())))
        for item in candidates:
            with patch.object(pair.http.client, "HTTPConnection") as connect, self.assertRaises(tunnel.ProtocolError):
                gateway.exchange(item, RecordingWire())
            connect.assert_not_called()

    def test_codex_uses_the_dedicated_chatgpt_login_and_backend_shape(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(pair, "private_output", side_effect=Path), \
                patch.object(pair.http.client, "HTTPSConnection") as connect:
            connect.return_value.getresponse.return_value = Response()
            with pair.CodexLogin(codex_login_file(temporary, pair.time.time() + 3600)) as login:
                with self.assertRaises(tunnel.ProtocolError):
                    pair.CodexLogin(Path(temporary) / "codex-login.json").__enter__()  # one run per login
                gateway = pair.ModelGateway("codex", model="explicit-model", login=login)
                body = {"model": "attacker-model", "store": True, "background": True, "max_output_tokens": 99999, "stream": True,
                        "tools": catalog("codex")}
                gateway.exchange(frame(body=tunnel.pack(json.dumps(body).encode())), RecordingWire())
            self.assertFalse((Path(temporary) / "codex-login.json.lock").exists())
            self.assertEqual(connect.call_args.args[:2], ("chatgpt.com", 443))
            args = connect.return_value.request.call_args
            self.assertEqual(args.args, ("POST", "/backend-api/codex/responses"))
            sent = json.loads(args.kwargs["body"])
            self.assertEqual(sent["model"], "explicit-model")
            self.assertFalse(sent["store"])
            self.assertNotIn("background", sent)
            self.assertNotIn("max_output_tokens", sent)
            headers = args.kwargs["headers"]
            self.assertTrue(headers["Authorization"].startswith("Bearer ") and headers["ChatGPT-Account-ID"] == "account-1")

    def test_codex_refreshes_a_rotated_login_before_use_and_on_401(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(pair, "private_output", side_effect=Path), \
                patch.object(pair.http.client, "HTTPSConnection") as connect:
            path = codex_login_file(temporary, pair.time.time() + 60)
            refreshed = json.dumps({"access_token": jwt({"exp": pair.time.time() + 3600}), "refresh_token": "refresh-2"}).encode()
            connect.return_value.getresponse.side_effect = [Response(200, refreshed), Response(401), Response(200, refreshed), Response()]
            with pair.CodexLogin(path) as login:
                gateway = pair.ModelGateway("codex", model="explicit-model", login=login)
                body = {"stream": True, "tools": catalog("codex")}
                gateway.exchange(frame(body=tunnel.pack(json.dumps(body).encode())), RecordingWire())
            hosts = [call.args[0] for call in connect.call_args_list]
            self.assertEqual(hosts, ["auth.openai.com", "chatgpt.com", "auth.openai.com", "chatgpt.com"])
            self.assertFalse(path.with_name(path.name + ".lock").exists())
            refresh = json.loads(connect.return_value.request.call_args_list[0].kwargs["body"])
            self.assertEqual(refresh, {"client_id": pair.CODEX_CLIENT_ID, "grant_type": "refresh_token", "refresh_token": "refresh-1"})
            saved = json.loads(path.read_text())
            self.assertEqual(saved["tokens"]["refresh_token"], "refresh-2")
            self.assertEqual(saved["tokens"]["account_id"], "account-1")
            if os.name != "nt":
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_codex_login_survives_a_failed_run_and_limits_rotations(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(pair, "private_output", side_effect=Path), \
                patch.object(pair.http.client, "HTTPSConnection") as connect:
            path = codex_login_file(temporary, pair.time.time() + 3600)
            refreshed = json.dumps({"access_token": jwt({"exp": pair.time.time() + 3600})}).encode()
            connect.return_value.getresponse.side_effect = [Response(401), Response(200, refreshed), Response(401)] * 4
            with self.assertRaises(tunnel.ProtocolError), pair.CodexLogin(path) as login:
                gateway = pair.ModelGateway("codex", model="explicit-model", login=login)
                for identifier in range(1, 5):
                    gateway.exchange(frame(id=identifier, body=tunnel.pack(json.dumps({"stream": True, "tools": catalog("codex")}).encode())),
                                     RecordingWire())
            self.assertFalse(path.with_name(path.name + ".lock").exists())  # released although the run failed
            self.assertEqual(json.loads(path.read_text())["tokens"]["refresh_token"], "refresh-1")  # not rotated by the server

    def test_codex_login_saves_only_a_complete_device_login(self):
        auth = {"auth_mode": "chatgpt", "tokens": {"access_token": jwt({"exp": 1}), "refresh_token": "r", "account_id": "account-1"}}
        good = b"progress\nREA-CODEX-LOGIN\n" + base64.b64encode(json.dumps(auth).encode())
        for stdout, saved in ((good, True), (b"REA-CODEX-LOGIN\n" + base64.b64encode(b'{"tokens":{}}'), False), (b"no marker", False)):
            with self.subTest(saved=saved), tempfile.TemporaryDirectory() as temporary, \
                    patch.object(pair, "private_output", side_effect=Path), \
                    patch.object(pair, "load_config", return_value=(None, {"client": "codex", "agent_image_id": IMAGE}, {"docker": "/docker", "docker_config": "/cfg", "context": "default"})), \
                    patch.object(pair.boundary, "preflight"), patch.object(pair.subprocess, "Popen") as popen:
                popen.return_value.stdout.read.return_value = stdout
                popen.return_value.poll.return_value = 0
                popen.return_value.returncode = 0
                target = Path(temporary) / "codex-login.json"
                args = SimpleNamespace(config="unused", output=str(target))
                if saved:
                    pair.codex_login(args)
                    self.assertEqual(json.loads(target.read_text())["tokens"]["account_id"], "account-1")
                    if os.name != "nt":
                        self.assertEqual(target.stat().st_mode & 0o777, 0o600)
                    argv = popen.call_args.args[0]
                    self.assertIn("--read-only", argv)
                    self.assertFalse(any(item.startswith(("--volume", "--mount", "-v")) for item in argv))
                else:
                    with self.assertRaises(tunnel.ProtocolError):
                        pair.codex_login(args)
                    self.assertFalse(target.exists())

    def test_codex_models_lists_only_listed_model_ids(self):
        listing = {"models": [{"slug": "gpt-6.1-sol", "visibility": "list"}, {"slug": "gpt-reserve", "visibility": "hide"},
                              {"slug": "bad id\r\n", "visibility": "list"}]}
        with tempfile.TemporaryDirectory() as temporary, patch.object(pair, "private_output", side_effect=Path), \
                patch.object(pair.http.client, "HTTPSConnection") as connect:
            connect.return_value.getresponse.return_value = Response(200, json.dumps(listing).encode())
            result = pair.codex_models(SimpleNamespace(codex_login=str(codex_login_file(temporary, pair.time.time() + 3600))))
            self.assertEqual(result, {"models": ["gpt-6.1-sol"]})
            self.assertEqual(connect.call_args.args[:2], ("chatgpt.com", 443))
            self.assertEqual(connect.return_value.request.call_args.args[0], "GET")

    def test_malformed_codex_tokens_never_reach_a_header_or_stderr(self):
        secret = "synthetic-oauth-access-token"
        for bad in (secret + "\n", secret + "\r", secret + "\r\n", "synthetic oauth"):
            with self.subTest(token=repr(bad)), tempfile.TemporaryDirectory() as temporary, \
                    patch.object(pair, "private_output", side_effect=Path), \
                    patch.object(pair.http.client, "HTTPSConnection") as connect:
                path = Path(temporary) / "codex-login.json"
                pair.write_private(path, {"tokens": {"access_token": bad, "refresh_token": "refresh-1", "account_id": "account-1"}})
                stderr = io.StringIO()
                with patch.object(sys, "argv", ["agent_container.py", "codex-models", "--codex-login", str(path)]), \
                        patch.object(sys, "stderr", stderr), patch.object(sys, "stdout", io.StringIO()):
                    self.assertEqual(pair.main(), 1)
                self.assertNotIn(secret, stderr.getvalue())
                self.assertNotIn("synthetic", stderr.getvalue())
                connect.assert_not_called()
                self.assertFalse(path.with_name(path.name + ".lock").exists())

    def test_rejected_header_errors_are_reported_without_their_value(self):
        class Connection:
            def request(self, *args, **kwargs):
                raise ValueError("Invalid header value b'Bearer synthetic-oauth-access-token\\n'")
        with self.assertRaises(tunnel.ProtocolError) as caught:
            pair.send(Connection(), "GET", "/", headers={})
        self.assertNotIn("synthetic", str(caught.exception))

    def test_gateway_and_model_list_never_quote_a_rejected_header(self):
        invalid = {"Authorization": "Bearer synthetic-secret\n", "ChatGPT-Account-ID": "account-1"}
        offline = lambda *args, **kwargs: pair.http.client.HTTPConnection("127.0.0.1", 9, timeout=1)
        with tempfile.TemporaryDirectory() as temporary, patch.object(pair, "private_output", side_effect=Path), \
                patch.object(pair.http.client, "HTTPSConnection", side_effect=offline), \
                patch.object(pair.CodexLogin, "headers", return_value=invalid):
            path = codex_login_file(temporary, pair.time.time() + 3600)
            with pair.CodexLogin(path) as login, self.assertRaises(tunnel.ProtocolError) as caught:
                gateway = pair.ModelGateway("codex", model="explicit-model", login=login)
                gateway.exchange(frame(body=tunnel.pack(json.dumps({"stream": True, "tools": catalog("codex")}).encode())), RecordingWire())
            self.assertNotIn("synthetic", str(caught.exception))
            with self.assertRaises(tunnel.ProtocolError) as caught:
                pair.codex_models(SimpleNamespace(codex_login=str(path)))
            self.assertNotIn("synthetic", str(caught.exception))

    def test_a_refreshed_token_that_cannot_be_a_header_is_refused(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(pair, "private_output", side_effect=Path), \
                patch.object(pair.http.client, "HTTPSConnection") as connect:
            path = codex_login_file(temporary, pair.time.time() + 60)
            bad = json.dumps({"access_token": "synthetic-refreshed-token\r\n", "refresh_token": "refresh-2"}).encode()
            connect.return_value.getresponse.return_value = Response(200, bad)
            with pair.CodexLogin(path) as login, self.assertRaises(tunnel.ProtocolError) as caught:
                login.headers()
            self.assertNotIn("synthetic", str(caught.exception))
            self.assertEqual(json.loads(path.read_text())["tokens"]["refresh_token"], "refresh-1")

    def test_codex_client_credentials_and_gateway_without_login_are_refused(self):
        with self.assertRaises(tunnel.ProtocolError):
            pair.ModelGateway("codex", model="explicit-model")
        with patch.object(pair.http.client, "HTTPConnection") as connect, self.assertRaises(tunnel.ProtocolError):
            pair.ModelGateway("codex", fixture_port=1).exchange(frame(auth="Bearer smuggled"), RecordingWire())
        connect.assert_not_called()

    def test_cross_os_receipts_and_changed_helpers_cannot_authorize_a_live_run(self):
        report = {"status": "verified-contained-offline", "identity": {"host_os": "other-os"}}
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "pair.json"
            pair.receipt_path(path).write_text(json.dumps(report))
            args = type("Args", (), {"config": str(path)})()
            with patch.object(pair, "load_config", return_value=(path, {}, {})), \
                    patch.object(pair, "identity", return_value={"host_os": sys.platform}), \
                    patch.object(pair, "exercise") as exercise, self.assertRaises(tunnel.ProtocolError):
                pair.run(args)
            exercise.assert_not_called()


if __name__ == "__main__":
    unittest.main()
