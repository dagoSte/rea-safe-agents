"""Reproducible controller boundary properties, with no services or subprocesses.

Run with ``python3 -m unittest discover -s tests -p test_generated_inputs.py -v``.
Seeds and case numbers appear in subtest failures. Small patched byte budgets
exercise exact edges without allocating production-sized hostile inputs. The
oracles use generated trees/event semantics, rather than the parsers' scanners.
"""

import base64
from collections import deque
import copy
import hashlib
import io
import json
from pathlib import Path
import random
import sys
import unittest
from unittest.mock import patch


SCRIPTS = Path(__file__).resolve().parents[1] / "skills/rea-isolated/scripts"
sys.path.insert(0, str(SCRIPTS))
import agent_container as pair
import tunnel


SEEDS = (0x524541, 0xC0FFEE, 0x5EED2026)
LOGIN = "sk-ant-oat01-" + "f" * 40
TEXT_ALPHABET = tuple('aZ09{}[],:"\\/ \n\t') + (
    "\u00e9", "\u0301", "\u4e2d", "\U0001f680", "\u2028", "\u2029",
)


def text(rng, maximum=24):
    return "".join(rng.choice(TEXT_ALPHABET) for _ in range(rng.randrange(maximum + 1)))


def tree(rng, remaining=4):
    if not remaining or rng.randrange(3) == 0:
        return rng.choice((None, True, False, rng.randrange(-100000, 100000),
                           rng.randrange(-1000, 1000) / 8, text(rng)))
    if rng.randrange(2):
        return [tree(rng, remaining - 1) for _ in range(rng.randrange(5))]
    return {"k" + str(index) + text(rng, 8): tree(rng, remaining - 1)
            for index in range(rng.randrange(5))}


def tree_budget(value):
    """Count structural tokens and depth from a value, without parsing its JSON."""
    if not isinstance(value, (list, dict)):
        return 0, 0
    children = list(value.values()) if isinstance(value, dict) else value
    child_budgets = [tree_budget(child) for child in children]
    # Opening container, separators, and one colon per object member.
    own = 1 + max(0, len(children) - 1)
    if isinstance(value, dict):
        own += len(children)
    return (1 + max((depth for depth, _ in child_budgets), default=0),
            own + sum(items for _, items in child_budgets))


def catalog(client):
    if client == "codex":
        return [{"type": "namespace", "name": "mcp__rea",
                 "tools": [{"type": "function", "name": "binary_session"}]}]
    return [{"name": "mcp__rea__binary_session", "input_schema": {"type": "object"}}]


def model_frame(client="codex", body=None, **changes):
    value = {"type": "model", "id": 1,
             "path": "/v1/responses" if client == "codex" else "/v1/messages?beta=true",
             "beta": "" if client == "codex" else pair.OAUTH_BETA,
             "auth": "" if client == "codex" else "Bearer " + LOGIN,
             "body": tunnel.pack(json.dumps(body if body is not None else
                                            {"tools": catalog(client)}).encode())}
    value.update(changes)
    return value


class MemoryResponse:
    def __init__(self, chunks=(), *, status=200, content_type="text/event-stream"):
        self.status, self.content_type = status, content_type
        self.chunks = deque(chunks)

    def getheader(self, name, default=None):
        return self.content_type

    def getheaders(self):
        return []

    def read1(self, size):
        chunk = self.chunks.popleft() if self.chunks else b""
        if len(chunk) > size:
            self.chunks.appendleft(chunk[size:])
        return chunk[:size]


class MemoryConnection:
    def __init__(self, response):
        self.response, self.requests, self.closed = response, [], False

    def request(self, *args, **kwargs):
        self.requests.append((args, kwargs))

    def getresponse(self):
        return self.response

    def close(self):
        self.closed = True


class RecordingWire:
    def __init__(self):
        self.frames = []

    def send(self, item):
        self.frames.append(item)


def chunks(raw, rng, mode):
    if mode == "whole":
        return [raw]
    if mode == "bytes":
        return [raw[index:index + 1] for index in range(len(raw))]
    result, offset = [], 0
    while offset < len(raw):
        size = rng.randrange(1, 38)
        result.append(raw[offset:offset + size])
        offset += size
    return result


def assistant(texts, phase="final_answer", **changes):
    item = {"type": "message", "role": "assistant", "phase": phase,
            "content": [{"type": "output_text", "text": part} for part in texts]}
    item.update(changes)
    return {"type": "response.output_item.done", "item": item}


def sse_event(event, ending, *, pretty=False):
    raw = json.dumps(event, ensure_ascii=False, indent=2 if pretty else None).encode()
    lines = [b": generated comment", b"event: response.output_item.done"]
    lines.extend(b"data: " + line for line in raw.split(b"\n"))
    return ending.join(lines) + ending * 2


class GeneratedTunnelTests(unittest.TestCase):
    def test_generated_tree_budgets_and_unicode_round_trips(self):
        for seed in SEEDS:
            rng = random.Random(seed)
            for case in range(48):
                value = tree(rng)
                depth, items = tree_budget(value)
                for ascii_only in (True, False):
                    raw = json.dumps(value, ensure_ascii=ascii_only,
                                     indent=rng.choice((None, 1, 3))).encode("utf-8")
                    with self.subTest(seed=seed, case=case, ascii=ascii_only,
                                      depth=depth, items=items):
                        self.assertEqual(tunnel.decode_json(raw, depth_limit=depth,
                                                            item_limit=items), value)
                        if depth:
                            with self.assertRaises(tunnel.ProtocolError):
                                tunnel.decode_json(raw, depth_limit=depth - 1,
                                                   item_limit=items)
                        if items:
                            with self.assertRaises(tunnel.ProtocolError):
                                tunnel.decode_json(raw, depth_limit=depth,
                                                   item_limit=items - 1)

    def test_generated_duplicate_keys_rejected_after_unescaping(self):
        for seed in SEEDS:
            rng = random.Random(seed)
            for case in range(24):
                key = "a" + text(rng)
                first = json.dumps(key, ensure_ascii=False)
                # A distinct spelling with an identical decoded first character.
                second = '"\\u0061' + json.dumps(key[1:], ensure_ascii=True)[1:]
                duplicate = "{" + first + ":1," + second + ":2}"
                for prefix, suffix in (("", ""), ('[{"nested":', "}]")):
                    raw = (prefix + duplicate + suffix).encode()
                    with self.subTest(seed=seed, case=case, nested=bool(prefix)):
                        with self.assertRaises(tunnel.ProtocolError):
                            tunnel.decode_json(raw)
                        control = raw.replace(b"\\u0061", b"\\u0062", 1)
                        self.assertEqual(tunnel.decode_json(control), json.loads(control))

    def test_generated_numeric_and_utf8_boundaries(self):
        for seed in SEEDS:
            rng = random.Random(seed)
            for case in range(24):
                number = rng.choice(("NaN", "Infinity", "-Infinity",
                                     str(rng.randrange(1, 10)) + "e" + str(rng.randrange(400, 1000))))
                raw = ('{"value":[' + number + "]}").encode()
                with self.subTest(seed=seed, case=case, number=number):
                    with self.assertRaises(tunnel.ProtocolError):
                        tunnel.decode_json(raw)
                    self.assertEqual(tunnel.decode_json(json.dumps([number]).encode()), [number])
                    finite = str(rng.randrange(1, 10)) + "e-" + str(rng.randrange(1, 500))
                    self.assertEqual(tunnel.decode_json(finite.encode()), float(finite))
                bad = rng.choice((b"\x80", b"\xc0\xaf", b"\xed\xa0\x80", b"\xf4\x90\x80\x80", b"\xe2\x82"))
                with self.subTest(seed=seed, case=case, invalid_utf8=bad):
                    with self.assertRaises(tunnel.ProtocolError):
                        tunnel.decode_json(b'{"text":"' + bad + b'"}')
            value = {"data": [text(rng), [[[]]]]}
            for encoding in ("utf-16", "utf-16-le", "utf-16-be", "utf-32", "utf-32-le", "utf-32-be"):
                with self.subTest(seed=seed, encoding=encoding):
                    with self.assertRaises(tunnel.ProtocolError):
                        tunnel.decode_json(json.dumps(value).encode(encoding))

    def test_generated_payload_and_frame_byte_edges(self):
        for seed in SEEDS:
            rng = random.Random(seed)
            for case in range(24):
                limit = rng.randrange(1, 129)
                raw = bytes(rng.randrange(256) for _ in range(limit))
                with self.subTest(seed=seed, case=case, budget=limit), \
                        patch.object(tunnel, "MAX_BODY", limit):
                    encoded = base64.b64encode(raw).decode("ascii")
                    self.assertEqual(tunnel.pack(raw), encoded)
                    self.assertEqual(tunnel.unpack(encoded), raw)
                    with self.assertRaises(tunnel.ProtocolError):
                        tunnel.pack(raw + b"x")
                    with self.assertRaises(tunnel.ProtocolError):
                        tunnel.unpack(base64.b64encode(raw + b"x").decode("ascii"))
                    with self.assertRaises(tunnel.ProtocolError):
                        tunnel.unpack(encoded[:1] + "!" + encoded[1:])
                value = {"type": "mcp", "text": text(rng)}
                stream = io.BytesIO()
                tunnel.Wire(stream).send(value)
                frame = stream.getvalue()
                with self.subTest(seed=seed, case=case, control="frame-json"):
                    self.assertEqual(json.loads(frame), value)
                for maximum, allowed in ((len(frame) - 1, False), (len(frame), True), (len(frame) + 1, True)):
                    with self.subTest(seed=seed, case=case, frame_budget=maximum), \
                            patch.object(tunnel, "MAX_FRAME", maximum):
                        if allowed:
                            self.assertEqual(tunnel.read_frame(io.BytesIO(frame)), value)
                            out = io.BytesIO()
                            tunnel.Wire(out).send(value)
                            self.assertEqual(out.getvalue(), frame)
                        else:
                            with self.assertRaises(tunnel.ProtocolError):
                                tunnel.read_frame(io.BytesIO(frame))
                            out = io.BytesIO()
                            with self.assertRaises(tunnel.ProtocolError):
                                tunnel.Wire(out).send(value)
                            self.assertEqual(out.getvalue(), b"")

    def test_generated_frame_concatenation_and_truncation(self):
        for seed in SEEDS:
            rng = random.Random(seed)
            values = [{"type": "mcp", "text": text(rng)} for _ in range(24)]
            stream = io.BytesIO()
            for value in values:
                tunnel.Wire(stream).send(value)
            raw = stream.getvalue()
            stream.seek(0)
            for case, value in enumerate(values):
                with self.subTest(seed=seed, case=case):
                    self.assertEqual(tunnel.read_frame(stream), value)
            with self.subTest(seed=seed, case="eof"):
                self.assertIsNone(tunnel.read_frame(stream))
            first = raw.split(b"\n", 1)[0]
            for cut in sorted({1, len(first) // 2, len(first)}):
                with self.subTest(seed=seed, cut=cut), self.assertRaises(tunnel.ProtocolError):
                    tunnel.read_frame(io.BytesIO(first[:cut]))

    def test_generated_frame_structure_edges_ignore_string_punctuation(self):
        for seed in SEEDS:
            rng = random.Random(seed)
            for case in range(12):
                for nested_lists in (6, 7, 8):
                    data = text(rng) + '\\"' * rng.randrange(1, 8) + "[{,:}]"
                    for _ in range(nested_lists):
                        data = [data]
                    value = {"type": "mcp", "data": data}
                    depth, _ = tree_budget(value)
                    raw = json.dumps(value, ensure_ascii=bool(case % 2)).encode() + b"\n"
                    with self.subTest(seed=seed, case=case, frame_depth=depth):
                        if depth <= 8:
                            self.assertEqual(tunnel.read_frame(io.BytesIO(raw)), value)
                        else:
                            with self.assertRaises(tunnel.ProtocolError):
                                tunnel.read_frame(io.BytesIO(raw))
                for width in (123, 124, 125):
                    value = {"type": "mcp", "data": [text(rng, 3) for _ in range(width)]}
                    _, items = tree_budget(value)
                    raw = json.dumps(value).encode() + b"\n"
                    with self.subTest(seed=seed, case=case, frame_items=items):
                        if items <= 128:
                            self.assertEqual(tunnel.read_frame(io.BytesIO(raw)), value)
                        else:
                            with self.assertRaises(tunnel.ProtocolError):
                                tunnel.read_frame(io.BytesIO(raw))


class GeneratedGatewayTests(unittest.TestCase):
    def exchange(self, gateway, response, frame=None):
        connection = MemoryConnection(response)
        wire = RecordingWire()
        with patch.object(pair.http.client, "HTTPConnection", return_value=connection), \
                patch.object(pair.http.client, "HTTPSConnection", side_effect=AssertionError("Unexpected live connection")):
            gateway.exchange(frame or model_frame(gateway.client, id=gateway.requests + 1), wire)
        self.assertTrue(connection.closed)
        return wire

    def assert_stream(self, wire, raw):
        self.assertEqual(wire.frames[0]["type"], "model-start")
        self.assertEqual(wire.frames[-1]["type"], "model-end")
        self.assertTrue(all(frame["id"] == wire.frames[0]["id"] for frame in wire.frames))
        self.assertEqual(b"".join(base64.b64decode(frame["body"], validate=True)
                                  for frame in wire.frames if frame["type"] == "model-data"), raw)

    def test_generated_sse_chunking_newlines_and_last_text_association(self):
        for seed in SEEDS:
            rng = random.Random(seed)
            for case in range(18):
                parts = [text(rng) for _ in range(rng.randrange(1, 5))]
                phase = rng.choice(("final_answer", "commentary", "analysis"))
                ending = rng.choice((b"\n", b"\r", b"\r\n"))
                events = [assistant(["an earlier final answer"], "final_answer"),
                          assistant(parts, phase),
                          assistant(["tool decoy"], "final_answer", type="function_call"),
                          assistant(["user decoy"], "final_answer", role="user"),
                          {"type": "response.output_item.added", "item": assistant(["added decoy"])["item"]}]
                raw = b"".join(sse_event(event, ending, pretty=bool(rng.randrange(2))) for event in events)
                if case % 2:
                    raw = b"\xef\xbb\xbf" + raw
                # A complete final-answer JSON value without the blank dispatch line is incomplete.
                raw += sse_event(assistant(["incomplete decoy"]), ending)[:-len(ending)]
                expected_hash = hashlib.sha256("".join(parts).encode("utf-8")).hexdigest()
                for mode in ("whole", "bytes", "random"):
                    with self.subTest(seed=seed, case=case, newline=ending, partition=mode):
                        gateway = pair.ModelGateway("codex", fixture_port=1)
                        wire = self.exchange(gateway, MemoryResponse(chunks(raw, rng, mode)))
                        self.assert_stream(wire, raw)
                        self.assertEqual(gateway.final_phase, phase)
                        self.assertEqual(gateway.final_text_sha256, expected_hash)

    def test_generated_sse_invalid_evidence_replaces_stale_phase_and_text(self):
        for seed in SEEDS:
            rng = random.Random(seed)
            for case in range(18):
                ending = rng.choice((b"\n", b"\r", b"\r\n"))
                variant = case % 3
                if variant == 0:
                    last = assistant([text(rng)], rng.choice((None, "Final Answer", 42, "x" * 33)))
                    expected_hash = hashlib.sha256(last["item"]["content"][0]["text"].encode()).hexdigest()
                    expected_phase = None
                else:
                    last = assistant([], "commentary", content=rng.choice((None, "text", [None],
                                     [{"type": "input_text", "text": text(rng)}],
                                     [{"type": "output_text", "text": 42}])))
                    expected_phase, expected_hash = "commentary", None
                raw = sse_event(assistant(["old"], "final_answer"), ending) + sse_event(last, ending)
                with self.subTest(seed=seed, case=case):
                    gateway = pair.ModelGateway("codex", fixture_port=1)
                    self.assert_stream(self.exchange(gateway, MemoryResponse(chunks(raw, rng, "random"))), raw)
                    self.assertEqual(gateway.final_phase, expected_phase)
                    self.assertEqual(gateway.final_text_sha256, expected_hash)

    def test_generated_sse_partial_events_cannot_cross_requests(self):
        for seed in SEEDS:
            rng = random.Random(seed)
            for case in range(12):
                ending = rng.choice((b"\n", b"\r", b"\r\n"))
                gateway = pair.ModelGateway("codex", fixture_port=1)
                partial = sse_event(assistant(["partial"]), ending)[:-len(ending)]
                with self.subTest(seed=seed, case=case, control="incomplete"):
                    self.exchange(gateway, MemoryResponse(chunks(partial, rng, "random")))
                    self.assertIsNone(gateway.final_phase)
                    self.assertIsNone(gateway.final_text_sha256)
                answer = text(rng)
                raw = sse_event(assistant([answer], "commentary"), ending)
                with self.subTest(seed=seed, case=case):
                    self.exchange(gateway, MemoryResponse(chunks(raw, rng, "random")))
                    self.assertEqual(gateway.final_phase, "commentary")
                    self.assertEqual(gateway.final_text_sha256, hashlib.sha256(answer.encode()).hexdigest())

    def test_generated_sse_hash_binds_visible_unicode_control_rendering(self):
        replacements = (("\x00", ""), ("\x1b", ""), ("\x85", ""),
                        ("\u202e", "[U+202E]"), ("\u200b", "[U+200B]"),
                        ("\ud800", "[U+D800]"), ("\U000e0061", "[U+E0061]"))
        for seed in SEEDS:
            rng = random.Random(seed)
            for case in range(24):
                raw_parts, visible_parts = [], []
                for _ in range(rng.randrange(1, 10)):
                    ordinary, (control, visible) = text(rng), rng.choice(replacements)
                    raw_parts.extend((ordinary, control))
                    visible_parts.extend((ordinary, visible))
                event = assistant(raw_parts)
                # ASCII JSON also represents unpaired surrogate escapes safely on the wire.
                raw = b"data: " + json.dumps(event, ensure_ascii=True).encode() + b"\n\n"
                with self.subTest(seed=seed, case=case):
                    gateway = pair.ModelGateway("codex", fixture_port=1)
                    self.assert_stream(self.exchange(gateway, MemoryResponse(chunks(raw, rng, "random"))), raw)
                    self.assertEqual(gateway.final_phase, "final_answer")
                    self.assertEqual(gateway.final_text_sha256,
                                     hashlib.sha256("".join(visible_parts).encode()).hexdigest())

    def test_generated_response_byte_budgets_are_partition_independent(self):
        for seed in SEEDS:
            rng = random.Random(seed)
            for case in range(12):
                raw = bytes(rng.randrange(256) for _ in range(rng.randrange(2, 130)))
                for mode in ("whole", "bytes", "random"):
                    for maximum in (len(raw) - 1, len(raw)):
                        gateway = pair.ModelGateway("codex", fixture_port=1)
                        with self.subTest(seed=seed, case=case, partition=mode, budget=maximum), \
                                patch.object(pair, "MAX_RESPONSE", maximum):
                            response = MemoryResponse(chunks(raw, rng, mode), content_type="application/json")
                            if maximum == len(raw):
                                self.assert_stream(self.exchange(gateway, response), raw)
                            else:
                                connection, wire = MemoryConnection(response), RecordingWire()
                                with patch.object(pair.http.client, "HTTPConnection", return_value=connection), \
                                        self.assertRaises(tunnel.ProtocolError):
                                    gateway.exchange(model_frame(), wire)
                                self.assertTrue(connection.closed)
                                self.assertNotIn("model-end", [item["type"] for item in wire.frames])
                                self.assertLessEqual(sum(len(base64.b64decode(item["body"])) for item in wire.frames
                                                         if item["type"] == "model-data"), maximum)

    def test_generated_closed_model_fields_and_remote_features_never_connect(self):
        for seed in SEEDS:
            rng = random.Random(seed)
            for case in range(24):
                client = "codex" if case % 2 else "claude"
                block = {"type": "input_text" if client == "codex" else "text", "text": text(rng)}
                message = {"role": "user", "content": [block]}
                body = {"tools": catalog(client), "input" if client == "codex" else "messages": [message]}
                gateway = pair.ModelGateway(client, fixture_port=1, login=LOGIN if client == "claude" else None)
                with self.subTest(seed=seed, case=case, client=client, control="accepted"):
                    wire = self.exchange(gateway, MemoryResponse(content_type="application/json"), model_frame(client, body))
                    self.assertEqual(wire.frames[-1]["type"], "model-end")
                candidates = []
                for location in ("body", "message", "text", "tool"):
                    changed = copy.deepcopy(body)
                    target = {"body": changed, "message": changed["input" if client == "codex" else "messages"][0],
                              "text": changed["input" if client == "codex" else "messages"][0]["content"][0],
                              "tool": changed["tools"][0]}[location]
                    target["unapproved_" + str(rng.randrange(1_000_000))] = {"url": "https://unapproved.invalid/" + str(case)}
                    candidates.append((location, changed))
                remote = copy.deepcopy(body)
                remote["input" if client == "codex" else "messages"][0]["content"][0] = rng.choice(
                    [{"type": "input_file", "file_url": "https://unapproved.invalid/file"},
                     {"type": "image", "source": {"type": "url", "url": "https://unapproved.invalid/image"}}])
                candidates.append(("remote-content", remote))
                for location, changed in candidates:
                    with self.subTest(seed=seed, case=case, client=client, mutation=location), \
                            patch.object(pair.http.client, "HTTPConnection", return_value=MemoryConnection(
                                MemoryResponse(content_type="application/json"))) as connect, \
                            patch.object(pair.http.client, "HTTPSConnection", side_effect=AssertionError(
                                "Unexpected live connection")) as secure:
                        with self.assertRaises(tunnel.ProtocolError):
                            gateway.exchange(model_frame(client, changed), RecordingWire())
                        connect.assert_not_called()
                        secure.assert_not_called()


class GeneratedMCPTests(unittest.TestCase):
    @staticmethod
    def request(tool, path, **extra):
        key = "input_path" if tool == "analyze_javascript_application" else "path"
        return json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                           "params": {"name": tool, "arguments": {key: path, **extra}}}).encode()

    def test_generated_target_sets_are_monotonic_and_component_scoped(self):
        for seed in SEEDS:
            rng = random.Random(seed)
            for case in range(24):
                directory = "app" + str(rng.randrange(100000))
                name = directory + "/" + rng.choice(("a file.js", "\u00e9.apk", "\U0001f680.bin"))
                target = {"path": name, "size": rng.randrange(1, 4096)}
                sibling = {"path": directory + "-other/extra.js", "size": 1}
                tool = rng.choice(("open_binary", "inspect_android_package", "analyze_javascript_application"))
                selected = "/input/" + name
                for inputs, accepted in (([], False), ([sibling], False), ([target], True), ([target, sibling], True)):
                    with self.subTest(seed=seed, case=case, tool=tool, selected=accepted, size=len(inputs)):
                        policy = pair.MCPPolicy(inputs)
                        if accepted:
                            relayed = json.loads(policy.request(self.request(tool, selected)))
                            self.assertEqual(relayed["params"]["arguments"].get("input_path", relayed["params"]["arguments"].get("path")), selected)
                        else:
                            with self.assertRaises(tunnel.ProtocolError):
                                policy.request(self.request(tool, selected))
                # A string prefix without a directory boundary is never ancestry.
                directory_request = self.request("analyze_javascript_application", "/input/" + directory)
                with self.subTest(seed=seed, case=case, directory=directory):
                    self.assertIsNotNone(pair.MCPPolicy([target]).request(directory_request))
                    with self.assertRaises(tunnel.ProtocolError):
                        pair.MCPPolicy([sibling]).request(directory_request)

    def test_generated_path_mutations_and_extra_path_arguments_are_rejected(self):
        for seed in SEEDS:
            rng = random.Random(seed)
            for case in range(24):
                name = "target" + str(rng.randrange(100000)) + ".bin"
                valid = "/input/" + name
                invalid = ("/input/../" + name, "/input/a/../../" + name, "/input\\" + name,
                           "/input/" + name + "\x00", "/input/" + name + "\r", "/input/" + name + "\n",
                           "/inputs/" + name, "/etc/" + name, "file:///input/" + name, "/input/" + name + "/../" + name)
                tool = rng.choice(("open_binary", "inspect_android_package", "analyze_javascript_application"))
                for path in invalid:
                    # No selected-target check: lexical confinement must stand on its own.
                    with self.subTest(seed=seed, case=case, path=repr(path), tool=tool), self.assertRaises(tunnel.ProtocolError):
                        pair.MCPPolicy().request(self.request(tool, path))
                for key in ("output_path", "snapshot_path", "PaTh", "cachePath" + str(case)):
                    with self.subTest(seed=seed, case=case, extra=key), self.assertRaises(tunnel.ProtocolError):
                        pair.MCPPolicy().request(self.request(tool, valid, **{key: "/unapproved"}))
                with self.subTest(seed=seed, case=case, control="literal path text"):
                    self.assertIsNotNone(pair.MCPPolicy().request(self.request(tool, valid, note="/etc/passwd")))


class GeneratorSensitivityTests(unittest.TestCase):
    """The same generated checks must fail against intentionally weakened guards."""

    def assert_killed(self, test_class, method, target, replacement):
        result = unittest.TestResult()
        with patch.object(target[0], target[1], replacement):
            test_class(method).run(result)
        self.assertGreater(len(result.failures), 0, "Generated assertions did not kill the mutant")
        self.assertEqual(result.errors, [], "A fixture error is not evidence that an assertion killed a mutant")

    def test_duplicate_and_payload_guards_have_negative_controls(self):
        self.assert_killed(GeneratedTunnelTests, "test_generated_duplicate_keys_rejected_after_unescaping",
                           (tunnel, "decode_json"), lambda raw, **kwargs: json.loads(raw))
        self.assert_killed(GeneratedTunnelTests, "test_generated_payload_and_frame_byte_edges",
                           (tunnel, "pack"), lambda raw: base64.b64encode(raw).decode("ascii"))

    def test_sse_and_target_guards_have_negative_controls(self):
        original = pair.ModelGateway.note_phase

        def retain_first_answer(gateway, lines):
            if gateway.final_phase is None:
                original(gateway, lines)

        self.assert_killed(GeneratedGatewayTests, "test_generated_sse_chunking_newlines_and_last_text_association",
                           (pair.ModelGateway, "note_phase"), retain_first_answer)
        self.assert_killed(GeneratedMCPTests, "test_generated_target_sets_are_monotonic_and_component_scoped",
                           (pair.MCPPolicy, "request"), lambda policy, raw: raw)

    def test_structure_model_policy_and_answer_hash_have_negative_controls(self):
        self.assert_killed(GeneratedTunnelTests, "test_generated_frame_structure_edges_ignore_string_punctuation",
                           (tunnel, "read_frame"), lambda stream: json.loads(stream.readline()))
        self.assert_killed(GeneratedGatewayTests, "test_generated_closed_model_fields_and_remote_features_never_connect",
                           (pair, "validate_body"), lambda *args: None)
        self.assert_killed(GeneratedGatewayTests, "test_generated_sse_hash_binds_visible_unicode_control_rendering",
                           (pair, "answer_sha256"), lambda value: hashlib.sha256(b"unrelated text").hexdigest())


if __name__ == "__main__":
    unittest.main()
