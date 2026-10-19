#!/usr/bin/env python3
"""Native Docker integration: both real contained clients analyze an inert ZIP
and a minimal ELF through REA's Ghidra provider.

No provider credentials or real model calls are used; Claude runs its
subscription profile with an inert login that only the localhost fixture sees. Run on each supported
host OS; a Linux container on macOS does not establish native Linux coverage.
"""

import argparse
import hashlib
import json
from pathlib import Path
import platform
import shutil
import struct
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import patch
import zipfile
import zlib

SCRIPTS = Path(__file__).resolve().parents[1] / "skills/rea-isolated/scripts"
sys.path.insert(0, str(SCRIPTS))
import agent_container as pair
from offline_model import FINAL_TEXT

PAYLOAD = b"REA independent forward-test fixture only\n"
EXPECTED = hashlib.sha256(PAYLOAD).hexdigest()
NATIVE_MARKER = b"REA native fixture: benign marker 7731"
ANDROID_MARKER = b"REA android fixture: benign marker 4417"
ANDROID_PACKAGE, ANDROID_PERMISSION = "fixture.rea", "android.permission.INTERNET"
JADX_REVISION = "5844800a486d2248fa949b74c9896285f5b54de2"  # REA reports it only for the audited JAR
APK = "/input/android-fixture.apk"
STEPS = [("open_binary", {"path": "/input/inert.zip"}), ("inspect_artifact", {}), ("close_binary", {}),
         ("open_binary", {"path": "/input/native-fixture"}), ("list_strings", {}), ("close_binary", {}),
         ("inspect_android_package", {"path": APK, "detail": "summary"}), ("search_android_classes", {"path": APK, "query": "Marker"}),
         ("inspect_android_method", {"path": APK, "class_name": "fixture.Marker", "method_name": "marker"})]


def native_fixture():
    """A minimal static x86-64 ELF: _start loads the marker's address and exits 0."""
    base, text_offset = 0x400000, 0x78
    rodata = NATIVE_MARKER + b"\0"
    rodata_offset = text_offset + 16
    # lea rsi, [rip + 9]; mov eax, 60; xor edi, edi; syscall
    text = bytes.fromhex("488d3509000000" "b83c000000" "31ff0f05")
    strtab = b"\0_start\0rea_marker\0"
    shstrtab = b"\0.text\0.rodata\0.symtab\0.strtab\0.shstrtab\0"
    symtab_offset = (rodata_offset + len(rodata) + 7) & ~7
    symtab = (bytes(24) + struct.pack("<IBBHQQ", 1, 0x12, 0, 1, base + text_offset, len(text))
              + struct.pack("<IBBHQQ", 8, 0x11, 0, 2, base + rodata_offset, len(rodata)))
    strtab_offset = symtab_offset + len(symtab)
    shstrtab_offset = strtab_offset + len(strtab)
    sections_offset = (shstrtab_offset + len(shstrtab) + 7) & ~7
    header = struct.pack("<16sHHIQQQIHHHHHH", b"\x7fELF\x02\x01\x01" + bytes(9), 2, 0x3E, 1, base + text_offset,
                         64, sections_offset, 0, 64, 56, 1, 64, 6, 5)
    loaded = rodata_offset + len(rodata)
    program = struct.pack("<IIQQQQQQ", 1, 5, 0, base, base, loaded, loaded, 0x1000)
    sections = bytes(64)
    for name, kind, flags, address, offset, size, link, info, align, entry in (
            (1, 1, 6, base + text_offset, text_offset, len(text), 0, 0, 1, 0),
            (7, 1, 2, base + rodata_offset, rodata_offset, len(rodata), 0, 0, 1, 0),
            (15, 2, 0, 0, symtab_offset, len(symtab), 4, 1, 8, 24),
            (23, 3, 0, 0, strtab_offset, len(strtab), 0, 0, 1, 0),
            (31, 3, 0, 0, shstrtab_offset, len(shstrtab), 0, 0, 1, 0)):
        sections += struct.pack("<IIQQQQIIQQ", name, kind, flags, address, offset, size, link, info, align, entry)
    image = bytearray(sections_offset)
    for offset, data in ((0, header), (64, program), (text_offset, text), (rodata_offset, rodata),
                         (symtab_offset, symtab), (strtab_offset, strtab), (shstrtab_offset, shstrtab)):
        image[offset:offset + len(data)] = data
    return bytes(image) + sections


def uleb128(value):
    out = bytearray()
    while True:
        byte, value = value & 0x7F, value >> 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def android_dex():
    """A minimal DEX: public class fixture.Marker { public static String marker() { return MARKER; } }"""
    strings = sorted([b"L", b"Lfixture/Marker;", b"Ljava/lang/Object;", b"Ljava/lang/String;", ANDROID_MARKER, b"marker"])
    index = {value: number for number, value in enumerate(strings)}
    types = [index[b"Lfixture/Marker;"], index[b"Ljava/lang/Object;"], index[b"Ljava/lang/String;"]]
    string_ids = 0x70
    type_ids = string_ids + 4 * len(strings)
    proto_ids = type_ids + 4 * len(types)
    method_ids = proto_ids + 12
    class_defs = method_ids + 8
    code_off = class_defs + 32
    # const-string v0, MARKER; return-object v0
    code = struct.pack("<HHHHII", 1, 0, 0, 0, 0, 3) + struct.pack("<HHH", 0x001A, index[ANDROID_MARKER], 0x0011)
    string_data_off = code_off + len(code)
    string_data, offsets = bytearray(), []
    for value in strings:
        offsets.append(string_data_off + len(string_data))
        string_data += uleb128(len(value)) + value + b"\0"
    class_data_off = string_data_off + len(string_data)
    class_data = uleb128(0) + uleb128(0) + uleb128(1) + uleb128(0) + uleb128(0) + uleb128(0x9) + uleb128(code_off)
    map_off = (class_data_off + len(class_data) + 3) & ~3
    sections = [(0x0000, 1, 0), (0x0001, len(strings), string_ids), (0x0002, len(types), type_ids), (0x0003, 1, proto_ids),
                (0x0005, 1, method_ids), (0x0006, 1, class_defs), (0x2001, 1, code_off), (0x2002, len(strings), string_data_off),
                (0x2000, 1, class_data_off), (0x1000, 1, map_off)]
    map_list = struct.pack("<I", len(sections)) + b"".join(struct.pack("<HHII", kind, 0, size, offset) for kind, size, offset in sections)
    size = map_off + len(map_list)
    image = bytearray(size)
    for offset, data in ((string_ids, b"".join(struct.pack("<I", value) for value in offsets)),
                         (type_ids, b"".join(struct.pack("<I", value) for value in types)),
                         (proto_ids, struct.pack("<III", index[b"L"], 2, 0)),
                         (method_ids, struct.pack("<HHI", 0, 0, index[b"marker"])),
                         (class_defs, struct.pack("<8I", 0, 0x1, 1, 0, 0xFFFFFFFF, 0, class_data_off, 0)),
                         (code_off, code), (string_data_off, string_data), (class_data_off, class_data), (map_off, map_list)):
        image[offset:offset + len(data)] = data
    image[0:8] = b"dex\n035\0"
    image[32:112] = struct.pack("<20I", size, 0x70, 0x12345678, 0, 0, map_off, len(strings), string_ids, len(types), type_ids,
                                1, proto_ids, 0, 0, 1, method_ids, 1, class_defs, size - code_off, code_off)
    image[12:32] = hashlib.sha1(image[32:]).digest()
    image[8:12] = struct.pack("<I", zlib.adler32(image[12:]))
    return bytes(image)


def android_manifest():
    """A binary AndroidManifest.xml: package, version, SDK levels and one permission."""
    # Attribute names come first, in the order of their framework resource IDs below.
    strings = ["versionCode", "versionName", "minSdkVersion", "targetSdkVersion", "name", "android",
               "http://schemas.android.com/apk/res/android", "package", "manifest", ANDROID_PACKAGE, "1.0",
               "uses-sdk", "uses-permission", ANDROID_PERMISSION]
    s = {value: number for number, value in enumerate(strings)}
    offsets, data = [], b""
    for value in strings:
        offsets.append(len(data))
        data += struct.pack("<H", len(value)) + value.encode("utf-16-le") + b"\0\0"
    data += b"\0" * (-len(data) % 4)
    pool = struct.pack("<IIIII", len(strings), 0, 0, 28 + 4 * len(strings), 0) + b"".join(struct.pack("<I", value) for value in offsets) + data
    ids = [0x0101021B, 0x0101021C, 0x0101020C, 0x01010270, 0x01010003]
    none, android = 0xFFFFFFFF, s["http://schemas.android.com/apk/res/android"]
    def node(kind, line, body):
        return struct.pack("<HHIII", kind, 16, 16 + len(body), line, none) + body
    def attribute(namespace, name, value):
        if isinstance(value, int):
            return struct.pack("<IIIHBBI", namespace, s[name], none, 8, 0, 0x10, value)
        return struct.pack("<IIIHBBI", namespace, s[name], s[value], 8, 0, 0x03, s[value])
    def start(line, name, *attributes):
        return node(0x0102, line, struct.pack("<IIHHHHHH", none, s[name], 20, 20, len(attributes), 0, 0, 0) + b"".join(attributes))
    def end(line, name):
        return node(0x0103, line, struct.pack("<II", none, s[name]))
    namespace = struct.pack("<II", s["android"], android)
    content = (struct.pack("<HHI", 0x0001, 28, 8 + len(pool)) + pool
               + struct.pack("<HHI", 0x0180, 8, 8 + 4 * len(ids)) + b"".join(struct.pack("<I", value) for value in ids)
               + node(0x0100, 1, namespace)
               + start(1, "manifest", attribute(android, "versionCode", 1), attribute(android, "versionName", "1.0"),
                       attribute(none, "package", ANDROID_PACKAGE))
               + start(2, "uses-sdk", attribute(android, "minSdkVersion", 21), attribute(android, "targetSdkVersion", 34)) + end(2, "uses-sdk")
               + start(3, "uses-permission", attribute(android, "name", ANDROID_PERMISSION)) + end(3, "uses-permission")
               + end(4, "manifest") + node(0x0101, 4, namespace))
    return struct.pack("<HHI", 0x0003, 8, 8 + len(content)) + content


def android_fixture(path):
    """An unsigned APK with the manifest and DEX above; JADX reads it statically, nothing runs it."""
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in (("AndroidManifest.xml", android_manifest()), ("classes.dex", android_dex())):
            archive.writestr(zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0)), data)


class RecordingPolicy(pair.MCPPolicy):
    def __init__(self, inputs, *, rea_profile):
        super().__init__(inputs, rea_profile=rea_profile)
        self.results = []
        self.calls = []

    def request(self, raw):
        value = json.loads(raw)
        result = super().request(raw)
        if value.get("method") == "tools/call":
            self.calls.append(value["params"]["name"])
        return result

    def response(self, raw):
        value = json.loads(raw)
        if value.get("id") in self.requested_tools:
            self.results.append(value)
        return super().response(raw)


def verify(args):
    scratch = Path(args.scratch_root).expanduser().resolve(strict=True)
    # On Windows choose e.g. C:\REA Verification, outside AppData/USERPROFILE.
    with tempfile.TemporaryDirectory(prefix="rea-runtime-test-", dir=scratch) as temporary:
        root = Path(temporary)
        selected, control, staging = root / "selected", root / "control", root / "staging"
        selected.mkdir()
        control.mkdir(mode=0o700)
        staging.mkdir(mode=0o700)
        with zipfile.ZipFile(selected / "inert.zip", "w", compression=zipfile.ZIP_STORED) as archive:
            archive.writestr("fixture-only.txt", PAYLOAD)
        (selected / "native-fixture").write_bytes(native_fixture())
        android_fixture(selected / "android-fixture.apk")
        deployment = {
            "schema": 1, "docker": str(Path(shutil.which("docker") or "missing-docker").resolve()),
            "docker_config": str(Path(args.docker_config).expanduser().resolve(strict=True)),
            "context": args.context, "image_id": "sha256:" + "0" * 64,
            "input_dir": str(selected.resolve()), "staging_root": str(staging.resolve()),
            "desktop_share_policy": "diagnostic",
        }
        pair.boundary.validate_config(deployment)
        pair.boundary.preflight(deployment)
        deployment["image_id"] = pair.boundary.docker_json(deployment, ["image", "inspect", args.rea_image])[0]["Id"]
        reports = []
        # Claude runs against the large REA profile, so Docker's acceptance and
        # exact inspection of those limits and settings are verified as well.
        for client, resources in (("codex", "standard"), ("claude", "large")):
            print("Verifying contained " + client + " against real REA (" + resources + " profile)", file=sys.stderr, flush=True)
            rea_path = control / ("rea-" + resources + ".json")
            pair.profile.write_json(rea_path, {**deployment, "profile": resources})
            config_path = control / (client + ".json")
            pair.configure(SimpleNamespace(rea_config=str(rea_path), image=args.agent_image, client=client, output=str(config_path)))
            # Include undeclared host-tool rejection and a real safe REA call.
            boundary_report = pair.verify(SimpleNamespace(config=str(config_path)))
            _, config, rea = pair.load_config(config_path)
            policy = RecordingPolicy(config["inputs"], rea_profile=resources)
            login = pair.profile.OFFLINE_CLAUDE_LOGIN if client == "claude" else None
            with pair.fixture(client, steps=STEPS, test_refusals=False) as server, patch.object(pair, "MCPPolicy", return_value=policy):
                gateway = pair.ModelGateway(client, fixture_port=server.server_port, login=login)
                result, transcripts = pair.exercise(config, rea,
                    prompt="Inspect /input/inert.zip and report the child SHA256, list the strings of /input/native-fixture, "
                           "then inspect " + APK + " and decompile its marker method.",
                    gateway=gateway, timeout=900, login=login, tool_timeout=pair.boundary.PROFILES[resources]["tool_timeout"])
            pair.require(policy.calls == [name for name, _ in STEPS] == result["completed_rea_calls"], "Actual REA dispatch sequence did not complete")
            pair.require(len(policy.results) == len(STEPS) and not any("error" in item or item.get("result", {}).get("isError") for item in policy.results), "REA analysis returned an error")
            pair.require(EXPECTED in json.dumps(policy.results[:3]), "Actual REA inventory did not contain the known child SHA256")
            pair.require(NATIVE_MARKER.decode() in json.dumps(policy.results[4]), "Ghidra did not recover the known native string")
            package = json.dumps(policy.results[6])
            pair.require(all(value in package for value in (ANDROID_PACKAGE, ANDROID_PERMISSION, JADX_REVISION)),
                         "JADX did not report the known package and permission from the audited bridge")
            pair.require("fixture.Marker" in json.dumps(policy.results[7]), "JADX did not find the known class")
            pair.require(ANDROID_MARKER.decode() in json.dumps(policy.results[8]), "JADX did not decompile the known method")
            # The report reads the transcript this pinned client actually wrote.
            answer = pair.final_answer(bytes(transcripts["stdout"]).split(b"\n"))
            pair.require(answer == (FINAL_TEXT, "codex" if client == "codex" else "claude-success"),
                         "The report did not find the client's final answer")
            pair.require(client == "claude" or (gateway.final_phase == "final_answer" and gateway.final_text_sha256 == pair.answer_sha256(answer[0])),
                         "The provider's final answer was not associated with the exported text")
            pair.require(not list(staging.iterdir()), "Frozen snapshots or diagnostic inputs remained in staging")
            reports.append({"client": client, "rea_profile": rea["profile"], "client_version": result["client_version"], "passed": True,
                            "completed_rea_calls": policy.calls, "child_sha256": EXPECTED, "native_string_recovered": True,
                            "android_package_and_method_recovered": True,
                            "dedicated_staging_cleanup": True,
                            "final_answer_extracted": True, "agent_probe": result["agent_probe"], "undeclared_tools_rejected": boundary_report["undeclared_tools_rejected"],
                            "model_requests": result["model_requests"], "real_provider_requests": 0})
        return {"host_os": sys.platform, "host_arch": platform.machine(), "rea_image_id": deployment["image_id"],
                "agent_image_id": config["agent_image_id"], "clients": reports, "fixture_cleanup": "completed",
                "sharing_policy": "diagnostic", "effective_vm_verified": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", required=True)
    parser.add_argument("--docker-config", default=str(Path.home() / ".docker"))
    parser.add_argument("--rea-image", default="rea-local:6.7.0-ghidra-12.1.4-locked")
    parser.add_argument("--agent-image", default="rea-agent-local:codex-0.163.0-claude-2.1.302-locked")
    parser.add_argument("--scratch-root", required=True, help="Existing private, Docker-shareable directory outside protected host state")
    args = parser.parse_args()
    try:
        print(json.dumps(verify(args), indent=2))
        return 0
    except (pair.ProtocolError, pair.boundary.BoundaryError, OSError, ValueError, KeyError, TypeError) as exc:
        print("Native REA integration FAILED: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
