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

SCRIPTS = Path(__file__).resolve().parents[1] / "skills/rea-isolated/scripts"
sys.path.insert(0, str(SCRIPTS))
import agent_container as pair

PAYLOAD = b"REA independent forward-test fixture only\n"
EXPECTED = hashlib.sha256(PAYLOAD).hexdigest()
NATIVE_MARKER = b"REA native fixture: benign marker 7731"
STEPS = [("open_binary", {"path": "/input/inert.zip"}), ("inspect_artifact", {}), ("close_binary", {}),
         ("open_binary", {"path": "/input/native-fixture"}), ("list_strings", {}), ("close_binary", {})]


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


class RecordingPolicy(pair.MCPPolicy):
    def __init__(self):
        super().__init__()
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
        selected, control = root / "selected", root / "control"
        selected.mkdir()
        control.mkdir(mode=0o700)
        with zipfile.ZipFile(selected / "inert.zip", "w", compression=zipfile.ZIP_STORED) as archive:
            archive.writestr("fixture-only.txt", PAYLOAD)
        (selected / "native-fixture").write_bytes(native_fixture())
        deployment = {
            "schema": 1, "docker": str(Path(shutil.which("docker") or "missing-docker").resolve()),
            "docker_config": str(Path(args.docker_config).expanduser().resolve(strict=True)),
            "context": args.context, "image_id": "sha256:" + "0" * 64,
            "input_dir": str(selected.resolve()),
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
            policy = RecordingPolicy()
            login = pair.profile.OFFLINE_CLAUDE_LOGIN if client == "claude" else None
            with pair.fixture(client, steps=STEPS, test_refusals=False) as server, patch.object(pair, "MCPPolicy", return_value=policy):
                result, _ = pair.exercise(config, rea,
                    prompt="Inspect /input/inert.zip and report the child SHA256, then list the strings of /input/native-fixture.",
                    gateway=pair.ModelGateway(client, fixture_port=server.server_port, login=login), timeout=900, login=login)
            pair.require(policy.calls == [name for name, _ in STEPS] == result["completed_rea_calls"], "Actual REA dispatch sequence did not complete")
            pair.require(len(policy.results) == len(STEPS) and not any("error" in item or item.get("result", {}).get("isError") for item in policy.results), "REA analysis returned an error")
            pair.require(EXPECTED in json.dumps(policy.results[:3]), "Actual REA inventory did not contain the known child SHA256")
            pair.require(NATIVE_MARKER.decode() in json.dumps(policy.results[4]), "Ghidra did not recover the known native string")
            reports.append({"client": client, "rea_profile": rea["profile"], "client_version": result["client_version"], "passed": True,
                            "completed_rea_calls": policy.calls, "child_sha256": EXPECTED, "native_string_recovered": True,
                            "agent_probe": result["agent_probe"], "undeclared_tools_rejected": boundary_report["undeclared_tools_rejected"],
                            "model_requests": result["model_requests"], "real_provider_requests": 0})
        return {"host_os": sys.platform, "host_arch": platform.machine(), "rea_image_id": deployment["image_id"],
                "agent_image_id": config["agent_image_id"], "clients": reports, "fixture_cleanup": "completed"}


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
