"""Select the pinned native ELF binaries without running npm install scripts."""

from pathlib import Path

root = Path("/opt/clients/node_modules")
destination = Path("/opt/agent-bin")
destination.mkdir()
for client in ("codex", "claude"):
    candidates = []
    for path in root.rglob(client + "*"):
        if path.name not in (client, client + ".exe") or not path.is_file():
            continue
        with path.open("rb") as stream:
            if stream.read(4) == b"\x7fELF":
                candidates.append(path)
    if len(candidates) != 1:
        raise SystemExit("Expected exactly one pinned Linux binary for " + client)
    candidates[0].chmod(0o555)
    (destination / client).symlink_to(candidates[0])
