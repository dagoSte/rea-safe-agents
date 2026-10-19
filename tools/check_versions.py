#!/usr/bin/env python3
"""Compare the versions this project pins with the newest upstream releases.

The weekly workflow in .github/workflows/versions.yml runs this script and
opens or updates one issue when something is behind. It never changes a pin:
an update stays a reviewed change (new version, new checksum or digest, new
reviewed-client constants, rebuilt images and a fresh verification).

Exit status: 0 when every pin is current, 1 when an update is available or an
upstream source could not be checked.
"""

import argparse
import json
import os
from pathlib import Path
import re
import sys
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
ASSETS = Path("skills/rea-isolated/assets")
TEXT_SUFFIXES = {".py", ".md", ".yml", ".yaml", ".json", ".txt", ""}


def version_key(value):
    return tuple(int(part) for part in re.findall(r"\d+", value))


def read_pins(root):
    """Return {component: pinned version} read from the files that pin them."""
    rea = json.loads((root / ASSETS / "package.json").read_text(encoding="utf-8"))["dependencies"]
    clients = json.loads((root / ASSETS / "agent/package.json").read_text(encoding="utf-8"))["dependencies"]
    rea_image = (root / ASSETS / "Dockerfile").read_text(encoding="utf-8")
    agent_image = (root / ASSETS / "agent/Dockerfile").read_text(encoding="utf-8")
    ghidra = re.search(r"/Ghidra_(\d+(?:\.\d+)+)_build/", rea_image)
    jdk = re.search(r"/jdk-(21(?:\.\d+)+)%2B(\d+)/", rea_image)
    nodes = {re.search(r"^FROM node:(\d+\.\d+\.\d+)-bookworm-slim@sha256:[0-9a-f]{64}", text, re.M) for text in (rea_image, agent_image)}
    if not (ghidra and jdk and all(nodes)):
        raise ValueError("A pinned version could not be found in the Dockerfiles")
    node = {match.group(1) for match in nodes}
    if len(node) != 1:
        raise ValueError("The two Dockerfiles pin different Node images")
    return {"rea-agents": rea["rea-agents"], "claude-code": clients["@anthropic-ai/claude-code"],
            "codex": clients["@openai/codex"], "ghidra": ghidra.group(1),
            "temurin-jdk-21": jdk.group(1) + "+" + jdk.group(2), "node": node.pop()}


def fetch_json(url):
    request = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "rea-safe-agents-version-check"})
    token = os.environ.get("GITHUB_TOKEN")
    if token and urllib.parse.urlsplit(url).hostname == "api.github.com":
        request.add_header("Authorization", "Bearer " + token)
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read(8 * 1024 * 1024))


def npm_latest(package):
    return fetch_json("https://registry.npmjs.org/" + urllib.parse.quote(package, safe="@") + "/latest")["version"]


def ghidra_releases():
    releases = fetch_json("https://api.github.com/repos/NationalSecurityAgency/ghidra/releases?per_page=50")
    return [match.group(1) for match in (re.fullmatch(r"Ghidra_(\d+(?:\.\d+)+)_build", item.get("tag_name", ""))
                                         for item in releases if not item.get("prerelease") and not item.get("draft")) if match]


def temurin_21_latest():
    assets = fetch_json("https://api.adoptium.net/v3/assets/latest/21/hotspot?architecture=x64&image_type=jdk&os=linux&vendor=eclipse")
    return re.fullmatch(r"jdk-(.+)", assets[0]["release_name"]).group(1)


def node_latest(major):
    return next(item["version"].lstrip("v") for item in fetch_json("https://nodejs.org/dist/index.json")
                if item["version"].startswith("v" + major + "."))


def latest_versions(pins):
    """Return {component: (newest usable version, note)}; a failure becomes None."""
    ghidra_line = ".".join(pins["ghidra"].split(".")[:2])
    sources = {
        "rea-agents": lambda: (npm_latest("rea-agents"), ""),
        "claude-code": lambda: (npm_latest("@anthropic-ai/claude-code"), ""),
        "codex": lambda: (npm_latest("@openai/codex"), ""),
        "temurin-jdk-21": lambda: (temurin_21_latest(), ""),
        "node": lambda: (node_latest(pins["node"].split(".")[0]), ""),
    }
    def ghidra():
        releases = ghidra_releases()
        compatible = max((item for item in releases if item.startswith(ghidra_line + ".") or item == ghidra_line), key=version_key)
        newest = max(releases, key=version_key)
        note = "" if newest == compatible else "newest overall is " + newest + "; REA verifies one Ghidra line, check its support first"
        return compatible, note
    sources["ghidra"] = ghidra
    results = {}
    for name, source in sources.items():
        try:
            results[name] = source()
        except Exception as exc:  # one unavailable source must not hide the others
            results[name] = (None, "check failed: " + type(exc).__name__)
    return results


def locations(root, version):
    """Repository files that mention a pinned version and need the same update."""
    found = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if not path.is_file() or relative.parts[0] in {".git", "media", "docs"} or path.suffix not in TEXT_SUFFIXES and path.name != "Dockerfile":
            continue
        try:
            if version in path.read_text(encoding="utf-8"):
                found.append(relative.as_posix())
        except (UnicodeDecodeError, OSError):
            continue
    return found


def report(root, pins, latest):
    rows, behind = [], False
    for name, pinned in pins.items():
        newest, note = latest[name]
        if newest is None:
            status, behind = "could not check", True
        elif version_key(newest) > version_key(pinned):
            status, behind = "update available", True
        else:
            status = "current"
        search = pinned.split("+")[0] if name == "temurin-jdk-21" else pinned
        where = ", ".join("`" + item + "`" for item in locations(root, search)) if status == "update available" else ""
        rows.append({"component": name, "pinned": pinned, "latest": newest, "status": status, "note": note, "files": where})
    lines = ["Weekly comparison of the versions pinned by REA Safe Agent with upstream releases.", "",
             "| Component | Pinned | Latest | Status | Files that mention the pinned version |", "| --- | --- | --- | --- | --- |"]
    for row in rows:
        detail = row["files"] + ((" — " if row["files"] else "") + row["note"] if row["note"] else "")
        lines.append("| {component} | {pinned} | {latest} | {status} | {detail} |".format(detail=detail, latest=row["latest"] or "?", **{
            key: row[key] for key in ("component", "pinned", "status")}))
    lines += ["", "Node is compared within its pinned major line; a Node update also needs the new image digest.", "",
              "To update a component: change its pin and checksum or digest, update the reviewed-client "
              "constants and image tags where they appear, rebuild both images, run the unit suite and "
              "`tests/verify_runtime.py`, and record the result in `docs/validation.md`. A new client "
              "version also needs a review of its tools, flags and request fields before it is trusted."]
    return rows, behind, "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--markdown", help="Write the report as Markdown to this file")
    parser.add_argument("--json", action="store_true", help="Print the rows as JSON instead of Markdown")
    args = parser.parse_args()
    pins = read_pins(ROOT)
    rows, behind, markdown = report(ROOT, pins, latest_versions(pins))
    if args.markdown:
        Path(args.markdown).write_text(markdown, encoding="utf-8")
    print(json.dumps(rows, indent=2) if args.json else markdown)
    return 1 if behind else 0


if __name__ == "__main__":
    sys.exit(main())
