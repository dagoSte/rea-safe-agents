#!/usr/bin/env python3
"""Compare the versions this project pins with the newest upstream releases.

The weekly workflow in .github/workflows/versions.yml runs this script with
--sync-issue, which keeps one labelled issue open while anything is behind,
inconsistent or uncheckable, and closes it once everything is current. The
script never changes a pin: an update stays a reviewed change (new version,
new checksum or digest, new reviewed-client constants, rebuilt images and a
fresh verification).

Exit status without --sync-issue: 0 when every pin is current and consistent,
1 otherwise. With --sync-issue: 0 when the issue was reconciled.
"""

import argparse
import ast
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
ASSETS = Path("skills/rea-isolated/assets")
SCRIPTS = Path("skills/rea-isolated/scripts")
TITLE, LABEL = "Pinned versions to review", "pinned-versions"
MARKER = "<!-- rea-safe-agents:pinned-versions -->"
BOTS = {"app/github-actions", "github-actions[bot]"}
HISTORICAL = ("docs/validation.md", "docs/npm-audit.md", "docs/evidence/")  # dated records: listed, never rewritten
SKIPPED = ("media/", "node_modules/", ".git/")
HOSTS = {"registry.npmjs.org", "api.github.com", "api.adoptium.net", "nodejs.org", "auth.docker.io", "registry-1.docker.io"}
# Release versions only: an npm "latest" tag pointing at a prerelease or a build
# suffix is reported as uncheckable rather than proposed as an update.
NUMBER = r"(?:0|[1-9][0-9]*)"  # canonical ASCII: no leading zeros, no other digit scripts
SEMVER = NUMBER + r"\." + NUMBER + r"\." + NUMBER
SYNTAX = {"rea-agents": SEMVER, "claude-code": SEMVER, "codex": SEMVER,
          "ghidra": NUMBER + r"\." + NUMBER + r"(?:\." + NUMBER + r")?", "temurin-jdk-21": r"21(?:\." + NUMBER + r"){1,3}\+" + NUMBER,
          "node": SEMVER, "node-image": r"sha256:[0-9a-f]{64}", "trivy": SEMVER}
IMAGE_TAG = re.compile(r"rea-(?:agent-)?local:[A-Za-z0-9._-]+")
NODE_TAG = "{}-bookworm-slim"


class _RefuseRedirects(urllib.request.HTTPRedirectHandler):
    # A redirect could carry the GitHub token to another host; no source needs one.
    def redirect_request(self, request, fp, code, message, headers, url):
        raise urllib.error.HTTPError(request.full_url, code, "Redirects are refused", headers, fp)


OPENER = urllib.request.build_opener(_RefuseRedirects)


def open_url(url, headers=None, method="GET"):
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or parts.hostname not in HOSTS:
        raise ValueError("Unexpected upstream URL")
    request = urllib.request.Request(url, headers={"User-Agent": "rea-safe-agents-version-check", **(headers or {})}, method=method)
    token = os.environ.get("GITHUB_TOKEN")
    if token and parts.hostname == "api.github.com":
        request.add_header("Authorization", "Bearer " + token)
    return OPENER.open(request, timeout=30)


def fetch_json(url, headers=None):
    with open_url(url, {"Accept": "application/json", **(headers or {})}) as response:
        return json.loads(response.read(8 * 1024 * 1024))


def comparable(component, version):
    """Validate a version and return its ordering key; digests compare by equality."""
    if not isinstance(version, str) or not re.fullmatch(SYNTAX[component], version):
        raise ValueError("Unexpected version format")
    if component == "node-image":
        return version
    release, _, build = version.partition("+")
    numbers = [int(part) for part in release.split(".")]
    return tuple(numbers + [0] * (4 - len(numbers))), int(build or 0)


def read_pins(root):
    """Return {component: pinned version} read from the files that pin them."""
    rea = json.loads((root / ASSETS / "package.json").read_text(encoding="utf-8"))["dependencies"]
    clients = json.loads((root / ASSETS / "agent/package.json").read_text(encoding="utf-8"))["dependencies"]
    rea_image = (root / ASSETS / "Dockerfile").read_text(encoding="utf-8")
    agent_image = (root / ASSETS / "agent/Dockerfile").read_text(encoding="utf-8")
    ghidra = re.search(r"/Ghidra_([0-9]+(?:\.[0-9]+)+)_build/", rea_image)
    jdk = re.search(r"/jdk-(21(?:\.[0-9]+)+)%2B([0-9]+)/", rea_image)
    nodes = [re.search(r"^FROM node:([0-9]+\.[0-9]+\.[0-9]+)-bookworm-slim@(sha256:[0-9a-f]{64})", text, re.M) for text in (rea_image, agent_image)]
    if not (ghidra and jdk and all(nodes)):
        raise ValueError("A pinned version could not be found in the Dockerfiles")
    if len({match.groups() for match in nodes}) != 1:
        raise ValueError("The two Dockerfiles pin different Node images")
    pins = {"rea-agents": rea["rea-agents"], "claude-code": clients["@anthropic-ai/claude-code"],
            "codex": clients["@openai/codex"], "ghidra": ghidra.group(1),
            "temurin-jdk-21": jdk.group(1) + "+" + jdk.group(2), "node": nodes[0].group(1), "node-image": nodes[0].group(2)}
    scanner, _ = python_values(root / "tools/scan_images.py")
    pins["trivy"] = scanner.get("SCANNER_VERSION")
    if (not isinstance(scanner.get("SCANNER_IMAGE"), str)
            or not re.fullmatch(r"ghcr\.io/aquasecurity/trivy:" + re.escape(str(pins["trivy"])) + r"@sha256:[0-9a-f]{64}", scanner["SCANNER_IMAGE"])):
        raise ValueError("Trivy version and digest-pinned scanner image disagree")
    for name, value in pins.items():
        comparable(name, value)  # a pin outside the canonical syntax is an error, not a version
    return pins


def python_values(path):
    """Module constants and the REA equality required by exercise(), read from Python syntax."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    assigned, compared = {}, []
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            try:
                assigned[node.targets[0].id] = ast.literal_eval(node.value)
            except ValueError:
                assigned[node.targets[0].id] = None
    def required_versions(condition):
        if isinstance(condition, ast.BoolOp) and isinstance(condition.op, ast.And):
            return [value for item in condition.values for value in required_versions(item)]
        if (isinstance(condition, ast.Compare) and len(condition.ops) == 1 and isinstance(condition.ops[0], ast.Eq)
                and isinstance(condition.left, ast.Attribute) and condition.left.attr == "server_version"
                and isinstance(condition.left.value, ast.Name) and condition.left.value.id == "policy"
                and isinstance(condition.comparators[0], ast.Constant) and isinstance(condition.comparators[0].value, str)):
            return [condition.comparators[0].value]
        return []
    for function in tree.body:
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)) or function.name != "exercise":
            continue
        pending = list(function.body)
        while pending:
            node = pending.pop()
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                continue
            if (isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
                    and isinstance(node.value.func, ast.Name) and node.value.func.id == "require" and node.value.args):
                compared += required_versions(node.value.args[0])
            pending.extend(ast.iter_child_nodes(node))
    return assigned, compared


def consistency(root, pins):
    """Executable places that must agree with the pins; return each disagreement."""
    problems = []
    def lock(path, package, version):
        packages = json.loads((root / path).read_text(encoding="utf-8")).get("packages", {})
        main = packages.get("node_modules/" + package, {})
        if packages.get("", {}).get("dependencies", {}).get(package) != version or main.get("version") != version:
            problems.append(f"{path} does not lock {package} {version}")
        # The package's own native builds hold the binaries the image runs: each must be the same release.
        optional = main.get("optionalDependencies") or {}
        locked = {name[len("node_modules/"):] for name in packages if name.startswith("node_modules/" + package + "-")}
        natives = sorted(name for name in optional.keys() | locked if name.startswith(package + "-"))
        for name in [package, *natives]:
            spec = version if name == package else optional.get(name)
            entry = packages.get("node_modules/" + name, {})
            entry_version = entry.get("version", "")
            aliased = package == "@openai/codex" and name != package
            expected_version = version + name[len(package):] if aliased else version
            expected_spec = "npm:" + package + "@" + expected_version if aliased else version
            artifact = package if aliased else name
            expected_tarball = f"https://registry.npmjs.org/{artifact}/-/{artifact.rsplit('/', 1)[-1]}-{expected_version}.tgz"
            if spec != expected_spec:
                problems.append(f"{path} pins {name} to {spec}, not {expected_spec}")
            if entry_version != expected_version or entry.get("resolved") != expected_tarball:
                problems.append(f"{path} does not lock {name} {expected_version} from {expected_tarball}")
    lock(ASSETS / "package-lock.json", "rea-agents", pins["rea-agents"])
    lock(ASSETS / "agent/package-lock.json", "@anthropic-ai/claude-code", pins["claude-code"])
    lock(ASSETS / "agent/package-lock.json", "@openai/codex", pins["codex"])
    session, _ = python_values(root / SCRIPTS / "agent_session.py")
    if session.get("REVIEWED") != {"codex": "codex-cli " + pins["codex"], "claude": pins["claude-code"] + " (Claude Code)"}:
        problems.append(f"{SCRIPTS}/agent_session.py REVIEWED does not name both pinned clients")
    container, compared = python_values(root / SCRIPTS / "agent_container.py")
    if container.get("CODEX_VERSION") != pins["codex"]:
        problems.append(f"{SCRIPTS}/agent_container.py CODEX_VERSION is not {pins['codex']}")
    if compared != [pins["rea-agents"]]:
        problems.append(f"{SCRIPTS}/agent_container.py does not require REA {pins['rea-agents']}")
    expected = {f"rea-local:{pins['rea-agents']}-ghidra-{pins['ghidra']}-locked",
                f"rea-agent-local:codex-{pins['codex']}-claude-{pins['claude-code']}-locked"}
    for path in (".github/workflows/checks.yml", "tests/verify_runtime.py"):
        tags = set(IMAGE_TAG.findall((root / path).read_text(encoding="utf-8")))  # every mention, comments included
        if tags != expected:
            problems.append(f"{path} uses image tags {', '.join(sorted(tags)) or 'none'} instead of {', '.join(sorted(expected))}")
    return problems


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
    return next(item["version"][1:] for item in fetch_json("https://nodejs.org/dist/index.json")
                if isinstance(item.get("version"), str) and item["version"].startswith("v" + major + "."))


def trivy_latest():
    release = fetch_json("https://api.github.com/repos/aquasecurity/trivy/releases/latest")
    if release.get("draft") or release.get("prerelease") or not isinstance(release.get("tag_name"), str) or not release["tag_name"].startswith("v"):
        raise ValueError("Unexpected Trivy release")
    return release["tag_name"][1:]


def node_image_digest(version):
    """The current digest of the pinned tag: a rebuilt image keeps its version."""
    token = fetch_json("https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/node:pull")["token"]
    accept = "application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json"
    with open_url("https://registry-1.docker.io/v2/library/node/manifests/" + NODE_TAG.format(version),
                  {"Authorization": "Bearer " + token, "Accept": accept}, method="HEAD") as response:
        return response.headers.get("Docker-Content-Digest")


def latest_versions(pins):
    """Return {component: (newest usable value, note)}; any failure or bad data becomes None."""
    ghidra_line = ".".join(pins["ghidra"].split(".")[:2])
    def ghidra():
        releases = [item for item in ghidra_releases() if re.fullmatch(SYNTAX["ghidra"], item)]
        compatible = max((item for item in releases if item == ghidra_line or item.startswith(ghidra_line + ".")),
                         key=lambda item: comparable("ghidra", item))
        newest = max(releases, key=lambda item: comparable("ghidra", item))
        note = "" if newest == compatible else f"newest overall is {newest}; REA verifies one Ghidra line, check its support first"
        return compatible, note
    sources = {
        "rea-agents": lambda: (npm_latest("rea-agents"), ""),
        "claude-code": lambda: (npm_latest("@anthropic-ai/claude-code"), ""),
        "codex": lambda: (npm_latest("@openai/codex"), ""),
        "ghidra": ghidra,
        "temurin-jdk-21": lambda: (temurin_21_latest(), ""),
        "node": lambda: (node_latest(pins["node"].split(".")[0]), ""),
        "node-image": lambda: (node_image_digest(pins["node"]), "current digest of node:" + NODE_TAG.format(pins["node"])),
        "trivy": lambda: (trivy_latest(), "release version only; scanner tag rebuilds are not checked; review the GHCR digest when updating"),
    }
    results = {}
    for name, source in sources.items():
        try:
            value, note = source()
            comparable(name, value)
            results[name] = (value, note)
        except Exception as exc:  # one unavailable or malformed source must not hide the others
            results[name] = (None, "check failed: " + type(exc).__name__)
    return results


class EnumerationError(RuntimeError):
    pass


def tracked_files(root):
    """Files under version control; untracked local files are never listed."""
    try:
        output = subprocess.run(["git", "-C", str(root), "ls-files", "-z"], capture_output=True, check=True).stdout
        names = [name for name in output.decode("utf-8").split("\0") if name]
    except (OSError, subprocess.CalledProcessError, UnicodeDecodeError) as exc:
        raise EnumerationError("tracked files could not be listed (" + type(exc).__name__ + ")") from None
    return sorted(name for name in names if not name.startswith(SKIPPED))


def locations(root, version):
    """Tracked text files that mention a version: (to update, historical records)."""
    # v1.2.3 and name_1.2.3 count; 11.2.3, 1.2.30 and 1.2.3.4 do not.
    pattern = re.compile(r"(?<![0-9.])" + re.escape(version) + r"(?![0-9]|\.[0-9])")
    active, historical = [], []
    for name in tracked_files(root):
        path = root / name
        try:
            if path.stat().st_size > 4 * 1024 * 1024 or not pattern.search(path.read_text(encoding="utf-8")):
                continue
        except (UnicodeDecodeError, OSError):
            continue
        (historical if name.startswith(HISTORICAL) else active).append(name)
    return active, historical


def escape(text):
    """Plain text for a Markdown table cell: nothing upstream can add structure."""
    text = re.sub(r"\s+", " ", str(text))
    return re.sub(r"([\\`*_\[\]<>#!|~])", r"\\\1", text)


def report(root, pins, latest, problems):
    rows, behind = [], bool(problems)
    for name, pinned in pins.items():
        newest, note = latest[name]
        if newest is None:
            status = "could not check"
        elif name == "node-image":
            status = "current" if newest == pinned else "rebuilt upstream"
        else:
            status = "update available" if comparable(name, newest) > comparable(name, pinned) else "current"
        behind = behind or status != "current"
        active, historical = [], []
        if status != "current":
            try:
                active, historical = locations(root, pinned.split("+")[0])
            except EnumerationError as exc:
                if str(exc) not in problems:
                    problems = [*problems, str(exc)]
                behind = True
        rows.append({"component": name, "pinned": pinned, "latest": newest, "status": status, "note": note,
                     "files": active, "historical": historical})
    lines = [MARKER, "Weekly comparison of the versions pinned by REA Safe Agent with upstream releases.", "",
             "| Component | Pinned | Latest | Status | Files to update |", "| --- | --- | --- | --- | --- |"]
    for row in rows:
        detail = ", ".join(escape(name) for name in row["files"])
        if row["historical"]:
            detail += (" " if detail else "") + "(also in dated records, left as history: " + ", ".join(escape(n) for n in row["historical"]) + ")"
        if row["note"]:
            detail += (" " if detail else "") + "— " + escape(row["note"])
        lines.append(" | ".join(["", escape(row["component"]), escape(row["pinned"]), escape(row["latest"] or "?"), escape(row["status"]), detail, ""]).strip())
    if problems:
        lines += ["", "Pins that disagree with each other (fix these before closing):", ""]
        lines += ["- " + escape(problem) for problem in problems]
    lines += ["", "Node is compared within its pinned major line, and its image digest is compared with the "
              "tag's current digest, because a tag can be rebuilt without a new version.", "",
              "To update a component: change its pin and checksum or digest, update the reviewed-client "
              "constants and image tags where they appear, rebuild both images, run the unit suite and "
              "tests/verify\\_runtime.py, and record the result in docs/validation.md. A new client "
              "version also needs a review of its tools, flags and request fields before it is trusted. "
              "A new REA version may audit a different jadx-headless-mcp JAR: match the Dockerfile to its "
              "JADX\\_RELEASE version and SHA-256."]
    lines += ["", "The Trivy scanner release is monitored. Its digest is pinned and recorded by tools/scan\\_images.py; "
              "same-version scanner tag rebuilds are outside this automatic check. Review the official GHCR "
              "digest and scanner release before changing that pin, then rerun the image scan."]
    return rows, behind, "\n".join(lines) + "\n"


def gh(*args):
    return subprocess.run(["gh", *args], capture_output=True, text=True, check=True).stdout


def sync_issue(repo, behind, body_file):
    """Keep exactly one managed issue: open while behind, closed when current."""
    gh("label", "create", LABEL, "--repo", repo, "--color", "C5DEF5", "--force",
       "--description", "Managed by the weekly pinned-version check")
    issues = json.loads(gh("issue", "list", "--repo", repo, "--state", "open", "--label", LABEL,
                           "--json", "number,author,body", "--limit", "100"))
    # Only issues this workflow created and marked are managed; a same-title
    # issue from a person is never edited or closed.
    managed = sorted(item["number"] for item in issues
                     if item.get("author", {}).get("login") in BOTS and MARKER in (item.get("body") or ""))
    keep, duplicates = (managed[0], managed[1:]) if managed else (None, [])
    for number in duplicates:
        gh("issue", "close", str(number), "--repo", repo, "--comment", f"Duplicate of #{keep}.")
    if behind and keep:
        gh("issue", "edit", str(keep), "--repo", repo, "--body-file", body_file)
    elif behind:
        gh("issue", "create", "--repo", repo, "--title", TITLE, "--label", LABEL, "--body-file", body_file)
    elif keep:
        gh("issue", "close", str(keep), "--repo", repo, "--comment", "Every pinned version is current and consistent again.")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--markdown", help="Write the report as Markdown to this file")
    parser.add_argument("--json", action="store_true", help="Print the rows as JSON instead of Markdown")
    parser.add_argument("--sync-issue", metavar="OWNER/REPO", help="Open, update or close the managed issue with gh")
    args = parser.parse_args()
    try:
        pins = read_pins(ROOT)
        rows, behind, markdown = report(ROOT, pins, latest_versions(pins), consistency(ROOT, pins))
    except Exception as exc:  # the report itself failed: say so instead of looking current
        rows, behind = [], True
        markdown = MARKER + "\nThe pinned-version check could not run: " + escape(type(exc).__name__) + ".\n"
    if args.markdown or args.sync_issue:
        body_file = Path(args.markdown or ROOT / ".pinned-versions.md")
        body_file.write_text(markdown, encoding="utf-8")
    print(json.dumps(rows, indent=2) if args.json else markdown)
    if args.sync_issue:
        sync_issue(args.sync_issue, behind, str(body_file))
        return 0
    return 1 if behind else 0


if __name__ == "__main__":
    sys.exit(main())
