"""The weekly pinned-version check: reading pins, comparing, reporting and the issue."""

import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import check_versions as versions

DIGEST_A, DIGEST_B = "sha256:" + "a" * 64, "sha256:" + "b" * 64
PINNED_FILES = ("package.json", "package-lock.json", "Dockerfile", "agent/package.json", "agent/package-lock.json", "agent/Dockerfile")
EXECUTABLE_FILES = (versions.SCRIPTS / "agent_session.py", versions.SCRIPTS / "agent_container.py",
                    Path(".github/workflows/checks.yml"), Path("tests/verify_runtime.py"))


def copy_pinned_tree(root):
    for name in PINNED_FILES:
        target = root / versions.ASSETS / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(ROOT / versions.ASSETS / name, target)
    for path in EXECUTABLE_FILES:
        (root / path).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(ROOT / path, root / path)


def current_latest(pins):
    return {name: (value, "") for name, value in pins.items()}


class Response(io.BytesIO):
    def __init__(self, payload=b"", headers=None):
        super().__init__(payload)
        self.headers = headers or {}


class PinTests(unittest.TestCase):
    def test_every_pin_is_read_and_well_formed(self):
        pins = versions.read_pins(ROOT)
        self.assertEqual(set(pins), set(versions.SYNTAX))
        for name, value in pins.items():
            with self.subTest(name=name):
                versions.comparable(name, value)

    def test_pins_follow_the_files_not_constants(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            copy_pinned_tree(root)
            real = versions.read_pins(ROOT)
            replaced = {"rea-agents": "7.8.9", "claude-code": "5.6.7", "codex": "0.900.1", "ghidra": "7.3.2",
                        "temurin-jdk-21": "21.0.99+4", "node": "24.98.1", "node-image": DIGEST_A}
            for name, components in {"package.json": ["rea-agents"], "agent/package.json": ["claude-code", "codex"],
                                     "Dockerfile": ["ghidra", "node", "node-image"], "agent/Dockerfile": ["node", "node-image"]}.items():
                path = root / versions.ASSETS / name
                text = path.read_text()
                for component in components:
                    text = text.replace(real[component], replaced[component])
                path.write_text(text)
            dockerfile = root / versions.ASSETS / "Dockerfile"
            old_jdk, old_build = real["temurin-jdk-21"].split("+")
            dockerfile.write_text(dockerfile.read_text().replace("jdk-" + old_jdk + "%2B" + old_build, "jdk-21.0.99%2B4"))
            self.assertEqual(versions.read_pins(root), replaced)
            agent = root / versions.ASSETS / "agent/Dockerfile"
            agent.write_text(agent.read_text().replace(DIGEST_A, DIGEST_B))
            with self.assertRaises(ValueError):  # both images must share one Node version and digest
                versions.read_pins(root)

    def test_a_partial_update_is_reported_as_inconsistent(self):
        self.assertEqual(versions.consistency(ROOT, versions.read_pins(ROOT)), [])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            copy_pinned_tree(root)
            manifest = root / versions.ASSETS / "package.json"
            real = versions.read_pins(root)
            manifest.write_text(manifest.read_text().replace(real["rea-agents"], "7.8.9"))
            pins = versions.read_pins(root)
            problems = versions.consistency(root, pins)
            self.assertTrue(any("package-lock.json" in problem for problem in problems))
            self.assertTrue(any("REA 7.8.9" in problem for problem in problems))
            self.assertTrue(any("checks.yml" in problem for problem in problems))
            _, behind, markdown = versions.report(root, pins, current_latest(pins), problems)
            self.assertTrue(behind)  # every upstream row is "current", yet the issue must stay open
            self.assertIn("disagree", markdown)


class ComparisonTests(unittest.TestCase):
    def test_versions_compare_per_component(self):
        key = versions.comparable
        self.assertLess(key("temurin-jdk-21", "21.0.12+11"), key("temurin-jdk-21", "21.0.12.1+1"))
        self.assertLess(key("temurin-jdk-21", "21.0.12.1+1"), key("temurin-jdk-21", "21.0.13+11"))
        self.assertLess(key("ghidra", "7.3"), key("ghidra", "7.3.2"))
        self.assertLess(key("codex", "0.99.0"), key("codex", "0.150.0"))
        for component, value in (("codex", "2.0.0-beta.1"), ("codex", "2.0.0+build.9"), ("codex", "not-a-version"),
                                 ("codex", []), ("node-image", "sha256:short"), ("ghidra", "7.3\n# heading")):
            with self.subTest(value=value), self.assertRaises(ValueError):
                key(component, value)

    def test_malformed_upstream_data_is_never_reported_as_current(self):
        pins = versions.read_pins(ROOT)
        npm = {"rea-agents": "not-a-version", "@anthropic-ai/claude-code": [], "@openai/codex": "9.9.9-rc.1"}
        with patch.object(versions, "npm_latest", side_effect=npm.get), \
                patch.object(versions, "ghidra_releases", return_value=[pins["ghidra"]]), \
                patch.object(versions, "temurin_21_latest", return_value=pins["temurin-jdk-21"]), \
                patch.object(versions, "node_latest", return_value=pins["node"]), \
                patch.object(versions, "node_image_digest", return_value=pins["node-image"]):
            latest = versions.latest_versions(pins)
        for name in ("rea-agents", "claude-code", "codex"):
            self.assertEqual(latest[name], (None, "check failed: ValueError"))
        self.assertEqual(latest["node"], (pins["node"], ""))
        rows, behind, _ = versions.report(ROOT, pins, latest, [])
        self.assertTrue(behind)
        self.assertEqual({row["component"]: row["status"] for row in rows}["codex"], "could not check")

    def test_ghidra_stays_on_the_line_rea_verifies_and_notes_newer_lines(self):
        pins = versions.read_pins(ROOT) | {"ghidra": "7.3.2"}
        with patch.object(versions, "ghidra_releases", return_value=["7.4", "7.3.5", "7.3.2", "7.2.9"]), \
                patch.object(versions, "npm_latest", side_effect=OSError("offline")), \
                patch.object(versions, "temurin_21_latest", return_value="21.0.13+11"), \
                patch.object(versions, "node_latest", return_value=pins["node"]), \
                patch.object(versions, "node_image_digest", return_value=pins["node-image"]):
            latest = versions.latest_versions(pins)
        self.assertEqual(latest["ghidra"][0], "7.3.5")
        self.assertIn("7.4", latest["ghidra"][1])
        self.assertEqual(latest["codex"], (None, "check failed: OSError"))  # one failed source hides nothing else
        self.assertEqual(latest["temurin-jdk-21"], ("21.0.13+11", ""))

    def test_a_rebuilt_node_image_is_reported(self):
        pins = versions.read_pins(ROOT)
        latest = current_latest(pins) | {"node-image": (DIGEST_B if pins["node-image"] != DIGEST_B else DIGEST_A, "")}
        rows, behind, _ = versions.report(ROOT, pins, latest, [])
        self.assertTrue(behind)
        self.assertEqual({row["component"]: row["status"] for row in rows}["node-image"], "rebuilt upstream")
        self.assertFalse(versions.report(ROOT, pins, current_latest(pins), [])[1])


class SourceTests(unittest.TestCase):
    def test_each_upstream_source_is_queried_and_parsed(self):
        answers = {
            "https://registry.npmjs.org/rea-agents/latest": {"version": "6.8.0"},
            "https://registry.npmjs.org/@anthropic-ai%2Fclaude-code/latest": {"version": "3.0.0"},
            "https://api.github.com/repos/NationalSecurityAgency/ghidra/releases?per_page=50": [
                {"tag_name": "Ghidra_7.4_build"}, {"tag_name": "Ghidra_7.3.3_build"},
                {"tag_name": "Ghidra_7.3.9_build", "prerelease": True}, {"tag_name": "not-a-release"}],
            "https://api.adoptium.net/v3/assets/latest/21/hotspot?architecture=x64&image_type=jdk&os=linux&vendor=eclipse": [
                {"release_name": "jdk-21.0.13+11"}],
            "https://nodejs.org/dist/index.json": [{"version": "v25.1.0"}, {"version": "v24.30.2"}, {"version": "v24.30.1"}],
            "https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/node:pull": {"token": "registry-token"},
        }
        seen = []
        def answer(request, timeout):
            seen.append((request.full_url, request.get_method(), request.get_header("Authorization")))
            if request.full_url.startswith("https://registry-1.docker.io/"):
                return Response(headers={"Docker-Content-Digest": DIGEST_B})
            return Response(json.dumps(answers[request.full_url]).encode())
        with patch.object(versions.OPENER, "open", side_effect=answer), patch.dict(versions.os.environ, {"GITHUB_TOKEN": "synthetic"}):
            self.assertEqual(versions.npm_latest("rea-agents"), "6.8.0")
            self.assertEqual(versions.npm_latest("@anthropic-ai/claude-code"), "3.0.0")
            self.assertEqual(versions.ghidra_releases(), ["7.4", "7.3.3"])
            self.assertEqual(versions.temurin_21_latest(), "21.0.13+11")
            self.assertEqual(versions.node_latest("24"), "24.30.2")
            self.assertEqual(versions.node_image_digest("24.30.2"), DIGEST_B)
        authorization = {url: token for url, _, token in seen}
        self.assertEqual(authorization["https://api.github.com/repos/NationalSecurityAgency/ghidra/releases?per_page=50"], "Bearer synthetic")
        manifest = "https://registry-1.docker.io/v2/library/node/manifests/24.30.2-bookworm-slim"
        self.assertEqual(authorization[manifest], "Bearer registry-token")
        self.assertIn((manifest, "HEAD", "Bearer registry-token"), seen)
        self.assertTrue(all("synthetic" not in (token or "") for url, _, token in seen if "api.github.com" not in url))

    def test_redirects_are_refused_and_only_known_https_hosts_are_contacted(self):
        self.assertTrue(any(isinstance(handler, versions._RefuseRedirects) for handler in versions.OPENER.handlers))
        request = versions.urllib.request.Request("https://api.github.com/repos")
        with self.assertRaises(versions.urllib.error.HTTPError):
            versions._RefuseRedirects().redirect_request(request, None, 302, "Found", {}, "https://example.invalid/")
        with patch.object(versions.OPENER, "open") as opened:
            for url in ("http://api.github.com/repos", "https://example.invalid/latest", "https://api.github.com.example.invalid/"):
                with self.subTest(url=url), self.assertRaises(ValueError):
                    versions.open_url(url)
            opened.assert_not_called()


class ReportTests(unittest.TestCase):
    def test_upstream_text_cannot_add_markdown_structure(self):
        pins = versions.read_pins(ROOT)
        hostile = "line\n# Heading [link](https://example.invalid) <b>bold</b> | cell `code`"
        latest = current_latest(pins) | {"ghidra": (None, hostile)}
        _, _, markdown = versions.report(ROOT, pins, latest, [hostile])
        self.assertNotIn("\n# Heading", markdown)
        self.assertNotIn("<b>", markdown)
        self.assertNotIn("[link](", markdown)
        self.assertNotIn("`code`", markdown)
        table = [line for line in markdown.splitlines() if line.startswith("| ghidra")]
        self.assertEqual(len(table), 1)
        self.assertEqual(table[0].count(" | "), 4)  # an escaped pipe adds no column

    def test_locations_use_version_boundaries_tracked_files_and_history(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            files = {"assets/Dockerfile": "FROM x:3.4.98-slim", "assets/package-lock.json": '"version": "3.4.98"',
                     "scripts/session.py": "uses 3.4.98.", "scripts/other.py": "3.4.980 and 13.4.98",
                     "docs/validation.md": "verified 3.4.98", "docs/evidence/run.json": '"3.4.98"', "media/notes.md": "3.4.98"}
            for name, text in files.items():
                (root / name).parent.mkdir(parents=True, exist_ok=True)
                (root / name).write_text(text + "\n")
            (root / "node_modules").mkdir()
            (root / "node_modules/dependency.js").write_text("3.4.98\n")  # untracked
            (root / "scripts/local-notes.py").write_text("3.4.98\n")  # untracked, outside skipped folders
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            subprocess.run(["git", "-C", str(root), "add", *files], check=True)
            active, historical = versions.locations(root, "3.4.98")
        self.assertEqual(active, ["assets/Dockerfile", "assets/package-lock.json", "scripts/session.py"])
        self.assertEqual(historical, ["docs/evidence/run.json", "docs/validation.md"])


class IssueTests(unittest.TestCase):
    def run_sync(self, issues, behind):
        calls = []
        def gh(*args):
            calls.append(args)
            return json.dumps(issues) if args[:2] == ("issue", "list") else ""
        with patch.object(versions, "gh", side_effect=gh):
            versions.sync_issue("owner/repo", behind, "/tmp/body.md")
        return [call for call in calls if call[0] == "issue" and call[1] != "list"]

    def test_the_issue_is_created_once_and_labelled(self):
        actions = self.run_sync([], True)
        self.assertEqual(actions, [("issue", "create", "--repo", "owner/repo", "--title", versions.TITLE,
                                    "--label", versions.LABEL, "--body-file", "/tmp/body.md")])
        self.assertEqual(self.run_sync([], False), [])

    def test_only_marked_bot_issues_are_managed_and_duplicates_are_closed(self):
        bot, person = {"login": "app/github-actions"}, {"login": "someone"}
        issues = [{"number": 5, "author": bot, "body": versions.MARKER}, {"number": 3, "author": bot, "body": "x " + versions.MARKER},
                  {"number": 4, "author": person, "body": versions.MARKER}, {"number": 6, "author": bot, "body": "same title, no marker"}]
        actions = self.run_sync(issues, True)
        self.assertEqual(actions, [("issue", "close", "5", "--repo", "owner/repo", "--comment", "Duplicate of #3."),
                                   ("issue", "edit", "3", "--repo", "owner/repo", "--body-file", "/tmp/body.md")])
        actions = self.run_sync(issues[1:], False)
        self.assertEqual([action[:3] for action in actions], [("issue", "close", "3")])

    def test_a_failed_check_still_writes_a_body_and_keeps_the_issue_open(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(versions, "read_pins", side_effect=KeyError("missing")), \
                patch.object(versions, "sync_issue") as sync, patch.object(sys, "stdout", io.StringIO()):
            body = Path(temporary) / "body.md"
            with patch.object(sys, "argv", ["check_versions.py", "--markdown", str(body), "--sync-issue", "owner/repo"]):
                self.assertEqual(versions.main(), 0)
            self.assertIn("could not run", body.read_text())
            sync.assert_called_once_with("owner/repo", True, str(body))


if __name__ == "__main__":
    unittest.main()
