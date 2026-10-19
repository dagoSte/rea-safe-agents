"""The weekly pinned-version check: reading pins, comparing and reporting."""

import io
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import check_versions as versions


class VersionCheckTests(unittest.TestCase):
    def test_every_pin_is_read_from_the_files_that_set_it(self):
        pins = versions.read_pins(ROOT)
        self.assertEqual(set(pins), {"rea-agents", "claude-code", "codex", "ghidra", "temurin-jdk-21", "node"})
        for name, value in pins.items():
            with self.subTest(name=name):
                self.assertRegex(value, r"^\d+(\.\d+)+(\+\d+)?$")

    def test_pins_follow_the_files_not_constants(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ("package.json", "Dockerfile", "agent/package.json", "agent/Dockerfile"):
                target = root / versions.ASSETS / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy(ROOT / versions.ASSETS / name, target)
            real = versions.read_pins(ROOT)
            replaced = {"rea-agents": "7.8.9", "claude-code": "5.6.7", "codex": "0.900.1", "ghidra": "7.3.2",
                        "temurin-jdk-21": "21.0.99+4", "node": "24.98.1"}
            edits = {"package.json": [("rea-agents", replaced["rea-agents"])],
                     "agent/package.json": [("claude-code", replaced["claude-code"]), ("codex", replaced["codex"])],
                     "Dockerfile": [("ghidra", replaced["ghidra"]), ("node", replaced["node"])],
                     "agent/Dockerfile": [("node", replaced["node"])]}
            for name, changes in edits.items():
                path = root / versions.ASSETS / name
                text = path.read_text()
                for component, value in changes:
                    text = text.replace(real[component], value)
                path.write_text(text)
            dockerfile = root / versions.ASSETS / "Dockerfile"
            old_jdk, old_build = real["temurin-jdk-21"].split("+")
            dockerfile.write_text(dockerfile.read_text().replace("jdk-" + old_jdk + "%2B" + old_build, "jdk-21.0.99%2B4"))
            self.assertEqual(versions.read_pins(root), replaced)
            agent = root / versions.ASSETS / "agent/Dockerfile"
            agent.write_text(agent.read_text().replace(replaced["node"], "24.97.0"))
            with self.assertRaises(ValueError):  # the two images must share one Node pin
                versions.read_pins(root)

    def test_each_upstream_source_is_queried_and_parsed(self):
        answers = {
            "https://registry.npmjs.org/rea-agents/latest": {"version": "6.8.0"},
            "https://registry.npmjs.org/@anthropic-ai%2Fclaude-code/latest": {"version": "3.0.0"},
            "https://api.github.com/repos/NationalSecurityAgency/ghidra/releases?per_page=50": [
                {"tag_name": "Ghidra_7.4_build"}, {"tag_name": "Ghidra_7.3.3_build"}, {"tag_name": "Ghidra_7.3.9_build", "prerelease": True},
                {"tag_name": "not-a-release"}],
            "https://api.adoptium.net/v3/assets/latest/21/hotspot?architecture=x64&image_type=jdk&os=linux&vendor=eclipse": [
                {"release_name": "jdk-21.0.13+11"}],
            "https://nodejs.org/dist/index.json": [{"version": "v25.1.0"}, {"version": "v24.30.2"}, {"version": "v24.30.1"}],
        }
        seen = []
        def answer(request, timeout):
            seen.append((request.full_url, request.get_header("Authorization")))
            return io.BytesIO(json.dumps(answers[request.full_url]).encode())
        with patch.object(versions.urllib.request, "urlopen", side_effect=answer), patch.dict(versions.os.environ, {"GITHUB_TOKEN": "synthetic"}):
            self.assertEqual(versions.npm_latest("rea-agents"), "6.8.0")
            self.assertEqual(versions.npm_latest("@anthropic-ai/claude-code"), "3.0.0")
            self.assertEqual(versions.ghidra_releases(), ["7.4", "7.3.3"])
            self.assertEqual(versions.temurin_21_latest(), "21.0.13+11")
            self.assertEqual(versions.node_latest("24"), "24.30.2")
        tokens = {url: token for url, token in seen}
        self.assertEqual(tokens["https://api.github.com/repos/NationalSecurityAgency/ghidra/releases?per_page=50"], "Bearer synthetic")
        self.assertTrue(all(token is None for url, token in seen if "api.github.com" not in url))  # the token goes only to GitHub

    def test_locations_include_dockerfiles_and_lockfiles_and_skip_history(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ("assets/Dockerfile", "assets/package-lock.json", "scripts/session.py", "docs/validation.md", ".git/config", "media/film.mp4"):
                (root / name).parent.mkdir(parents=True, exist_ok=True)
                (root / name).write_text("pinned 3.4.98\n")
            self.assertEqual(versions.locations(root, "3.4.98"), ["assets/Dockerfile", "assets/package-lock.json", "scripts/session.py"])

    def test_versions_compare_numerically(self):
        self.assertLess(versions.version_key("9.0.7.1+1"), versions.version_key("9.0.8+11"))
        self.assertLess(versions.version_key("7.3"), versions.version_key("7.3.2"))
        self.assertLess(versions.version_key("3.4.98"), versions.version_key("3.4.99"))
        self.assertLess(versions.version_key("0.99.0"), versions.version_key("0.150.0"))

    def test_report_lists_updates_failures_and_the_files_to_change(self):
        # Read the real pins so this file never mentions them and never needs updating.
        real = versions.read_pins(ROOT)
        pins = {name: real[name] for name in ("claude-code", "codex", "ghidra")}
        newer = real["claude-code"].rsplit(".", 1)[0] + "." + str(int(real["claude-code"].rsplit(".", 1)[1]) + 1)
        latest = {"claude-code": (newer, ""), "codex": (real["codex"], ""), "ghidra": (None, "check failed: URLError")}
        rows, behind, markdown = versions.report(ROOT, pins, latest)
        self.assertTrue(behind)
        status = {row["component"]: row["status"] for row in rows}
        self.assertEqual(status, {"claude-code": "update available", "codex": "current", "ghidra": "could not check"})
        self.assertIn("`skills/rea-isolated/scripts/agent_session.py`", markdown)
        self.assertNotIn("tests/test_versions.py", markdown)
        _, behind, _ = versions.report(ROOT, {"codex": real["codex"]}, {"codex": (real["codex"], "")})
        self.assertFalse(behind)

    def test_ghidra_stays_on_the_line_rea_verifies_and_notes_newer_lines(self):
        pins = dict.fromkeys(("rea-agents", "claude-code", "codex", "temurin-jdk-21", "node"), "1.0.0")
        pins["ghidra"] = "7.3.2"
        with patch.object(versions, "ghidra_releases", return_value=["7.4", "7.3.5", "7.3.2", "7.2.9"]), \
                patch.object(versions, "npm_latest", side_effect=OSError("offline")), \
                patch.object(versions, "temurin_21_latest", return_value="9.0.8+11"), \
                patch.object(versions, "node_latest", return_value="1.0.0"):
            latest = versions.latest_versions(pins)
        self.assertEqual(latest["ghidra"][0], "7.3.5")
        self.assertIn("7.4", latest["ghidra"][1])
        # One unavailable source is reported without hiding the others.
        self.assertEqual(latest["codex"], (None, "check failed: OSError"))
        self.assertEqual(latest["temurin-jdk-21"], ("9.0.8+11", ""))


if __name__ == "__main__":
    unittest.main()
