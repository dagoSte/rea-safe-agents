"""The weekly pinned-version check: reading pins, comparing and reporting."""

from pathlib import Path
import sys
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
