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
        self.assertLess(versions.version_key("21.0.12.1+1"), versions.version_key("21.0.13+11"))
        self.assertLess(versions.version_key("12.1"), versions.version_key("12.1.4"))
        self.assertLess(versions.version_key("2.1.302"), versions.version_key("2.1.303"))
        self.assertLess(versions.version_key("0.99.0"), versions.version_key("0.163.0"))

    def test_report_lists_updates_failures_and_the_files_to_change(self):
        pins = {"claude-code": "2.1.302", "codex": "0.163.0", "ghidra": "12.1.4"}
        latest = {"claude-code": ("2.1.303", ""), "codex": ("0.163.0", ""), "ghidra": (None, "check failed: URLError")}
        rows, behind, markdown = versions.report(ROOT, pins, latest)
        self.assertTrue(behind)
        status = {row["component"]: row["status"] for row in rows}
        self.assertEqual(status, {"claude-code": "update available", "codex": "current", "ghidra": "could not check"})
        self.assertIn("`skills/rea-isolated/scripts/agent_session.py`", markdown)
        _, behind, _ = versions.report(ROOT, {"codex": "0.163.0"}, {"codex": ("0.163.0", "")})
        self.assertFalse(behind)

    def test_ghidra_stays_on_the_line_rea_verifies_and_notes_newer_lines(self):
        pins = dict.fromkeys(("rea-agents", "claude-code", "codex", "temurin-jdk-21", "node"), "1.0.0")
        pins["ghidra"] = "12.1.4"
        with patch.object(versions, "ghidra_releases", return_value=["12.2", "12.1.5", "12.1.4", "12.0.4"]), \
                patch.object(versions, "npm_latest", side_effect=OSError("offline")), \
                patch.object(versions, "temurin_21_latest", return_value="21.0.13+11"), \
                patch.object(versions, "node_latest", return_value="1.0.0"):
            latest = versions.latest_versions(pins)
        self.assertEqual(latest["ghidra"][0], "12.1.5")
        self.assertIn("12.2", latest["ghidra"][1])
        # One unavailable source is reported without hiding the others.
        self.assertEqual(latest["codex"], (None, "check failed: OSError"))
        self.assertEqual(latest["temurin-jdk-21"], ("21.0.13+11", ""))


if __name__ == "__main__":
    unittest.main()
