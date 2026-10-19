"""Tracked text files hold no invisible or reordering characters: code reads as it runs."""

from pathlib import Path
import subprocess
import unicodedata
import unittest

ROOT = Path(__file__).resolve().parents[1]
BINARY = (".png", ".jpg", ".gif", ".mp4", ".webm", ".ico", ".zip", ".so", ".pdf")


class SourceTextTests(unittest.TestCase):
    def test_no_format_or_separator_characters_appear_literally(self):
        listed = subprocess.run(["git", "-C", str(ROOT), "ls-files", "-z"], capture_output=True, check=True).stdout
        found = []
        for name in filter(None, listed.decode("utf-8").split("\0")):
            if name.lower().endswith(BINARY):
                continue
            try:
                text = (ROOT / name).read_text(encoding="utf-8")
            except (UnicodeDecodeError, FileNotFoundError):
                continue
            for number, line in enumerate(text.split("\n"), 1):
                # Cf covers bidirectional controls and zero-width characters; write them as escapes.
                hidden = {character for character in line if unicodedata.category(character) in ("Cf", "Zl", "Zp", "Co", "Cs")}
                if hidden:
                    found.append("{}:{} {}".format(name, number, ", ".join(sorted("U+{:04X}".format(ord(c)) for c in hidden))))
        self.assertEqual(found, [])


if __name__ == "__main__":
    unittest.main()
