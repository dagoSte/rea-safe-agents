"""Require the actual Windows account-profile test to pass, never skip."""

import os
import sys
import unittest

if os.name != "nt":
    raise SystemExit("Run this check on native Windows")


def cases(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from cases(item)
        else:
            yield item


discovered = unittest.defaultTestLoader.discover("tests", pattern="test_container.py")
selected = [case for case in cases(discovered) if case.id().endswith(".test_redirected_userprofile_does_not_unprotect_the_windows_profile")]
if len(selected) != 1:
    raise SystemExit("Exactly one native Windows profile test must be present")
result = unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(selected))
sys.exit(0 if result.testsRun == 1 and result.wasSuccessful() and not result.skipped else 1)
