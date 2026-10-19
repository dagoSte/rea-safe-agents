"""Inspect saved Docker Desktop sharing settings without changing Desktop.

This checks the saved macOS virtual-share list, not the effective VM state or
other sharing mechanisms. It is not evidence of protection against VM escape.
"""

import argparse
import json
from pathlib import Path
import sys


def projection(path):
    if path.stat().st_size > 4 * 1024 * 1024:
        raise ValueError("Desktop settings exceed the inspection limit")
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("Duplicate Desktop setting")
            value[key] = item
        return value
    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise ValueError("Invalid Desktop settings")
    selected = {}
    for key, item in value.items():
        name = key.lower()
        if name in {"filesharingdirectories", "enhancedcontainerisolation"}:
            if name in selected and selected[name] != item:
                raise ValueError("Conflicting Desktop settings")
            selected[name] = item
    shares = selected.get("filesharingdirectories")
    eci = selected.get("enhancedcontainerisolation")
    if not isinstance(shares, list) or not shares or not all(isinstance(item, str) and Path(item).is_absolute() for item in shares):
        raise ValueError("Unknown saved Desktop virtual shares")
    if eci is not None and type(eci) is not bool:
        raise ValueError("Invalid saved ECI setting")
    return {"shares": shares, "eci": eci}


def inspect(staging_root=None, *, desktop=True, host_os=None, home=None):
    host_os = host_os or sys.platform
    result = {"scope": "saved-macos-virtual-shares-only", "effective_vm_verified": False,
              "status": "unsupported-desktop-host", "host_os": host_os}
    if not desktop:
        return {**result, "status": "not-applicable-to-engine"}
    if host_os != "darwin":
        return result
    if home is None:
        import os
        import pwd
        home = Path(pwd.getpwuid(os.getuid()).pw_dir)
    folder = Path(home) / "Library/Group Containers/group.com.docker"
    try:
        paths = [path for path in (folder / "settings-store.json", folder / "settings.json") if path.exists()]
        if not paths:
            raise ValueError("Desktop settings were not found")
        values = [projection(path) for path in paths]
        if any(value != values[0] for value in values[1:]):
            raise ValueError("Saved Desktop sharing settings disagree")
        selected = values[0]
        result.update(settings_files=[str(path) for path in paths], **selected)
        root = Path(staging_root).resolve(strict=True) if staging_root else None
        only_staging = root is not None and selected["shares"] == [str(root)]
        result["status"] = "saved-share-policy-satisfied" if only_staging else "broad-or-unexpected-shares"
    except (OSError, ValueError, RecursionError, KeyError) as exc:
        result.update(status="unknown-saved-sharing", error=type(exc).__name__)
    return result


def check(config, *, desktop):
    result = inspect(config.get("staging_root"), desktop=desktop)
    if config.get("desktop_share_policy", "diagnostic") == "strict":
        if result["status"] not in {"saved-share-policy-satisfied", "not-applicable-to-engine"}:
            raise ValueError("Desktop sharing policy refused: " + result["status"] + ". Share only the dedicated staging root; see the Desktop hardening guide")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--staging-root")
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args()
    result = inspect(args.staging_root)
    print(json.dumps(result, indent=2))
    return int(args.strict and result["status"] != "saved-share-policy-satisfied")


if __name__ == "__main__":
    sys.exit(main())
