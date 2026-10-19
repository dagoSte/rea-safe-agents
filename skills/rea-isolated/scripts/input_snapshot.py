"""Freeze explicitly approved regular file bytes before sending any to Docker."""

import hashlib
import io
import os
from pathlib import Path, PurePosixPath
import stat
import tarfile
import tempfile

from tunnel import require

MAX_FILES = 2048
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024
MAX_DEPTH = 24
MAX_DIRECTORIES = 2048


def regular_stat(path, *, directory=False):
    value = path.lstat()
    require(not stat.S_ISLNK(value.st_mode) and not (getattr(value, "st_file_attributes", 0) & 0x400),
            "Symlinks and Windows reparse points cannot enter an input snapshot")
    require(stat.S_ISDIR(value.st_mode) if directory else stat.S_ISREG(value.st_mode), "Only regular files and directories are supported")
    if not directory:
        require(value.st_nlink == 1, "Hard-linked input files require separate copies")
        require(value.st_size <= MAX_FILE_BYTES, "Input file exceeds byte limit")
    return value


def relative_name(raw):
    require(isinstance(raw, str) and 0 < len(raw.encode()) <= 2048, "Invalid snapshot path")
    path = PurePosixPath(raw)
    require(not path.is_absolute() and str(path) == raw and len(path.parts) <= MAX_DEPTH, "Non-canonical snapshot path")
    require(all(part not in (".", "..") and not any(c in part for c in '\\:\x00\r\n') for part in path.parts), "Unsafe snapshot path")
    return path


def file_bytes(root, raw):
    name = relative_name(raw)
    current = root
    for part in name.parts[:-1]:
        current = current / part
        regular_stat(current, directory=True)
    path = current / name.name
    before = regular_stat(path)
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(descriptor, "rb") as handle:
        opened = os.fstat(handle.fileno())
        require(stat.S_ISREG(opened.st_mode) and opened.st_nlink == 1 and (opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino),
                "Input file changed identity while opening")
        data = handle.read(MAX_FILE_BYTES + 1)
        after = os.fstat(handle.fileno())
    # Compare two reads of the open handle. A path stat can return stale
    # directory-entry times and sizes on Windows; the identity check above
    # already ties the handle to the inspected path.
    require(len(data) <= MAX_FILE_BYTES and len(data) == opened.st_size == after.st_size
            and (opened.st_mtime_ns, opened.st_ctime_ns) == (after.st_mtime_ns, after.st_ctime_ns), "Input changed while reading")
    return data


def manifest(root):
    root = Path(root)
    regular_stat(root, directory=True)
    files = []
    total, count = 0, 0
    def errors(error):
        raise error
    for directory, children, names in os.walk(root, followlinks=False, onerror=errors):
        count += 1
        require(count <= MAX_DIRECTORIES, "Input directory count exceeds limit")
        parent = Path(directory)
        require(len(parent.relative_to(root).parts) <= MAX_DEPTH, "Input nesting exceeds limit")
        for child in children:
            regular_stat(parent / child, directory=True)
        for name in sorted(names):
            raw = (parent / name).relative_to(root).as_posix()
            data = file_bytes(root, raw)
            total += len(data)
            require(len(files) < MAX_FILES and total <= MAX_TOTAL_BYTES, "Input snapshot exceeds limits")
            files.append({"path": raw, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    return sorted(files, key=lambda item: item["path"])


def archive(root, approved):
    """Never expose partial/unverified bytes: finish this private archive first."""
    root = Path(root)
    regular_stat(root, directory=True)
    require(isinstance(approved, list) and len(approved) <= MAX_FILES, "Invalid input manifest")
    frozen = tempfile.TemporaryFile(mode="w+b")
    try:
        seen, directories, total = set(), set(), 0
        with tarfile.open(fileobj=frozen, mode="w", format=tarfile.PAX_FORMAT) as target:
            for item in approved:
                require(isinstance(item, dict) and set(item) == {"path", "size", "sha256"}, "Invalid manifest entry")
                name = relative_name(item["path"])
                require(str(name) not in seen, "Duplicate manifest path")
                seen.add(str(name))
                data = file_bytes(root, str(name))
                total += len(data)
                require(type(item["size"]) is int and len(data) == item["size"] and hashlib.sha256(data).hexdigest() == item["sha256"],
                        "Input differs from the approved manifest; configure and review again")
                require(total <= MAX_TOTAL_BYTES, "Input snapshot exceeds byte limit")
                for parent in reversed(name.parents):
                    raw = str(parent)
                    if raw == "." or raw in directories:
                        continue
                    directories.add(raw)
                    entry = tarfile.TarInfo(raw)
                    entry.type, entry.mode, entry.uid, entry.gid = tarfile.DIRTYPE, 0o555, 0, 0
                    target.addfile(entry)
                entry = tarfile.TarInfo(str(name))
                entry.size, entry.mode, entry.uid, entry.gid = len(data), 0o444, 0, 0
                target.addfile(entry, io.BytesIO(data))
        frozen.seek(0)
        return frozen
    except BaseException:
        frozen.close()
        raise


def stage(root, approved):
    """Private temporary copies only; the original directory is never mounted."""
    frozen = archive(root, approved)
    temporary = tempfile.TemporaryDirectory(prefix="rea-frozen-input-")
    destination = Path(temporary.name) / "input"
    destination.mkdir(mode=0o755)
    try:
        with frozen, tarfile.open(fileobj=frozen, mode="r") as source:
            for entry in source:
                name = relative_name(entry.name)
                target = destination.joinpath(*name.parts)
                if entry.isdir():
                    target.mkdir(mode=0o755, parents=True, exist_ok=True)
                else:
                    require(entry.isfile(), "Unexpected staged archive member")
                    target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                    with source.extractfile(entry) as incoming, target.open("xb") as output:
                        while chunk := incoming.read(1024 * 1024):
                            output.write(chunk)
                    target.chmod(0o444)
        for directory, _, _ in os.walk(destination, topdown=False):
            Path(directory).chmod(0o555)
        return temporary, destination
    except BaseException:
        temporary.cleanup()
        raise
