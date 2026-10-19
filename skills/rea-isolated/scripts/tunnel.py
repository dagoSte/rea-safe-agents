"""Bounded data framing shared by the host controller and contained worker."""

import base64
import hashlib
import json
import math
from pathlib import Path
import threading

MAX_BODY = 8 * 1024 * 1024
MAX_FRAME = 12 * 1024 * 1024
MAX_RESPONSE = 16 * 1024 * 1024
MAX_TRANSCRIPT = 16 * 1024 * 1024
# One relayed tool result, in UTF-8 bytes. Both clients keep results up to this
# size inline instead of persisting or silently cutting them.
MAX_TOOL_TEXT = 200_000
# Read-only queries of the open target through the native provider. None takes
# a filesystem path; annotation and snapshot tools stay outside the profile.
NATIVE_TOOLS = {"binary_overview", "list_segments", "inspect_native_load_image", "list_strings", "search_strings",
                "list_procedures", "search_procedures", "procedure_info", "procedure_pseudo_code", "procedure_assembly",
                "procedure_callees", "procedure_callers", "xrefs", "list_names", "read_bytes", "analyze_function"}
# Static APK queries through the pinned JADX bridge. Each names its APK with a
# path, which the broker confines to the frozen snapshot; the APK never runs.
ANDROID_TOOLS = {"inspect_android_package", "search_android_classes", "inspect_android_class", "inspect_android_method",
                 "trace_android_references"}
STATIC_TOOLS = {"open_binary", "close_binary", "binary_session", "inspect_artifact", "inspect_analysis_view",
                "analyze_javascript_application"} | NATIVE_TOOLS | ANDROID_TOOLS


class ProtocolError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise ProtocolError(message)


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "Duplicate JSON key")
        result[key] = value
    return result


def json_budget(raw, depth_limit, item_limit):
    """Bound parser allocation before creating untrusted Python containers."""
    position, depth, items = 0, 0, 0
    while position < len(raw):
        value = raw[position]
        if value == 34:
            position += 1
            while True:
                end = raw.find(b'"', position)
                require(end >= 0, "Unterminated JSON string")
                back = end - 1
                while back >= position and raw[back] == 92:
                    back -= 1
                if (end - 1 - back) % 2 == 0:
                    position = end + 1
                    break
                position = end + 1
            continue
        if value in (123, 91):
            depth += 1
            require(depth <= depth_limit, "JSON nesting exceeds limit")
        elif value in (125, 93):
            depth -= 1
        if value in (123, 91, 44, 58):
            items += 1
            require(items <= item_limit, "JSON item count exceeds limit")
        position += 1


def finite_float(raw):
    value = float(raw)
    require(math.isfinite(value), "Non-finite JSON number")
    return value


def decode_json(raw, *, depth_limit=64, item_limit=1000000):
    try:
        require(isinstance(raw, (bytes, str)), "JSON must be UTF-8 text")
        value = raw.decode("utf-8") if isinstance(raw, bytes) else raw
        # Decode once, strictly: json.loads(bytes) would autodetect UTF-16/32
        # while the allocation pre-parser sees a different byte structure.
        json_budget(value.encode("utf-8"), depth_limit, item_limit)
        return json.loads(value, object_pairs_hook=unique_pairs,
                          parse_float=finite_float,
                          parse_constant=lambda value: (_ for _ in ()).throw(ProtocolError("Non-finite JSON number")))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ProtocolError("Invalid JSON") from exc


def read_frame(stream):
    line = stream.readline(MAX_FRAME + 1)
    if not line:
        return None
    require(len(line) <= MAX_FRAME and line.endswith(b"\n"), "Oversized or incomplete tunnel frame")
    value = decode_json(line, depth_limit=8, item_limit=128)
    require(isinstance(value, dict) and isinstance(value.get("type"), str), "Invalid tunnel frame")
    return value


def pack(raw):
    require(isinstance(raw, bytes) and len(raw) <= MAX_BODY, "Payload exceeds byte limit")
    return base64.b64encode(raw).decode("ascii")


def unpack(value):
    require(isinstance(value, str) and len(value) <= (MAX_BODY + 2) // 3 * 4, "Invalid encoded payload")
    try:
        raw = base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise ProtocolError("Invalid base64 payload") from exc
    require(len(raw) <= MAX_BODY, "Payload exceeds byte limit")
    return raw


class Wire:
    def __init__(self, stream):
        self.stream = stream
        self.lock = threading.Lock()

    def send(self, value):
        raw = json.dumps(value, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode() + b"\n"
        require(len(raw) <= MAX_FRAME, "Outgoing frame exceeds byte limit")
        with self.lock:
            self.stream.write(raw)
            self.stream.flush()


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()
