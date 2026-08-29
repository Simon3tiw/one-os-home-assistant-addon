"""Draft-4 strict JSON byte codec and exact-schema validator (stdlib only)."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import json.decoder
import re
from typing import Any

BUNDLE_ID = 'phase2c-p-telemetry-authority-v2-draft4-20260825'
ROLE_ID = 'strict_wire_codec'
GENERATION = 4
CANDIDATE_STATUS = 'UNFROZEN_STAGING'
ROLE_API_VERSION = 1

JsonValue = None | bool | int | str | list["JsonValue"] | dict[str, "JsonValue"]
_TS_RE = re.compile(r"^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]\.[0-9]{3}Z$")
_INT_RE = re.compile(r"-?(?:0|[1-9][0-9]*)")


@dataclass(eq=False)
class Reject(Exception):
    code: str
    json_pointer: str = ""
    detail: str = ""

    def __post_init__(self) -> None:
        super().__init__(self.code, self.json_pointer, self.detail)

    @property
    def pointer(self) -> str:
        return self.json_pointer

    def diagnostic(self) -> bytes:
        return canonical_json_bytes({"code": self.code, "pointer": self.json_pointer, "status": "REJECT"}) + b"\n"


def _ptr(parent: str, token: str | int) -> str:
    escaped = str(token).replace("~", "~0").replace("/", "~1")
    return parent + "/" + escaped


def _reject(code: str, pointer: str, detail: str = "") -> None:
    raise Reject(code, pointer, detail)


class _Parser:
    def __init__(self, text: str, max_depth: int):
        self.text = text
        self.n = len(text)
        self.i = 0
        self.max_depth = max_depth

    def ws(self) -> None:
        while self.i < self.n and self.text[self.i] in " \t\r\n":
            self.i += 1

    def parse(self) -> JsonValue:
        self.ws()
        value = self.value("", 1)
        self.ws()
        if self.i != self.n:
            _reject("D4W004_TRAILING_DATA", "", "bytes after first JSON value")
        return value

    def value(self, pointer: str, depth: int) -> JsonValue:
        if depth > self.max_depth:
            _reject("D4W012_DEPTH_LIMIT", pointer, "maximum nesting exceeded")
        if self.i >= self.n:
            _reject("D4W004_TRAILING_DATA", pointer, "incomplete JSON value")
        c = self.text[self.i]
        if c == "{": return self.object(pointer, depth)
        if c == "[": return self.array(pointer, depth)
        if c == '"': return self.string(pointer)
        if self.text.startswith("true", self.i): self.i += 4; return True
        if self.text.startswith("false", self.i): self.i += 5; return False
        if self.text.startswith("null", self.i): self.i += 4; return None
        if self.text.startswith(("NaN", "Infinity", "-Infinity"), self.i):
            _reject("D4W007_NONFINITE_NUMBER", pointer)
        if c in "+-0123456789": return self.number(pointer)
        _reject("D4W004_TRAILING_DATA", pointer, "invalid JSON token")

    def string(self, pointer: str) -> str:
        try:
            value, end = json.decoder.scanstring(self.text, self.i + 1, True)
        except (json.decoder.JSONDecodeError, UnicodeDecodeError) as exc:
            _reject("D4W004_TRAILING_DATA", pointer, str(exc))
        self.i = end
        for ch in value:
            if 0xD800 <= ord(ch) <= 0xDFFF:
                _reject("D4W009_SURROGATE", pointer)
        return value

    def number(self, pointer: str) -> int:
        start = self.i
        while self.i < self.n and self.text[self.i] not in " \t\r\n,]}:":
            self.i += 1
        token = self.text[start:self.i]
        if any(ch in token for ch in ".eE"):
            _reject("D4W006_FLOAT_FORBIDDEN", pointer, token)
        if not _INT_RE.fullmatch(token) or token == "-0":
            _reject("D4W008_INTEGER_LEXEME", pointer, token)
        return int(token)

    def object(self, pointer: str, depth: int) -> dict[str, JsonValue]:
        out: dict[str, JsonValue] = {}
        self.i += 1; self.ws()
        if self.i < self.n and self.text[self.i] == "}": self.i += 1; return out
        while True:
            if self.i >= self.n or self.text[self.i] != '"':
                _reject("D4W004_TRAILING_DATA", pointer, "object key must be string")
            key = self.string(pointer)
            key_pointer = _ptr(pointer, key)
            if key in out:
                _reject("D4W005_DUPLICATE_KEY", pointer, key)
            self.ws()
            if self.i >= self.n or self.text[self.i] != ":":
                _reject("D4W004_TRAILING_DATA", key_pointer, "missing colon")
            self.i += 1; self.ws()
            out[key] = self.value(key_pointer, depth + 1)
            self.ws()
            if self.i < self.n and self.text[self.i] == "}": self.i += 1; return out
            if self.i >= self.n or self.text[self.i] != ",":
                _reject("D4W004_TRAILING_DATA", pointer, "missing comma")
            self.i += 1; self.ws()

    def array(self, pointer: str, depth: int) -> list[JsonValue]:
        out: list[JsonValue] = []
        self.i += 1; self.ws()
        if self.i < self.n and self.text[self.i] == "]": self.i += 1; return out
        while True:
            out.append(self.value(_ptr(pointer, len(out)), depth + 1))
            self.ws()
            if self.i < self.n and self.text[self.i] == "]": self.i += 1; return out
            if self.i >= self.n or self.text[self.i] != ",":
                _reject("D4W004_TRAILING_DATA", pointer, "missing comma")
            self.i += 1; self.ws()


def strict_decode(raw: bytes, *, max_bytes: int, expected_root: type, max_depth: int = 64) -> JsonValue:
    if type(raw) is not bytes or type(max_bytes) is not int or max_bytes < 0:
        raise TypeError("raw must be bytes and max_bytes a non-negative exact int")
    if len(raw) > max_bytes:
        _reject("D4W001_SIZE_LIMIT", "")
    if raw.startswith(b"\xef\xbb\xbf"):
        _reject("D4W002_UTF8_BOM", "")
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        _reject("D4W003_INVALID_UTF8", "", str(exc))
    value = _Parser(text, max_depth).parse()
    if type(value) is not expected_root:
        _reject("D4W010_ROOT_TYPE", "")
    return value


def _encode_string(value: str) -> bytes:
    parts = ['"']
    escapes = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}
    for char in value:
        cp = ord(char)
        if 0xD800 <= cp <= 0xDFFF:
            _reject("D4W009_SURROGATE", "")
        if char in escapes: parts.append(escapes[char])
        elif cp < 0x20: parts.append(f"\\u{cp:04x}")
        else: parts.append(char)
    parts.append('"')
    return "".join(parts).encode("utf-8")


def canonical_json_bytes(value: JsonValue) -> bytes:
    if value is None: return b"null"
    if type(value) is bool: return b"true" if value else b"false"
    if type(value) is int: return str(value).encode("ascii")
    if type(value) is str: return _encode_string(value)
    if type(value) is list: return b"[" + b",".join(canonical_json_bytes(v) for v in value) + b"]"
    if type(value) is dict:
        if any(type(k) is not str for k in value): raise TypeError("JSON object keys must be exact strings")
        return b"{" + b",".join(_encode_string(k) + b":" + canonical_json_bytes(value[k]) for k in sorted(value)) + b"}"
    raise TypeError(f"unsupported JSON type: {type(value).__name__}")


def strict_decode_canonical(raw: bytes, *, max_bytes: int, expected_root: type, max_depth: int = 64) -> JsonValue:
    value = strict_decode(raw, max_bytes=max_bytes, expected_root=expected_root, max_depth=max_depth)
    if raw != canonical_json_bytes(value):
        _reject("D4W011_NONCANONICAL_BYTES", "")
    return value


def validate_calendar_timestamp(value: str, pointer: str, *, milliseconds: bool = True) -> None:
    pattern = _TS_RE if milliseconds else re.compile(r"^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$")
    if type(value) is not str or pattern.fullmatch(value) is None:
        _reject("D4J005_TIMESTAMP_LEXICAL", pointer)
    try:
        microseconds = int(value[20:23]) * 1000 if milliseconds else 0
        datetime(int(value[0:4]), int(value[5:7]), int(value[8:10]), int(value[11:13]), int(value[14:16]), int(value[17:19]), microseconds)
    except ValueError as exc:
        _reject("D4J006_TIMESTAMP_CALENDAR", pointer, str(exc))


def _resolve_ref(ref: str, schema: dict[str, Any], registry: dict[str, dict[str, Any]]) -> dict[str, Any]:
    if ref.startswith("#/"):
        node: Any = schema
        for part in ref[2:].split("/"):
            node = node[part.replace("~1", "/").replace("~0", "~")]
        return node
    try: return registry[ref]
    except KeyError: _reject("D4J003_SCHEMA_CONSTRAINT", "", f"unknown $ref {ref}")


def validate_exact_schema(value: JsonValue, schema: dict[str, Any], *, schema_registry: dict[str, dict[str, Any]], pointer: str = "") -> set[str]:
    visited: set[str] = set()
    root_schema = schema
    def walk(x: JsonValue, s: dict[str, Any], p: str) -> None:
        if "$ref" in s: walk(x, _resolve_ref(s["$ref"], root_schema, schema_registry), p); return
        if "oneOf" in s:
            successes = 0
            for branch in s["oneOf"]:
                try: walk(x, branch, p); successes += 1
                except Reject: pass
            if successes == 0: _reject("D4J003_SCHEMA_CONSTRAINT", p)
            if successes > 1: _reject("D4J004_UNION_AMBIGUOUS", p)
            return
        expected = s.get("type")
        types = {"object": dict, "array": list, "string": str, "integer": int, "boolean": bool, "null": type(None)}
        if expected is not None and (expected not in types or type(x) is not types[expected]): _reject("D4J001_EXACT_TYPE", p)
        if "const" in s and (type(x) is not type(s["const"]) or x != s["const"]): _reject("D4J003_SCHEMA_CONSTRAINT", p)
        if "enum" in s and not any(type(x) is type(v) and x == v for v in s["enum"]): _reject("D4J003_SCHEMA_CONSTRAINT", p)
        if type(x) is dict:
            required = s.get("required", [])
            if any(k not in x for k in required): _reject("D4J002_KEYSET", p)
            props = s.get("properties", {})
            if s.get("additionalProperties") is False and set(x) - set(props): _reject("D4J002_KEYSET", p)
            for key, child in x.items():
                if key in props: walk(child, props[key], _ptr(p, key))
        elif type(x) is list:
            if len(x) < s.get("minItems", 0) or ("maxItems" in s and len(x) > s["maxItems"]): _reject("D4J003_SCHEMA_CONSTRAINT", p)
            if "items" in s:
                for index, child in enumerate(x): walk(child, s["items"], _ptr(p, index))
        elif type(x) is int:
            if x < s.get("minimum", x) or x > s.get("maximum", x): _reject("D4J003_SCHEMA_CONSTRAINT", p)
        elif type(x) is str:
            if "minLength" in s and len(x) < s["minLength"]: _reject("D4J003_SCHEMA_CONSTRAINT", p)
            if "maxLength" in s and len(x) > s["maxLength"]: _reject("D4J003_SCHEMA_CONSTRAINT", p)
            if "pattern" in s and re.fullmatch(s["pattern"], x) is None: _reject("D4J003_SCHEMA_CONSTRAINT", p)
            if s.get("format") == "one-os-rfc3339-ms-utc": validate_calendar_timestamp(x, p, milliseconds=True); visited.add(p)
            if s.get("format") == "one-os-rfc3339-s-utc": validate_calendar_timestamp(x, p, milliseconds=False); visited.add(p)
    walk(value, schema, pointer)
    return visited
