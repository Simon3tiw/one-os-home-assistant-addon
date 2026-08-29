from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import unicodedata
from dataclasses import dataclass
from datetime import datetime
from typing import Any, NoReturn
from uuid import UUID

MAX_BATCH_BYTES = 1_048_576
MAX_RECORDS = 500
MAX_STREAMS = 256
MAX_RECORD_BYTES = 1_024
MAX_JSON_DEPTH = 8
MAX_SIGNED_INT64 = 9_223_372_036_854_775_807

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$", re.ASCII)
_DIGEST = re.compile(r"^[A-Za-z0-9_-]{43}$", re.ASCII)
_DECIMAL = re.compile(
    r"^(?:0|-?[1-9][0-9]{0,17}|-?0\.[0-9]{0,8}[1-9]"
    r"|-?[1-9](?=[0-9.]{1,18}$)[0-9]{0,17}\.[0-9]{0,8}[1-9])$",
    re.ASCII,
)
_TIMESTAMP = re.compile(
    r"^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])"
    r"T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](?:\.[0-9]{1,3})?Z$",
    re.ASCII,
)
_RECORD_DOMAIN = b"ONE.OS-TELEMETRY-RECORD-V1\0"
_PAYLOAD_DOMAIN = b"ONE.OS-TELEMETRY-BATCH-PAYLOAD-V1\0"


class TelemetryValidationError(ValueError):
    def __init__(self, message: str, *, code: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class ParsedTelemetryBatch:
    document: dict[str, Any]
    canonical_bytes: bytes
    request_sha256: str
    payload_sha256: str


def _fail(code: str, message: str) -> NoReturn:
    raise TelemetryValidationError(message, code=code)


def _b64digest(value: bytes) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(value).digest()).rstrip(b"=").decode("ascii")


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail("duplicate_json_member", f"Duplicate JSON member: {key}")
        result[key] = value
    return result


def _parse_json_int(lexeme: str) -> int:
    if (
        len(lexeme) > 19
        or lexeme == "-0"
        or (lexeme != "0" and (not lexeme[0].isdigit() or lexeme[0] == "0"))
    ):
        _fail("invalid_json_number", "JSON integer is not canonical or is out of range")
    return int(lexeme)


def _reject_json_float(lexeme: str) -> NoReturn:
    _fail("invalid_json_number", f"JSON decimal/exponent number is forbidden: {lexeme[:32]}")


def _parse_raw(raw: bytes, *, maximum: int) -> dict[str, Any]:
    if not raw or len(raw) > maximum:
        _fail("payload_too_large", "Telemetry payload size is invalid")
    if raw.startswith(b"\xef\xbb\xbf"):
        _fail("invalid_utf8_or_scalar", "UTF-8 BOM is forbidden")
    _scan_json_depth(raw)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise TelemetryValidationError(
            "Telemetry payload is not valid UTF-8", code="invalid_utf8_or_scalar"
        ) from error
    try:
        document = json.loads(
            text,
            object_pairs_hook=_reject_duplicates,
            parse_int=_parse_json_int,
            parse_float=_reject_json_float,
            parse_constant=lambda value: _fail(
                "invalid_json_constant", f"Invalid JSON constant: {value}"
            ),
        )
    except TelemetryValidationError:
        raise
    except RecursionError as error:
        raise TelemetryValidationError(
            "Telemetry JSON exceeds maximum depth", code="json_too_deep"
        ) from error
    except json.JSONDecodeError as error:
        raise TelemetryValidationError("Invalid telemetry JSON", code="invalid_json") from error
    except ValueError as error:
        raise TelemetryValidationError(
            "Telemetry JSON contains an invalid number", code="invalid_json_number"
        ) from error
    if not isinstance(document, dict):
        _fail("invalid_shape", "Telemetry payload must be an object")
    _validate_strings_and_depth(document)
    if not hmac.compare_digest(canonical_json(document), raw):
        _fail("noncanonical_payload", "Telemetry payload is not canonical JSON")
    return document


def _scan_json_depth(raw: bytes) -> None:
    depth = 0
    in_string = False
    escaped = False
    for byte in raw:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:
                escaped = True
            elif byte == 0x22:
                in_string = False
            continue
        if byte == 0x22:
            in_string = True
        elif byte in (0x5B, 0x7B):
            depth += 1
            if depth > MAX_JSON_DEPTH:
                _fail("json_too_deep", "Telemetry JSON exceeds maximum depth")
        elif byte in (0x5D, 0x7D):
            depth -= 1


def _validate_strings_and_depth(value: Any, depth: int = 1) -> None:
    if depth > MAX_JSON_DEPTH:
        _fail("json_too_deep", "Telemetry JSON exceeds maximum depth")
    if isinstance(value, dict):
        for key, child in value.items():
            _validate_string(key)
            _validate_strings_and_depth(child, depth + 1)
    elif isinstance(value, list):
        for child in value:
            _validate_strings_and_depth(child, depth + 1)
    elif isinstance(value, str):
        _validate_string(value)


def _validate_string(value: str) -> None:
    if unicodedata.normalize("NFC", value) != value or any(
        ord(character) < 32 or ord(character) == 127 or 0xD800 <= ord(character) <= 0xDFFF
        for character in value
    ):
        _fail("invalid_utf8_or_scalar", "Non-NFC, control or surrogate string is forbidden")


def _closed(document: dict[str, Any], expected: set[str], required: set[str] | None = None) -> None:
    unknown = set(document) - expected
    if unknown:
        _fail("unknown_member", f"Unknown telemetry member: {sorted(unknown)[0]}")
    missing = (required or expected) - set(document)
    if missing:
        _fail("invalid_shape", f"Missing telemetry member: {sorted(missing)[0]}")


def _strict_int(value: Any, *, code: str = "invalid_type") -> int:
    if type(value) is not int or not 0 <= value <= MAX_SIGNED_INT64:
        _fail(code, "Expected nonnegative signed-int64 integer")
    return value


def _uuid4(value: Any) -> str:
    if not isinstance(value, str):
        _fail("invalid_type", "UUID must be a string")
    try:
        parsed = UUID(value)
    except ValueError as error:
        raise TelemetryValidationError("Invalid UUID", code="invalid_uuid") from error
    if parsed.version != 4 or str(parsed) != value:
        _fail("invalid_uuid", "UUID must be canonical lowercase UUIDv4")
    return value


def _digest(value: Any) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        _fail("invalid_digest", "Digest must be unpadded base64url SHA-256")
    try:
        decoded = base64.b64decode(value + "=", altchars=b"-_", validate=True)
    except ValueError as error:
        raise TelemetryValidationError("Invalid digest", code="invalid_digest") from error
    if len(decoded) != 32 or base64.urlsafe_b64encode(decoded).rstrip(b"=").decode() != value:
        _fail("invalid_digest", "Digest is not canonical")
    return value


def _timestamp(value: Any) -> datetime:
    if not isinstance(value, str) or _TIMESTAMP.fullmatch(value) is None:
        _fail("invalid_timestamp", "Timestamp must be strict UTC with at most milliseconds")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise TelemetryValidationError(
            "Timestamp is not a real instant", code="invalid_timestamp"
        ) from error


def _point(value: Any) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        _fail("invalid_point_id", "Point ID is invalid")
    return value


def _base_record(record: dict[str, Any]) -> tuple[datetime, datetime]:
    if record["schemaVersion"] != "1.0":
        _fail("invalid_schema_version", "Record schemaVersion must be 1.0")
    _uuid4(record["installationId"])
    _strict_int(record["configVersion"])
    _uuid4(record["snapshotId"])
    _digest(record["projectionSha256"])
    _point(record["pointId"])
    _uuid4(record["streamEpochId"])
    _strict_int(record["sequence"])
    observed = _timestamp(record["observedAt"])
    received = _timestamp(record["receivedAtEdge"])
    if received < observed:
        _fail("time_order", "receivedAtEdge precedes observedAt")
    return observed, received


_BASE_RECORD = {
    "schemaVersion",
    "sampleId",
    "installationId",
    "configVersion",
    "snapshotId",
    "projectionSha256",
    "pointId",
    "streamEpochId",
    "sequence",
    "observedAt",
    "receivedAtEdge",
    "valueQuality",
}


def _validate_sample(record: Any) -> datetime:
    if not isinstance(record, dict):
        _fail("invalid_shape", "Sample must be an object")
    allowed = _BASE_RECORD | {"booleanValue", "decimalValue"}
    _closed(record, allowed, _BASE_RECORD)
    has_boolean = "booleanValue" in record
    has_decimal = "decimalValue" in record
    if has_boolean == has_decimal:
        _fail("typed_value_ambiguity", "Sample must contain exactly one typed value")
    if not isinstance(record["valueQuality"], str) or record["valueQuality"] not in {
        "good",
        "stale",
    }:
        _fail("invalid_quality", "Sample quality is invalid")
    if has_boolean and type(record["booleanValue"]) is not bool:
        _fail("invalid_type", "booleanValue must be an exact JSON boolean")
    if has_decimal:
        decimal = record["decimalValue"]
        if not isinstance(decimal, str) or _DECIMAL.fullmatch(decimal) is None:
            _fail("noncanonical_decimal", "decimalValue is not canonical")
    _base_record(record)
    _digest(record["sampleId"])
    without_id = {key: value for key, value in record.items() if key != "sampleId"}
    expected = _b64digest(_RECORD_DOMAIN + canonical_json(without_id))
    if not hmac.compare_digest(expected, record["sampleId"]):
        _fail("sample_id_mismatch", "Deterministic sample ID mismatch")
    if len(canonical_json(record)) > MAX_RECORD_BYTES:
        _fail("record_too_large", "Sample exceeds canonical record limit")
    return _timestamp(record["receivedAtEdge"])


def _validate_quality_event(record: Any) -> datetime:
    if not isinstance(record, dict):
        _fail("invalid_shape", "Quality event must be an object")
    _closed(record, _BASE_RECORD)
    if not isinstance(record["valueQuality"], str) or record["valueQuality"] not in {
        "invalid",
        "unknown",
        "unavailable",
    }:
        _fail("invalid_quality", "Quality event valueQuality is invalid")
    _base_record(record)
    _digest(record["sampleId"])
    without_id = {key: value for key, value in record.items() if key != "sampleId"}
    expected = _b64digest(_RECORD_DOMAIN + canonical_json(without_id))
    if not hmac.compare_digest(expected, record["sampleId"]):
        _fail("sample_id_mismatch", "Deterministic quality event ID mismatch")
    if len(canonical_json(record)) > MAX_RECORD_BYTES:
        _fail("record_too_large", "Quality event exceeds canonical record limit")
    return _timestamp(record["receivedAtEdge"])


_GAP_FIELDS = {
    "schemaVersion",
    "installationId",
    "configVersion",
    "snapshotId",
    "projectionSha256",
    "pointId",
    "streamEpochId",
    "firstMissingSequence",
    "lastMissingSequence",
    "detectedAt",
    "reason",
}
_GAP_REASONS = {
    "outbox_capacity",
    "retention_expired",
    "storage_failure",
    "clock_discontinuity",
    "operator_reset",
}


def _validate_gap(gap: Any) -> datetime:
    if not isinstance(gap, dict):
        _fail("invalid_shape", "Gap must be an object")
    _closed(gap, _GAP_FIELDS)
    if gap["schemaVersion"] != "1.0":
        _fail("invalid_schema_version", "Gap schemaVersion must be 1.0")
    _uuid4(gap["installationId"])
    _strict_int(gap["configVersion"])
    _uuid4(gap["snapshotId"])
    _digest(gap["projectionSha256"])
    _point(gap["pointId"])
    _uuid4(gap["streamEpochId"])
    first = _strict_int(gap["firstMissingSequence"])
    last = _strict_int(gap["lastMissingSequence"])
    if last < first:
        _fail("gap_range", "Gap range is reversed")
    if not isinstance(gap["reason"], str) or gap["reason"] not in _GAP_REASONS:
        _fail("invalid_gap_reason", "Gap reason is invalid")
    detected = _timestamp(gap["detectedAt"])
    if len(canonical_json(gap)) > MAX_RECORD_BYTES:
        _fail("record_too_large", "Gap exceeds canonical record limit")
    return detected


def _record_key(record: dict[str, Any]) -> tuple[str, str, int]:
    return record["pointId"], record["streamEpochId"], record["sequence"]


def _gap_key(gap: dict[str, Any]) -> tuple[str, str, int]:
    return gap["pointId"], gap["streamEpochId"], gap["firstMissingSequence"]


def _require_order(records: list[dict[str, Any]], *, gap: bool = False) -> None:
    keys = [_gap_key(value) if gap else _record_key(value) for value in records]
    if keys != sorted(keys) or len(keys) != len(set(keys)):
        _fail("noncanonical_order", "Telemetry records are not strictly sorted and unique")


def _prevalidate_order_fields(records: list[Any], *, kind: str) -> None:
    for record in records:
        if not isinstance(record, dict):
            _fail("invalid_shape", f"{kind} record must be an object")
        if kind == "sample":
            _closed(record, _BASE_RECORD | {"booleanValue", "decimalValue"}, _BASE_RECORD)
            sequence_key = "sequence"
        elif kind == "quality":
            _closed(record, _BASE_RECORD)
            sequence_key = "sequence"
        else:
            _closed(record, _GAP_FIELDS)
            sequence_key = "firstMissingSequence"
        _point(record["pointId"])
        _uuid4(record["streamEpochId"])
        _strict_int(record[sequence_key])


def parse_telemetry_batch(raw: bytes) -> ParsedTelemetryBatch:
    document = _parse_raw(raw, maximum=MAX_BATCH_BYTES)
    batch_fields = {
        "schemaVersion",
        "batchId",
        "installationId",
        "installationRevision",
        "credentialId",
        "createdAt",
        "payloadSha256",
        "samples",
        "qualityEvents",
        "gaps",
    }
    _closed(document, batch_fields)
    if document["schemaVersion"] != "1.0":
        _fail("invalid_schema_version", "Batch schemaVersion must be 1.0")
    _uuid4(document["batchId"])
    installation_id = _uuid4(document["installationId"])
    _strict_int(document["installationRevision"])
    _uuid4(document["credentialId"])
    created_at = _timestamp(document["createdAt"])
    _digest(document["payloadSha256"])
    arrays = (document["samples"], document["qualityEvents"], document["gaps"])
    if not all(isinstance(value, list) for value in arrays):
        _fail("invalid_shape", "Telemetry record collections must be arrays")
    samples, quality_events, gaps = arrays
    count = len(samples) + len(quality_events) + len(gaps)
    if not 1 <= count <= MAX_RECORDS:
        _fail("invalid_record_count", "Batch record count is invalid")
    _prevalidate_order_fields(samples, kind="sample")
    _prevalidate_order_fields(quality_events, kind="quality")
    _prevalidate_order_fields(gaps, kind="gap")
    _require_order(samples)
    _require_order(quality_events)
    _require_order(gaps, gap=True)

    all_records = [*samples, *quality_events, *gaps]
    if any(
        not isinstance(record, dict) or record.get("installationId") != installation_id
        for record in all_records
    ):
        _fail("installation_binding_mismatch", "Record installation differs from batch")

    latest_times: list[datetime] = []
    for record in samples:
        latest_times.append(_validate_sample(record))
    for record in quality_events:
        latest_times.append(_validate_quality_event(record))
    for gap in gaps:
        latest_times.append(_validate_gap(gap))

    if latest_times and created_at < max(latest_times):
        _fail("time_order", "Batch createdAt precedes contained record time")

    positions: dict[tuple[str, str, int], str] = {}
    for record in [*samples, *quality_events]:
        key = _record_key(record)
        prior = positions.setdefault(key, record["sampleId"])
        if (
            prior != record["sampleId"]
            or sum(_record_key(item) == key for item in [*samples, *quality_events]) > 1
        ):
            _fail("sequence_conflict", "Telemetry stream position is duplicated")

    by_stream: dict[tuple[str, str], list[tuple[int, int]]] = {}
    for gap in gaps:
        stream = (gap["pointId"], gap["streamEpochId"])
        ranges = by_stream.setdefault(stream, [])
        current = (gap["firstMissingSequence"], gap["lastMissingSequence"])
        if ranges and current[0] <= ranges[-1][1]:
            _fail("gap_overlap", "Telemetry gaps overlap")
        ranges.append(current)
    for record in [*samples, *quality_events]:
        stream = (record["pointId"], record["streamEpochId"])
        if any(first <= record["sequence"] <= last for first, last in by_stream.get(stream, [])):
            _fail("gap_overlap", "Gap overlaps a delivered record")

    streams = {(record["pointId"], record["streamEpochId"]) for record in all_records}
    if len(streams) > MAX_STREAMS:
        _fail("too_many_streams", "Batch exceeds stream cardinality")

    payload = {
        key: document[key] for key in ("gaps", "installationRevision", "qualityEvents", "samples")
    }
    payload_sha256 = _b64digest(_PAYLOAD_DOMAIN + canonical_json(payload))
    if not hmac.compare_digest(payload_sha256, document["payloadSha256"]):
        _fail("payload_digest_mismatch", "Batch payload digest mismatch")
    return ParsedTelemetryBatch(
        document=document,
        canonical_bytes=raw,
        request_sha256=_b64digest(raw),
        payload_sha256=payload_sha256,
    )


_ACK_FIELDS = {
    "schemaVersion",
    "installationId",
    "installationRevision",
    "credentialId",
    "batchId",
    "requestSha256",
    "acceptedSamples",
    "duplicateSamples",
    "acceptedQualityEvents",
    "duplicateQualityEvents",
    "acceptedGaps",
    "duplicateGaps",
    "ingestCursor",
    "acceptedAt",
}


def parse_telemetry_ack(
    raw: bytes,
    *,
    expected_batch: dict[str, Any],
    expected_request_sha256: str,
    previous_ingest_cursor: int,
) -> dict[str, Any]:
    document = _parse_raw(raw, maximum=16_384)
    _closed(document, _ACK_FIELDS)
    if document["schemaVersion"] != "1.0":
        _fail("invalid_schema_version", "ACK schemaVersion must be 1.0")
    for key in ("installationId", "credentialId", "batchId"):
        _uuid4(document[key])
    _digest(document["requestSha256"])
    for key in (
        "acceptedSamples",
        "duplicateSamples",
        "acceptedQualityEvents",
        "duplicateQualityEvents",
        "acceptedGaps",
        "duplicateGaps",
        "ingestCursor",
        "installationRevision",
    ):
        _strict_int(document[key])
    _timestamp(document["acceptedAt"])
    if any(
        document[key] != expected_batch[key]
        for key in ("installationId", "installationRevision", "credentialId", "batchId")
    ) or not hmac.compare_digest(document["requestSha256"], expected_request_sha256):
        _fail("ack_binding_mismatch", "ACK does not bind the exact request")
    count_pairs = (
        ("acceptedSamples", "duplicateSamples", len(expected_batch["samples"])),
        (
            "acceptedQualityEvents",
            "duplicateQualityEvents",
            len(expected_batch["qualityEvents"]),
        ),
        ("acceptedGaps", "duplicateGaps", len(expected_batch["gaps"])),
    )
    if any(
        document[accepted] + document[duplicate] != count
        for accepted, duplicate, count in count_pairs
    ):
        _fail("ack_count_mismatch", "ACK record counts do not match the request")
    if document["ingestCursor"] <= previous_ingest_cursor:
        _fail("ack_cursor_regression", "ACK ingest cursor is not strictly monotone")
    return document
