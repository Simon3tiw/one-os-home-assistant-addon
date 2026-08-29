from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import struct
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

_DIGEST = re.compile(r"^[A-Za-z0-9_-]{43}$", re.ASCII)
_DECIMAL = re.compile(r"^-?(?:0|[1-9][0-9]{0,17})(?:\.[0-9]{1,9})?$", re.ASCII)
_TIMESTAMP = re.compile(
    r"^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])"
    r"T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]\.[0-9]{3}Z$",
    re.ASCII,
)
_TIMESTAMP_SECONDS = re.compile(
    r"^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])"
    r"T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$",
    re.ASCII,
)
_RECORD_DOMAIN = b"ONE.OS-TELEMETRY-RECORD-V1\0"
_PAYLOAD_DOMAIN = b"ONE.OS-TELEMETRY-BATCH-PAYLOAD-V2\0"


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


def _canonical_object(
    value: bytes | dict[str, Any], *, maximum: int, code: str
) -> tuple[dict[str, Any], bytes]:
    try:
        if isinstance(value, bytes):
            document = _parse_raw(value, maximum=maximum)
            return document, value
        if type(value) is not dict:
            _fail(code, "Expected canonical JSON object bytes or object")
        raw = canonical_json(value)
        document = _parse_raw(raw, maximum=maximum)
        return document, raw
    except (TelemetryValidationError, TypeError, ValueError) as error:
        if isinstance(error, TelemetryValidationError) and error.code == code:
            raise
        raise TelemetryValidationError(str(error), code=code) from error


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
        _fail("invalid_timestamp", "Timestamp must be strict millisecond UTC")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise TelemetryValidationError(
            "Timestamp is not a real instant", code="invalid_timestamp"
        ) from error


def _timestamp_seconds(value: Any) -> datetime:
    if not isinstance(value, str) or _TIMESTAMP_SECONDS.fullmatch(value) is None:
        _fail("invalid_timestamp", "Timestamp must be strict whole-second UTC")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise TelemetryValidationError(
            "Timestamp is not a real instant", code="invalid_timestamp"
        ) from error


def _point(value: Any) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 80:
        _fail("invalid_point_id", "Point ID is invalid")
    _validate_string(value)
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
_GAP_REASONS = {"storage_failure"}


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
        "batchAuthorizationRevision",
        "credentialId",
        "createdAt",
        "payloadSha256",
        "samples",
        "qualityEvents",
        "gaps",
    }
    _closed(document, batch_fields)
    if document["schemaVersion"] != "one-os-telemetry-batch/v2":
        _fail(
            "invalid_schema_version",
            "Batch schemaVersion must be one-os-telemetry-batch/v2",
        )
    _uuid4(document["batchId"])
    installation_id = _uuid4(document["installationId"])
    if _strict_int(document["batchAuthorizationRevision"]) < 1:
        _fail("invalid_authorization_revision", "Batch authorization revision must be positive")
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
        key: document[key]
        for key in ("batchAuthorizationRevision", "gaps", "qualityEvents", "samples")
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


_ACK_COMMON_FIELDS = {
    "schemaVersion",
    "authorizationMode",
    "installationId",
    "credentialId",
    "batchId",
    "batchAuthorizationRevision",
    "ingestAuthorizationRevision",
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
_HISTORICAL_RECEIPT_FIELD = "historicalAuthorizationReceiptSha256"


def parse_telemetry_ack(
    raw: bytes,
    *,
    expected_batch: dict[str, Any],
    expected_request_sha256: str,
    expected_ingest_authorization_revision: int,
    previous_ingest_cursor: int,
    expected_historical_receipt_sha256: str | None = None,
) -> dict[str, Any]:
    document = _parse_raw(raw, maximum=16_384)
    mode = document.get("authorizationMode")
    expected_fields = set(_ACK_COMMON_FIELDS)
    if mode == "historical_backlog":
        expected_fields.add(_HISTORICAL_RECEIPT_FIELD)
    elif mode != "current":
        _fail("invalid_authorization_mode", "ACK authorization mode is invalid")
    _closed(document, expected_fields)
    if document["schemaVersion"] != "one-os-telemetry-ack/v2":
        _fail("invalid_schema_version", "ACK schemaVersion must be one-os-telemetry-ack/v2")
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
        "batchAuthorizationRevision",
        "ingestAuthorizationRevision",
    ):
        _strict_int(document[key])
    if document["batchAuthorizationRevision"] < 1 or document["ingestAuthorizationRevision"] < 1:
        _fail("invalid_authorization_revision", "ACK authorization revisions must be positive")
    _timestamp_seconds(document["acceptedAt"])
    if any(
        document[key] != expected_batch[key]
        for key in ("installationId", "credentialId", "batchId", "batchAuthorizationRevision")
    ) or not hmac.compare_digest(document["requestSha256"], expected_request_sha256):
        _fail("ack_binding_mismatch", "ACK does not bind the exact request")
    if document["ingestAuthorizationRevision"] != expected_ingest_authorization_revision:
        _fail("ack_binding_mismatch", "ACK ingest authorization revision differs")
    if mode == "current":
        if (
            expected_historical_receipt_sha256 is not None
            or document["batchAuthorizationRevision"] != document["ingestAuthorizationRevision"]
        ):
            _fail("ack_binding_mismatch", "Current ACK authority differs")
    else:
        if expected_historical_receipt_sha256 is None:
            _fail("ack_binding_mismatch", "Historical receipt authority is missing")
        _digest(document[_HISTORICAL_RECEIPT_FIELD])
        if not hmac.compare_digest(
            document[_HISTORICAL_RECEIPT_FIELD], expected_historical_receipt_sha256
        ):
            _fail("ack_binding_mismatch", "Historical receipt authority differs")
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


_MANIFEST_FIELDS = {
    "schemaVersion",
    "renewalOperationId",
    "installationId",
    "lineageId",
    "cutMarkerId",
    "cutJournalMaxId",
    "firstJournalId",
    "lastJournalId",
    "entryCount",
    "totalRequestBytes",
    "batchAuthorizationRevision",
    "entries",
    "createdAt",
}
_RECEIPT_FIELDS = {
    "schemaVersion",
    "renewalOperationId",
    "renewalRequestSha256",
    "backlogManifestSha256",
    "cutMarkerId",
    "cutJournalMaxId",
    "installationId",
    "lineageId",
    "historicalAuthorizationRevision",
    "ingestAuthorizationRevision",
    "allowedTransportCredentialIds",
    "entryCount",
    "totalRequestBytes",
    "entries",
    "notBefore",
    "expiresAt",
    "receiptNonce",
}
_ENTRY_FIELDS = {
    "journalId",
    "batchId",
    "credentialId",
    "batchAuthorizationRevision",
    "requestSha256",
    "requestLength",
}


def _validate_authority_entries(value: Any, *, allow_empty: bool) -> list[dict[str, Any]]:
    if type(value) is not list or len(value) > 256 or (not allow_empty and not value):
        _fail("invalid_authority_artifact", "Authority entries have invalid cardinality")
    entries: list[dict[str, Any]] = []
    for entry in value:
        if type(entry) is not dict:
            _fail("invalid_authority_artifact", "Authority entry must be an object")
        _closed(entry, _ENTRY_FIELDS)
        if _strict_int(entry["journalId"]) < 1:
            _fail("invalid_authority_artifact", "Journal ID must be positive")
        if _strict_int(entry["batchAuthorizationRevision"]) < 1:
            _fail("invalid_authority_artifact", "Batch authority revision must be positive")
        length = _strict_int(entry["requestLength"])
        if not 1 <= length <= MAX_BATCH_BYTES:
            _fail("invalid_authority_artifact", "Request length is invalid")
        _uuid4(entry["batchId"])
        _uuid4(entry["credentialId"])
        _digest(entry["requestSha256"])
        entries.append(entry)
    journal_ids = [entry["journalId"] for entry in entries]
    if journal_ids and journal_ids != list(range(journal_ids[0], journal_ids[-1] + 1)):
        _fail("invalid_authority_artifact", "Authority entries are not contiguous and ordered")
    return entries


def parse_backlog_manifest(value: bytes | dict[str, Any]) -> tuple[dict[str, Any], bytes]:
    try:
        document, raw = _canonical_object(value, maximum=60_256, code="invalid_manifest")
        _closed(document, _MANIFEST_FIELDS)
        if document["schemaVersion"] != "one-os-telemetry-backlog-manifest/v2":
            _fail("invalid_manifest", "Manifest schemaVersion is invalid")
        for field in ("renewalOperationId", "installationId", "lineageId", "cutMarkerId"):
            _uuid4(document[field])
        for field in (
            "cutJournalMaxId",
            "firstJournalId",
            "lastJournalId",
            "entryCount",
            "totalRequestBytes",
            "batchAuthorizationRevision",
        ):
            _strict_int(document[field])
        _timestamp_seconds(document["createdAt"])
        entries = _validate_authority_entries(document["entries"], allow_empty=True)
        if document["entryCount"] != len(entries) or document["totalRequestBytes"] != sum(
            entry["requestLength"] for entry in entries
        ):
            _fail("invalid_manifest", "Manifest aggregate is inconsistent")
        expected_first = entries[0]["journalId"] if entries else 0
        expected_last = entries[-1]["journalId"] if entries else 0
        if (
            document["firstJournalId"] != expected_first
            or document["lastJournalId"] != expected_last
            or document["cutJournalMaxId"] != expected_last
            or any(
                entry["batchAuthorizationRevision"] != document["batchAuthorizationRevision"]
                for entry in entries
            )
        ):
            _fail("invalid_manifest", "Manifest relational aliases are inconsistent")
        return document, raw
    except TelemetryValidationError as error:
        if error.code == "invalid_manifest":
            raise ValueError("invalid_manifest") from error
        raise ValueError("invalid_manifest") from error


def parse_historical_receipt(value: bytes | dict[str, Any]) -> tuple[dict[str, Any], bytes]:
    try:
        document, raw = _canonical_object(value, maximum=60_628, code="invalid_receipt")
        _closed(document, _RECEIPT_FIELDS)
        if document["schemaVersion"] != "one-os-historical-authorization-receipt/v2":
            _fail("invalid_receipt", "Receipt schemaVersion is invalid")
        for field in ("renewalOperationId", "installationId", "lineageId", "cutMarkerId"):
            _uuid4(document[field])
        for field in (
            "cutJournalMaxId",
            "historicalAuthorizationRevision",
            "ingestAuthorizationRevision",
            "entryCount",
            "totalRequestBytes",
        ):
            _strict_int(document[field])
        for field in ("renewalRequestSha256", "backlogManifestSha256"):
            _digest(document[field])
        credentials = document["allowedTransportCredentialIds"]
        if type(credentials) is not list or len(credentials) != 2:
            _fail("invalid_receipt", "Receipt credential set is invalid")
        for credential in credentials:
            _uuid4(credential)
        if credentials != sorted(set(credentials)):
            _fail("invalid_receipt", "Receipt credential set is not canonical")
        nonce = document["receiptNonce"]
        if not isinstance(nonce, str) or re.fullmatch(r"[0-9a-f]{64}", nonce) is None:
            _fail("invalid_receipt", "Receipt nonce is invalid")
        not_before = _timestamp_seconds(document["notBefore"])
        expires_at = _timestamp_seconds(document["expiresAt"])
        if expires_at.timestamp() - not_before.timestamp() != 86_400:
            _fail("invalid_receipt", "Receipt lifetime is invalid")
        entries = _validate_authority_entries(document["entries"], allow_empty=False)
        if (
            document["entryCount"] != len(entries)
            or document["totalRequestBytes"] != sum(entry["requestLength"] for entry in entries)
            or document["cutJournalMaxId"] != entries[-1]["journalId"]
            or document["historicalAuthorizationRevision"] < 1
            or document["ingestAuthorizationRevision"]
            != document["historicalAuthorizationRevision"] + 1
        ):
            _fail("invalid_receipt", "Receipt relational aliases are inconsistent")
        return document, raw
    except TelemetryValidationError as error:
        raise ValueError("invalid_receipt") from error


_ENABLE_FIELDS = {
    "protocol",
    "requestId",
    "installationId",
    "currentCredentialId",
    "currentCertificateSha256",
    "protocolId",
    "telemetryBatchSchemaSha256",
    "telemetryAckSchemaSha256",
    "telemetryErrorSchemaSha256",
    "renewalControlSchemaSha256",
    "capabilitySha256",
    "capabilityServerNonce",
    "issuedAt",
    "expiresAt",
    "expectedTelemetryAuthorizationRevision",
    "edgeNonce",
    "signature",
}


def _decode_digest(value: Any, *, expected_length: int = 32) -> bytes:
    if not isinstance(value, str):
        _fail("invalid_digest", "Encoded value must be a string")
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except ValueError as error:
        raise TelemetryValidationError("Invalid base64url", code="invalid_digest") from error
    if (
        len(decoded) != expected_length
        or base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != value
    ):
        _fail("invalid_digest", "Encoded value is not canonical")
    return decoded


def parse_enable_request(raw: bytes) -> dict[str, Any]:
    document = _parse_raw(raw, maximum=16_384)
    _closed(document, _ENABLE_FIELDS)
    if document["protocol"] != "2.0" or document["protocolId"] != "one-os-telemetry-authority/v2":
        _fail("invalid_schema_version", "Enable protocol is invalid")
    for name in ("requestId", "installationId", "currentCredentialId"):
        _uuid4(document[name])
    for name in (
        "currentCertificateSha256",
        "telemetryBatchSchemaSha256",
        "telemetryAckSchemaSha256",
        "telemetryErrorSchemaSha256",
        "renewalControlSchemaSha256",
        "capabilitySha256",
    ):
        _digest(document[name])
    _decode_digest(document["capabilityServerNonce"])
    _decode_digest(document["edgeNonce"])
    _decode_digest(document["signature"], expected_length=64)
    issued_at = _timestamp_seconds(document["issuedAt"])
    expires_at = _timestamp_seconds(document["expiresAt"])
    if expires_at.timestamp() - issued_at.timestamp() != 300:
        _fail("invalid_capability_window", "Capability window must be exactly five minutes")
    if _strict_int(document["expectedTelemetryAuthorizationRevision"]) < 1:
        _fail("invalid_authorization_revision", "Expected authority revision must be positive")
    return document


def build_enable_preimage(document: dict[str, Any]) -> bytes:
    names = (
        "telemetryBatchSchemaSha256",
        "telemetryAckSchemaSha256",
        "telemetryErrorSchemaSha256",
        "renewalControlSchemaSha256",
    )
    values = [
        document["protocol"].encode(),
        UUID(document["requestId"]).bytes,
        UUID(document["installationId"]).bytes,
        UUID(document["currentCredentialId"]).bytes,
        _decode_digest(document["currentCertificateSha256"]),
        document["protocolId"].encode(),
        *(_decode_digest(document[name]) for name in names),
        _decode_digest(document["capabilitySha256"]),
        _decode_digest(document["capabilityServerNonce"]),
        document["issuedAt"].encode(),
        document["expiresAt"].encode(),
        document["expectedTelemetryAuthorizationRevision"].to_bytes(8, "big"),
        _decode_digest(document["edgeNonce"]),
    ]
    return b"ONE.OS-TELEMETRY-AUTHORITY-ENABLE-V2\0" + b"".join(
        struct.pack(">HI", index, len(value)) + value for index, value in enumerate(values, 1)
    )
