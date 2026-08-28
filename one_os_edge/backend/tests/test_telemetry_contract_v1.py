from __future__ import annotations

import base64
import copy
import hashlib
import json
import re
from pathlib import Path

import pytest
from one_os_addon.telemetry_contract_v1 import (
    MAX_BATCH_BYTES,
    TelemetryValidationError,
    canonical_json,
    parse_telemetry_ack,
    parse_telemetry_batch,
)

CONTRACT = Path(__file__).resolve().parents[3] / "docs/reference/contracts/telemetry/v1"


def _vectors() -> dict:
    return json.loads((CONTRACT / "canonical-vectors.json").read_text(encoding="utf-8"))


def _materialize(base: dict, operations: list[dict]) -> dict:
    document = copy.deepcopy(base)
    for operation in operations:
        target = document
        parts = operation["path"].split(".")
        for part in parts[:-1]:
            target = target[int(part)] if isinstance(target, list) else target[part]
        final = parts[-1]
        if operation["op"] == "set":
            if isinstance(target, list):
                target[int(final)] = copy.deepcopy(operation["value"])
            else:
                target[final] = copy.deepcopy(operation["value"])
        elif operation["op"] == "append":
            target[final].append(copy.deepcopy(operation["value"]))
        else:
            raise AssertionError(operation)
    return document


def test_golden_batch_matches_canonical_bytes_ids_and_hashes() -> None:
    vectors = _vectors()
    raw = vectors["batchCanonical"].encode("utf-8")

    parsed = parse_telemetry_batch(raw)

    assert parsed.canonical_bytes == raw
    assert parsed.request_sha256 == vectors["requestSha256"]
    assert parsed.payload_sha256 == vectors["payloadSha256"]
    assert parsed.document["samples"][0]["sampleId"] == vectors["sampleId"]
    assert len(raw) == vectors["batchCanonicalLength"]


def test_shared_semantic_vectors_have_stable_results() -> None:
    vectors = json.loads((CONTRACT / "semantic-vectors.json").read_text(encoding="utf-8"))
    canonical = _vectors()
    expected_batch = canonical["batch"]
    expected_request_sha = canonical["requestSha256"]

    for case in vectors["cases"]:
        base = vectors["baseBatch"] if case["target"] == "batch" else vectors["baseAck"]
        document = _materialize(base, case["operations"])
        raw = canonical_json(document)
        try:
            if case["target"] == "batch":
                parse_telemetry_batch(raw)
            else:
                parse_telemetry_ack(
                    raw,
                    expected_batch=expected_batch,
                    expected_request_sha256=expected_request_sha,
                    previous_ingest_cursor=41,
                )
        except TelemetryValidationError as error:
            actual = error.code
        else:
            actual = "valid"
        assert actual == case["code"], case["name"]


def test_raw_negative_vectors_are_rejected_with_stable_codes() -> None:
    vectors = json.loads((CONTRACT / "raw-negative-vectors.json").read_text(encoding="utf-8"))
    for case in vectors["cases"]:
        raw = base64.b64decode(case["rawBase64"], validate=True)
        with pytest.raises(TelemetryValidationError) as caught:
            parse_telemetry_batch(raw)
        assert caught.value.code == case["code"], case["name"]


def test_batch_limits_depth_and_empty_payload_are_fail_closed() -> None:
    with pytest.raises(TelemetryValidationError) as oversized:
        parse_telemetry_batch(b"{" + b" " * MAX_BATCH_BYTES + b"}")
    assert oversized.value.code == "payload_too_large"

    deep: object = 0
    for _ in range(9):
        deep = {"x": deep}
    with pytest.raises(TelemetryValidationError) as depth:
        parse_telemetry_batch(canonical_json(deep))
    assert depth.value.code == "json_too_deep"

    batch = copy.deepcopy(_vectors()["batch"])
    batch["samples"] = []
    batch["qualityEvents"] = []
    batch["gaps"] = []
    batch["payloadSha256"] = _payload_digest(batch)
    with pytest.raises(TelemetryValidationError) as empty:
        parse_telemetry_batch(canonical_json(batch))
    assert empty.value.code == "invalid_record_count"


def test_500_records_are_allowed_and_501_are_rejected() -> None:
    batch = copy.deepcopy(_vectors()["batch"])
    sample = batch["samples"][0]
    batch["qualityEvents"] = []
    batch["gaps"] = []
    batch["samples"] = []
    for index in range(500):
        item = copy.deepcopy(sample)
        item["pointId"] = f"point-{index // 2:03d}"
        item["sequence"] = index % 2
        item["sampleId"] = _record_id(item)
        batch["samples"].append(item)
    batch["payloadSha256"] = _payload_digest(batch)
    assert len(parse_telemetry_batch(canonical_json(batch)).document["samples"]) == 500

    item = copy.deepcopy(batch["samples"][-1])
    item["pointId"] = "point-250"
    item["sequence"] = 0
    item["sampleId"] = _record_id(item)
    batch["samples"].append(item)
    batch["payloadSha256"] = _payload_digest(batch)
    with pytest.raises(TelemetryValidationError) as too_many:
        parse_telemetry_batch(canonical_json(batch))
    assert too_many.value.code == "invalid_record_count"


def test_ack_cursor_regression_and_wrong_counts_are_rejected() -> None:
    vectors = _vectors()
    ack = copy.deepcopy(vectors["ack"])
    raw = canonical_json(ack)
    parsed = parse_telemetry_ack(
        raw,
        expected_batch=vectors["batch"],
        expected_request_sha256=vectors["requestSha256"],
        previous_ingest_cursor=41,
    )
    assert parsed["ingestCursor"] == 42

    with pytest.raises(TelemetryValidationError) as regression:
        parse_telemetry_ack(
            raw,
            expected_batch=vectors["batch"],
            expected_request_sha256=vectors["requestSha256"],
            previous_ingest_cursor=42,
        )
    assert regression.value.code == "ack_cursor_regression"


def test_manifest_binds_every_normative_artifact() -> None:
    manifest = json.loads((CONTRACT / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["schemaVersion"] == "1.0"
    for name, expected in manifest["artifacts"].items():
        assert hashlib.sha256((CONTRACT / name).read_bytes()).hexdigest() == expected


def test_record_schema_version_is_closed_for_samples_and_quality_events() -> None:
    vectors = _vectors()
    for collection in ("samples", "qualityEvents"):
        for hostile in (
            "2.0",
            None,
            1,
            {"command": {"service": "unlock", "target": "door"}},
        ):
            batch = copy.deepcopy(vectors["batch"])
            record = batch[collection][0]
            record["schemaVersion"] = hostile
            record["sampleId"] = _record_id(record)
            batch["payloadSha256"] = _payload_digest(batch)
            with pytest.raises(TelemetryValidationError) as rejected:
                parse_telemetry_batch(canonical_json(batch))
            assert rejected.value.code == "invalid_schema_version"


@pytest.mark.parametrize(
    ("hostile_record", "expected_code"),
    [
        (None, "invalid_shape"),
        ([], "invalid_shape"),
        ({}, "invalid_shape"),
        ({"pointId": {}}, "invalid_shape"),
        ({"pointId": "point.power", "streamEpochId": []}, "invalid_shape"),
    ],
)
def test_hostile_record_shapes_fail_with_stable_contract_error(
    hostile_record: object, expected_code: str
) -> None:
    batch = copy.deepcopy(_vectors()["batch"])
    batch["samples"] = [hostile_record]
    batch["qualityEvents"] = []
    batch["gaps"] = []
    batch["payloadSha256"] = _payload_digest(batch)
    with pytest.raises(TelemetryValidationError) as rejected:
        parse_telemetry_batch(canonical_json(batch))
    assert rejected.value.code == expected_code


def test_quality_and_gap_hostile_types_are_total() -> None:
    vectors = _vectors()
    cases = [
        ("qualityEvents", None, "invalid_shape"),
        ("gaps", None, "invalid_shape"),
    ]
    for collection, hostile, expected in cases:
        batch = copy.deepcopy(vectors["batch"])
        batch["samples"] = []
        batch["qualityEvents"] = []
        batch["gaps"] = []
        batch[collection] = [hostile]
        batch["payloadSha256"] = _payload_digest(batch)
        with pytest.raises(TelemetryValidationError) as rejected:
            parse_telemetry_batch(canonical_json(batch))
        assert rejected.value.code == expected

    mutations = [
        ("samples", "valueQuality"),
        ("qualityEvents", "valueQuality"),
        ("gaps", "reason"),
    ]
    for collection, field in mutations:
        batch = copy.deepcopy(vectors["batch"])
        batch[collection][0][field] = {"command": "unlock"}
        if collection != "gaps":
            batch[collection][0]["sampleId"] = _record_id(batch[collection][0])
        batch["payloadSha256"] = _payload_digest(batch)
        with pytest.raises(TelemetryValidationError):
            parse_telemetry_batch(canonical_json(batch))


def test_parser_limits_are_total_for_extreme_depth_and_integer_length() -> None:
    deep = b'{"x":' + (b"[" * 10_000) + b"0" + (b"]" * 10_000) + b"}"
    with pytest.raises(TelemetryValidationError) as depth:
        parse_telemetry_batch(deep)
    assert depth.value.code == "json_too_deep"

    vectors = _vectors()
    raw = canonical_json(vectors["batch"])
    raw = raw.replace(b'"sequence":0', b'"sequence":' + (b"1" * 5_000), 1)
    with pytest.raises(TelemetryValidationError) as integer:
        parse_telemetry_batch(raw)
    assert integer.value.code == "invalid_json_number"

    canonical = canonical_json(vectors["batch"])
    for token in (b"1.0", b"1e0", b"1e999", b"-1e999", b"-0"):
        hostile = canonical.replace(b'"sequence":0', b'"sequence":' + token, 1)
        with pytest.raises(TelemetryValidationError) as number:
            parse_telemetry_batch(hostile)
        assert number.value.code == "invalid_json_number", token


def test_decimal_schema_and_validator_share_exact_boundary_grammar() -> None:
    schema = json.loads((CONTRACT / "telemetry-sample-v1.schema.json").read_text())
    pattern = re.compile(schema["properties"]["decimalValue"]["pattern"], re.ASCII)
    cases = {
        "0": True,
        "-0": False,
        "0.0": False,
        "-0.0": False,
        "-0.1": True,
        "-0.000000001": True,
        "-0.0000000001": False,
        "999999999999999999": True,
        "-999999999999999999": True,
        "99999999999999999.9": True,
        "-123456789.123456789": True,
        "-1234567890.123456789": False,
        "999999999999999999.1": False,
        "123456789012345678.123456789": False,
        "0.123456789": True,
        "0.1234567890": False,
    }
    vectors = _vectors()
    for decimal, accepted in cases.items():
        assert (pattern.fullmatch(decimal) is not None) is accepted, decimal
        batch = copy.deepcopy(vectors["batch"])
        sample = batch["samples"][0]
        sample.pop("booleanValue", None)
        sample["decimalValue"] = decimal
        sample["sampleId"] = _record_id(sample)
        batch["payloadSha256"] = _payload_digest(batch)
        try:
            parse_telemetry_batch(canonical_json(batch))
        except TelemetryValidationError:
            actual = False
        else:
            actual = True
        assert actual is accepted, decimal


def _record_id(record: dict) -> str:
    without_id = {key: value for key, value in record.items() if key != "sampleId"}
    digest = hashlib.sha256(b"ONE.OS-TELEMETRY-RECORD-V1\0" + canonical_json(without_id)).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _payload_digest(batch: dict) -> str:
    payload = {key: batch[key] for key in ("gaps", "qualityEvents", "samples")}
    digest = hashlib.sha256(
        b"ONE.OS-TELEMETRY-BATCH-PAYLOAD-V1\0" + canonical_json(payload)
    ).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
