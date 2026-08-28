from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

try:
    from app.telemetry_contract_v2 import (
        TelemetryValidationError,
        canonical_json,
        parse_telemetry_ack,
        parse_telemetry_batch,
    )
except ModuleNotFoundError:
    from one_os_addon.telemetry_contract_v2 import (
        TelemetryValidationError,
        canonical_json,
        parse_telemetry_ack,
        parse_telemetry_batch,
    )

_VECTOR_NAME = "one-os-phase2c-p-canonical-vectors-v2-draft4-20260825.json"


def _vector_path() -> Path:
    for parent in Path(__file__).resolve().parents:
        for relative in (
            Path("contracts/telemetry/v2") / _VECTOR_NAME,
            Path("docs/reference/contracts/telemetry/v2") / _VECTOR_NAME,
        ):
            candidate = parent / relative
            if candidate.is_file():
                return candidate
    raise AssertionError("Draft-4 telemetry-v2 vector mirror is missing")


@pytest.fixture(scope="module")
def vectors() -> dict:
    return json.loads(_vector_path().read_bytes())


def test_all_accepted_draft4_batches_parse_exactly(vectors: dict) -> None:
    assert len(vectors["telemetryBatches256"]) == 256
    for vector in vectors["telemetryBatches256"]:
        raw = vector["canonicalUtf8"].encode()
        parsed = parse_telemetry_batch(raw)
        assert parsed.canonical_bytes == raw
        assert parsed.document == vector["object"]
        assert parsed.request_sha256 == vector["sha256"]
        assert len(raw) == vector["length"]


def test_v1_batch_and_detached_authority_revision_fail_closed(vectors: dict) -> None:
    vector = vectors["telemetryBatches256"][0]
    detached = copy.deepcopy(vector["object"])
    detached["batchAuthorizationRevision"] += 1
    with pytest.raises(TelemetryValidationError, match="digest"):
        parse_telemetry_batch(canonical_json(detached))

    v1 = copy.deepcopy(vector["object"])
    v1["schemaVersion"] = "1.0"
    with pytest.raises(TelemetryValidationError) as error:
        parse_telemetry_batch(canonical_json(v1))
    assert error.value.code == "invalid_schema_version"


def _ack(batch: dict, request_sha256: str, *, mode: str, ingest_revision: int) -> dict:
    value = {
        "schemaVersion": "one-os-telemetry-ack/v2",
        "authorizationMode": mode,
        "installationId": batch["installationId"],
        "credentialId": batch["credentialId"],
        "batchId": batch["batchId"],
        "batchAuthorizationRevision": batch["batchAuthorizationRevision"],
        "ingestAuthorizationRevision": ingest_revision,
        "requestSha256": request_sha256,
        "acceptedSamples": len(batch["samples"]),
        "duplicateSamples": 0,
        "acceptedQualityEvents": len(batch["qualityEvents"]),
        "duplicateQualityEvents": 0,
        "acceptedGaps": len(batch["gaps"]),
        "duplicateGaps": 0,
        "ingestCursor": 1,
        "acceptedAt": "2030-01-01T12:00:01Z",
    }
    return value


def test_current_ack_requires_equal_authority_revision(vectors: dict) -> None:
    batch_vector = vectors["telemetryBatches256"][0]
    batch = batch_vector["object"]
    ack = _ack(
        batch,
        batch_vector["sha256"],
        mode="current",
        ingest_revision=batch["batchAuthorizationRevision"],
    )
    assert (
        parse_telemetry_ack(
            canonical_json(ack),
            expected_batch=batch,
            expected_request_sha256=batch_vector["sha256"],
            expected_ingest_authorization_revision=batch["batchAuthorizationRevision"],
            previous_ingest_cursor=0,
        )
        == ack
    )
    ack["ingestAuthorizationRevision"] += 1
    with pytest.raises(TelemetryValidationError) as error:
        parse_telemetry_ack(
            canonical_json(ack),
            expected_batch=batch,
            expected_request_sha256=batch_vector["sha256"],
            expected_ingest_authorization_revision=ack["ingestAuthorizationRevision"],
            previous_ingest_cursor=0,
        )
    assert error.value.code == "ack_binding_mismatch"


def test_historical_ack_requires_exact_receipt_hash(vectors: dict) -> None:
    batch_vector = vectors["telemetryBatches256"][0]
    batch = batch_vector["object"]
    receipt_sha256 = vectors["receipt"]["sha256"]
    ack = _ack(
        batch,
        batch_vector["sha256"],
        mode="historical_backlog",
        ingest_revision=batch["batchAuthorizationRevision"] + 1,
    )
    ack["historicalAuthorizationReceiptSha256"] = receipt_sha256
    assert (
        parse_telemetry_ack(
            canonical_json(ack),
            expected_batch=batch,
            expected_request_sha256=batch_vector["sha256"],
            expected_ingest_authorization_revision=batch["batchAuthorizationRevision"] + 1,
            expected_historical_receipt_sha256=receipt_sha256,
            previous_ingest_cursor=0,
        )
        == ack
    )
    with pytest.raises(TelemetryValidationError) as error:
        parse_telemetry_ack(
            canonical_json(ack),
            expected_batch=batch,
            expected_request_sha256=batch_vector["sha256"],
            expected_ingest_authorization_revision=batch["batchAuthorizationRevision"] + 1,
            expected_historical_receipt_sha256=vectors["manifest256"]["sha256"],
            previous_ingest_cursor=0,
        )
    assert error.value.code == "ack_binding_mismatch"
