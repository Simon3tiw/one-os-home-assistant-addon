import base64
import hashlib
from datetime import UTC, datetime, timedelta

import pytest
from one_os_addon.app import create_app
from one_os_addon.models import (
    EdgeIdentity,
    TelemetryAuthorityCut,
    TelemetryBatch,
    TelemetryJournalState,
)
from one_os_addon.telemetry_authority_cut import TelemetryAuthorityCutRepository
from one_os_addon.telemetry_contract_v2 import canonical_json
from sqlalchemy.exc import IntegrityError

_CUT_ID = "44444444-4444-4444-8444-444444444444"
_RENEWAL_ID = "55555555-5555-4555-8555-555555555555"
_BATCH_ID = "33333333-3333-4333-8333-333333333333"
_CREDENTIAL_ID = "22222222-2222-4222-8222-222222222222"


def _b64digest(value: bytes) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(value).digest()).rstrip(b"=").decode()


def _authority_fixture(app, *, status: str = "pending") -> tuple[dict, dict]:
    request = b'{"accepted":"draft4"}'
    with app.state.session() as session:
        identity = session.get(EdgeIdentity, 1)
        identity.status = "paired"
        identity.credential_id = _CREDENTIAL_ID
        identity.installation_revision = 1
        state = session.get(TelemetryJournalState, 1)
        state.last_journal_id = 1
        session.add(
            TelemetryBatch(
                batch_id=_BATCH_ID,
                installation_id=identity.installation_id,
                installation_revision=1,
                batch_authorization_revision=1,
                journal_id=1,
                credential_id=_CREDENTIAL_ID,
                payload_sha256="a" * 43,
                request_sha256=_b64digest(request),
                request_bytes=request,
                sample_count=1,
                quality_event_count=0,
                gap_count=0,
                status=status,
                lease_owner=None,
                lease_until=None,
                attempt_count=0,
                last_attempt_at=None,
                next_attempt_at=None,
                ack_bytes=b"{}" if status == "acked" else None,
                ingest_cursor=1 if status == "acked" else None,
                acked_at=datetime(2030, 1, 1, tzinfo=UTC) if status == "acked" else None,
                created_at=datetime(2030, 1, 1, tzinfo=UTC),
            )
        )
        installation_id = identity.installation_id
        lineage_id = identity.lineage_id
        session.commit()
    entry = {
        "batchAuthorizationRevision": 1,
        "batchId": _BATCH_ID,
        "credentialId": _CREDENTIAL_ID,
        "journalId": 1,
        "requestLength": len(request),
        "requestSha256": _b64digest(request),
    }
    manifest = {
        "batchAuthorizationRevision": 1,
        "createdAt": "2030-01-01T00:00:00Z",
        "cutJournalMaxId": 1,
        "cutMarkerId": _CUT_ID,
        "entries": [entry],
        "entryCount": 1,
        "firstJournalId": 1,
        "installationId": installation_id,
        "lastJournalId": 1,
        "lineageId": lineage_id,
        "renewalOperationId": _RENEWAL_ID,
        "schemaVersion": "one-os-telemetry-backlog-manifest/v2",
        "totalRequestBytes": len(request),
    }
    receipt = {
        "allowedTransportCredentialIds": [_CREDENTIAL_ID, _RENEWAL_ID],
        "backlogManifestSha256": _b64digest(canonical_json(manifest)),
        "cutJournalMaxId": 1,
        "cutMarkerId": _CUT_ID,
        "entries": [entry],
        "entryCount": 1,
        "expiresAt": "2030-01-02T00:00:00Z",
        "historicalAuthorizationRevision": 1,
        "ingestAuthorizationRevision": 2,
        "installationId": installation_id,
        "lineageId": lineage_id,
        "notBefore": "2030-01-01T00:00:00Z",
        "receiptNonce": "4" * 64,
        "renewalOperationId": _RENEWAL_ID,
        "renewalRequestSha256": "A" * 43,
        "schemaVersion": "one-os-historical-authorization-receipt/v2",
        "totalRequestBytes": len(request),
    }
    return manifest, receipt


def test_cut_repository_is_wired_only_with_default_off_v2_authority(tmp_path) -> None:
    disabled = create_app(
        database_url=f"sqlite:///{tmp_path / 'disabled.db'}",
        pairing_backend=False,
        telemetry_enabled=True,
    )
    assert disabled.state.telemetry_authority_cut is None

    enabled = create_app(
        database_url=f"sqlite:///{tmp_path / 'enabled.db'}",
        identity_dir=tmp_path / "identity",
        telemetry_enabled=True,
        telemetry_authority_enabled=True,
        start_pairing_worker=False,
    )
    assert isinstance(enabled.state.telemetry_authority_cut, TelemetryAuthorityCutRepository)


def test_cut_repository_accepts_only_strict_canonical_draft4_artifacts(tmp_path) -> None:
    app = create_app(database_url=f"sqlite:///{tmp_path / 'cut.db'}", pairing_backend=False)
    repository = TelemetryAuthorityCutRepository(app.state.session)
    manifest, receipt = _authority_fixture(app)
    opened = datetime(2030, 1, 1, tzinfo=UTC)
    repository.open(_CUT_ID, _RENEWAL_ID, canonical_json(manifest), 1, opened)
    repository.store_receipt(_CUT_ID, receipt, opened)
    with app.state.session() as session:
        batch = session.get(TelemetryBatch, _BATCH_ID)
        batch.status = "acked"
        batch.ack_bytes = b"{}"
        batch.ingest_cursor = 1
        batch.acked_at = opened
        session.commit()
    repository.promote_identity(_CUT_ID, opened)
    repository.mark_backlog_drained(_CUT_ID, opened)
    repository.finish(_CUT_ID, opened)
    with app.state.session() as session:
        row = session.get(TelemetryAuthorityCut, _CUT_ID)
        assert row.manifest_bytes == canonical_json(manifest)
        assert row.receipt_bytes == canonical_json(receipt)
        assert row.milestone == "terminal"


def test_cut_repository_rejects_arbitrary_objects_without_mutating_revision(tmp_path) -> None:
    app = create_app(
        database_url=f"sqlite:///{tmp_path / 'cut-arbitrary.db'}", pairing_backend=False
    )
    repository = TelemetryAuthorityCutRepository(app.state.session)
    with pytest.raises(ValueError, match="invalid_manifest"):
        repository.open(
            _CUT_ID, _RENEWAL_ID, {"z": 1, "a": []}, 0, datetime(2030, 1, 1, tzinfo=UTC)
        )
    with app.state.session() as session:
        assert session.get(EdgeIdentity, 1).telemetry_authorization_revision == 1
        assert session.get(TelemetryAuthorityCut, _CUT_ID) is None


def test_receipt_relation_and_promotion_are_revalidated_under_authority_lock(tmp_path) -> None:
    app = create_app(
        database_url=f"sqlite:///{tmp_path / 'cut-revalidate.db'}", pairing_backend=False
    )
    repository = TelemetryAuthorityCutRepository(app.state.session)
    manifest, receipt = _authority_fixture(app)
    at = datetime(2030, 1, 1, tzinfo=UTC)
    repository.open(_CUT_ID, _RENEWAL_ID, manifest, 1, at)
    invalid = {**receipt, "cutMarkerId": "66666666-6666-4666-8666-666666666666"}
    with pytest.raises(ValueError, match="receipt_relation_conflict"):
        repository.store_receipt(_CUT_ID, invalid, at)
    repository.store_receipt(_CUT_ID, receipt, at)
    with app.state.engine.begin() as connection:
        connection.exec_driver_sql(
            "UPDATE telemetry_batches SET status='pending', ack_bytes=NULL, "
            "ingest_cursor=NULL, acked_at=NULL WHERE batch_id=?",
            (_BATCH_ID,),
        )
    with pytest.raises(ValueError, match="historical_backlog_not_drained"):
        repository.promote_identity(_CUT_ID, at + timedelta(seconds=1))
    with app.state.session() as session:
        assert session.get(EdgeIdentity, 1).telemetry_authorization_revision == 1
        assert session.get(TelemetryAuthorityCut, _CUT_ID).milestone == "receipt_stored"


def test_cut_repository_rejects_skipped_milestone(tmp_path) -> None:
    app = create_app(database_url=f"sqlite:///{tmp_path / 'cut-skip.db'}", pairing_backend=False)
    repository = TelemetryAuthorityCutRepository(app.state.session)
    manifest, _receipt = _authority_fixture(app)
    repository.open(_CUT_ID, _RENEWAL_ID, manifest, 1, datetime(2030, 1, 1, tzinfo=UTC))
    with pytest.raises(ValueError, match="cut_transition_conflict"):
        repository.promote_identity(_CUT_ID, datetime(2030, 1, 1, tzinfo=UTC))


def test_direct_model_write_rejects_wrong_hash_and_database_rejects_skipped_milestone(
    tmp_path,
) -> None:
    app = create_app(
        database_url=f"sqlite:///{tmp_path / 'cut-mutations.db'}", pairing_backend=False
    )
    with app.state.session() as session:
        identity = session.get(EdgeIdentity, 1)
        session.add(
            TelemetryAuthorityCut(
                cut_marker_id="44444444-4444-4444-8444-444444444444",
                renewal_request_id="55555555-5555-4555-8555-555555555555",
                installation_id=identity.installation_id,
                lineage_id=identity.lineage_id,
                historical_authorization_revision=1,
                ingest_authorization_revision=2,
                cut_journal_max_id=0,
                backlog_mode="none",
                manifest_bytes=b"{}",
                manifest_sha256=b"x" * 32,
                milestone="cut_open",
                cut_opened_at=datetime(2030, 1, 1, tzinfo=UTC),
            )
        )
        with pytest.raises(ValueError, match="manifest_sha256_mismatch"):
            session.commit()
        session.rollback()

    repository = TelemetryAuthorityCutRepository(app.state.session)
    at = datetime(2030, 1, 1, tzinfo=UTC)
    manifest, _receipt = _authority_fixture(app)
    repository.open(_CUT_ID, _RENEWAL_ID, manifest, 1, at)
    with app.state.engine.begin() as connection, pytest.raises(IntegrityError):
        connection.exec_driver_sql(
            "UPDATE telemetry_authority_cuts SET milestone='identity_promoted', "
            "identity_promoted_at=? WHERE cut_marker_id=?",
            (at.isoformat(), _CUT_ID),
        )
