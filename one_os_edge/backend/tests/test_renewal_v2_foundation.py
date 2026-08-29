from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from one_os_addon.app import create_app
from one_os_addon.models import EdgeIdentity, TelemetryAuthorityCut, TelemetryRenewalOperation
from sqlalchemy import inspect
from sqlalchemy.exc import IntegrityError


def _config(database: Path) -> Config:
    config = Config("one_os_edge/alembic.ini")
    config.set_main_option("sqlalchemy.url", f"sqlite:///{database}")
    config.attributes["explicit_database_url"] = True
    return config


def _cut(session) -> TelemetryAuthorityCut:
    identity = session.get(EdgeIdentity, 1)
    manifest = b'{"schemaVersion":"one-os-telemetry-backlog-manifest/v2"}'
    return TelemetryAuthorityCut(
        cut_marker_id="33333333-3333-4333-8333-333333333333",
        renewal_request_id="11111111-1111-4111-8111-111111111111",
        installation_id=identity.installation_id,
        lineage_id=identity.lineage_id,
        historical_authorization_revision=1,
        ingest_authorization_revision=2,
        cut_journal_max_id=0,
        backlog_mode="none",
        manifest_bytes=manifest,
        manifest_sha256=hashlib.sha256(manifest).digest(),
        milestone="cut_open",
        cut_opened_at=datetime(2030, 1, 1, tzinfo=UTC),
    )


def _operation() -> TelemetryRenewalOperation:
    request = b'{"protocol":"2.0"}'
    manifest = b'{"schemaVersion":"one-os-telemetry-backlog-manifest/v2"}'
    csr = b"csr-der"
    spki = b"pending-spki"
    return TelemetryRenewalOperation(
        id=1,
        status="start_requested",
        request_id="11111111-1111-4111-8111-111111111111",
        pending_credential_id="22222222-2222-4222-8222-222222222222",
        installation_revision_before=1,
        telemetry_authorization_revision_before=1,
        telemetry_authorization_revision_after=2,
        cut_marker_id="33333333-3333-4333-8333-333333333333",
        cut_journal_max_id=0,
        pending_spki_der=spki,
        pending_spki_sha256=hashlib.sha256(spki).digest(),
        csr_der=csr,
        csr_sha256=hashlib.sha256(csr).digest(),
        manifest_bytes=manifest,
        manifest_sha256=hashlib.sha256(manifest).digest(),
        start_request_bytes=request,
        start_request_sha256=hashlib.sha256(request).digest(),
    )


def test_0018_adds_exact_durable_renewal_operation_schema(tmp_path) -> None:
    app = create_app(database_url=f"sqlite:///{tmp_path / 'renewal.db'}", pairing_backend=False)
    columns = {
        column["name"]
        for column in inspect(app.state.engine).get_columns("telemetry_renewal_operation")
    }
    assert columns == {
        "id",
        "status",
        "request_id",
        "pending_credential_id",
        "installation_revision_before",
        "telemetry_authorization_revision_before",
        "telemetry_authorization_revision_after",
        "cut_marker_id",
        "cut_journal_max_id",
        "pending_spki_der",
        "pending_spki_sha256",
        "csr_der",
        "csr_sha256",
        "manifest_bytes",
        "manifest_sha256",
        "start_request_bytes",
        "start_request_sha256",
        "pending_response_bytes",
        "pending_response_sha256",
        "receipt_bytes",
        "receipt_sha256",
        "issued_response_bytes",
        "issued_response_sha256",
        "ack_request_bytes",
        "ack_request_sha256",
        "ack_response_bytes",
        "ack_response_sha256",
        "cancel_request_id",
        "cancel_request_bytes",
        "cancel_request_sha256",
        "cancel_response_bytes",
        "cancel_response_sha256",
        "created_at",
        "updated_at",
    }
    with app.state.session() as session:
        session.add(_cut(session))
        session.flush()
        session.add(_operation())
        session.commit()
        row = session.get(TelemetryRenewalOperation, 1)
        assert row.start_request_bytes == b'{"protocol":"2.0"}'
        assert row.pending_spki_der == b"pending-spki"
    app.state.engine.dispose()


def test_renewal_operation_rejects_wrong_exact_hash_and_fractional_revision(tmp_path) -> None:
    app = create_app(database_url=f"sqlite:///{tmp_path / 'constraints.db'}", pairing_backend=False)
    with app.state.session() as session:
        row = _operation()
        row.csr_sha256 = b"x" * 32
        session.add(row)
        with pytest.raises(ValueError, match="csr_sha256_mismatch"):
            session.commit()
        session.rollback()
    with app.state.engine.begin() as connection, pytest.raises(IntegrityError):
        connection.exec_driver_sql(
            "INSERT INTO telemetry_renewal_operation (id,status,request_id,pending_credential_id,"
            "installation_revision_before,telemetry_authorization_revision_before,"
            "telemetry_authorization_revision_after,cut_marker_id,cut_journal_max_id,"
            "pending_spki_der,pending_spki_sha256,csr_der,csr_sha256,manifest_bytes,manifest_sha256,"
            "start_request_bytes,start_request_sha256,created_at,updated_at) VALUES "
            "(1,'start_requested','11111111-1111-4111-8111-111111111111',"
            "'22222222-2222-4222-8222-222222222222',1.5,1,2,"
            "'33333333-3333-4333-8333-333333333333',0,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)",
            (
                b"spki",
                hashlib.sha256(b"spki").digest(),
                b"csr",
                hashlib.sha256(b"csr").digest(),
                b"manifest",
                hashlib.sha256(b"manifest").digest(),
                b"request",
                hashlib.sha256(b"request").digest(),
            ),
        )
    app.state.engine.dispose()


def test_0018_downgrade_refuses_populated_durable_state(tmp_path) -> None:
    database = tmp_path / "downgrade.db"
    app = create_app(database_url=f"sqlite:///{database}", pairing_backend=False)
    with app.state.session() as session:
        session.add(_cut(session))
        session.flush()
        session.add(_operation())
        session.commit()
    app.state.engine.dispose()
    with pytest.raises(RuntimeError, match="refusing to discard durable renewal v2 state"):
        command.downgrade(_config(database), "0017")
    assert command.current(_config(database)) is None
