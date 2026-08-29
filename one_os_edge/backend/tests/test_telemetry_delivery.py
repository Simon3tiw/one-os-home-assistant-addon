import base64
import hashlib
from datetime import UTC, datetime, timedelta

import pytest
from one_os_addon.app import create_app
from one_os_addon.models import (
    Asset,
    ConfigurationSnapshot,
    EdgeIdentity,
    Point,
    Site,
    Space,
    Structure,
    TelemetryBatch,
    TelemetryBatchRecord,
    TelemetryIngestState,
    TelemetryOutboxRecord,
    TelemetryOutboxSegment,
)
from one_os_addon.telemetry_contract_v1 import canonical_json, parse_telemetry_batch
from one_os_addon.telemetry_delivery import TelemetryDeliveryError
from one_os_addon.telemetry_transport import TelemetryTransportError
from one_os_addon.telemetry_worker import TelemetryDeliveryWorker
from sqlalchemy import inspect, select

_INSTALLATION_ID = "00000000-0000-4000-8000-000000000002"
_CREDENTIAL_ID = "11111111-1111-4111-8111-111111111111"
_SNAPSHOT_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
_EPOCH_ID = "22222222-2222-4222-8222-222222222222"
_SEGMENT_ID = "33333333-3333-4333-8333-333333333333"
_BATCH_ID = "44444444-4444-4444-8444-444444444444"
_PROJECTION_SHA256 = "wSVUqL2kxfm_YRmU5wB4Lfm8KmbyOJjeVIdmKa73RVc"


def _delivery_identity():
    return {
        "status": "paired",
        "installationId": _INSTALLATION_ID,
        "credentialId": _CREDENTIAL_ID,
        "activeSpkiSha256": "spki",
        "certificateSha256": "certificate",
        "certificateNotAfter": "2030-01-02T12:00:00Z",
        "revision": 7,
        "certificatePem": "certificatechain",
        "privateKeyPem": "private-key",
    }


def _b64digest(value: bytes) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(value).digest()).rstrip(b"=").decode()


def _selected_point_and_snapshot(session) -> None:
    identity = session.get(EdgeIdentity, 1)
    assert identity is not None
    identity.installation_id = _INSTALLATION_ID
    identity.status = "paired"
    identity.credential_id = _CREDENTIAL_ID
    identity.installation_revision = 7
    session.add(Site(id="site-1", installation_id=_INSTALLATION_ID, name="Site"))
    session.flush()
    session.add(
        Structure(
            id="structure-1",
            site_id="site-1",
            parent_id=None,
            type="Building",
            name="Building",
            source_key="floor:1",
        )
    )
    session.flush()
    session.add(
        Space(
            id="space-1",
            structure_id="structure-1",
            type="Room",
            name="Room",
            source_key="area:1",
        )
    )
    session.flush()
    session.add(
        Asset(
            id="asset-1",
            space_id="space-1",
            source_space_id="space-1",
            type="Equipment",
            name="Meter",
            source_key="device:1",
        )
    )
    session.flush()
    session.add(
        Point(
            id="point-1",
            asset_id="asset-1",
            source_asset_id="asset-1",
            source_key="entity:test|entry|power",
            registry_id="sensor.power",
            current_entity_id="sensor.power",
            source_name="Power",
            source_unit="W",
            raw_value="21.25",
            lifecycle="active",
            quality="good",
            review_status="reviewed",
            selection_intent="include",
            ontology_class="https://brickschema.org/schema/Brick#Power_Sensor",
            ontology_class_source="home_assistant_inferred",
        )
    )
    projection = {
        "schemaVersion": "1.0",
        "snapshotId": _SNAPSHOT_ID,
        "installationId": _INSTALLATION_ID,
        "configVersion": 9,
        "capturedAt": "2030-01-01T11:59:00Z",
        "projectionSha256": _PROJECTION_SHA256,
        "structures": [],
        "spaces": [],
        "assets": [],
        "points": [
            {
                "id": "point-1",
                "assetId": "asset-1",
                "name": "Power",
                "ontologyClass": "Power_Sensor",
                "valueType": "number",
                "canonicalUnit": "W",
                "displayUnit": "W",
                "decimals": 2,
            }
        ],
    }
    payload = canonical_json(projection)
    session.add(
        ConfigurationSnapshot(
            snapshot_id=_SNAPSHOT_ID,
            installation_id=_INSTALLATION_ID,
            config_version=9,
            projection_sha256=_PROJECTION_SHA256,
            request_sha256=_b64digest(payload),
            payload=payload,
            status="acked",
            created_at=datetime(2030, 1, 1, 11, 59, tzinfo=UTC),
            attempt_count=1,
            needs_status_check=False,
            acked_at=datetime(2030, 1, 1, 11, 59, 1, tzinfo=UTC),
        )
    )
    session.commit()


def _pending_sample(tmp_path, database_name: str):
    from one_os_addon.telemetry_delivery import TelemetryDeliveryJournal
    from one_os_addon.telemetry_outbox import TelemetryOutbox

    app = create_app(
        database_url=f"sqlite:///{tmp_path / database_name}",
        pairing_backend=False,
    )
    with app.state.session() as session:
        _selected_point_and_snapshot(session)
    identifiers = iter((_EPOCH_ID, _SEGMENT_ID))
    spool = tmp_path / f"{database_name}-spool"
    TelemetryOutbox(
        app.state.session,
        spool,
        uuid_factory=lambda: next(identifiers),
        clock=lambda: datetime(2030, 1, 1, 12, 0, tzinfo=UTC),
    ).append_state(
        point_id="point-1",
        raw_value="21.25",
        quality="good",
        observed_at="2030-01-01T12:00:00Z",
    )
    journal = TelemetryDeliveryJournal(
        app.state.session,
        spool,
        uuid_factory=lambda: _BATCH_ID,
        clock=lambda: datetime(2030, 1, 1, 12, 1, tzinfo=UTC),
    )
    assert journal.get_or_create_pending() is not None
    return app, spool


def test_delivery_journal_migration_and_orm_are_in_parity(tmp_path) -> None:
    from one_os_addon.models import (
        TelemetryBatch,
        TelemetryBatchGap,
        TelemetryBatchRecord,
        TelemetryIngestState,
    )

    app = create_app(
        database_url=f"sqlite:///{tmp_path / 'delivery.db'}",
        pairing_backend=False,
    )
    inspector = inspect(app.state.engine)
    expected_columns = {
        "telemetry_batches": {
            "batch_id",
            "installation_id",
            "installation_revision",
            "batch_authorization_revision",
            "journal_id",
            "credential_id",
            "payload_sha256",
            "request_sha256",
            "request_bytes",
            "sample_count",
            "quality_event_count",
            "gap_count",
            "status",
            "lease_owner",
            "lease_until",
            "attempt_count",
            "last_attempt_at",
            "next_attempt_at",
            "current_attempt_request_sha256",
            "current_attempt_authorization_revision",
            "current_attempt_at",
            "ack_bytes",
            "ingest_cursor",
            "acked_at",
            "terminal_reason",
            "quarantined_at",
            "created_at",
        },
        "telemetry_batch_records": {"sample_id", "batch_id", "record_kind", "ordinal"},
        "telemetry_batch_gaps": {"gap_id", "batch_id", "ordinal"},
        "telemetry_ingest_state": {"installation_id", "last_ingest_cursor", "updated_at"},
    }
    for table, columns in expected_columns.items():
        assert {column["name"] for column in inspector.get_columns(table)} == columns
    checks = {
        constraint["name"]: constraint["sqltext"]
        for constraint in inspector.get_check_constraints("telemetry_batches")
    }
    assert "quarantined" in checks["ck_telemetry_batch_status"]
    assert "immutable_conflict" in checks["ck_telemetry_batch_quarantine"]
    assert "expired_payload" in checks["ck_telemetry_batch_quarantine"]

    assert TelemetryBatch.__table__.name == "telemetry_batches"
    assert TelemetryBatchRecord.__table__.name == "telemetry_batch_records"
    assert TelemetryBatchGap.__table__.name == "telemetry_batch_gaps"
    assert TelemetryIngestState.__table__.name == "telemetry_ingest_state"
    app.state.engine.dispose()


def test_revision_binding_migration_cycles_empty_database_deterministically(tmp_path) -> None:
    import sqlite3
    from contextlib import closing

    from alembic import command
    from alembic.config import Config

    database = tmp_path / "telemetry-0013-empty.db"
    config = Config("one_os_edge/alembic.ini")
    config.set_main_option("sqlalchemy.url", f"sqlite:///{database}")
    config.attributes["explicit_database_url"] = True

    command.upgrade(config, "0014")
    command.downgrade(config, "0013")
    command.upgrade(config, "0014")

    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == ("0014",)


def test_expired_quarantine_refuses_semantics_losing_downgrade(tmp_path) -> None:
    import sqlite3
    from contextlib import closing

    from alembic import command
    from alembic.config import Config
    from one_os_addon.telemetry_delivery import TelemetryDeliveryJournal

    database = tmp_path / "telemetry-0013-expired.db"
    app, spool = _pending_sample(tmp_path, database.name)
    journal = TelemetryDeliveryJournal(
        app.state.session,
        spool,
        clock=lambda: datetime(2030, 1, 1, 12, 2, tzinfo=UTC),
    )
    leased = journal.acquire(owner="worker-a", lease_for=timedelta(seconds=30))
    assert leased is not None
    journal.quarantine(
        batch_id=leased.batch_id,
        owner="worker-a",
        reason="expired_payload",
    )
    app.state.engine.dispose()

    config = Config("one_os_edge/alembic.ini")
    config.set_main_option("sqlalchemy.url", f"sqlite:///{database}")
    config.attributes["explicit_database_url"] = True
    with pytest.raises(
        RuntimeError,
        match="refusing to discard durable telemetry authority state",
    ):
        command.downgrade(config, "0012")
    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == ("0015",)


def test_delivery_migration_refuses_to_drop_nonempty_journal(tmp_path) -> None:
    import sqlite3
    from contextlib import closing

    from alembic import command
    from alembic.config import Config

    database = tmp_path / "telemetry-0011-nonempty.db"
    config = Config("one_os_edge/alembic.ini")
    config.set_main_option("sqlalchemy.url", f"sqlite:///{database}")
    config.attributes["explicit_database_url"] = True
    command.upgrade(config, "0011")
    with closing(sqlite3.connect(database)) as connection:
        connection.execute(
            """
            INSERT INTO telemetry_batches (
              batch_id, installation_id, credential_id, payload_sha256, request_sha256,
              request_bytes, sample_count, quality_event_count, gap_count, status,
              lease_owner, lease_until, attempt_count, last_attempt_at, next_attempt_at,
              ack_bytes, ingest_cursor, acked_at, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, 1, 0, 0, 'pending', NULL, NULL, 0, NULL, NULL,
                      NULL, NULL, NULL, ?)
            """,
            (
                _BATCH_ID,
                _INSTALLATION_ID,
                _CREDENTIAL_ID,
                _PROJECTION_SHA256,
                _PROJECTION_SHA256,
                b"x",
                "2030-01-01 12:00:00",
            ),
        )
        connection.commit()

    with pytest.raises(RuntimeError, match="refusing to drop non-empty"):
        command.downgrade(config, "0010")
    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == ("0011",)
        assert connection.execute("SELECT COUNT(*) FROM telemetry_batches").fetchone() == (1,)


@pytest.mark.parametrize(
    "replacement_index",
    (
        None,
        "CREATE INDEX ix_telemetry_batches_delivery ON telemetry_batches (created_at)",
    ),
)
def test_delivery_downgrade_bad_index_fails_before_any_ddl(tmp_path, replacement_index) -> None:
    import sqlite3
    from contextlib import closing

    from alembic import command
    from alembic.config import Config

    database = tmp_path / "telemetry-0011-missing-index.db"
    config = Config("one_os_edge/alembic.ini")
    config.set_main_option("sqlalchemy.url", f"sqlite:///{database}")
    config.attributes["explicit_database_url"] = True
    command.upgrade(config, "0011")
    with closing(sqlite3.connect(database)) as connection:
        connection.execute("DROP INDEX ix_telemetry_batches_delivery")
        if replacement_index is not None:
            connection.execute(replacement_index)
        connection.commit()

    with pytest.raises(RuntimeError, match="required telemetry delivery index"):
        command.downgrade(config, "0010")
    with closing(sqlite3.connect(database)) as connection:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        assert {
            "telemetry_batches",
            "telemetry_batch_records",
            "telemetry_batch_gaps",
            "telemetry_ingest_state",
        } <= tables
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == ("0011",)


def test_pending_batch_is_immutable_and_byte_identical_after_restart(tmp_path) -> None:
    from one_os_addon.telemetry_delivery import TelemetryDeliveryJournal
    from one_os_addon.telemetry_outbox import TelemetryOutbox

    app = create_app(
        database_url=f"sqlite:///{tmp_path / 'delivery.db'}",
        pairing_backend=False,
    )
    with app.state.session() as session:
        _selected_point_and_snapshot(session)
    identifiers = iter((_EPOCH_ID, _SEGMENT_ID))
    spool = tmp_path / "telemetry-outbox"
    TelemetryOutbox(
        app.state.session,
        spool,
        uuid_factory=lambda: next(identifiers),
        clock=lambda: datetime(2030, 1, 1, 12, 0, tzinfo=UTC),
    ).append_state(
        point_id="point-1",
        raw_value="21.25",
        quality="good",
        observed_at="2030-01-01T12:00:00Z",
    )

    first = TelemetryDeliveryJournal(
        app.state.session,
        spool,
        uuid_factory=lambda: _BATCH_ID,
        clock=lambda: datetime(2030, 1, 1, 12, 1, tzinfo=UTC),
    ).get_or_create_pending()
    assert first is not None
    parsed = parse_telemetry_batch(first.request_bytes)
    assert parsed.document["batchId"] == _BATCH_ID
    assert parsed.document["credentialId"] == _CREDENTIAL_ID
    assert parsed.request_sha256 == first.request_sha256

    def forbidden_uuid():
        raise AssertionError("restart must reuse the durable pending batch")

    restarted = TelemetryDeliveryJournal(
        app.state.session,
        spool,
        uuid_factory=forbidden_uuid,
        clock=lambda: datetime(2030, 1, 1, 12, 2, tzinfo=UTC),
    ).get_or_create_pending()
    assert restarted is not None
    assert restarted.batch_id == first.batch_id
    assert restarted.request_bytes == first.request_bytes
    assert restarted.request_sha256 == first.request_sha256
    with app.state.session() as session:
        assert len(session.scalars(select(TelemetryBatch)).all()) == 1
        membership = session.scalar(select(TelemetryBatchRecord))
        assert membership is not None
        assert membership.batch_id == _BATCH_ID
    app.state.engine.dispose()


def test_retention_does_not_mutate_record_in_open_batch(tmp_path) -> None:
    from one_os_addon.telemetry_delivery import TelemetryDeliveryJournal
    from one_os_addon.telemetry_outbox import TelemetryOutbox

    app = create_app(
        database_url=f"sqlite:///{tmp_path / 'delivery-retention.db'}",
        pairing_backend=False,
    )
    with app.state.session() as session:
        _selected_point_and_snapshot(session)
    second_segment = "55555555-5555-4555-8555-555555555555"
    identifiers = iter((_EPOCH_ID, _SEGMENT_ID, second_segment))
    spool = tmp_path / "telemetry-outbox"
    initial = TelemetryOutbox(
        app.state.session,
        spool,
        uuid_factory=lambda: next(identifiers),
        clock=lambda: datetime(2030, 1, 1, 12, 0, tzinfo=UTC),
    ).append_state(
        point_id="point-1",
        raw_value="21.25",
        quality="good",
        observed_at="2030-01-01T12:00:00Z",
    )
    TelemetryDeliveryJournal(
        app.state.session,
        spool,
        uuid_factory=lambda: _BATCH_ID,
        clock=lambda: datetime(2030, 1, 1, 12, 1, tzinfo=UTC),
    ).get_or_create_pending()

    resumed = TelemetryOutbox(
        app.state.session,
        spool,
        uuid_factory=lambda: next(identifiers),
        clock=lambda: datetime(2030, 1, 9, 12, 0, tzinfo=UTC),
        max_age=timedelta(days=7),
    ).append_state(
        point_id="point-1",
        raw_value="22",
        quality="good",
        observed_at="2030-01-09T12:00:00Z",
    )

    with app.state.session() as session:
        records = session.scalars(select(TelemetryOutboxRecord)).all()
        assert {record.sample_id for record in records} == {
            initial.document["sampleId"],
            resumed.document["sampleId"],
        }
        membership = session.scalar(select(TelemetryBatchRecord))
        assert membership is not None
        assert membership.sample_id == initial.document["sampleId"]


def test_active_lease_cannot_be_stolen_and_expired_lease_reuses_batch(tmp_path) -> None:
    from one_os_addon.telemetry_delivery import TelemetryDeliveryJournal

    app, spool = _pending_sample(tmp_path, "delivery-lease.db")
    first = TelemetryDeliveryJournal(
        app.state.session,
        spool,
        clock=lambda: datetime(2030, 1, 1, 12, 1, tzinfo=UTC),
    ).acquire(owner="worker-a", lease_for=timedelta(seconds=30))
    assert first is not None
    assert first.batch_id == _BATCH_ID
    assert first.attempt_count == 1

    blocked = TelemetryDeliveryJournal(
        app.state.session,
        spool,
        clock=lambda: datetime(2030, 1, 1, 12, 1, 29, tzinfo=UTC),
    ).acquire(owner="worker-b", lease_for=timedelta(seconds=30))
    assert blocked is None

    recovered = TelemetryDeliveryJournal(
        app.state.session,
        spool,
        clock=lambda: datetime(2030, 1, 1, 12, 1, 30, tzinfo=UTC),
    ).acquire(owner="worker-b", lease_for=timedelta(seconds=30))
    assert recovered is not None
    assert recovered.batch_id == first.batch_id
    assert recovered.request_bytes == first.request_bytes
    assert recovered.attempt_count == 2


def test_ack_is_exactly_bound_and_cleans_members_only_after_commit(tmp_path) -> None:
    from one_os_addon.telemetry_delivery import (
        TelemetryDeliveryError,
        TelemetryDeliveryJournal,
    )

    app, spool = _pending_sample(tmp_path, "delivery-ack.db")
    journal = TelemetryDeliveryJournal(
        app.state.session,
        spool,
        clock=lambda: datetime(2030, 1, 1, 12, 2, tzinfo=UTC),
    )
    leased = journal.acquire(owner="worker-a", lease_for=timedelta(seconds=30))
    assert leased is not None
    ack = {
        "schemaVersion": "1.0",
        "installationId": _INSTALLATION_ID,
        "installationRevision": 7,
        "credentialId": _CREDENTIAL_ID,
        "batchId": _BATCH_ID,
        "requestSha256": leased.request_sha256,
        "acceptedSamples": 1,
        "duplicateSamples": 0,
        "acceptedQualityEvents": 0,
        "duplicateQualityEvents": 0,
        "acceptedGaps": 0,
        "duplicateGaps": 0,
        "ingestCursor": 1,
        "acceptedAt": "2030-01-01T12:02:01Z",
    }
    mismatched = dict(ack)
    mismatched["installationRevision"] = 8
    with pytest.raises(TelemetryDeliveryError, match="invalid_ack"):
        journal.acknowledge(
            batch_id=_BATCH_ID,
            owner="worker-a",
            ack_bytes=canonical_json(mismatched),
        )
    with app.state.session() as session:
        assert session.scalar(select(TelemetryOutboxRecord)) is not None
        assert session.scalar(select(TelemetryBatchRecord)) is not None

    accepted = journal.acknowledge(
        batch_id=_BATCH_ID,
        owner="worker-a",
        ack_bytes=canonical_json(ack),
    )
    assert accepted["ingestCursor"] == 1
    with app.state.session() as session:
        batch = session.get(TelemetryBatch, _BATCH_ID)
        assert batch is not None
        assert batch.status == "acked"
        cursor = session.get(TelemetryIngestState, _INSTALLATION_ID)
        assert cursor is not None
        assert cursor.last_ingest_cursor == 1
        assert session.scalar(select(TelemetryBatchRecord)) is None
        assert session.scalar(select(TelemetryOutboxRecord)) is None
        assert session.scalar(select(TelemetryOutboxSegment)) is None
    assert not list(spool.glob("*.seg"))


def test_recovery_preserves_immutable_batch_when_source_segment_is_missing(tmp_path) -> None:
    from one_os_addon.telemetry_delivery import TelemetryDeliveryJournal
    from one_os_addon.telemetry_outbox import TelemetryOutbox

    app, spool = _pending_sample(tmp_path, "delivery-recovery.db")
    pending = TelemetryDeliveryJournal(app.state.session, spool).get_or_create_pending()
    assert pending is not None
    segment_path = next(spool.glob("*.seg"))
    segment_path.unlink()

    recovered = TelemetryOutbox(app.state.session, spool).recover()
    assert recovered["convertedMissingRecords"] == 0
    restarted = TelemetryDeliveryJournal(app.state.session, spool).get_or_create_pending()
    assert restarted is not None
    assert restarted.request_bytes == pending.request_bytes
    with app.state.session() as session:
        assert session.scalar(select(TelemetryBatchRecord)) is not None
        assert session.scalar(select(TelemetryOutboxRecord)) is not None


def test_retry_delay_blocks_reacquire_until_monotone_deadline(tmp_path) -> None:
    from one_os_addon.telemetry_delivery import TelemetryDeliveryJournal

    app, spool = _pending_sample(tmp_path, "delivery-retry.db")
    leased = TelemetryDeliveryJournal(
        app.state.session,
        spool,
        clock=lambda: datetime(2030, 1, 1, 12, 1, tzinfo=UTC),
    ).acquire(owner="worker-a", lease_for=timedelta(seconds=30))
    assert leased is not None
    TelemetryDeliveryJournal(
        app.state.session,
        spool,
        clock=lambda: datetime(2030, 1, 1, 12, 1, 5, tzinfo=UTC),
    ).release_for_retry(
        batch_id=_BATCH_ID,
        owner="worker-a",
        delay=timedelta(seconds=10),
    )
    assert (
        TelemetryDeliveryJournal(
            app.state.session,
            spool,
            clock=lambda: datetime(2030, 1, 1, 12, 1, 14, 999000, tzinfo=UTC),
        ).acquire(owner="worker-b", lease_for=timedelta(seconds=30))
        is None
    )
    retried = TelemetryDeliveryJournal(
        app.state.session,
        spool,
        clock=lambda: datetime(2030, 1, 1, 12, 1, 15, tzinfo=UTC),
    ).acquire(owner="worker-b", lease_for=timedelta(seconds=30))
    assert retried is not None
    assert retried.request_bytes == leased.request_bytes
    assert retried.attempt_count == 2


def test_expired_lease_cannot_release_or_ack_batch(tmp_path) -> None:
    from one_os_addon.telemetry_delivery import (
        TelemetryDeliveryError,
        TelemetryDeliveryJournal,
    )

    app, spool = _pending_sample(tmp_path, "delivery-stale-lease.db")
    TelemetryDeliveryJournal(
        app.state.session,
        spool,
        clock=lambda: datetime(2030, 1, 1, 12, 1, tzinfo=UTC),
    ).acquire(owner="worker-a", lease_for=timedelta(seconds=30))
    stale = TelemetryDeliveryJournal(
        app.state.session,
        spool,
        clock=lambda: datetime(2030, 1, 1, 12, 1, 30, tzinfo=UTC),
    )
    with pytest.raises(TelemetryDeliveryError, match="lease_expired"):
        stale.release_for_retry(
            batch_id=_BATCH_ID,
            owner="worker-a",
            delay=timedelta(seconds=10),
        )
    pending = TelemetryDeliveryJournal(app.state.session, spool).get_or_create_pending()
    assert pending is not None
    ack = {
        "schemaVersion": "1.0",
        "installationId": _INSTALLATION_ID,
        "installationRevision": 7,
        "credentialId": _CREDENTIAL_ID,
        "batchId": _BATCH_ID,
        "requestSha256": pending.request_sha256,
        "acceptedSamples": 1,
        "duplicateSamples": 0,
        "acceptedQualityEvents": 0,
        "duplicateQualityEvents": 0,
        "acceptedGaps": 0,
        "duplicateGaps": 0,
        "ingestCursor": 1,
        "acceptedAt": "2030-01-01T12:01:31Z",
    }
    with pytest.raises(TelemetryDeliveryError, match="lease_expired"):
        stale.acknowledge(
            batch_id=_BATCH_ID,
            owner="worker-a",
            ack_bytes=canonical_json(ack),
        )
    with app.state.session() as session:
        batch = session.get(TelemetryBatch, _BATCH_ID)
        assert batch is not None
        assert batch.status == "leased"
        assert session.scalar(select(TelemetryOutboxRecord)) is not None


def test_retry_release_rechecks_clock_after_waiting_for_sqlite_write_lock(tmp_path) -> None:
    import sqlite3
    import threading

    from one_os_addon.telemetry_delivery import (
        TelemetryDeliveryError,
        TelemetryDeliveryJournal,
    )
    from sqlalchemy import event

    database_name = "delivery-lock-wait.db"
    app, spool = _pending_sample(tmp_path, database_name)
    TelemetryDeliveryJournal(
        app.state.session,
        spool,
        clock=lambda: datetime(2030, 1, 1, 12, 1, tzinfo=UTC),
    ).acquire(owner="worker-a", lease_for=timedelta(seconds=30))

    begin_attempted = threading.Event()
    worker_thread_id: list[int] = []

    def observe_begin(_conn, _cursor, statement, _parameters, _context, _many):
        if worker_thread_id and threading.get_ident() == worker_thread_id[0]:
            if statement.strip().upper() == "BEGIN IMMEDIATE":
                begin_attempted.set()

    event.listen(app.state.engine, "before_cursor_execute", observe_begin)
    blocker = sqlite3.connect(tmp_path / database_name)
    blocker.execute("BEGIN IMMEDIATE")
    outcome: list[BaseException | None] = []

    def release_after_wait() -> None:
        worker_thread_id.append(threading.get_ident())
        journal = TelemetryDeliveryJournal(
            app.state.session,
            spool,
            clock=lambda: (
                datetime(2030, 1, 1, 12, 1, 30, tzinfo=UTC)
                if begin_attempted.is_set()
                else datetime(2030, 1, 1, 12, 1, 29, tzinfo=UTC)
            ),
        )
        try:
            journal.release_for_retry(
                batch_id=_BATCH_ID,
                owner="worker-a",
                delay=timedelta(seconds=10),
            )
        except BaseException as error:
            outcome.append(error)
        else:
            outcome.append(None)

    worker = threading.Thread(target=release_after_wait)
    worker.start()
    assert begin_attempted.wait(timeout=2)
    blocker.commit()
    blocker.close()
    worker.join(timeout=2)
    event.remove(app.state.engine, "before_cursor_execute", observe_begin)

    assert not worker.is_alive()
    assert len(outcome) == 1
    assert isinstance(outcome[0], TelemetryDeliveryError)
    assert str(outcome[0]) == "lease_expired"
    with app.state.session() as session:
        batch = session.get(TelemetryBatch, _BATCH_ID)
        assert batch is not None
        assert batch.status == "leased"
        assert batch.next_attempt_at is None


def test_acquire_starts_lease_deadline_after_sqlite_write_lock(tmp_path) -> None:
    import sqlite3
    import threading

    from one_os_addon.telemetry_delivery import TelemetryDeliveryJournal
    from sqlalchemy import event

    database_name = "delivery-acquire-lock-wait.db"
    app, spool = _pending_sample(tmp_path, database_name)
    begin_attempted = threading.Event()
    second_session_entered = threading.Event()
    allow_second_session = threading.Event()
    worker_thread_id: list[int] = []
    session_calls = 0
    session_calls_lock = threading.Lock()

    def gated_session_factory():
        nonlocal session_calls
        with session_calls_lock:
            session_calls += 1
            current_call = session_calls
        if current_call == 2:
            second_session_entered.set()
            assert allow_second_session.wait(timeout=2)
        return app.state.session()

    def observe_begin(_conn, _cursor, statement, _parameters, _context, _many):
        if (
            worker_thread_id
            and threading.get_ident() == worker_thread_id[0]
            and second_session_entered.is_set()
            and allow_second_session.is_set()
        ):
            if statement.strip().upper() == "BEGIN IMMEDIATE":
                begin_attempted.set()

    event.listen(app.state.engine, "before_cursor_execute", observe_begin)
    outcome = []

    def acquire_after_wait() -> None:
        worker_thread_id.append(threading.get_ident())
        leased = TelemetryDeliveryJournal(
            gated_session_factory,
            spool,
            clock=lambda: (
                datetime(2030, 1, 1, 12, 1, 30, tzinfo=UTC)
                if begin_attempted.is_set()
                else datetime(2030, 1, 1, 12, 1, 29, tzinfo=UTC)
            ),
        ).acquire(owner="worker-a", lease_for=timedelta(seconds=30))
        outcome.append(leased)

    worker = threading.Thread(target=acquire_after_wait)
    worker.start()
    assert second_session_entered.wait(timeout=2)
    blocker = sqlite3.connect(tmp_path / database_name)
    blocker.execute("BEGIN IMMEDIATE")
    allow_second_session.set()
    assert begin_attempted.wait(timeout=2)
    blocker.commit()
    blocker.close()
    worker.join(timeout=2)
    event.remove(app.state.engine, "before_cursor_execute", observe_begin)

    assert not worker.is_alive()
    assert len(outcome) == 1
    assert outcome[0] is not None
    lease_until = outcome[0].lease_until
    assert lease_until is not None
    if lease_until.tzinfo is None:
        lease_until = lease_until.replace(tzinfo=UTC)
    assert lease_until == datetime(2030, 1, 1, 12, 2, tzinfo=UTC)


def _ack_for(request_bytes: bytes) -> bytes:
    parsed = parse_telemetry_batch(request_bytes)
    document = parsed.document
    return canonical_json(
        {
            "schemaVersion": "1.0",
            "installationId": document["installationId"],
            "installationRevision": document["installationRevision"],
            "credentialId": document["credentialId"],
            "batchId": document["batchId"],
            "requestSha256": parsed.request_sha256,
            "acceptedSamples": len(document["samples"]),
            "duplicateSamples": 0,
            "acceptedQualityEvents": len(document["qualityEvents"]),
            "duplicateQualityEvents": 0,
            "acceptedGaps": len(document["gaps"]),
            "duplicateGaps": 0,
            "ingestCursor": 1,
            "acceptedAt": "2030-01-01T12:02:01Z",
        }
    )


class _AcceptingTransport:
    def __init__(self):
        self.requests = []

    def upload(self, request_bytes, certificate_pem, private_key_pem):
        self.requests.append((request_bytes, certificate_pem, private_key_pem))
        return _ack_for(request_bytes)


class _FailingTransport:
    def __init__(self, code="unreachable"):
        self.code = code
        self.requests = []

    def upload(self, request_bytes, certificate_pem, private_key_pem):
        self.requests.append((request_bytes, certificate_pem, private_key_pem))
        raise TelemetryTransportError(self.code)


class _InvalidAckTransport:
    def upload(self, _request_bytes, _certificate_pem, _private_key_pem):
        return b"{}"


class _ConflictThenAcceptTransport:
    def __init__(self, terminal_error="immutable_conflict"):
        self.terminal_error = terminal_error
        self.requests = []

    def upload(self, request_bytes, _certificate_pem, _private_key_pem):
        self.requests.append(request_bytes)
        if len(self.requests) == 1:
            raise TelemetryTransportError(self.terminal_error)
        return _ack_for(request_bytes)


def _delivery_worker(journal, transport, *, identity_provider=_delivery_identity):
    return TelemetryDeliveryWorker(
        journal,
        identity_provider,
        lambda _credential_id, _revision: True,
        transport,
        owner="worker-a",
        random_uniform=lambda _floor, _ceiling: 5,
        clock=lambda: datetime(2030, 1, 1, 12, 2, tzinfo=UTC),
    )


def test_delivery_worker_fails_closed_before_lease_when_identity_is_ineligible(tmp_path) -> None:
    from one_os_addon.telemetry_delivery import TelemetryDeliveryJournal

    app, spool = _pending_sample(tmp_path, "delivery-worker-ineligible.db")
    journal = TelemetryDeliveryJournal(
        app.state.session,
        spool,
        clock=lambda: datetime(2030, 1, 1, 12, 2, tzinfo=UTC),
    )
    identity = _delivery_identity()
    identity["status"] = "repair_required"
    transport = _AcceptingTransport()

    result = _delivery_worker(journal, transport, identity_provider=lambda: identity).run_once()

    assert result == "identity_ineligible"
    assert transport.requests == []
    with app.state.session() as session:
        batch = session.get(TelemetryBatch, _BATCH_ID)
        assert batch is not None and batch.status == "pending" and batch.attempt_count == 0


def test_delivery_worker_commits_exact_ack_and_uses_active_material(tmp_path) -> None:
    from one_os_addon.telemetry_delivery import TelemetryDeliveryJournal

    app, spool = _pending_sample(tmp_path, "delivery-worker-ack.db")
    journal = TelemetryDeliveryJournal(
        app.state.session,
        spool,
        clock=lambda: datetime(2030, 1, 1, 12, 2, tzinfo=UTC),
    )
    transport = _AcceptingTransport()

    assert _delivery_worker(journal, transport).run_once() == "acked"

    assert len(transport.requests) == 1
    request_bytes, certificate, private_key = transport.requests[0]
    assert parse_telemetry_batch(request_bytes).document["credentialId"] == _CREDENTIAL_ID
    assert certificate == "certificatechain"
    assert private_key == "private-key"
    with app.state.session() as session:
        batch = session.get(TelemetryBatch, _BATCH_ID)
        assert batch is not None and batch.status == "acked"
        assert batch.ack_bytes == _ack_for(request_bytes)
        state = session.get(TelemetryIngestState, _INSTALLATION_ID)
        assert state is not None and state.last_ingest_cursor == 1


def test_delivery_worker_keeps_old_batch_bytes_but_uses_renewed_active_identity(tmp_path) -> None:
    from one_os_addon.telemetry_delivery import TelemetryDeliveryJournal

    app, spool = _pending_sample(tmp_path, "delivery-worker-renewed-identity.db")
    journal = TelemetryDeliveryJournal(
        app.state.session,
        spool,
        clock=lambda: datetime(2030, 1, 1, 12, 2, tzinfo=UTC),
    )
    renewed = _delivery_identity()
    renewed["credentialId"] = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    transport = _AcceptingTransport()

    result = _delivery_worker(journal, transport, identity_provider=lambda: renewed).run_once()

    assert result == "acked"
    request_bytes, certificate, private_key = transport.requests[0]
    assert parse_telemetry_batch(request_bytes).document["credentialId"] == _CREDENTIAL_ID
    assert certificate == "certificatechain"
    assert private_key == "private-key"


def test_delivery_worker_materializes_outbox_before_leasing_and_uploading(tmp_path) -> None:
    from one_os_addon.telemetry_delivery import TelemetryDeliveryJournal

    app, spool = _pending_sample(tmp_path, "delivery-worker-materializes.db")
    with app.state.session() as session:
        existing = session.get(TelemetryBatch, _BATCH_ID)
        assert existing is not None
        session.delete(existing)
        session.commit()
        assert session.query(TelemetryBatch).count() == 0
        assert session.query(TelemetryBatchRecord).count() == 0
        assert session.query(TelemetryOutboxRecord).count() == 1
    journal = TelemetryDeliveryJournal(
        app.state.session,
        spool,
        uuid_factory=lambda: _BATCH_ID,
        clock=lambda: datetime(2030, 1, 1, 12, 2, tzinfo=UTC),
    )
    transport = _AcceptingTransport()

    assert _delivery_worker(journal, transport).run_once() == "acked"

    assert len(transport.requests) == 1
    uploaded = parse_telemetry_batch(transport.requests[0][0]).document
    assert len(uploaded["samples"]) == 1
    with app.state.session() as session:
        batch = session.get(TelemetryBatch, _BATCH_ID)
        assert batch is not None and batch.status == "acked"
        assert session.query(TelemetryBatchRecord).count() == 0
        assert session.query(TelemetryOutboxRecord).count() == 0


def test_delivery_worker_releases_invalid_ack_without_cleaning_batch(tmp_path) -> None:
    from one_os_addon.telemetry_delivery import TelemetryDeliveryJournal

    app, spool = _pending_sample(tmp_path, "delivery-worker-invalid-ack.db")
    journal = TelemetryDeliveryJournal(
        app.state.session,
        spool,
        clock=lambda: datetime(2030, 1, 1, 12, 2, tzinfo=UTC),
    )

    assert _delivery_worker(journal, _InvalidAckTransport()).run_once() == "invalid_ack"

    with app.state.session() as session:
        batch = session.get(TelemetryBatch, _BATCH_ID)
        assert batch is not None and batch.status == "pending" and batch.ack_bytes is None
        assert session.query(TelemetryBatchRecord).count() == 1
        assert session.query(TelemetryOutboxRecord).count() == 1


@pytest.mark.parametrize("code", ["unreachable", "rate_limited", "trust_error"])
def test_delivery_worker_releases_transport_failure_for_durable_retry(tmp_path, code) -> None:
    from one_os_addon.telemetry_delivery import TelemetryDeliveryJournal

    app, spool = _pending_sample(tmp_path, f"delivery-worker-{code}.db")
    journal = TelemetryDeliveryJournal(
        app.state.session,
        spool,
        clock=lambda: datetime(2030, 1, 1, 12, 2, tzinfo=UTC),
    )

    assert _delivery_worker(journal, _FailingTransport(code)).run_once() == code

    with app.state.session() as session:
        batch = session.get(TelemetryBatch, _BATCH_ID)
        assert batch is not None and batch.status == "pending"
        assert batch.attempt_count == 1
        expected_delay = 5
        next_attempt = batch.next_attempt_at
        assert next_attempt is not None
        if next_attempt.tzinfo is None:
            next_attempt = next_attempt.replace(tzinfo=UTC)
        assert next_attempt == datetime(2030, 1, 1, 12, 2, expected_delay, tzinfo=UTC)


def test_delivery_worker_revocation_marks_identity_and_blocks_second_upload(tmp_path) -> None:
    from one_os_addon.telemetry_delivery import TelemetryDeliveryJournal

    app, spool = _pending_sample(tmp_path, "delivery-worker-revoked.db")
    journal = TelemetryDeliveryJournal(
        app.state.session,
        spool,
        clock=lambda: datetime(2030, 1, 1, 12, 2, tzinfo=UTC),
    )
    transport = _FailingTransport("revoked")
    marked = []
    worker = TelemetryDeliveryWorker(
        journal,
        _delivery_identity,
        lambda credential_id, revision: marked.append((credential_id, revision)) or True,
        transport,
        owner="worker-a",
        clock=lambda: datetime(2030, 1, 1, 12, 2, tzinfo=UTC),
    )

    assert worker.run_once() == "revoked"
    assert worker.run_once() == "identity_ineligible"
    assert len(transport.requests) == 1
    assert marked == [(_CREDENTIAL_ID, 7)]


def test_delivery_worker_late_fenced_401_does_not_block_newer_revision(tmp_path) -> None:
    from one_os_addon.telemetry_delivery import TelemetryDeliveryJournal

    app, spool = _pending_sample(tmp_path, "delivery-worker-stale-revocation.db")
    current = [datetime(2030, 1, 1, 12, 2, tzinfo=UTC)]
    journal = TelemetryDeliveryJournal(app.state.session, spool, clock=lambda: current[0])
    transport = _FailingTransport("revoked")
    identity = _delivery_identity()
    fenced = []

    def stale_revocation(credential_id: str, revision: int) -> bool:
        fenced.append((credential_id, revision))
        identity["revision"] = revision + 1
        return False

    worker = TelemetryDeliveryWorker(
        journal,
        lambda: identity.copy(),
        stale_revocation,
        transport,
        owner="worker-a",
        base_backoff=5,
        max_backoff=5,
        clock=lambda: current[0],
    )

    assert worker.run_once() == "revocation_unconfirmed"
    current[0] += timedelta(seconds=6)
    assert worker.run_once() == "revocation_unconfirmed"
    assert len(transport.requests) == 2
    assert fenced == [(_CREDENTIAL_ID, 7), (_CREDENTIAL_ID, 8)]
    assert worker._blocked_identity is None


@pytest.mark.parametrize("terminal_error", ["immutable_conflict", "expired_payload"])
def test_terminal_batch_is_quarantined_once_and_does_not_block_later_batch(
    tmp_path, terminal_error
) -> None:
    from one_os_addon.telemetry_delivery import TelemetryDeliveryJournal

    app, spool = _pending_sample(tmp_path, "delivery-worker-quarantine.db")
    second_batch_id = "55555555-5555-4555-8555-555555555555"
    with app.state.session() as session:
        first = session.get(TelemetryBatch, _BATCH_ID)
        assert first is not None
        second_document = parse_telemetry_batch(first.request_bytes).document.copy()
        second_document["batchId"] = second_batch_id
        second_bytes = canonical_json(second_document)
        parsed_second = parse_telemetry_batch(second_bytes)
        session.add(
            TelemetryBatch(
                batch_id=second_batch_id,
                installation_id=first.installation_id,
                installation_revision=first.installation_revision,
                batch_authorization_revision=first.batch_authorization_revision,
                journal_id=first.journal_id + 1,
                credential_id=first.credential_id,
                payload_sha256=first.payload_sha256,
                request_sha256=parsed_second.request_sha256,
                request_bytes=second_bytes,
                sample_count=first.sample_count,
                quality_event_count=first.quality_event_count,
                gap_count=first.gap_count,
                status="pending",
                lease_owner=None,
                lease_until=None,
                attempt_count=0,
                last_attempt_at=None,
                next_attempt_at=None,
                ack_bytes=None,
                ingest_cursor=None,
                acked_at=None,
                created_at=datetime(2030, 1, 1, 12, 2, 1, tzinfo=UTC),
            )
        )
        session.commit()
    journal = TelemetryDeliveryJournal(
        app.state.session,
        spool,
        clock=lambda: datetime(2030, 1, 1, 12, 2, 2, tzinfo=UTC),
    )
    transport = _ConflictThenAcceptTransport(terminal_error)
    worker = _delivery_worker(journal, transport)

    assert worker.run_once() == terminal_error
    restarted_worker = _delivery_worker(journal, transport)
    assert restarted_worker.run_once() == "acked"
    assert len(transport.requests) == 2
    assert parse_telemetry_batch(transport.requests[0]).document["batchId"] == _BATCH_ID
    assert parse_telemetry_batch(transport.requests[1]).document["batchId"] == second_batch_id
    with app.state.session() as session:
        first = session.get(TelemetryBatch, _BATCH_ID)
        second = session.get(TelemetryBatch, second_batch_id)
        assert first is not None and first.status == "quarantined"
        assert first.terminal_reason == terminal_error
        assert first.quarantined_at == datetime(2030, 1, 1, 12, 2, 2)
        assert first.lease_owner is None and first.lease_until is None
        assert session.query(TelemetryBatchRecord).filter_by(batch_id=_BATCH_ID).count() == 1
        assert session.query(TelemetryOutboxRecord).count() == 1
        assert second is not None and second.status == "acked"


def test_quarantine_is_reason_owner_and_deadline_fenced(tmp_path) -> None:
    from one_os_addon.telemetry_delivery import (
        TelemetryDeliveryError,
        TelemetryDeliveryJournal,
    )

    app, spool = _pending_sample(tmp_path, "delivery-quarantine-fencing.db")
    leased = TelemetryDeliveryJournal(
        app.state.session,
        spool,
        clock=lambda: datetime(2030, 1, 1, 12, 2, tzinfo=UTC),
    ).acquire(owner="worker-a", lease_for=timedelta(seconds=30))
    assert leased is not None
    active = TelemetryDeliveryJournal(
        app.state.session,
        spool,
        clock=lambda: datetime(2030, 1, 1, 12, 2, 29, tzinfo=UTC),
    )
    with pytest.raises(TelemetryDeliveryError, match="invalid_terminal_reason"):
        active.quarantine(batch_id=_BATCH_ID, owner="worker-a", reason="operator_reset")
    with pytest.raises(TelemetryDeliveryError, match="lease_not_owned"):
        active.quarantine(batch_id=_BATCH_ID, owner="worker-stale", reason="immutable_conflict")
    expired = TelemetryDeliveryJournal(
        app.state.session,
        spool,
        clock=lambda: datetime(2030, 1, 1, 12, 2, 30, tzinfo=UTC),
    )
    with pytest.raises(TelemetryDeliveryError, match="lease_expired"):
        expired.quarantine(batch_id=_BATCH_ID, owner="worker-a", reason="immutable_conflict")
    with app.state.session() as session:
        batch = session.get(TelemetryBatch, _BATCH_ID)
        assert batch is not None and batch.status == "leased"
        assert batch.terminal_reason is None and batch.quarantined_at is None


def test_quarantine_migration_refuses_downgrade_that_would_discard_terminal_batch(
    tmp_path,
) -> None:
    from alembic import command
    from alembic.config import Config
    from one_os_addon.telemetry_delivery import TelemetryDeliveryJournal

    database_name = "delivery-quarantine-migration.db"
    app, spool = _pending_sample(tmp_path, database_name)
    journal = TelemetryDeliveryJournal(
        app.state.session,
        spool,
        clock=lambda: datetime(2030, 1, 1, 12, 2, tzinfo=UTC),
    )
    assert journal.acquire(owner="worker-a", lease_for=timedelta(seconds=30)) is not None
    journal.quarantine(batch_id=_BATCH_ID, owner="worker-a", reason="immutable_conflict")
    app.state.engine.dispose()
    config = Config("one_os_edge/alembic.ini")
    config.set_main_option("sqlalchemy.url", f"sqlite:///{tmp_path / database_name}")
    config.attributes["explicit_database_url"] = True

    with pytest.raises(
        RuntimeError,
        match="refusing to discard durable telemetry authority state",
    ):
        command.downgrade(config, "0011")


def test_response_loss_retries_byte_identical_batch_and_commits_later_ack(tmp_path) -> None:
    from one_os_addon.telemetry_delivery import TelemetryDeliveryJournal

    app, spool = _pending_sample(tmp_path, "delivery-worker-response-loss.db")
    first_journal = TelemetryDeliveryJournal(
        app.state.session,
        spool,
        clock=lambda: datetime(2030, 1, 1, 12, 2, tzinfo=UTC),
    )
    lost = _FailingTransport()
    assert _delivery_worker(first_journal, lost).run_once() == "unreachable"

    retry_journal = TelemetryDeliveryJournal(
        app.state.session,
        spool,
        clock=lambda: datetime(2030, 1, 1, 12, 2, 5, tzinfo=UTC),
    )
    accepted = _AcceptingTransport()
    retry_worker = TelemetryDeliveryWorker(
        retry_journal,
        _delivery_identity,
        lambda _credential_id, _revision: True,
        accepted,
        owner="worker-b",
        clock=lambda: datetime(2030, 1, 1, 12, 2, 5, tzinfo=UTC),
    )

    assert retry_worker.run_once() == "acked"
    assert accepted.requests[0][0] == lost.requests[0][0]
    with app.state.session() as session:
        batch = session.get(TelemetryBatch, _BATCH_ID)
        assert batch is not None and batch.status == "acked" and batch.attempt_count == 2


def test_current_authority_v2_batch_and_ack_require_durable_activation(tmp_path) -> None:
    import json
    from pathlib import Path

    from one_os_addon.telemetry_authority import TelemetryAuthorityManager
    from one_os_addon.telemetry_contract_v2 import (
        canonical_json as canonical_json_v2,
    )
    from one_os_addon.telemetry_contract_v2 import (
        parse_telemetry_ack as parse_ack_v2,
    )
    from one_os_addon.telemetry_contract_v2 import (
        parse_telemetry_batch as parse_batch_v2,
    )
    from one_os_addon.telemetry_delivery import TelemetryDeliveryJournal

    app, spool = _pending_sample(tmp_path, "delivery-v2.db")
    with app.state.session() as session:
        batch = session.get(TelemetryBatch, _BATCH_ID)
        session.delete(batch)
        identity = session.get(EdgeIdentity, 1)
        identity.certificate_sha256 = "s5-H8FWELCE6O7LgjcBTbUc6RyjNQp33u6Vk4NKCvv8"
        identity.telemetry_authorization_revision = 7
        session.commit()

    vector_path = (
        Path(__file__).resolve().parents[3] / "docs/reference/contracts/telemetry/v2/"
        "one-os-phase2c-p-canonical-vectors-v2-draft4-20260825.json"
    )
    capability = json.loads(vector_path.read_text())["capability"]["canonicalUtf8"].encode()

    class Client:
        def get_capability(self, *_):
            return capability

        def enable(self, request_bytes, *_):
            request = json.loads(request_bytes)
            cap = json.loads(capability)
            return canonical_json_v2(
                {
                    "protocol": "2.0",
                    "requestId": request["requestId"],
                    "installationId": request["installationId"],
                    "status": "enabled",
                    "protocolId": request["protocolId"],
                    "telemetryBatchSchemaSha256": request["telemetryBatchSchemaSha256"],
                    "telemetryAckSchemaSha256": request["telemetryAckSchemaSha256"],
                    "telemetryErrorSchemaSha256": request["telemetryErrorSchemaSha256"],
                    "renewalControlSchemaSha256": request["renewalControlSchemaSha256"],
                    "capabilitySha256": request["capabilitySha256"],
                    "capabilityServerNonce": request["capabilityServerNonce"],
                    "issuedAt": cap["issuedAt"],
                    "expiresAt": cap["expiresAt"],
                    "telemetryAuthorizationRevision": 7,
                    "enabledAt": "2030-01-01T12:00:30Z",
                }
            )

    identity = _delivery_identity()
    identity["certificateSha256"] = "s5-H8FWELCE6O7LgjcBTbUc6RyjNQp33u6Vk4NKCvv8"
    authority = TelemetryAuthorityManager(
        app.state.session,
        Client(),
        lambda: identity,
        lambda _: b"s" * 64,
        uuid_factory=lambda: "00000000-0000-4000-8000-00000000aaaa",
        nonce_factory=lambda: b"z" * 32,
        clock=lambda: datetime(2030, 1, 1, 12, 0, 30, tzinfo=UTC),
    )
    authority.activate()
    journal = TelemetryDeliveryJournal(
        app.state.session,
        spool,
        authority_manager=authority,
        uuid_factory=lambda: _BATCH_ID,
        clock=lambda: datetime(2030, 1, 1, 12, 1, tzinfo=UTC),
    )
    pending = journal.get_or_create_pending()
    assert pending is not None and pending.protocol == "2.0"
    parsed = parse_batch_v2(pending.request_bytes)
    assert parsed.document["batchAuthorizationRevision"] == 7
    assert "installationRevision" not in parsed.document

    leased = journal.acquire(owner="worker-v2", lease_for=timedelta(seconds=30))
    assert leased is not None
    journal.mark_current_attempt(batch_id=leased.batch_id, owner="worker-v2")
    with app.state.session() as session:
        durable = session.get(TelemetryBatch, leased.batch_id)
        assert durable.current_attempt_request_sha256 == parsed.request_sha256
        assert durable.current_attempt_authorization_revision == 7
        assert durable.current_attempt_at is not None
    ack = canonical_json_v2(
        {
            "schemaVersion": "one-os-telemetry-ack/v2",
            "authorizationMode": "current",
            "installationId": _INSTALLATION_ID,
            "credentialId": _CREDENTIAL_ID,
            "batchId": _BATCH_ID,
            "batchAuthorizationRevision": 7,
            "ingestAuthorizationRevision": 7,
            "requestSha256": parsed.request_sha256,
            "acceptedSamples": 1,
            "duplicateSamples": 0,
            "acceptedQualityEvents": 0,
            "duplicateQualityEvents": 0,
            "acceptedGaps": 0,
            "duplicateGaps": 0,
            "ingestCursor": 1,
            "acceptedAt": "2030-01-01T12:01:01Z",
        }
    )
    parse_ack_v2(
        ack,
        expected_batch=parsed.document,
        expected_request_sha256=parsed.request_sha256,
        expected_ingest_authorization_revision=7,
        previous_ingest_cursor=-1,
    )
    result = journal.acknowledge(batch_id=leased.batch_id, owner="worker-v2", ack_bytes=ack)
    assert result["authorizationMode"] == "current"


@pytest.mark.parametrize(
    "reason",
    [
        "outbox_capacity",
        "retention_expired",
        "storage_failure",
        "clock_discontinuity",
        "operator_reset",
    ],
)
def test_v2_gap_projection_closes_v1_reason_lexicon(reason) -> None:
    from one_os_addon.telemetry_delivery import _v2_record

    projected = _v2_record(
        {
            "detectedAt": "2030-01-01T12:00:00Z",
            "reason": reason,
        }
    )

    assert projected == {
        "detectedAt": "2030-01-01T12:00:00.000Z",
        "reason": "storage_failure",
    }


def test_v2_static_activation_conflict_fails_closed_to_no_new_protocol_mix(tmp_path) -> None:
    from one_os_addon.telemetry_delivery import TelemetryDeliveryJournal

    app, spool = _pending_sample(tmp_path, "delivery-v2-conflict.db")
    with app.state.session() as session:
        row = session.get(TelemetryBatch, _BATCH_ID)
        assert row is not None
        row.request_bytes = row.request_bytes.replace(
            b'"schemaVersion":"1.0"', b'"schemaVersion":"one-os-telemetry-batch/v2"'
        )
        session.commit()
    journal = TelemetryDeliveryJournal(app.state.session, spool)
    with pytest.raises(TelemetryDeliveryError, match="stored_batch_protocol_conflict"):
        journal.get_or_create_pending()


def test_stale_v2_activation_fails_before_batch_mutation_without_v1_downgrade(tmp_path) -> None:
    from one_os_addon.models import TelemetryJournalState
    from one_os_addon.telemetry_authority import TelemetryAuthorityError
    from one_os_addon.telemetry_delivery import TelemetryDeliveryJournal
    from sqlalchemy import func, select

    app = create_app(
        database_url=f"sqlite:///{tmp_path / 'stale-activation.db'}", pairing_backend=False
    )

    class StaleAuthority:
        def enabled_revision(self):
            raise TelemetryAuthorityError("durable_activation_conflict")

    with app.state.session() as session:
        before = (
            session.get(TelemetryJournalState, 1).last_journal_id,
            session.scalar(select(func.count()).select_from(TelemetryBatch)),
        )

    journal = TelemetryDeliveryJournal(
        app.state.session,
        tmp_path / "spool",
        authority_manager=StaleAuthority(),
    )
    with pytest.raises(TelemetryDeliveryError, match="activation_state_conflict"):
        journal.get_or_create_pending()

    with app.state.session() as session:
        after = (
            session.get(TelemetryJournalState, 1).last_journal_id,
            session.scalar(select(func.count()).select_from(TelemetryBatch)),
        )
    assert after == before


def test_historical_ack_requires_exact_durable_receipt_hash(tmp_path) -> None:
    import json
    from pathlib import Path

    from one_os_addon.models import TelemetryJournalState
    from one_os_addon.telemetry_authority_cut import TelemetryAuthorityCutRepository
    from one_os_addon.telemetry_contract_v2 import canonical_json as canonical_json_v2
    from one_os_addon.telemetry_contract_v2 import parse_telemetry_batch as parse_batch_v2
    from one_os_addon.telemetry_delivery import TelemetryDeliveryJournal

    app = create_app(database_url=f"sqlite:///{tmp_path / 'historical.db'}", pairing_backend=False)
    spool = tmp_path / "spool"
    vector_path = (
        Path(__file__).resolve().parents[3] / "docs/reference/contracts/telemetry/v2/"
        "one-os-phase2c-p-canonical-vectors-v2-draft4-20260825.json"
    )
    vector = json.loads(vector_path.read_text())
    request = vector["telemetryBatches256"][0]["canonicalUtf8"].encode()
    parsed = parse_batch_v2(request)
    operation_id = "55555555-5555-4555-8555-555555555555"
    cut_id = "66666666-6666-4666-8666-666666666666"
    pending_id = "77777777-7777-4777-8777-777777777777"
    now = datetime(2030, 1, 1, 12, 0, tzinfo=UTC)
    with app.state.session() as session:
        identity = session.get(EdgeIdentity, 1)
        identity.installation_id = parsed.document["installationId"]
        identity.lineage_id = parsed.document["credentialId"]
        identity.status = "paired"
        identity.credential_id = parsed.document["credentialId"]
        identity.installation_revision = 5
        identity.telemetry_authorization_revision = 7
        session.add(
            Site(
                id="historical-site",
                installation_id=parsed.document["installationId"],
                name="Historical delivery fixture",
            )
        )
        session.get(TelemetryJournalState, 1).last_journal_id = 1
        session.add(
            TelemetryBatch(
                batch_id=parsed.document["batchId"],
                installation_id=parsed.document["installationId"],
                installation_revision=5,
                batch_authorization_revision=7,
                journal_id=1,
                credential_id=parsed.document["credentialId"],
                payload_sha256=parsed.payload_sha256,
                request_sha256=parsed.request_sha256,
                request_bytes=request,
                sample_count=1,
                quality_event_count=0,
                gap_count=0,
                status="pending",
                lease_owner=None,
                lease_until=None,
                attempt_count=0,
                last_attempt_at=None,
                next_attempt_at=None,
                ack_bytes=None,
                ingest_cursor=None,
                acked_at=None,
                created_at=now,
            )
        )
        session.commit()
        lineage_id = identity.lineage_id
    entry = {
        "batchAuthorizationRevision": 7,
        "batchId": parsed.document["batchId"],
        "credentialId": parsed.document["credentialId"],
        "journalId": 1,
        "requestLength": len(request),
        "requestSha256": parsed.request_sha256,
    }
    manifest = {
        "batchAuthorizationRevision": 7,
        "createdAt": "2030-01-01T12:00:00Z",
        "cutJournalMaxId": 1,
        "cutMarkerId": cut_id,
        "entries": [entry],
        "entryCount": 1,
        "firstJournalId": 1,
        "installationId": parsed.document["installationId"],
        "lastJournalId": 1,
        "lineageId": lineage_id,
        "renewalOperationId": operation_id,
        "schemaVersion": "one-os-telemetry-backlog-manifest/v2",
        "totalRequestBytes": len(request),
    }
    manifest_bytes = canonical_json_v2(manifest)
    receipt = {
        "allowedTransportCredentialIds": sorted([parsed.document["credentialId"], pending_id]),
        "backlogManifestSha256": _b64digest(manifest_bytes),
        "cutJournalMaxId": 1,
        "cutMarkerId": cut_id,
        "entries": [entry],
        "entryCount": 1,
        "expiresAt": "2030-01-02T12:00:00Z",
        "historicalAuthorizationRevision": 7,
        "ingestAuthorizationRevision": 8,
        "installationId": parsed.document["installationId"],
        "lineageId": lineage_id,
        "notBefore": "2030-01-01T12:00:00Z",
        "receiptNonce": "4" * 64,
        "renewalOperationId": operation_id,
        "renewalRequestSha256": "A" * 43,
        "schemaVersion": "one-os-historical-authorization-receipt/v2",
        "totalRequestBytes": len(request),
    }
    cuts = TelemetryAuthorityCutRepository(app.state.session)
    cuts.open(cut_id, operation_id, manifest_bytes, 1, now)
    cuts.store_receipt(cut_id, receipt, now)
    receipt_hash = _b64digest(canonical_json_v2(receipt))
    journal = TelemetryDeliveryJournal(app.state.session, spool, clock=lambda: now)
    leased = journal.acquire(owner="historical", lease_for=timedelta(seconds=30))
    assert leased is not None and leased.historical_receipt_sha256 == receipt_hash

    def ack(receipt_sha: str) -> bytes:
        return canonical_json_v2(
            {
                "schemaVersion": "one-os-telemetry-ack/v2",
                "authorizationMode": "historical_backlog",
                "installationId": parsed.document["installationId"],
                "credentialId": parsed.document["credentialId"],
                "batchId": parsed.document["batchId"],
                "batchAuthorizationRevision": 7,
                "ingestAuthorizationRevision": 8,
                "requestSha256": parsed.request_sha256,
                "historicalAuthorizationReceiptSha256": receipt_sha,
                "acceptedSamples": 1,
                "duplicateSamples": 0,
                "acceptedQualityEvents": 0,
                "duplicateQualityEvents": 0,
                "acceptedGaps": 0,
                "duplicateGaps": 0,
                "ingestCursor": 1,
                "acceptedAt": "2030-01-01T12:00:01Z",
            }
        )

    with pytest.raises(TelemetryDeliveryError, match="invalid_ack"):
        journal.acknowledge(batch_id=leased.batch_id, owner="historical", ack_bytes=ack("B" * 43))

    current_ack = canonical_json_v2(
        {
            "schemaVersion": "one-os-telemetry-ack/v2",
            "authorizationMode": "current",
            "installationId": parsed.document["installationId"],
            "credentialId": parsed.document["credentialId"],
            "batchId": parsed.document["batchId"],
            "batchAuthorizationRevision": 7,
            "ingestAuthorizationRevision": 7,
            "requestSha256": parsed.request_sha256,
            "acceptedSamples": 1,
            "duplicateSamples": 0,
            "acceptedQualityEvents": 0,
            "duplicateQualityEvents": 0,
            "acceptedGaps": 0,
            "duplicateGaps": 0,
            "ingestCursor": 1,
            "acceptedAt": "2030-01-01T12:00:01Z",
        }
    )
    with pytest.raises(TelemetryDeliveryError, match="invalid_ack"):
        journal.acknowledge(
            batch_id=leased.batch_id,
            owner="historical",
            ack_bytes=current_ack,
        )
    with app.state.session() as session:
        durable = session.get(TelemetryBatch, leased.batch_id)
        assert durable.status == "leased"
        durable.current_attempt_request_sha256 = durable.request_sha256
        durable.current_attempt_authorization_revision = durable.batch_authorization_revision
        durable.current_attempt_at = now - timedelta(minutes=1)
        session.commit()

    restarted = TelemetryDeliveryJournal(app.state.session, spool, clock=lambda: now)
    assert (
        restarted.acknowledge(
            batch_id=leased.batch_id,
            owner="historical",
            ack_bytes=current_ack,
        )["authorizationMode"]
        == "current"
    )
    with app.state.session() as session:
        assert session.get(TelemetryBatch, leased.batch_id).status == "acked"
    with pytest.raises(TelemetryDeliveryError, match="renewal_cut_blocks_batch_formation"):
        restarted.get_or_create_pending()
