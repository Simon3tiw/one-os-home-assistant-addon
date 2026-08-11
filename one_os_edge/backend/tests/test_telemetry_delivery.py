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
from sqlalchemy import inspect, select

_INSTALLATION_ID = "00000000-0000-4000-8000-000000000002"
_CREDENTIAL_ID = "11111111-1111-4111-8111-111111111111"
_SNAPSHOT_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
_EPOCH_ID = "22222222-2222-4222-8222-222222222222"
_SEGMENT_ID = "33333333-3333-4333-8333-333333333333"
_BATCH_ID = "44444444-4444-4444-8444-444444444444"
_PROJECTION_SHA256 = "wSVUqL2kxfm_YRmU5wB4Lfm8KmbyOJjeVIdmKa73RVc"


def _b64digest(value: bytes) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(value).digest()).rstrip(b"=").decode()


def _selected_point_and_snapshot(session) -> None:
    identity = session.get(EdgeIdentity, 1)
    assert identity is not None
    identity.installation_id = _INSTALLATION_ID
    identity.status = "paired"
    identity.credential_id = _CREDENTIAL_ID
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
            "ack_bytes",
            "ingest_cursor",
            "acked_at",
            "created_at",
        },
        "telemetry_batch_records": {"sample_id", "batch_id", "record_kind", "ordinal"},
        "telemetry_batch_gaps": {"gap_id", "batch_id", "ordinal"},
        "telemetry_ingest_state": {"installation_id", "last_ingest_cursor", "updated_at"},
    }
    for table, columns in expected_columns.items():
        assert {column["name"] for column in inspector.get_columns(table)} == columns

    assert TelemetryBatch.__table__.name == "telemetry_batches"
    assert TelemetryBatchRecord.__table__.name == "telemetry_batch_records"
    assert TelemetryBatchGap.__table__.name == "telemetry_batch_gaps"
    assert TelemetryIngestState.__table__.name == "telemetry_ingest_state"
    app.state.engine.dispose()


def test_delivery_migration_cycles_empty_database_deterministically(tmp_path) -> None:
    import sqlite3
    from contextlib import closing

    from alembic import command
    from alembic.config import Config

    database = tmp_path / "telemetry-0011-empty.db"
    config = Config("one_os_edge/alembic.ini")
    config.set_main_option("sqlalchemy.url", f"sqlite:///{database}")
    config.attributes["explicit_database_url"] = True

    command.upgrade(config, "0011")
    command.downgrade(config, "0010")
    command.upgrade(config, "0011")

    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == ("0011",)


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
    mismatched["credentialId"] = "66666666-6666-4666-8666-666666666666"
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
