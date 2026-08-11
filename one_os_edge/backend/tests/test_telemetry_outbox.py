import base64
import errno
import hashlib
import json
from datetime import UTC, datetime

import pytest
from one_os_addon.app import create_app, migrate_database
from one_os_addon.models import (
    Asset,
    ConfigurationSnapshot,
    EdgeIdentity,
    Point,
    Site,
    Space,
    Structure,
    TelemetryGap,
    TelemetryOutboxRecord,
    TelemetryOutboxSegment,
    TelemetryStream,
)
from one_os_addon.sync import SyncCoordinator
from one_os_addon.telemetry_contract_v1 import canonical_json
from sqlalchemy import create_engine, event, inspect, select

_INSTALLATION_ID = "00000000-0000-4000-8000-000000000002"
_CREDENTIAL_ID = "11111111-1111-4111-8111-111111111111"
_SNAPSHOT_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
_EPOCH_ID = "22222222-2222-4222-8222-222222222222"
_SEGMENT_ID = "33333333-3333-4333-8333-333333333333"
_SEGMENT_2_ID = "44444444-4444-4444-8444-444444444444"
_SEGMENT_3_ID = "55555555-5555-4555-8555-555555555555"
_GAP_ID = "66666666-6666-4666-8666-666666666666"
_SEGMENT_4_ID = "77777777-7777-4777-8777-777777777777"
_PROJECTION_SHA256 = "wSVUqL2kxfm_YRmU5wB4Lfm8KmbyOJjeVIdmKa73RVc"


def _b64digest(value: bytes) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(value).digest()).rstrip(b"=").decode()


def _segment_names(spool) -> list[str]:
    return sorted(path.name for path in spool.iterdir() if path.name.endswith(".seg"))


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
    session.flush()
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


def test_telemetry_migration_cycles_empty_database_deterministically(tmp_path) -> None:
    import sqlite3
    from contextlib import closing

    from alembic import command
    from alembic.config import Config

    database = tmp_path / "telemetry-0010-empty.db"
    config = Config("one_os_edge/alembic.ini")
    config.set_main_option("sqlalchemy.url", f"sqlite:///{database}")
    config.attributes["explicit_database_url"] = True

    command.upgrade(config, "0010")
    command.downgrade(config, "0009")
    command.upgrade(config, "0010")

    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == ("0010",)


def test_telemetry_outbox_metadata_schema_is_migration_owned(tmp_path) -> None:
    database_url = f"sqlite:///{tmp_path / 'commissioning.db'}"

    migrate_database(database_url)
    engine = create_engine(database_url)
    try:
        inspector = inspect(engine)
        assert {
            "telemetry_streams",
            "telemetry_outbox_segments",
            "telemetry_outbox_records",
            "telemetry_gaps",
        } <= set(inspector.get_table_names())

        stream_columns = {column["name"] for column in inspector.get_columns("telemetry_streams")}
        assert stream_columns == {
            "point_id",
            "installation_id",
            "stream_epoch_id",
            "next_sequence",
            "created_at",
            "updated_at",
        }

        record_columns = {
            column["name"] for column in inspector.get_columns("telemetry_outbox_records")
        }
        assert record_columns == {
            "sample_id",
            "point_id",
            "stream_epoch_id",
            "sequence",
            "record_kind",
            "config_version",
            "snapshot_id",
            "projection_sha256",
            "segment_id",
            "segment_offset",
            "record_length",
            "created_at",
        }

        gap_columns = {column["name"] for column in inspector.get_columns("telemetry_gaps")}
        assert gap_columns == {
            "gap_id",
            "installation_id",
            "point_id",
            "stream_epoch_id",
            "config_version",
            "snapshot_id",
            "projection_sha256",
            "first_missing_sequence",
            "last_missing_sequence",
            "detected_at",
            "reason",
            "status",
        }
    finally:
        engine.dispose()


def test_selected_numeric_state_is_durable_before_return(tmp_path) -> None:
    from one_os_addon.telemetry_outbox import TelemetryOutbox

    app = create_app(
        database_url=f"sqlite:///{tmp_path / 'commissioning.db'}", pairing_backend=False
    )
    with app.state.session() as session:
        _selected_point_and_snapshot(session)

    identifiers = iter((_EPOCH_ID, _SEGMENT_ID))
    outbox = TelemetryOutbox(
        app.state.session,
        tmp_path / "telemetry-outbox",
        uuid_factory=lambda: next(identifiers),
        clock=lambda: datetime(2030, 1, 1, 12, 0, 0, 100000, tzinfo=UTC),
    )

    stored = outbox.append_state(
        point_id="point-1",
        raw_value="21.25",
        quality="good",
        observed_at="2030-01-01T12:00:00.000Z",
    )

    expected_without_id = {
        "schemaVersion": "1.0",
        "installationId": _INSTALLATION_ID,
        "configVersion": 9,
        "snapshotId": _SNAPSHOT_ID,
        "projectionSha256": _PROJECTION_SHA256,
        "pointId": "point-1",
        "streamEpochId": _EPOCH_ID,
        "sequence": 0,
        "observedAt": "2030-01-01T12:00:00.000Z",
        "receivedAtEdge": "2030-01-01T12:00:00.100Z",
        "valueQuality": "good",
        "decimalValue": "21.25",
    }
    expected_id = _b64digest(b"ONE.OS-TELEMETRY-RECORD-V1\0" + canonical_json(expected_without_id))
    expected = {**expected_without_id, "sampleId": expected_id}
    expected_bytes = canonical_json(expected)

    assert stored.document == expected
    assert stored.canonical_bytes == expected_bytes
    assert (tmp_path / "telemetry-outbox" / f"{_SEGMENT_ID}.seg").read_bytes() == expected_bytes

    with app.state.session() as session:
        stream = session.get(TelemetryStream, "point-1")
        segment = session.get(TelemetryOutboxSegment, _SEGMENT_ID)
        record = session.scalar(select(TelemetryOutboxRecord))
        assert stream is not None
        assert (stream.stream_epoch_id, stream.next_sequence) == (_EPOCH_ID, 1)
        assert segment is not None
        assert (segment.committed_bytes, segment.live_bytes, segment.sealed) == (
            len(expected_bytes),
            len(expected_bytes),
            True,
        )
        assert record is not None
        assert (
            record.sample_id,
            record.sequence,
            record.segment_offset,
            record.record_length,
        ) == (expected_id, 0, 0, len(expected_bytes))


def test_segment_writer_fsyncs_spool_directory_before_return(tmp_path, monkeypatch) -> None:
    import one_os_addon.telemetry_outbox as telemetry_module

    app = create_app(
        database_url=f"sqlite:///{tmp_path / 'commissioning.db'}", pairing_backend=False
    )
    with app.state.session() as session:
        _selected_point_and_snapshot(session)

    synced_directories = []
    monkeypatch.setattr(
        telemetry_module,
        "_fsync_directory",
        lambda path: synced_directories.append(path),
        raising=False,
    )
    identifiers = iter((_EPOCH_ID, _SEGMENT_ID))
    spool = tmp_path / "telemetry-outbox"
    telemetry_module.TelemetryOutbox(
        app.state.session,
        spool,
        uuid_factory=lambda: next(identifiers),
        clock=lambda: datetime(2030, 1, 1, 12, 0, tzinfo=UTC),
        control_reserve_bytes=0,
    ).append_state(
        point_id="point-1",
        raw_value="20",
        quality="good",
        observed_at="2030-01-01T12:00:00Z",
    )

    assert synced_directories == [spool]


def test_revoked_identity_cannot_collect_new_telemetry(tmp_path) -> None:
    from one_os_addon.telemetry_outbox import TelemetryOutbox, TelemetryOutboxError

    app = create_app(
        database_url=f"sqlite:///{tmp_path / 'commissioning.db'}", pairing_backend=False
    )
    with app.state.session() as session:
        _selected_point_and_snapshot(session)
        identity = session.get(EdgeIdentity, 1)
        assert identity is not None
        identity.status = "revoked"
        session.commit()

    spool = tmp_path / "telemetry-outbox"
    with pytest.raises(TelemetryOutboxError, match="identity_not_telemetry_eligible"):
        TelemetryOutbox(
            app.state.session,
            spool,
            uuid_factory=lambda: _EPOCH_ID,
            clock=lambda: datetime(2030, 1, 1, 12, 0, tzinfo=UTC),
        ).append_state(
            point_id="point-1",
            raw_value="20",
            quality="good",
            observed_at="2030-01-01T12:00:00Z",
        )

    with app.state.session() as session:
        assert session.get(TelemetryStream, "point-1") is None
    assert _segment_names(spool) == []


def test_unavailable_state_is_stored_as_quality_event_without_value(tmp_path) -> None:
    from one_os_addon.telemetry_outbox import TelemetryOutbox

    app = create_app(
        database_url=f"sqlite:///{tmp_path / 'commissioning.db'}", pairing_backend=False
    )
    with app.state.session() as session:
        _selected_point_and_snapshot(session)

    identifiers = iter((_EPOCH_ID, _SEGMENT_ID))
    outbox = TelemetryOutbox(
        app.state.session,
        tmp_path / "telemetry-outbox",
        uuid_factory=lambda: next(identifiers),
        clock=lambda: datetime(2030, 1, 1, 12, 1, 0, 10000, tzinfo=UTC),
    )

    stored = outbox.append_state(
        point_id="point-1",
        raw_value="unavailable",
        quality="unavailable",
        observed_at="2030-01-01T12:01:00Z",
    )

    without_id = {
        "schemaVersion": "1.0",
        "installationId": _INSTALLATION_ID,
        "configVersion": 9,
        "snapshotId": _SNAPSHOT_ID,
        "projectionSha256": _PROJECTION_SHA256,
        "pointId": "point-1",
        "streamEpochId": _EPOCH_ID,
        "sequence": 0,
        "observedAt": "2030-01-01T12:01:00Z",
        "receivedAtEdge": "2030-01-01T12:01:00.010Z",
        "valueQuality": "unavailable",
    }
    expected_id = _b64digest(b"ONE.OS-TELEMETRY-RECORD-V1\0" + canonical_json(without_id))
    assert stored.document == {**without_id, "sampleId": expected_id}
    assert "decimalValue" not in stored.document
    assert "booleanValue" not in stored.document

    with app.state.session() as session:
        record = session.get(TelemetryOutboxRecord, expected_id)
        assert record is not None
        assert record.record_kind == "quality"


def test_crash_after_fsync_rolls_back_metadata_and_recovery_removes_orphan(tmp_path) -> None:
    from one_os_addon.telemetry_outbox import TelemetryOutbox

    app = create_app(
        database_url=f"sqlite:///{tmp_path / 'commissioning.db'}", pairing_backend=False
    )
    with app.state.session() as session:
        _selected_point_and_snapshot(session)

    class InjectedCrash(RuntimeError):
        pass

    def crash(point: str) -> None:
        if point == "after_segment_fsync":
            raise InjectedCrash

    identifiers = iter((_EPOCH_ID, _SEGMENT_ID))
    spool = tmp_path / "telemetry-outbox"
    outbox = TelemetryOutbox(
        app.state.session,
        spool,
        uuid_factory=lambda: next(identifiers),
        clock=lambda: datetime(2030, 1, 1, 12, 0, tzinfo=UTC),
        crash_hook=crash,
    )

    with pytest.raises(InjectedCrash):
        outbox.append_state(
            point_id="point-1",
            raw_value="21.25",
            quality="good",
            observed_at="2030-01-01T12:00:00Z",
        )

    orphan = spool / f"{_SEGMENT_ID}.seg"
    assert orphan.is_file()
    with app.state.session() as session:
        assert session.get(TelemetryStream, "point-1") is None
        assert session.get(TelemetryOutboxSegment, _SEGMENT_ID) is None
        assert session.scalar(select(TelemetryOutboxRecord)) is None

    recovered = TelemetryOutbox(app.state.session, spool).recover()
    assert recovered == {
        "removedOrphans": 1,
        "truncatedSegments": 0,
        "convertedMissingRecords": 0,
    }
    assert not orphan.exists()


@pytest.mark.asyncio
async def test_state_event_commits_point_and_telemetry_metadata_together(tmp_path) -> None:
    from one_os_addon.telemetry_outbox import TelemetryOutbox

    app = create_app(
        database_url=f"sqlite:///{tmp_path / 'commissioning.db'}", pairing_backend=False
    )
    with app.state.session() as session:
        _selected_point_and_snapshot(session)

    identifiers = iter((_EPOCH_ID, _SEGMENT_ID))
    outbox = TelemetryOutbox(
        app.state.session,
        tmp_path / "telemetry-outbox",
        uuid_factory=lambda: next(identifiers),
        clock=lambda: datetime(2030, 1, 1, 12, 2, tzinfo=UTC),
    )
    coordinator = SyncCoordinator(
        object(),
        app.state.session,
        telemetry_outbox=outbox,
        full_interval=60,
    )

    applied = await coordinator.apply_state_event(
        {
            "event_type": "state_changed",
            "data": {
                "new_state": {
                    "entity_id": "sensor.power",
                    "state": "22.00",
                    "last_updated": "2030-01-01T12:02:00Z",
                    "attributes": {"unit_of_measurement": "W"},
                }
            },
        },
        coordinator.generation,
    )

    assert applied is True
    with app.state.session() as session:
        point = session.get(Point, "point-1")
        record = session.scalar(select(TelemetryOutboxRecord))
        stream = session.get(TelemetryStream, "point-1")
        assert point is not None
        assert point.raw_value == "22.00"
        assert record is not None
        assert stream is not None
        assert (record.sequence, stream.next_sequence) == (0, 1)
        payload = (tmp_path / "telemetry-outbox" / f"{record.segment_id}.seg").read_bytes()
        document = json.loads(payload)
        assert document["decimalValue"] == "22"
        assert document["snapshotId"] == _SNAPSHOT_ID


@pytest.mark.asyncio
async def test_enospc_commits_point_and_storage_gap_in_one_transaction(tmp_path) -> None:
    from one_os_addon.telemetry_outbox import TelemetryOutbox

    app = create_app(
        database_url=f"sqlite:///{tmp_path / 'commissioning.db'}", pairing_backend=False
    )
    with app.state.session() as session:
        _selected_point_and_snapshot(session)

    def no_space(path, payload: bytes) -> None:
        path.write_bytes(payload[:7])
        raise OSError(errno.ENOSPC, "injected telemetry spool full")

    identifiers = iter((_EPOCH_ID, _SEGMENT_ID, _GAP_ID))
    spool = tmp_path / "telemetry-outbox"
    outbox = TelemetryOutbox(
        app.state.session,
        spool,
        uuid_factory=lambda: next(identifiers),
        clock=lambda: datetime(2030, 1, 1, 12, 2, tzinfo=UTC),
        segment_writer=no_space,
    )
    coordinator = SyncCoordinator(
        object(),
        app.state.session,
        telemetry_outbox=outbox,
        full_interval=60,
    )

    applied = await coordinator.apply_state_event(
        {
            "event_type": "state_changed",
            "data": {
                "new_state": {
                    "entity_id": "sensor.power",
                    "state": "22.00",
                    "last_updated": "2030-01-01T12:02:00Z",
                    "attributes": {"unit_of_measurement": "W"},
                }
            },
        },
        coordinator.generation,
    )

    assert applied is True
    with app.state.session() as session:
        point = session.get(Point, "point-1")
        gap = session.scalar(select(TelemetryGap))
        stream = session.get(TelemetryStream, "point-1")
        assert point is not None
        assert point.raw_value == "22.00"
        assert gap is not None
        assert (gap.first_missing_sequence, gap.last_missing_sequence) == (0, 0)
        assert (gap.reason, gap.status) == ("storage_failure", "pending")
        assert stream is not None
        assert stream.next_sequence == 1
        assert session.scalar(select(TelemetryOutboxRecord)) is None
        assert session.scalar(select(TelemetryOutboxSegment)) is None
    assert _segment_names(spool) == []


def test_byte_limit_evicts_oldest_record_into_durable_gap_after_commit(tmp_path) -> None:
    from one_os_addon.telemetry_outbox import TelemetryOutbox

    app = create_app(
        database_url=f"sqlite:///{tmp_path / 'commissioning.db'}", pairing_backend=False
    )
    with app.state.session() as session:
        _selected_point_and_snapshot(session)

    identifiers = iter((_EPOCH_ID, _SEGMENT_ID, _SEGMENT_2_ID, _GAP_ID, _SEGMENT_3_ID))
    times = iter(
        (
            datetime(2030, 1, 1, 12, 0, tzinfo=UTC),
            datetime(2030, 1, 1, 12, 1, tzinfo=UTC),
            datetime(2030, 1, 1, 12, 2, tzinfo=UTC),
        )
    )
    spool = tmp_path / "telemetry-outbox"
    outbox = TelemetryOutbox(
        app.state.session,
        spool,
        uuid_factory=lambda: next(identifiers),
        clock=lambda: next(times),
        max_bytes=1024,
    )

    for minute, value in enumerate(("20", "21", "22")):
        outbox.append_state(
            point_id="point-1",
            raw_value=value,
            quality="good",
            observed_at=f"2030-01-01T12:0{minute}:00Z",
        )

    with app.state.session() as session:
        records = session.scalars(
            select(TelemetryOutboxRecord).order_by(TelemetryOutboxRecord.sequence)
        ).all()
        gap = session.scalar(select(TelemetryGap))
        stream = session.get(TelemetryStream, "point-1")
        segments = session.scalars(select(TelemetryOutboxSegment)).all()
        assert [record.sequence for record in records] == [1, 2]
        assert gap is not None
        assert (
            gap.stream_epoch_id,
            gap.first_missing_sequence,
            gap.last_missing_sequence,
            gap.reason,
            gap.status,
        ) == (_EPOCH_ID, 0, 0, "outbox_capacity", "pending")
        assert stream is not None
        assert stream.next_sequence == 3
        assert sum(segment.live_bytes for segment in segments) <= 1024

    assert not (spool / f"{_SEGMENT_ID}.seg").exists()
    assert (spool / f"{_SEGMENT_2_ID}.seg").is_file()
    assert (spool / f"{_SEGMENT_3_ID}.seg").is_file()


def test_recovery_converts_missing_segment_record_to_storage_failure_gap(tmp_path) -> None:
    from one_os_addon.telemetry_outbox import TelemetryOutbox

    app = create_app(
        database_url=f"sqlite:///{tmp_path / 'commissioning.db'}", pairing_backend=False
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
        raw_value="20",
        quality="good",
        observed_at="2030-01-01T12:00:00Z",
    )
    (spool / f"{_SEGMENT_ID}.seg").unlink()

    recovered = TelemetryOutbox(
        app.state.session,
        spool,
        uuid_factory=lambda: _GAP_ID,
        clock=lambda: datetime(2030, 1, 2, 12, 0, tzinfo=UTC),
    ).recover()

    assert recovered["convertedMissingRecords"] == 1
    with app.state.session() as session:
        assert session.scalar(select(TelemetryOutboxRecord)) is None
        assert session.scalar(select(TelemetryOutboxSegment)) is None
        gap = session.scalar(select(TelemetryGap))
        stream = session.get(TelemetryStream, "point-1")
        assert gap is not None
        assert (
            gap.first_missing_sequence,
            gap.last_missing_sequence,
            gap.reason,
            gap.status,
        ) == (0, 0, "storage_failure", "pending")
        assert stream is not None
        assert stream.next_sequence == 1


def test_recovery_converts_same_size_corruption_to_storage_failure_gap(tmp_path) -> None:
    from one_os_addon.telemetry_outbox import TelemetryOutbox

    app = create_app(
        database_url=f"sqlite:///{tmp_path / 'commissioning.db'}", pairing_backend=False
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
        raw_value="20",
        quality="good",
        observed_at="2030-01-01T12:00:00Z",
    )
    segment_path = spool / f"{_SEGMENT_ID}.seg"
    corrupted = segment_path.read_bytes().replace(b'"decimalValue":"20"', b'"decimalValue":"21"')
    assert len(corrupted) == segment_path.stat().st_size
    segment_path.write_bytes(corrupted)

    recovered = TelemetryOutbox(
        app.state.session,
        spool,
        uuid_factory=lambda: _GAP_ID,
        clock=lambda: datetime(2030, 1, 2, 12, 0, tzinfo=UTC),
    ).recover()

    assert recovered["convertedMissingRecords"] == 1
    with app.state.session() as session:
        assert session.scalar(select(TelemetryOutboxRecord)) is None
        assert session.scalar(select(TelemetryOutboxSegment)) is None
        gap = session.scalar(select(TelemetryGap))
        assert gap is not None
        assert gap.reason == "storage_failure"
    assert not segment_path.exists()


def test_crash_after_retention_commit_leaves_recoverable_orphan(tmp_path) -> None:
    from one_os_addon.telemetry_outbox import TelemetryOutbox

    app = create_app(
        database_url=f"sqlite:///{tmp_path / 'commissioning.db'}", pairing_backend=False
    )
    with app.state.session() as session:
        _selected_point_and_snapshot(session)

    class InjectedCrash(RuntimeError):
        pass

    def crash(point: str) -> None:
        if point == "after_retention_commit_before_cleanup":
            raise InjectedCrash

    identifiers = iter((_EPOCH_ID, _SEGMENT_ID, _SEGMENT_2_ID, _GAP_ID, _SEGMENT_3_ID))
    spool = tmp_path / "telemetry-outbox"
    outbox = TelemetryOutbox(
        app.state.session,
        spool,
        uuid_factory=lambda: next(identifiers),
        clock=lambda: datetime(2030, 1, 1, 12, 0, tzinfo=UTC),
        crash_hook=crash,
        max_bytes=1024,
    )

    outbox.append_state(
        point_id="point-1",
        raw_value="20",
        quality="good",
        observed_at="2030-01-01T12:00:00Z",
    )
    outbox.append_state(
        point_id="point-1",
        raw_value="21",
        quality="good",
        observed_at="2030-01-01T12:00:00Z",
    )
    with pytest.raises(InjectedCrash):
        outbox.append_state(
            point_id="point-1",
            raw_value="22",
            quality="good",
            observed_at="2030-01-01T12:00:00Z",
        )

    with app.state.session() as session:
        sequences = list(
            session.scalars(
                select(TelemetryOutboxRecord.sequence).order_by(TelemetryOutboxRecord.sequence)
            )
        )
        gap = session.scalar(select(TelemetryGap))
        assert sequences == [1, 2]
        assert gap is not None
        assert (gap.first_missing_sequence, gap.last_missing_sequence) == (0, 0)
    assert (spool / f"{_SEGMENT_ID}.seg").is_file()

    recovered = TelemetryOutbox(app.state.session, spool).recover()

    assert recovered["removedOrphans"] == 1
    assert not (spool / f"{_SEGMENT_ID}.seg").exists()
    assert (spool / f"{_SEGMENT_2_ID}.seg").is_file()
    assert (spool / f"{_SEGMENT_3_ID}.seg").is_file()


def test_seven_day_boundary_evicts_record_into_retention_expired_gap(tmp_path) -> None:
    from one_os_addon.telemetry_outbox import TelemetryOutbox

    app = create_app(
        database_url=f"sqlite:///{tmp_path / 'commissioning.db'}", pairing_backend=False
    )
    with app.state.session() as session:
        _selected_point_and_snapshot(session)

    identifiers = iter((_EPOCH_ID, _SEGMENT_ID, _GAP_ID, _SEGMENT_2_ID))
    times = iter(
        (
            datetime(2030, 1, 1, 12, 0, tzinfo=UTC),
            datetime(2030, 1, 8, 12, 0, tzinfo=UTC),
        )
    )
    spool = tmp_path / "telemetry-outbox"
    outbox = TelemetryOutbox(
        app.state.session,
        spool,
        uuid_factory=lambda: next(identifiers),
        clock=lambda: next(times),
    )

    outbox.append_state(
        point_id="point-1",
        raw_value="20",
        quality="good",
        observed_at="2030-01-01T12:00:00Z",
    )
    outbox.append_state(
        point_id="point-1",
        raw_value="21",
        quality="good",
        observed_at="2030-01-08T12:00:00Z",
    )

    with app.state.session() as session:
        sequences = list(session.scalars(select(TelemetryOutboxRecord.sequence)))
        gap = session.scalar(select(TelemetryGap))
        stream = session.get(TelemetryStream, "point-1")
        assert sequences == [1]
        assert gap is not None
        assert (
            gap.first_missing_sequence,
            gap.last_missing_sequence,
            gap.reason,
            gap.status,
        ) == (0, 0, "retention_expired", "pending")
        assert stream is not None
        assert stream.next_sequence == 2
    assert not (spool / f"{_SEGMENT_ID}.seg").exists()
    assert (spool / f"{_SEGMENT_2_ID}.seg").is_file()


def test_enospc_consumes_sequence_only_with_durable_storage_failure_gap(tmp_path) -> None:
    from one_os_addon.telemetry_outbox import TelemetryOutbox

    app = create_app(
        database_url=f"sqlite:///{tmp_path / 'commissioning.db'}", pairing_backend=False
    )
    with app.state.session() as session:
        _selected_point_and_snapshot(session)

    def no_space(path, payload: bytes) -> None:
        path.write_bytes(payload[:7])
        raise OSError(errno.ENOSPC, "injected telemetry spool full")

    identifiers = iter((_EPOCH_ID, _SEGMENT_ID, _GAP_ID))
    spool = tmp_path / "telemetry-outbox"
    outbox = TelemetryOutbox(
        app.state.session,
        spool,
        uuid_factory=lambda: next(identifiers),
        clock=lambda: datetime(2030, 1, 1, 12, 0, tzinfo=UTC),
        segment_writer=no_space,
    )

    stored = outbox.append_state(
        point_id="point-1",
        raw_value="20",
        quality="good",
        observed_at="2030-01-01T12:00:00Z",
    )

    assert stored.document["reason"] == "storage_failure"
    assert stored.document["firstMissingSequence"] == 0
    assert stored.document["lastMissingSequence"] == 0
    assert stored.canonical_bytes == canonical_json(stored.document)
    with app.state.session() as session:
        assert session.scalar(select(TelemetryOutboxRecord)) is None
        assert session.scalar(select(TelemetryOutboxSegment)) is None
        gap = session.scalar(select(TelemetryGap))
        stream = session.get(TelemetryStream, "point-1")
        assert gap is not None
        assert (gap.reason, gap.status) == ("storage_failure", "pending")
        assert stream is not None
        assert stream.next_sequence == 1
    assert _segment_names(spool) == []


@pytest.mark.asyncio
async def test_database_commit_failure_rolls_back_state_and_removes_new_orphan(tmp_path) -> None:
    from one_os_addon.telemetry_outbox import TelemetryOutbox

    app = create_app(
        database_url=f"sqlite:///{tmp_path / 'commissioning.db'}", pairing_backend=False
    )
    with app.state.session() as session:
        _selected_point_and_snapshot(session)

    identifiers = iter((_EPOCH_ID, _SEGMENT_ID))
    spool = tmp_path / "telemetry-outbox"
    outbox = TelemetryOutbox(
        app.state.session,
        spool,
        uuid_factory=lambda: next(identifiers),
        clock=lambda: datetime(2030, 1, 1, 12, 2, tzinfo=UTC),
    )
    coordinator = SyncCoordinator(
        object(),
        app.state.session,
        telemetry_outbox=outbox,
        full_interval=60,
    )

    class InjectedCommitFailure(RuntimeError):
        pass

    def fail_commit(_session) -> None:
        raise InjectedCommitFailure

    session_class = app.state.session.class_
    event.listen(session_class, "before_commit", fail_commit)
    try:
        with pytest.raises(InjectedCommitFailure):
            await coordinator.apply_state_event(
                {
                    "event_type": "state_changed",
                    "data": {
                        "new_state": {
                            "entity_id": "sensor.power",
                            "state": "22.00",
                            "last_updated": "2030-01-01T12:02:00Z",
                            "attributes": {"unit_of_measurement": "W"},
                        }
                    },
                },
                coordinator.generation,
            )
    finally:
        event.remove(session_class, "before_commit", fail_commit)

    with app.state.session() as session:
        point = session.get(Point, "point-1")
        assert point is not None
        assert point.raw_value == "21.25"
        assert session.get(TelemetryStream, "point-1") is None
        assert session.scalar(select(TelemetryOutboxRecord)) is None
        assert session.scalar(select(TelemetryOutboxSegment)) is None
        assert session.scalar(select(TelemetryGap)) is None
    assert _segment_names(spool) == []


@pytest.mark.asyncio
async def test_post_append_precommit_failure_removes_new_orphan(tmp_path, monkeypatch) -> None:
    from one_os_addon.telemetry_outbox import TelemetryOutbox

    app = create_app(
        database_url=f"sqlite:///{tmp_path / 'commissioning.db'}", pairing_backend=False
    )
    with app.state.session() as session:
        _selected_point_and_snapshot(session)

    identifiers = iter((_EPOCH_ID, _SEGMENT_ID))
    spool = tmp_path / "telemetry-outbox"
    coordinator = SyncCoordinator(
        app.state.ha,
        app.state.session,
        telemetry_outbox=TelemetryOutbox(
            app.state.session,
            spool,
            uuid_factory=lambda: next(identifiers),
            clock=lambda: datetime(2030, 1, 1, 12, 0, tzinfo=UTC),
        ),
    )

    def fail_record_evidence(*_args, **_kwargs):
        raise RuntimeError("injected pre-commit failure")

    monkeypatch.setattr("one_os_addon.sync.record_evidence", fail_record_evidence)
    with pytest.raises(RuntimeError, match="injected pre-commit failure"):
        await coordinator.apply_state_event(
            {
                "event_type": "state_changed",
                "data": {
                    "new_state": {
                        "entity_id": "sensor.power",
                        "state": "20",
                        "last_updated": "2030-01-01T12:00:00Z",
                        "attributes": {"unit_of_measurement": "W"},
                    }
                },
            },
            coordinator.generation,
        )

    with app.state.session() as session:
        point = session.get(Point, "point-1")
        assert point is not None
        assert point.raw_value == "21.25"
        assert session.get(TelemetryStream, "point-1") is None
        assert session.scalar(select(TelemetryOutboxRecord)) is None
        assert session.scalar(select(TelemetryOutboxSegment)) is None
    assert _segment_names(spool) == []


def test_statvfs_watermark_uses_control_reserve_for_storage_gap(tmp_path, monkeypatch) -> None:
    import one_os_addon.telemetry_outbox as telemetry_module

    app = create_app(
        database_url=f"sqlite:///{tmp_path / 'commissioning.db'}", pairing_backend=False
    )
    with app.state.session() as session:
        _selected_point_and_snapshot(session)

    class NoFreeBlocks:
        f_bavail = 0
        f_frsize = 4096

    monkeypatch.setattr(telemetry_module.os, "statvfs", lambda _path: NoFreeBlocks())

    def forbidden_writer(_path, _payload):
        raise AssertionError("data writer must not run below the control watermark")

    identifiers = iter((_EPOCH_ID, _GAP_ID))
    spool = tmp_path / "telemetry-outbox"
    stored = telemetry_module.TelemetryOutbox(
        app.state.session,
        spool,
        uuid_factory=lambda: next(identifiers),
        clock=lambda: datetime(2030, 1, 1, 12, 0, tzinfo=UTC),
        segment_writer=forbidden_writer,
        control_reserve_bytes=4096,
        minimum_free_bytes=8192,
    ).append_state(
        point_id="point-1",
        raw_value="20",
        quality="good",
        observed_at="2030-01-01T12:00:00Z",
    )

    assert stored.document["reason"] == "storage_failure"
    with app.state.session() as session:
        stream = session.get(TelemetryStream, "point-1")
        gap = session.scalar(select(TelemetryGap))
        assert stream is not None
        assert stream.next_sequence == 1
        assert gap is not None
        assert gap.reason == "storage_failure"
        assert session.scalar(select(TelemetryOutboxRecord)) is None
    assert (spool / ".telemetry-control-reserve").stat().st_size == 4096


def test_enospc_releases_control_reserve_before_gap_commit_and_restores_it(tmp_path) -> None:
    from one_os_addon.telemetry_outbox import TelemetryOutbox

    app = create_app(
        database_url=f"sqlite:///{tmp_path / 'commissioning.db'}", pairing_backend=False
    )
    with app.state.session() as session:
        _selected_point_and_snapshot(session)

    spool = tmp_path / "telemetry-outbox"
    reserve = spool / ".telemetry-control-reserve"

    def no_space(_path, _payload):
        raise OSError(errno.ENOSPC, "injected full spool")

    def reserve_released_before_commit(_session) -> None:
        assert not reserve.exists()

    session_class = app.state.session.class_
    event.listen(session_class, "before_commit", reserve_released_before_commit)
    identifiers = iter((_EPOCH_ID, _SEGMENT_ID, _GAP_ID))
    try:
        stored = TelemetryOutbox(
            app.state.session,
            spool,
            uuid_factory=lambda: next(identifiers),
            clock=lambda: datetime(2030, 1, 1, 12, 0, tzinfo=UTC),
            segment_writer=no_space,
            control_reserve_bytes=4096,
            minimum_free_bytes=0,
        ).append_state(
            point_id="point-1",
            raw_value="20",
            quality="good",
            observed_at="2030-01-01T12:00:00Z",
        )
    finally:
        event.remove(session_class, "before_commit", reserve_released_before_commit)

    assert stored.document["reason"] == "storage_failure"
    assert reserve.stat().st_size == 4096


def test_enospc_gap_commit_failure_rolls_back_sequence_and_restores_reserve(tmp_path) -> None:
    from one_os_addon.telemetry_outbox import TelemetryOutbox

    app = create_app(
        database_url=f"sqlite:///{tmp_path / 'commissioning.db'}", pairing_backend=False
    )
    with app.state.session() as session:
        _selected_point_and_snapshot(session)

    spool = tmp_path / "telemetry-outbox"
    reserve = spool / ".telemetry-control-reserve"

    def no_space(_path, _payload):
        raise OSError(errno.ENOSPC, "injected full spool")

    def fail_gap_commit(_session) -> None:
        assert not reserve.exists()
        raise RuntimeError("injected gap commit failure")

    session_class = app.state.session.class_
    event.listen(session_class, "before_commit", fail_gap_commit)
    identifiers = iter((_EPOCH_ID, _SEGMENT_ID, _GAP_ID))
    try:
        with pytest.raises(RuntimeError, match="injected gap commit failure"):
            TelemetryOutbox(
                app.state.session,
                spool,
                uuid_factory=lambda: next(identifiers),
                clock=lambda: datetime(2030, 1, 1, 12, 0, tzinfo=UTC),
                segment_writer=no_space,
                control_reserve_bytes=4096,
                minimum_free_bytes=0,
            ).append_state(
                point_id="point-1",
                raw_value="20",
                quality="good",
                observed_at="2030-01-01T12:00:00Z",
            )
    finally:
        event.remove(session_class, "before_commit", fail_gap_commit)

    assert reserve.stat().st_size == 4096
    with app.state.session() as session:
        assert session.get(TelemetryStream, "point-1") is None
        assert session.scalar(select(TelemetryGap)) is None
        assert session.scalar(select(TelemetryOutboxRecord)) is None
    assert _segment_names(spool) == []


def test_future_observed_at_consumes_clock_discontinuity_gap(tmp_path) -> None:
    from one_os_addon.telemetry_outbox import TelemetryOutbox

    app = create_app(
        database_url=f"sqlite:///{tmp_path / 'commissioning.db'}", pairing_backend=False
    )
    with app.state.session() as session:
        _selected_point_and_snapshot(session)

    identifiers = iter((_EPOCH_ID, _GAP_ID))
    spool = tmp_path / "telemetry-outbox"
    stored = TelemetryOutbox(
        app.state.session,
        spool,
        uuid_factory=lambda: next(identifiers),
        clock=lambda: datetime(2030, 1, 1, 12, 0, tzinfo=UTC),
    ).append_state(
        point_id="point-1",
        raw_value="20",
        quality="good",
        observed_at="2030-01-01T12:00:01Z",
    )

    assert stored.document["reason"] == "clock_discontinuity"
    assert stored.document["firstMissingSequence"] == 0
    assert stored.document["lastMissingSequence"] == 0
    with app.state.session() as session:
        stream = session.get(TelemetryStream, "point-1")
        gap = session.scalar(select(TelemetryGap))
        assert stream is not None
        assert stream.next_sequence == 1
        assert gap is not None
        assert gap.reason == "clock_discontinuity"
        assert session.scalar(select(TelemetryOutboxRecord)) is None
        assert session.scalar(select(TelemetryOutboxSegment)) is None
    assert _segment_names(spool) == []


def test_expired_contiguous_sequences_coalesce_into_one_pending_gap(tmp_path) -> None:
    from one_os_addon.telemetry_outbox import TelemetryOutbox

    app = create_app(
        database_url=f"sqlite:///{tmp_path / 'commissioning.db'}", pairing_backend=False
    )
    with app.state.session() as session:
        _selected_point_and_snapshot(session)

    identifiers = iter(
        (_EPOCH_ID, _SEGMENT_ID, _SEGMENT_2_ID, _SEGMENT_3_ID, _GAP_ID, _SEGMENT_4_ID)
    )
    times = iter(
        (
            datetime(2030, 1, 1, 12, 0, tzinfo=UTC),
            datetime(2030, 1, 1, 12, 1, tzinfo=UTC),
            datetime(2030, 1, 1, 12, 2, tzinfo=UTC),
            datetime(2030, 1, 8, 12, 2, tzinfo=UTC),
        )
    )
    spool = tmp_path / "telemetry-outbox"
    outbox = TelemetryOutbox(
        app.state.session,
        spool,
        uuid_factory=lambda: next(identifiers),
        clock=lambda: next(times),
    )

    for minute, value in enumerate(("20", "21", "22")):
        outbox.append_state(
            point_id="point-1",
            raw_value=value,
            quality="good",
            observed_at=f"2030-01-01T12:0{minute}:00Z",
        )
    outbox.append_state(
        point_id="point-1",
        raw_value="23",
        quality="good",
        observed_at="2030-01-08T12:02:00Z",
    )

    with app.state.session() as session:
        gaps = session.scalars(select(TelemetryGap)).all()
        sequences = list(session.scalars(select(TelemetryOutboxRecord.sequence)))
        assert len(gaps) == 1
        assert (
            gaps[0].first_missing_sequence,
            gaps[0].last_missing_sequence,
            gaps[0].reason,
            gaps[0].status,
        ) == (0, 2, "retention_expired", "pending")
        assert sequences == [3]
    assert _segment_names(spool) == [f"{_SEGMENT_4_ID}.seg"]
