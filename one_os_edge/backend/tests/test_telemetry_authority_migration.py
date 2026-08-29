from __future__ import annotations

import hashlib
import os
import sqlite3
import subprocess
import sys
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from one_os_addon.app import create_app
from one_os_addon.models import (
    EdgeIdentity,
    TelemetryAuthorityCut,
    TelemetryBatch,
    TelemetryJournalState,
)
from sqlalchemy import BigInteger, inspect, text
from sqlalchemy.dialects import postgresql
from sqlalchemy.dialects import sqlite as sqlite_dialect
from sqlalchemy.exc import IntegrityError

_MAX_INT64 = 9_223_372_036_854_775_807
_INSTALLATION_ID = "00000000-0000-4000-8000-000000000002"
_LINEAGE_ID = "11111111-1111-4111-8111-111111111111"
_CREDENTIAL_ID = "22222222-2222-4222-8222-222222222222"
_BATCH_ID = "33333333-3333-4333-8333-333333333333"
_CUT_ID = "44444444-4444-4444-8444-444444444444"
_RENEWAL_ID = "55555555-5555-4555-8555-555555555555"


def _config(database: Path) -> Config:
    config = Config("one_os_edge/alembic.ini")
    config.set_main_option("sqlalchemy.url", f"sqlite:///{database}")
    config.attributes["explicit_database_url"] = True
    return config


def _catalog(connection: sqlite3.Connection) -> tuple[int, list[tuple[object, ...]]]:
    schema_version = connection.execute("PRAGMA schema_version").fetchone()[0]
    rows = connection.execute(
        "SELECT type, name, tbl_name, sql FROM sqlite_master "
        "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
    ).fetchall()
    return schema_version, rows


def _insert_identity(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        INSERT INTO edge_identity (
          id, installation_id, status, revision, active_spki_sha256, credential_id,
          certificate_sha256, certificate_not_after, installation_revision,
          renewal_status, renewal_request_id, renewal_issuance_expires_at,
          renewal_ack_expires_at, updated_at
        ) VALUES (1, ?, 'paired', 1, NULL, ?, NULL, NULL, 1, NULL, NULL, NULL, NULL, ?)
        """,
        (_INSTALLATION_ID, _CREDENTIAL_ID, "2030-01-01 00:00:00"),
    )


def _insert_fresh_identity(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        INSERT INTO edge_identity (
          id, installation_id, status, revision, active_spki_sha256, credential_id,
          certificate_sha256, certificate_not_after, installation_revision,
          renewal_status, renewal_request_id, renewal_issuance_expires_at,
          renewal_ack_expires_at, updated_at
        ) VALUES (1, ?, 'unpaired', 0, NULL, NULL, NULL, NULL, NULL,
                  NULL, NULL, NULL, NULL, ?)
        """,
        (_INSTALLATION_ID, "2030-01-01 00:00:00"),
    )


def _insert_batch(connection: sqlite3.Connection, status: str) -> None:
    lease_owner = "worker" if status == "leased" else None
    lease_until = "2030-01-01 00:01:00" if status == "leased" else None
    ack_bytes = b"ack" if status == "acked" else None
    ingest_cursor = 1 if status == "acked" else None
    acked_at = "2030-01-01 00:00:30" if status == "acked" else None
    terminal_reason = "immutable_conflict" if status == "quarantined" else None
    quarantined_at = "2030-01-01 00:00:30" if status == "quarantined" else None
    connection.execute(
        """
        INSERT INTO telemetry_batches (
          batch_id, installation_id, installation_revision, credential_id,
          payload_sha256, request_sha256, request_bytes, sample_count,
          quality_event_count, gap_count, status, lease_owner, lease_until,
          attempt_count, last_attempt_at, next_attempt_at, ack_bytes,
          ingest_cursor, acked_at, terminal_reason, quarantined_at, created_at
        ) VALUES (?, ?, 1, ?, ?, ?, ?, 1, 0, 0, ?, ?, ?, 0, NULL, NULL, ?, ?, ?,
                  ?, ?, ?)
        """,
        (
            _BATCH_ID,
            _INSTALLATION_ID,
            _CREDENTIAL_ID,
            "a" * 43,
            "b" * 43,
            b"{}",
            status,
            lease_owner,
            lease_until,
            ack_bytes,
            ingest_cursor,
            acked_at,
            terminal_reason,
            quarantined_at,
            "2030-01-01 00:00:00",
        ),
    )


def test_telemetry_authority_storage_migration_and_models_are_in_parity(tmp_path) -> None:
    app = create_app(
        database_url=f"sqlite:///{tmp_path / 'authority.db'}",
        pairing_backend=False,
    )
    inspector = inspect(app.state.engine)

    assert {column["name"] for column in inspector.get_columns("edge_identity")} >= {
        "telemetry_authorization_revision",
        "lineage_id",
    }
    assert {column["name"] for column in inspector.get_columns("telemetry_batches")} >= {
        "batch_authorization_revision",
        "journal_id",
    }
    assert {column["name"] for column in inspector.get_columns("telemetry_journal_state")} == {
        "id",
        "last_journal_id",
    }
    assert {column["name"] for column in inspector.get_columns("telemetry_authority_cuts")} == {
        "cut_marker_id",
        "renewal_request_id",
        "installation_id",
        "lineage_id",
        "historical_authorization_revision",
        "ingest_authorization_revision",
        "cut_journal_max_id",
        "backlog_mode",
        "manifest_bytes",
        "manifest_sha256",
        "receipt_bytes",
        "receipt_sha256",
        "milestone",
        "cut_opened_at",
        "receipt_stored_at",
        "identity_promoted_at",
        "backlog_drained_at",
        "terminal_at",
    }

    assert EdgeIdentity.__table__.c.telemetry_authorization_revision.nullable is False
    assert EdgeIdentity.__table__.c.lineage_id.nullable is False
    assert TelemetryBatch.__table__.c.batch_authorization_revision.nullable is False
    assert TelemetryBatch.__table__.c.journal_id.nullable is False
    assert TelemetryJournalState.__table__.name == "telemetry_journal_state"
    assert TelemetryAuthorityCut.__table__.name == "telemetry_authority_cuts"

    with app.state.session() as session:
        identity = session.get(EdgeIdentity, 1)
        assert identity is not None
        assert identity.telemetry_authorization_revision == 1
        assert identity.lineage_id == identity.installation_id
        state = session.get(TelemetryJournalState, 1)
        assert state is not None
        assert state.last_journal_id == 0
    app.state.engine.dispose()


def test_authority_storage_preserves_exact_manifest_and_receipt_bytes(tmp_path) -> None:
    app = create_app(
        database_url=f"sqlite:///{tmp_path / 'exact-bytes.db'}",
        pairing_backend=False,
    )
    manifest = b'{"entries":[],"schemaVersion":"one-os-backlog-manifest/v2"}'
    receipt = b'{"entries":[],"schemaVersion":"one-os-historical-receipt/v2"}'
    manifest_hash = hashlib.sha256(manifest).digest()
    receipt_hash = hashlib.sha256(receipt).digest()

    with app.state.session() as session:
        identity = session.get(EdgeIdentity, 1)
        assert identity is not None
        session.add(
            TelemetryAuthorityCut(
                cut_marker_id=_CUT_ID,
                renewal_request_id=_RENEWAL_ID,
                installation_id=identity.installation_id,
                lineage_id=identity.lineage_id,
                historical_authorization_revision=1,
                ingest_authorization_revision=2,
                cut_journal_max_id=1,
                backlog_mode="historical",
                manifest_bytes=manifest,
                manifest_sha256=manifest_hash,
                receipt_bytes=receipt,
                receipt_sha256=receipt_hash,
                milestone="receipt_stored",
                cut_opened_at=datetime(2030, 1, 1, tzinfo=UTC),
                receipt_stored_at=datetime(2030, 1, 1, 0, 0, 1, tzinfo=UTC),
            )
        )
        session.commit()
        session.expire_all()
        stored = session.get(TelemetryAuthorityCut, _CUT_ID)
        assert stored is not None
        assert stored.manifest_bytes == manifest
        assert stored.manifest_sha256 == manifest_hash
        assert stored.receipt_bytes == receipt
        assert stored.receipt_sha256 == receipt_hash
    app.state.engine.dispose()


def test_authority_revision_hash_and_journal_bounds_are_database_enforced(tmp_path) -> None:
    app = create_app(
        database_url=f"sqlite:///{tmp_path / 'bounds.db'}",
        pairing_backend=False,
    )
    with app.state.engine.begin() as connection:
        for revision in (0, _MAX_INT64 + 1):
            with pytest.raises(IntegrityError):
                connection.execute(
                    text(
                        "UPDATE edge_identity SET telemetry_authorization_revision=:revision "
                        "WHERE id=1"
                    ),
                    {"revision": revision},
                )
        with pytest.raises(IntegrityError):
            connection.execute(
                text("UPDATE telemetry_journal_state SET last_journal_id=:value WHERE id=1"),
                {"value": -1},
            )
        with pytest.raises(IntegrityError):
            connection.execute(
                text(
                    """
                    INSERT INTO telemetry_authority_cuts (
                      cut_marker_id, renewal_request_id, installation_id, lineage_id,
                      historical_authorization_revision, ingest_authorization_revision,
                      cut_journal_max_id, backlog_mode, manifest_bytes, manifest_sha256,
                      receipt_bytes, receipt_sha256, milestone, cut_opened_at
                    ) SELECT :cut, :renewal, installation_id, lineage_id, 1, 2, 0, 'none',
                             X'7B7D', X'00', NULL, NULL, 'cut_open', :opened
                      FROM edge_identity WHERE id=1
                    """
                ),
                {
                    "cut": _CUT_ID,
                    "renewal": _RENEWAL_ID,
                    "opened": "2030-01-01 00:00:00",
                },
            )
    app.state.engine.dispose()


@pytest.mark.parametrize("status", ("pending", "leased", "acked", "quarantined"))
def test_0015_refuses_every_existing_batch_state_before_ddl(tmp_path, status: str) -> None:
    database = tmp_path / f"dirty-{status}.db"
    config = _config(database)
    command.upgrade(config, "0014")
    with closing(sqlite3.connect(database)) as connection:
        _insert_identity(connection)
        _insert_batch(connection, status)
        connection.commit()
        before = _catalog(connection)

    with pytest.raises(RuntimeError, match="requires empty telemetry delivery state"):
        command.upgrade(config, "0015")

    with closing(sqlite3.connect(database)) as connection:
        assert _catalog(connection) == before
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == ("0014",)
        assert connection.execute("SELECT status FROM telemetry_batches").fetchone() == (status,)


@pytest.mark.parametrize(
    ("table", "insert_sql"),
    (
        (
            "telemetry_batch_records",
            "INSERT INTO telemetry_batch_records VALUES ('sample', 'missing', 'sample', 0)",
        ),
        (
            "telemetry_batch_gaps",
            "INSERT INTO telemetry_batch_gaps VALUES ('gap', 'missing', 0)",
        ),
        (
            "telemetry_ingest_state",
            "INSERT INTO telemetry_ingest_state VALUES ('installation', 0, '2030-01-01')",
        ),
    ),
)
def test_0015_refuses_every_existing_journal_row_before_ddl(
    tmp_path, table: str, insert_sql: str
) -> None:
    database = tmp_path / f"dirty-{table}.db"
    config = _config(database)
    command.upgrade(config, "0014")
    with closing(sqlite3.connect(database)) as connection:
        connection.execute("PRAGMA foreign_keys=OFF")
        connection.execute(insert_sql)
        connection.commit()
        before = _catalog(connection)

    with pytest.raises(RuntimeError, match=table):
        command.upgrade(config, "0015")

    with closing(sqlite3.connect(database)) as connection:
        assert _catalog(connection) == before
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == ("0014",)
        assert connection.execute(
            f"SELECT COUNT(*) FROM {table}"  # noqa: S608 - fixed parameter allowlist
        ).fetchone() == (1,)


def test_0015_cycles_an_empty_predecessor_without_losing_baseline(tmp_path) -> None:
    database = tmp_path / "cycle.db"
    config = _config(database)
    command.upgrade(config, "0014")
    with closing(sqlite3.connect(database)) as connection:
        _insert_fresh_identity(connection)
        connection.commit()

    command.upgrade(config, "0015")
    command.downgrade(config, "0014")
    command.upgrade(config, "0015")

    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == ("0015",)
        assert connection.execute(
            "SELECT telemetry_authorization_revision, lineage_id FROM edge_identity WHERE id=1"
        ).fetchone() == (1, _INSTALLATION_ID)


def test_0015_refuses_paired_identity_authority_inference_before_ddl(tmp_path) -> None:
    database = tmp_path / "paired-identity.db"
    config = _config(database)
    command.upgrade(config, "0014")
    with closing(sqlite3.connect(database)) as connection:
        _insert_identity(connection)
        connection.commit()
        before = _catalog(connection)

    with pytest.raises(RuntimeError, match="refuses non-fresh or paired"):
        command.upgrade(config, "0015")

    with closing(sqlite3.connect(database)) as connection:
        assert _catalog(connection) == before
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == ("0014",)


@pytest.mark.parametrize(
    "statement",
    (
        "UPDATE edge_identity SET telemetry_authorization_revision=:value WHERE id=1",
        "UPDATE telemetry_journal_state SET last_journal_id=:value WHERE id=1",
    ),
)
def test_signed_authority_and_journal_values_reject_fractional_storage(tmp_path, statement) -> None:
    app = create_app(database_url=f"sqlite:///{tmp_path / 'fractional.db'}", pairing_backend=False)
    with app.state.engine.begin() as connection, pytest.raises(IntegrityError):
        connection.execute(text(statement), {"value": 1.5})
    app.state.engine.dispose()


def test_activation_revision_rejects_fractional_storage_and_status_requires_exact_tuple(
    tmp_path,
) -> None:
    app = create_app(
        database_url=f"sqlite:///{tmp_path / 'activation-tuple.db'}", pairing_backend=False
    )
    statement = text("""
        INSERT INTO telemetry_authority_activation (
          id, installation_id, credential_id, certificate_sha256,
          telemetry_authorization_revision, capability_bytes, capability_sha256,
          server_nonce, issued_at, expires_at, enable_request_bytes, request_sha256,
          enable_response_bytes, response_sha256, status, enabled_at, updated_at
        ) SELECT 1, installation_id, :credential, :certificate, :revision, X'7B7D', zeroblob(32),
                 zeroblob(32), :issued, :expires, :request, :request_hash, NULL, NULL,
                 :status, NULL, :issued FROM edge_identity WHERE id=1
    """)
    common = {
        "credential": _CREDENTIAL_ID,
        "certificate": "a" * 43,
        "issued": "2030-01-01 00:00:00",
        "expires": "2030-01-01 00:05:00",
    }
    with app.state.engine.begin() as connection:
        with pytest.raises(IntegrityError):
            connection.execute(
                statement,
                {
                    **common,
                    "revision": 1.5,
                    "request": None,
                    "request_hash": None,
                    "status": "capability_stored",
                },
            )
        with pytest.raises(IntegrityError):
            connection.execute(
                statement,
                {
                    **common,
                    "revision": 1,
                    "request": None,
                    "request_hash": None,
                    "status": "enable_requested",
                },
            )
    app.state.engine.dispose()


def test_0016_contains_preflight_lock_before_drop() -> None:
    source = Path(
        "one_os_edge/backend/alembic/versions/0016_telemetry_authority_activation.py"
    ).read_text()
    lock = source.index("LOCK TABLE telemetry_authority_activation IN SHARE ROW EXCLUSIVE MODE")
    preflight = source.index("select(sa.literal(1))")
    drop = source.index('op.drop_table("telemetry_authority_activation")')
    assert lock < preflight < drop


def test_candidate_edge_chain_compiles_as_postgresql_offline_sql() -> None:
    environment = dict(os.environ, DATABASE_URL="postgresql://user:***@localhost/db")
    result = subprocess.run(  # noqa: S603 - fixed interpreter and argument vector
        [
            sys.executable,
            "-m",
            "alembic",
            "-c",
            "one_os_edge/alembic.ini",
            "upgrade",
            "0013:head",
            "--sql",
        ],
        cwd=Path(__file__).resolve().parents[3],
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    sql = result.stdout
    assert "BEGIN IMMEDIATE" not in sql
    assert "telemetry_authorization_revision BIGINT" in sql
    assert "request_sha256 BYTEA" in sql
    assert "response_sha256 BYTEA" in sql
    for witness in (
        "ALTER TABLE configuration_snapshots ALTER COLUMN config_version TYPE BIGINT",
        "ALTER TABLE telemetry_streams ALTER COLUMN next_sequence TYPE BIGINT",
        "ALTER TABLE telemetry_outbox_records ALTER COLUMN sequence TYPE BIGINT",
        "ALTER TABLE telemetry_gaps ALTER COLUMN first_missing_sequence TYPE BIGINT",
        "ALTER TABLE telemetry_batches ALTER COLUMN ingest_cursor TYPE BIGINT",
        "ALTER TABLE telemetry_ingest_state ALTER COLUMN last_ingest_cursor TYPE BIGINT",
        "ALTER TABLE edge_identity ALTER COLUMN installation_revision TYPE BIGINT",
    ):
        assert witness in sql


@pytest.mark.parametrize("column", ("batch_authorization_revision", "journal_id"))
def test_batch_authority_and_journal_ids_reject_fractional_storage(tmp_path, column) -> None:
    app = create_app(
        database_url=f"sqlite:///{tmp_path / 'fractional-batch.db'}", pairing_backend=False
    )
    values = {"batch_authorization_revision": 1, "journal_id": 1}
    values[column] = 1.5
    with app.state.engine.begin() as connection, pytest.raises(IntegrityError):
        connection.execute(
            text("""
            INSERT INTO telemetry_batches (
              batch_id, installation_id, installation_revision, batch_authorization_revision,
              journal_id, credential_id, payload_sha256, request_sha256, request_bytes,
              sample_count, quality_event_count, gap_count, status, attempt_count, created_at
            ) SELECT :batch, installation_id, 1, :authority, :journal, :credential,
                     :payload, :request, X'7B7D', 1, 0, 0, 'pending', 0, :created
              FROM edge_identity WHERE id=1
        """),
            {
                "batch": _BATCH_ID,
                "authority": values["batch_authorization_revision"],
                "journal": values["journal_id"],
                "credential": _CREDENTIAL_ID,
                "payload": "a" * 43,
                "request": "b" * 43,
                "created": "2030-01-01 00:00:00",
            },
        )
    app.state.engine.dispose()


@pytest.mark.parametrize("family", ("revision", "journal"))
def test_cut_authority_and_journal_ids_reject_fractional_storage(tmp_path, family) -> None:
    app = create_app(
        database_url=f"sqlite:///{tmp_path / 'fractional-cut.db'}", pairing_backend=False
    )
    historical, ingest, journal, mode = (
        (1.5, 2.5, 0, "none") if family == "revision" else (1, 2, 1.5, "historical")
    )
    with app.state.engine.begin() as connection, pytest.raises(IntegrityError):
        connection.execute(
            text("""
            INSERT INTO telemetry_authority_cuts (
              cut_marker_id, renewal_request_id, installation_id, lineage_id,
              historical_authorization_revision, ingest_authorization_revision,
              cut_journal_max_id, backlog_mode, manifest_bytes, manifest_sha256,
              milestone, cut_opened_at
            ) SELECT :cut, :renewal, installation_id, lineage_id, :historical, :ingest,
                     :journal, :mode, X'7B7D', :digest, 'cut_open', :opened
              FROM edge_identity WHERE id=1
        """),
            {
                "cut": _CUT_ID,
                "renewal": _RENEWAL_ID,
                "historical": historical,
                "ingest": ingest,
                "journal": journal,
                "mode": mode,
                "digest": hashlib.sha256(b"{}").digest(),
                "opened": "2030-01-01 00:00:00",
            },
        )
    app.state.engine.dispose()


_WIRE_INT64_COLUMNS = {
    "configuration_snapshots": ("config_version",),
    "telemetry_streams": ("next_sequence",),
    "telemetry_outbox_records": ("sequence", "config_version"),
    "telemetry_gaps": ("config_version", "first_missing_sequence", "last_missing_sequence"),
    "telemetry_batches": ("installation_revision", "ingest_cursor"),
    "telemetry_ingest_state": ("last_ingest_cursor",),
    "edge_identity": ("installation_revision",),
}


def test_0017_closes_every_edge_wire_signed_int64_type_and_check(tmp_path) -> None:
    from one_os_addon.models import Base

    app = create_app(database_url=f"sqlite:///{tmp_path / 'wire-int64.db'}", pairing_backend=False)
    with app.state.engine.connect() as connection:
        assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "0021"
    for table_name, column_names in _WIRE_INT64_COLUMNS.items():
        table = Base.metadata.tables[table_name]
        checks = " ".join(
            str(constraint.sqltext)
            for constraint in table.constraints
            if hasattr(constraint, "sqltext")
        )
        for column_name in column_names:
            assert isinstance(table.c[column_name].type, BigInteger)
            assert f"{column_name} = CAST({column_name} AS BIGINT)" in checks
    app.state.engine.dispose()


def test_0017_rejects_dirty_fractional_predecessor_before_any_ddl(tmp_path) -> None:
    database = tmp_path / "dirty-wire-int64.db"
    config = _config(database)
    command.upgrade(config, "0016")
    with closing(sqlite3.connect(database)) as connection:
        connection.execute(
            "INSERT INTO telemetry_ingest_state VALUES ('installation', 1.5, '2030-01-01')"
        )
        connection.commit()
        before = _catalog(connection)
    with pytest.raises(RuntimeError, match="dirty values in telemetry_ingest_state"):
        command.upgrade(config, "0017")
    with closing(sqlite3.connect(database)) as connection:
        assert _catalog(connection) == before
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == ("0016",)
        assert connection.execute(
            "SELECT last_ingest_cursor, typeof(last_ingest_cursor) FROM telemetry_ingest_state"
        ).fetchone() == (1.5, "real")


@pytest.mark.parametrize(
    ("family", "setup", "statement", "columns"),
    (
        (
            "config_version",
            "",
            "INSERT INTO configuration_snapshots VALUES "
            "('s','i',?, 'p','r',X'7B7D','pending','2030-01-01',0,NULL,0,NULL)",
            ("config_version",),
        ),
        (
            "sequence_config",
            "INSERT INTO telemetry_outbox_segments VALUES ('seg','seg.seg',1,1,1,'2030-01-01')",
            "INSERT INTO telemetry_outbox_records VALUES "
            "('sample','point','epoch',?, 'sample', ?, 'snap','p','seg',0,1,'2030-01-01')",
            ("sequence", "config_version"),
        ),
        (
            "gap_positions",
            "",
            "INSERT INTO telemetry_gaps VALUES "
            "('gap','i','point','epoch',?,'snap','p',?,?,'2030-01-01','storage_failure','pending')",
            ("config_version", "first_missing_sequence", "last_missing_sequence"),
        ),
        (
            "ingest_cursor",
            "",
            "INSERT INTO telemetry_ingest_state VALUES ('i',?,'2030-01-01')",
            ("last_ingest_cursor",),
        ),
    ),
)
def test_sqlite_wire_int64_families_reject_fractional_and_round_trip_max(
    tmp_path, family, setup, statement, columns
) -> None:
    database = tmp_path / f"wire-{family}.db"
    app = create_app(database_url=f"sqlite:///{database}", pairing_backend=False)
    app.state.engine.dispose()
    arity = statement.count("?")
    with closing(sqlite3.connect(database)) as connection:
        connection.execute("PRAGMA foreign_keys=OFF")
        if setup:
            connection.execute(setup)
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(statement, tuple(1.5 for _ in range(arity)))
        connection.execute(statement, tuple(_MAX_INT64 for _ in range(arity)))
        table_name = statement.split("INSERT INTO ", 1)[1].split(" ", 1)[0]
        selected = ",".join(f"{column}, typeof({column})" for column in columns)
        stored = connection.execute(
            f"SELECT {selected} FROM {table_name} ORDER BY rowid DESC LIMIT 1"  # noqa: S608
        ).fetchone()
        assert stored == tuple(value for _ in columns for value in (_MAX_INT64, "integer"))


def test_0019_downgrade_locks_writers_before_zero_backlog_preflight(tmp_path) -> None:
    source = Path(
        "one_os_edge/backend/alembic/versions/0019_renewal_v2_zero_backlog_state_tuple.py"
    ).read_text()
    postgres_statement = "LOCK TABLE telemetry_renewal_operation IN SHARE ROW EXCLUSIVE MODE"
    sqlite_statement = (
        "UPDATE alembic_version SET version_num = version_num WHERE version_num = '0019'"
    )
    postgres_lock = source.index(postgres_statement)
    sqlite_lock = source.index(sqlite_statement)
    preflight = source.index('"SELECT 1 FROM telemetry_renewal_operation WHERE "')
    replace = source.index("_replace_constraint(_STALE_EXPRESSION)")
    assert postgres_lock < preflight < replace
    assert sqlite_lock < preflight < replace

    assert str(text(postgres_statement).compile(dialect=postgresql.dialect())) == postgres_statement
    assert str(text(sqlite_statement).compile(dialect=sqlite_dialect.dialect())) == sqlite_statement

    database = tmp_path / "empty-0019-downgrade.db"
    config = _config(database)
    command.upgrade(config, "0019")
    command.downgrade(config, "0018")
    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == ("0018",)


def test_0020_empty_sqlite_round_trip_and_evidence_refusal(tmp_path) -> None:
    database = tmp_path / "current-attempt-evidence.db"
    config = _config(database)
    command.upgrade(config, "0020")
    command.downgrade(config, "0019")
    command.upgrade(config, "0020")
    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == ("0020",)
        connection.execute(
            """
            INSERT INTO telemetry_batches (
              batch_id, installation_id, installation_revision, batch_authorization_revision,
              journal_id, credential_id, payload_sha256, request_sha256, request_bytes,
              sample_count, quality_event_count, gap_count, status, attempt_count, created_at,
              current_attempt_request_sha256, current_attempt_authorization_revision,
              current_attempt_at
            ) VALUES (?, ?, 1, 7, 1, ?, ?, ?, X'7B7D', 1, 0, 0, 'pending', 1, ?, ?, 7, ?)
            """,
            (
                _BATCH_ID,
                _INSTALLATION_ID,
                _CREDENTIAL_ID,
                "a" * 43,
                "b" * 43,
                "2030-01-01 00:00:00",
                "b" * 43,
                "2030-01-01 00:00:01",
            ),
        )
        connection.commit()

    with pytest.raises(RuntimeError, match="refusing to discard durable telemetry current-attempt"):
        command.downgrade(config, "0019")
    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == ("0020",)
        assert connection.execute(
            "SELECT current_attempt_request_sha256, current_attempt_authorization_revision "
            "FROM telemetry_batches"
        ).fetchone() == ("b" * 43, 7)


@pytest.mark.parametrize(
    ("request_hash", "revision"),
    (("c" * 43, 7), ("b" * 43, 8), ("b" * 42, 7), ("b" * 43, 7.5)),
)
def test_0020_wrong_batch_evidence_is_database_rejected(tmp_path, request_hash, revision) -> None:
    app = create_app(
        database_url=f"sqlite:///{tmp_path / 'wrong-evidence.db'}", pairing_backend=False
    )
    with app.state.engine.begin() as connection:
        connection.execute(
            text(
                """
                INSERT INTO telemetry_batches (
                  batch_id, installation_id, installation_revision, batch_authorization_revision,
                  journal_id, credential_id, payload_sha256, request_sha256, request_bytes,
                  sample_count, quality_event_count, gap_count, status, attempt_count, created_at
                ) VALUES (:batch_id, :installation, 1, 7, 1, :credential, :payload, :request,
                          X'7B7D', 1, 0, 0, 'pending', 0, :created)
                """
            ),
            {
                "batch_id": _BATCH_ID,
                "installation": _INSTALLATION_ID,
                "credential": _CREDENTIAL_ID,
                "payload": "a" * 43,
                "request": "b" * 43,
                "created": "2030-01-01 00:00:00",
            },
        )
        with pytest.raises(IntegrityError):
            connection.execute(
                text(
                    """
                    UPDATE telemetry_batches
                       SET current_attempt_request_sha256=:proof_hash,
                           current_attempt_authorization_revision=:proof_revision,
                           current_attempt_at=:attempted
                     WHERE batch_id=:batch_id
                    """
                ),
                {
                    "proof_hash": request_hash,
                    "proof_revision": revision,
                    "attempted": "2030-01-01 00:00:01",
                    "batch_id": _BATCH_ID,
                },
            )
    app.state.engine.dispose()
