from __future__ import annotations

import importlib.util
import sqlite3
import threading
import time
from contextlib import closing
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from one_os_addon.models import TelemetryBatch
from sqlalchemy import CheckConstraint, create_engine, inspect

_ROOT = Path(__file__).parents[3]
_ALEMBIC_INI = _ROOT / "one_os_edge" / "alembic.ini"
_BATCH_ID = "33333333-3333-4333-8333-333333333333"
_INSTALLATION_ID = "00000000-0000-4000-8000-000000000002"
_CREDENTIAL_ID = "22222222-2222-4222-8222-222222222222"
_REQUEST_HASH = "b" * 43
_ATTEMPT_AT = "2030-01-01 00:00:01"
_CONSTRAINT = "ck_telemetry_batch_current_attempt"
_FIXED_CHECK = (
    "COALESCE(((current_attempt_request_sha256 IS NULL AND "
    "current_attempt_authorization_revision IS NULL AND current_attempt_at IS NULL) OR "
    "(current_attempt_request_sha256 IS NOT NULL AND "
    "current_attempt_authorization_revision IS NOT NULL AND current_attempt_at IS NOT NULL AND "
    "current_attempt_request_sha256 = request_sha256 AND "
    "length(current_attempt_request_sha256) = 43 AND "
    "current_attempt_authorization_revision = batch_authorization_revision AND "
    "current_attempt_authorization_revision = "
    "CAST(current_attempt_authorization_revision AS BIGINT))), FALSE)"
)


def _config(database: Path) -> Config:
    config = Config(_ALEMBIC_INI)
    config.set_main_option("sqlalchemy.url", f"sqlite:///{database}")
    config.attributes["explicit_database_url"] = True
    return config


def _insert_batch(
    connection: sqlite3.Connection,
    *,
    request_hash: str | None,
    revision: int | None,
    attempted_at: str | None,
    journal_id: int = 1,
) -> None:
    connection.execute(
        """
        INSERT INTO telemetry_batches (
          batch_id, installation_id, installation_revision, batch_authorization_revision,
          journal_id, credential_id, payload_sha256, request_sha256, request_bytes,
          sample_count, quality_event_count, gap_count, status, attempt_count, created_at,
          current_attempt_request_sha256, current_attempt_authorization_revision,
          current_attempt_at
        ) VALUES (?, ?, 1, 7, ?, ?, ?, ?, X'7B7D', 1, 0, 0, 'pending', 0, ?, ?, ?, ?)
        """,
        (
            _BATCH_ID,
            _INSTALLATION_ID,
            journal_id,
            _CREDENTIAL_ID,
            "a" * 43,
            _REQUEST_HASH,
            "2030-01-01 00:00:00",
            request_hash,
            revision,
            attempted_at,
        ),
    )


def _catalog(connection: sqlite3.Connection) -> tuple[int, list[tuple[object, ...]]]:
    return (
        connection.execute("PRAGMA schema_version").fetchone()[0],
        connection.execute(
            "SELECT type, name, tbl_name, sql FROM sqlite_master "
            "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
        ).fetchall(),
    )


@pytest.mark.parametrize("mask", range(8))
def test_current_head_sqlite_accepts_only_all_null_or_complete_current_attempt_tuple(
    tmp_path: Path, mask: int
) -> None:
    database = tmp_path / f"tuple-{mask}.db"
    command.upgrade(_config(database), "head")
    values = (
        _REQUEST_HASH if mask & 1 else None,
        7 if mask & 2 else None,
        _ATTEMPT_AT if mask & 4 else None,
    )
    with closing(sqlite3.connect(database)) as connection:
        if mask in (0, 7):
            _insert_batch(
                connection,
                request_hash=values[0],
                revision=values[1],
                attempted_at=values[2],
            )
            connection.commit()
        else:
            with pytest.raises(sqlite3.IntegrityError):
                _insert_batch(
                    connection,
                    request_hash=values[0],
                    revision=values[1],
                    attempted_at=values[2],
                )


def test_0020_to_0021_sqlite_refuses_partial_tuple_before_ddl(tmp_path: Path) -> None:
    database = tmp_path / "dirty-upgrade.db"
    config = _config(database)
    command.upgrade(config, "0020")
    with closing(sqlite3.connect(database)) as connection:
        _insert_batch(connection, request_hash=None, revision=None, attempted_at=_ATTEMPT_AT)
        connection.commit()
        before = _catalog(connection)

    with pytest.raises(RuntimeError, match="partial telemetry current-attempt evidence"):
        command.upgrade(config, "0021")

    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == ("0020",)
        assert _catalog(connection) == before
        assert connection.execute(
            "SELECT current_attempt_request_sha256, "
            "current_attempt_authorization_revision, current_attempt_at FROM telemetry_batches"
        ).fetchone() == (None, None, _ATTEMPT_AT)


def test_0020_to_0021_sqlite_write_boundary_waits_for_prior_writer(tmp_path: Path) -> None:
    database = tmp_path / "writer-boundary.db"
    config = _config(database)
    command.upgrade(config, "0020")
    writer = sqlite3.connect(database, timeout=5)
    writer.execute("BEGIN IMMEDIATE")
    _insert_batch(writer, request_hash=None, revision=None, attempted_at=_ATTEMPT_AT)

    errors: list[BaseException] = []

    def migrate() -> None:
        try:
            command.upgrade(config, "0021")
        except BaseException as error:  # asserted in the parent thread
            errors.append(error)

    thread = threading.Thread(target=migrate)
    thread.start()
    time.sleep(0.2)
    assert thread.is_alive(), "migration did not wait for the predecessor writer"
    writer.commit()
    writer.close()
    thread.join(timeout=5)
    assert not thread.is_alive()
    assert len(errors) == 1
    assert "partial telemetry current-attempt evidence" in str(errors[0])
    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == ("0020",)


def test_0021_model_constraint_and_migrated_head_are_exactly_in_parity(tmp_path: Path) -> None:
    database = tmp_path / "parity.db"
    config = _config(database)
    command.upgrade(config, "head")
    assert ScriptDirectory.from_config(config).get_current_head() == "0021"
    model_check = next(
        constraint
        for constraint in TelemetryBatch.__table__.constraints
        if isinstance(constraint, CheckConstraint) and constraint.name == _CONSTRAINT
    )
    engine = create_engine(f"sqlite:///{database}")
    migrated_check = next(
        check
        for check in inspect(engine).get_check_constraints("telemetry_batches")
        if check["name"] == _CONSTRAINT
    )
    engine.dispose()
    assert str(model_check.sqltext) == _FIXED_CHECK
    assert migrated_check["sqltext"] == _FIXED_CHECK


def test_0021_empty_sqlite_downgrade_and_reupgrade_round_trip(tmp_path: Path) -> None:
    database = tmp_path / "empty-round-trip.db"
    config = _config(database)
    command.upgrade(config, "0021")
    command.downgrade(config, "0020")
    command.upgrade(config, "0021")
    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == ("0021",)


def test_0021_populated_complete_tuple_survives_downgrade_and_reupgrade(tmp_path: Path) -> None:
    database = tmp_path / "populated-round-trip.db"
    config = _config(database)
    command.upgrade(config, "0021")
    with closing(sqlite3.connect(database)) as connection:
        _insert_batch(
            connection,
            request_hash=_REQUEST_HASH,
            revision=7,
            attempted_at=_ATTEMPT_AT,
        )
        connection.commit()
    command.downgrade(config, "0020")
    command.upgrade(config, "0021")
    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == ("0021",)
        assert connection.execute(
            "SELECT current_attempt_request_sha256, "
            "current_attempt_authorization_revision, current_attempt_at FROM telemetry_batches"
        ).fetchone() == (_REQUEST_HASH, 7, _ATTEMPT_AT)


def test_0021_downgrade_restores_historical_0020_constraint(tmp_path: Path) -> None:
    database = tmp_path / "historical-constraint.db"
    config = _config(database)
    command.upgrade(config, "0021")
    command.downgrade(config, "0020")
    with closing(sqlite3.connect(database)) as connection:
        _insert_batch(connection, request_hash=None, revision=None, attempted_at=_ATTEMPT_AT)
        connection.commit()
    with pytest.raises(RuntimeError, match="partial telemetry current-attempt evidence"):
        command.upgrade(config, "0021")
    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == ("0020",)


def test_0021_offline_postgresql_upgrade_emits_guard_before_constraint_ddl(capsys) -> None:
    config = Config(_ALEMBIC_INI)
    config.set_main_option("sqlalchemy.url", "postgresql://user:password@localhost/database")
    config.attributes["explicit_database_url"] = True
    command.upgrade(config, "0020:0021", sql=True)
    output = capsys.readouterr().out
    writer_lock = output.index("LOCK TABLE telemetry_batches IN SHARE ROW EXCLUSIVE MODE")
    guard = output.index("DO $$ BEGIN IF EXISTS")
    constraint_ddl = output.index("DROP CONSTRAINT ck_telemetry_batch_current_attempt")
    assert writer_lock < guard < constraint_ddl
    assert "NOT COALESCE" in output
    assert "refusing partial telemetry current-attempt evidence" in output


def test_0021_rejects_unsupported_online_dialects(monkeypatch) -> None:
    path = (
        _ROOT
        / "one_os_edge"
        / "backend"
        / "alembic"
        / "versions"
        / "0021_telemetry_current_attempt_null_closure.py"
    )
    spec = importlib.util.spec_from_file_location("migration_0021", path)
    assert spec is not None and spec.loader is not None
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)

    class Dialect:
        name = "mysql"

    class Bind:
        dialect = Dialect()

    monkeypatch.setattr(migration.context, "is_offline_mode", lambda: False)
    monkeypatch.setattr(migration.op, "get_bind", lambda: Bind())
    with pytest.raises(RuntimeError, match="unsupported database dialect"):
        migration.upgrade()
