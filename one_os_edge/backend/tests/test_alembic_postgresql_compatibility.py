import hashlib
import os
import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import IntegrityError

ROOT = Path(__file__).parents[3]
ALEMBIC_INI = ROOT / "one_os_edge" / "alembic.ini"
VERSIONS = ROOT / "one_os_edge" / "backend" / "alembic" / "versions"
POSTGRES_ADMIN_URL = os.getenv("ONE_OS_EDGE_TEST_POSTGRES_ADMIN_URL")
IMMUTABLE_MIGRATION_HASHES = {
    "0002_commissioning_lifecycle.py": (
        "dae75e23c67a670fd441fc627322aa95ffab51bcc5b9fa51b613a50d8c82766b"
    ),
    "0003_ontology_provenance.py": (
        "cb7653fafa2d39b0a6394a142097c1f85ca2c43ef40c94993febb7fb58cd3b9c"
    ),
    "0004_central_destination.py": (
        "f7c5be0868096b0bda87df07a4eb83962e945911e2e5403b0a3886aeb469cbc1"
    ),
    "0005_edge_pairing_metadata.py": (
        "f64f408347ceba70adfe516b66d30f6dab8037b4915daa0df61eaceeab733369"
    ),
    "0006_configuration_snapshots.py": (
        "4865713581b187c6ed9f6fb8fe5bb203cf3a26633fd6028a8d79ebb15292adec"
    ),
    "0007_edge_credential_renewal.py": (
        "20a977bdb2316fdd662c95982d5c65eb83f4b644c1cfabbeed7235cbb793ffbf"
    ),
    "0008_pairing_issuance_deadline.py": (
        "ffae700834ce8717bfe6993e1a657deb5f0856cd7746a6856dca0a2e1665a926"
    ),
    "0009_central_session_revision.py": (
        "25b934ea5b78a3b455a9c8f9ebdac845464aa20abadc195dee7bd8deea7cbb6b"
    ),
    "0010_telemetry_outbox.py": (
        "4d6ec51d48696d6175f03b39d9b70a02b5337da76d8b6ad75153699b22dff56f"
    ),
    "0011_telemetry_delivery.py": (
        "071148ad507c1838b7823fa6f37da8b6f4b0d573aaed9346ae4e48ae79bf9552"
    ),
    "0012_telemetry_batch_quarantine.py": (
        "6b9a8d0d38b3510114599736432f3f8653232349a43f09edabe0f86da8a83b0c"
    ),
    "0013_telemetry_expired_quarantine.py": (
        "d3d2ea5fd7efe418724413cf3fb3d94b984e55e916017c73725032537e6f4fba"
    ),
}


def _config(database_url: str) -> Config:
    config = Config(ALEMBIC_INI)
    config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    config.attributes["explicit_database_url"] = True
    return config


@contextmanager
def _disposable_database():
    if not POSTGRES_ADMIN_URL:
        pytest.skip("requires ONE_OS_EDGE_TEST_POSTGRES_ADMIN_URL")
    name = f"one_os_edge_migration_{uuid.uuid4().hex}"
    admin_engine = create_engine(POSTGRES_ADMIN_URL, isolation_level="AUTOCOMMIT")
    database_url = (
        make_url(POSTGRES_ADMIN_URL).set(database=name).render_as_string(hide_password=False)
    )
    with admin_engine.connect() as connection:
        connection.execute(text(f'CREATE DATABASE "{name}"'))  # noqa: S608
    try:
        yield database_url
    finally:
        with admin_engine.connect() as connection:
            connection.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))  # noqa: S608
        admin_engine.dispose()


def _compatibility_objects(connection) -> tuple[int, int, int]:
    schemas = connection.scalar(
        text(
            "SELECT count(*) FROM pg_namespace WHERE nspname LIKE 'one_os_alembic_boolean_compat_%'"
        )
    )
    operators = connection.scalar(
        text(
            "SELECT count(*) FROM pg_operator o "
            "JOIN pg_namespace n ON n.oid = o.oprnamespace "
            "WHERE n.nspname LIKE 'one_os_alembic_boolean_compat_%'"
        )
    )
    functions = connection.scalar(
        text(
            "SELECT count(*) FROM pg_proc p "
            "JOIN pg_namespace n ON n.oid = p.pronamespace "
            "WHERE n.nspname LIKE 'one_os_alembic_boolean_compat_%'"
        )
    )
    return schemas, operators, functions


def test_immutable_0002_through_0013_migration_hashes() -> None:
    actual = {
        filename: hashlib.sha256((VERSIONS / filename).read_bytes()).hexdigest()
        for filename in IMMUTABLE_MIGRATION_HASHES
    }
    assert actual == IMMUTABLE_MIGRATION_HASHES


def test_fresh_postgresql_base_to_current_head_leaves_no_compatibility_objects() -> None:
    with _disposable_database() as database_url:
        config = _config(database_url)
        expected_head = ScriptDirectory.from_config(config).get_current_head()
        command.upgrade(config, "head")

        engine = create_engine(database_url)
        with engine.connect() as connection:
            assert (
                connection.scalar(text("SELECT version_num FROM alembic_version")) == expected_head
            )
            assert _compatibility_objects(connection) == (0, 0, 0)
        engine.dispose()


def test_failed_0002_postgresql_upgrade_rolls_back_compatibility_objects() -> None:
    with _disposable_database() as database_url:
        config = _config(database_url)
        command.upgrade(config, "0001")
        engine = create_engine(database_url)
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO properties(id, object_id, key, value_type, value_json) "
                    "VALUES ('orphan', 'missing', 'key', 'string', '\"value\"')"
                )
            )

        with pytest.raises(RuntimeError, match="orphan or ambiguous"):
            command.upgrade(config, "0002")

        with engine.connect() as connection:
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "0001"
            assert _compatibility_objects(connection) == (0, 0, 0)
        engine.dispose()


_CURRENT_ATTEMPT_INSERT = text(
    """
    INSERT INTO telemetry_batches (
      batch_id, installation_id, installation_revision, batch_authorization_revision,
      journal_id, credential_id, payload_sha256, request_sha256, request_bytes,
      sample_count, quality_event_count, gap_count, status, attempt_count, created_at,
      current_attempt_request_sha256, current_attempt_authorization_revision, current_attempt_at
    ) VALUES (:batch_id, :installation, 1, 7, :journal_id, :credential, :payload, :request,
              decode('7b7d', 'hex'), 1, 0, 0, 'pending', 0, :created,
              :proof_hash, :proof_revision, :attempted_at)
    """
)


def _current_attempt_values(mask: int) -> dict[str, object]:
    return {
        "batch_id": f"33333333-3333-4333-8333-{mask:012d}",
        "installation": "00000000-0000-4000-8000-000000000002",
        "journal_id": mask + 1,
        "credential": "22222222-2222-4222-8222-222222222222",
        "payload": "a" * 43,
        "request": "b" * 43,
        "created": "2030-01-01 00:00:00+00",
        "proof_hash": "b" * 43 if mask & 1 else None,
        "proof_revision": 7 if mask & 2 else None,
        "attempted_at": "2030-01-01 00:00:01+00" if mask & 4 else None,
    }


@pytest.mark.parametrize("mask", range(8))
def test_current_head_postgresql_accepts_only_all_null_or_complete_current_attempt_tuple(
    mask: int,
) -> None:
    with _disposable_database() as database_url:
        config = _config(database_url)
        command.upgrade(config, "head")
        engine = create_engine(database_url)
        if mask in (0, 7):
            with engine.begin() as connection:
                connection.execute(_CURRENT_ATTEMPT_INSERT, _current_attempt_values(mask))
        else:
            with pytest.raises(IntegrityError):
                with engine.begin() as connection:
                    connection.execute(_CURRENT_ATTEMPT_INSERT, _current_attempt_values(mask))
        engine.dispose()


def test_0021_postgresql_empty_and_populated_round_trips() -> None:
    with _disposable_database() as database_url:
        config = _config(database_url)
        command.upgrade(config, "0021")
        command.downgrade(config, "0020")
        command.upgrade(config, "0021")
        engine = create_engine(database_url)
        with engine.begin() as connection:
            connection.execute(_CURRENT_ATTEMPT_INSERT, _current_attempt_values(7))
        command.downgrade(config, "0020")
        command.upgrade(config, "0021")
        with engine.connect() as connection:
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "0021"
            assert connection.execute(
                text(
                    "SELECT current_attempt_request_sha256, "
                    "current_attempt_authorization_revision, current_attempt_at IS NOT NULL "
                    "FROM telemetry_batches"
                )
            ).one() == ("b" * 43, 7, True)
        engine.dispose()


def test_0020_to_0021_postgresql_writer_lock_precedes_dirty_preflight() -> None:
    with _disposable_database() as database_url:
        config = _config(database_url)
        command.upgrade(config, "0020")
        engine = create_engine(database_url)
        with engine.begin() as connection:
            connection.execute(_CURRENT_ATTEMPT_INSERT, _current_attempt_values(0))

        writer = engine.connect()
        transaction = writer.begin()
        writer.execute(
            text(
                "UPDATE telemetry_batches SET current_attempt_at=:attempted "
                "WHERE batch_id=:batch_id"
            ),
            {
                "attempted": "2030-01-01 00:00:01+00",
                "batch_id": _current_attempt_values(0)["batch_id"],
            },
        )
        errors: list[BaseException] = []

        def migrate() -> None:
            try:
                command.upgrade(config, "0021")
            except BaseException as error:  # asserted in parent thread
                errors.append(error)

        thread = threading.Thread(target=migrate)
        thread.start()
        time.sleep(0.2)
        assert thread.is_alive(), "migration did not wait for the predecessor writer"
        transaction.commit()
        writer.close()
        thread.join(timeout=10)
        assert not thread.is_alive()
        assert len(errors) == 1
        assert "partial telemetry current-attempt evidence" in str(errors[0])
        with engine.connect() as connection:
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "0020"
            assert connection.scalar(
                text(
                    "SELECT current_attempt_at IS NOT NULL FROM telemetry_batches "
                    "WHERE batch_id=:batch_id"
                ),
                {"batch_id": _current_attempt_values(0)["batch_id"]},
            )
        engine.dispose()
