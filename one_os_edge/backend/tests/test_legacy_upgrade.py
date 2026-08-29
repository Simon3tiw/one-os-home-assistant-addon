from __future__ import annotations

import base64
import hashlib
import os
import re
import sqlite3
import threading
from contextlib import closing
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from cryptography.hazmat.primitives import serialization
from one_os_addon import legacy_upgrade
from one_os_addon.app import migrate_database
from one_os_addon.pairing_storage import IdentityStore
from test_pairing_backend import issue_client_certificate

_INSTALLATION_ID = "00000000-0000-4000-8000-000000000002"
_REGISTRATION_ID = "11111111-1111-4111-8111-111111111111"
_CANDIDATE_HASH = "A" * 43
_CSR_HASH = "B" * 43
_UPDATED_AT = "2030-01-01 00:00:00"


def _config(database: Path) -> Config:
    config = Config("one_os_edge/alembic.ini")
    config.set_main_option("sqlalchemy.url", f"sqlite:///{database}")
    config.attributes["explicit_database_url"] = True
    return config


def _create_real_v030_registering_shape(database: Path) -> Path:
    identity_dir = database.parent / "identity"
    store = IdentityStore(identity_dir)
    candidate = store.create_candidate()
    candidate_spki = candidate.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    candidate_hash = (
        base64.urlsafe_b64encode(hashlib.sha256(candidate_spki).digest())
        .rstrip(b"=")
        .decode("ascii")
    )
    store.write_transient(
        {
            "installationId": _INSTALLATION_ID,
            "registrationRequestId": _REGISTRATION_ID,
            "spkiSha256": candidate_hash,
            "bootstrapToken": "synthetic-bootstrap-token",
        }
    )
    command.upgrade(_config(database), "0009")
    with closing(sqlite3.connect(database)) as connection:
        connection.execute(
            """
            INSERT INTO edge_identity (
              id, installation_id, status, revision, active_spki_sha256, credential_id,
              certificate_sha256, certificate_not_after, installation_revision,
              renewal_status, renewal_request_id, renewal_issuance_expires_at,
              renewal_ack_expires_at, updated_at
            ) VALUES (1, ?, 'registering', 1, NULL, NULL, NULL, NULL, NULL,
                      NULL, NULL, NULL, NULL, ?)
            """,
            (_INSTALLATION_ID, _UPDATED_AT),
        )
        connection.execute(
            """
            INSERT INTO edge_pairing (
              id, revision, mode, status, registration_request_id, session_id,
              token_generation, candidate_spki_sha256, csr_sha256, tenant_id,
              site_id, claim_revision, installation_revision, credential_id,
              certificate_sha256, registration_expires_at, code_expires_at,
              claim_expires_at, ack_expires_at, last_error, updated_at,
              issuance_expires_at, central_session_revision
            ) VALUES (
              1, 1, 'initial', 'registering', ?, NULL, 0, ?, ?, NULL,
              NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, ?, NULL, NULL
            )
            """,
            (_REGISTRATION_ID, candidate_hash, _CSR_HASH, _UPDATED_AT),
        )
        connection.commit()
    return identity_dir


def test_migrate_database_copy_upgrades_real_v030_registering_state_without_reset(
    tmp_path: Path,
) -> None:
    database = tmp_path / "commissioning.db"
    identity_dir = _create_real_v030_registering_shape(database)
    before_inode = database.stat().st_ino
    with closing(sqlite3.connect(database)) as connection:
        identity_before = connection.execute("SELECT * FROM edge_identity WHERE id=1").fetchone()
        pairing_before = connection.execute("SELECT * FROM edge_pairing WHERE id=1").fetchone()

    migrate_database(f"sqlite:///{database}", identity_dir=identity_dir)

    assert database.stat().st_ino != before_inode
    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == ("0021",)
        identity_columns = [
            row[1] for row in connection.execute("PRAGMA table_info(edge_identity)")
        ]
        query = (
            "SELECT "  # noqa: S608 - reflected fixed application schema
            + ",".join(
                column
                for column in identity_columns
                if column not in {"telemetry_authorization_revision", "lineage_id"}
            )
            + " FROM edge_identity WHERE id=1"
        )
        identity_after = connection.execute(query).fetchone()
        assert identity_after == identity_before
        assert connection.execute(
            "SELECT telemetry_authorization_revision, lineage_id FROM edge_identity WHERE id=1"
        ).fetchone() == (1, _INSTALLATION_ID)
        assert (
            connection.execute("SELECT * FROM edge_pairing WHERE id=1").fetchone() == pairing_before
        )
        assert connection.execute(
            "SELECT last_journal_id FROM telemetry_journal_state"
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT COUNT(*) FROM telemetry_authority_activation"
        ).fetchone() == (0,)
        for table in (
            "telemetry_streams",
            "telemetry_outbox_segments",
            "telemetry_outbox_records",
            "telemetry_gaps",
            "telemetry_batches",
            "telemetry_batch_records",
            "telemetry_batch_gaps",
            "telemetry_ingest_state",
            "telemetry_authority_cuts",
        ):
            query = f"SELECT COUNT(*) FROM {table}"  # noqa: S608 - fixed test allowlist
            assert connection.execute(query).fetchone() == (0,)
    assert not list(tmp_path.glob(".commissioning.db.*legacy-upgrade*"))
    assert os.stat(database).st_mode & 0o077 == 0


def test_migrate_database_refuses_mismatched_paired_legacy_identity_before_upgrade(
    tmp_path: Path,
) -> None:
    database = tmp_path / "commissioning.db"
    command.upgrade(_config(database), "0009")
    with closing(sqlite3.connect(database)) as connection:
        connection.execute(
            """
            INSERT INTO edge_identity (
              id, installation_id, status, revision, active_spki_sha256, credential_id,
              certificate_sha256, certificate_not_after, installation_revision,
              renewal_status, renewal_request_id, renewal_issuance_expires_at,
              renewal_ack_expires_at, updated_at
            ) VALUES (1, ?, 'paired', 9, ?, ?, ?, ?, 7, NULL, NULL, NULL, NULL, ?)
            """,
            (
                _INSTALLATION_ID,
                "S" * 43,
                "22222222-2222-4222-8222-222222222222",
                "C" * 43,
                "2031-01-01 00:00:00",
                _UPDATED_AT,
            ),
        )
        connection.execute(
            """
            INSERT INTO edge_pairing (
              id, revision, mode, status, registration_request_id, token_generation,
              candidate_spki_sha256, csr_sha256, installation_revision, credential_id,
              certificate_sha256, tenant_id, site_id, updated_at
            ) VALUES (1, 9, 'initial', 'paired', ?, 0, ?, ?, 7, ?, ?, 'tenant-1', 'site-1', ?)
            """,
            (
                _REGISTRATION_ID,
                _CANDIDATE_HASH,
                _CSR_HASH,
                "33333333-3333-4333-8333-333333333333",
                "D" * 43,
                _UPDATED_AT,
            ),
        )
        connection.commit()
        before = connection.execute("SELECT * FROM edge_identity WHERE id=1").fetchone()

    with pytest.raises(RuntimeError, match="legacy paired identity binding mismatch"):
        migrate_database(f"sqlite:///{database}", identity_dir=tmp_path / "identity")

    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == ("0009",)
        assert connection.execute("SELECT * FROM edge_identity WHERE id=1").fetchone() == before
    assert not list(tmp_path.glob(".commissioning.db.*legacy-upgrade*"))


def _create_v030_paired_shape(database: Path) -> Path:
    credential = "22222222-2222-4222-8222-222222222222"
    identity_dir = database.parent / "identity"
    store = IdentityStore(identity_dir)
    key = store.load_or_create_identity()
    leaf, certificate_pem, chain_pem = issue_client_certificate(
        key.public_key(), _INSTALLATION_ID, tenant="tenant-1", site="site-1"
    )
    store.write_identity_credential(certificate_pem, chain_pem)
    certificate = (
        base64.urlsafe_b64encode(
            hashlib.sha256(leaf.public_bytes(serialization.Encoding.DER)).digest()
        )
        .rstrip(b"=")
        .decode("ascii")
    )
    active_spki = (
        base64.urlsafe_b64encode(
            hashlib.sha256(
                key.public_key().public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            ).digest()
        )
        .rstrip(b"=")
        .decode("ascii")
    )
    command.upgrade(_config(database), "0009")
    with closing(sqlite3.connect(database)) as connection:
        connection.execute(
            """
            INSERT INTO edge_identity (
              id, installation_id, status, revision, active_spki_sha256, credential_id,
              certificate_sha256, certificate_not_after, installation_revision,
              renewal_status, renewal_request_id, renewal_issuance_expires_at,
              renewal_ack_expires_at, updated_at
            ) VALUES (1, ?, 'paired', 9, ?, ?, ?, ?, 7, NULL, NULL, NULL, NULL, ?)
            """,
            (
                _INSTALLATION_ID,
                active_spki,
                credential,
                certificate,
                leaf.not_valid_after_utc.replace(tzinfo=None).isoformat(sep=" "),
                _UPDATED_AT,
            ),
        )
        connection.execute(
            """
            INSERT INTO edge_pairing (
              id, revision, mode, status, registration_request_id, token_generation,
              candidate_spki_sha256, csr_sha256, installation_revision, credential_id,
              certificate_sha256, tenant_id, site_id, updated_at
            ) VALUES (1, 9, 'initial', 'paired', ?, 0, ?, ?, 7, ?, ?, 'tenant-1', 'site-1', ?)
            """,
            (
                _REGISTRATION_ID,
                _CANDIDATE_HASH,
                _CSR_HASH,
                credential,
                certificate,
                _UPDATED_AT,
            ),
        )
        connection.commit()
    return identity_dir


def test_migrate_database_preserves_complete_paired_v030_bindings(tmp_path: Path) -> None:
    database = tmp_path / "commissioning.db"
    identity_dir = _create_v030_paired_shape(database)
    with closing(sqlite3.connect(database)) as connection:
        identity_before = connection.execute("SELECT * FROM edge_identity WHERE id=1").fetchone()
        pairing_before = connection.execute("SELECT * FROM edge_pairing WHERE id=1").fetchone()

    migrate_database(f"sqlite:///{database}", identity_dir=identity_dir)

    with closing(sqlite3.connect(database)) as connection:
        old_columns = [
            row[1]
            for row in connection.execute("PRAGMA table_info(edge_identity)")
            if row[1] not in {"telemetry_authorization_revision", "lineage_id"}
        ]
        query = (
            "SELECT "  # noqa: S608 - reflected fixed application schema
            + ",".join(old_columns)
            + " FROM edge_identity WHERE id=1"
        )
        assert connection.execute(query).fetchone() == identity_before
        assert (
            connection.execute("SELECT * FROM edge_pairing WHERE id=1").fetchone() == pairing_before
        )
        assert connection.execute(
            "SELECT telemetry_authorization_revision, lineage_id FROM edge_identity WHERE id=1"
        ).fetchone() == (1, _INSTALLATION_ID)
        assert connection.execute(
            "SELECT COUNT(*) FROM telemetry_authority_activation"
        ).fetchone() == (0,)


def test_migrate_database_refuses_nonempty_legacy_telemetry_without_changing_revision(
    tmp_path: Path,
) -> None:
    database = tmp_path / "commissioning.db"
    identity_dir = _create_real_v030_registering_shape(database)
    command.upgrade(_config(database), "0010")
    with closing(sqlite3.connect(database)) as connection:
        connection.execute(
            "INSERT INTO telemetry_outbox_segments "
            "(segment_id,relative_path,committed_bytes,live_bytes,sealed,created_at) "
            "VALUES ('11111111-1111-4111-8111-111111111111','segment.bin',0,0,0,?)",
            (_UPDATED_AT,),
        )
        connection.commit()
        identity_before = connection.execute("SELECT * FROM edge_identity WHERE id=1").fetchone()

    with pytest.raises(RuntimeError, match="requires empty state: telemetry_outbox_segments"):
        migrate_database(f"sqlite:///{database}", identity_dir=identity_dir)

    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == ("0010",)
        assert (
            connection.execute("SELECT * FROM edge_identity WHERE id=1").fetchone()
            == identity_before
        )
        assert connection.execute("SELECT COUNT(*) FROM telemetry_outbox_segments").fetchone() == (
            1,
        )
    assert not list(tmp_path.glob(".commissioning.db.*legacy-upgrade*"))


def test_migrate_database_swap_failure_keeps_original_legacy_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "commissioning.db"
    identity_dir = _create_real_v030_registering_shape(database)
    inode_before = database.stat().st_ino
    with closing(sqlite3.connect(database)) as connection:
        identity_before = connection.execute("SELECT * FROM edge_identity WHERE id=1").fetchone()
        pairing_before = connection.execute("SELECT * FROM edge_pairing WHERE id=1").fetchone()

    def fail_replace(_source, _destination) -> None:
        raise OSError("injected atomic swap failure")

    monkeypatch.setattr("one_os_addon.legacy_upgrade.os.replace", fail_replace)
    with pytest.raises(OSError, match="injected atomic swap failure"):
        migrate_database(f"sqlite:///{database}", identity_dir=identity_dir)

    assert database.stat().st_ino == inode_before
    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == ("0009",)
        assert (
            connection.execute("SELECT * FROM edge_identity WHERE id=1").fetchone()
            == identity_before
        )
        assert (
            connection.execute("SELECT * FROM edge_pairing WHERE id=1").fetchone() == pairing_before
        )
    assert not list(tmp_path.glob(".commissioning.db.*legacy-upgrade*"))


def test_migrate_database_refuses_paired_certificate_expiry_mismatch(tmp_path: Path) -> None:
    database = tmp_path / "commissioning.db"
    identity_dir = _create_v030_paired_shape(database)
    with closing(sqlite3.connect(database)) as connection:
        connection.execute(
            "UPDATE edge_identity SET certificate_not_after='2099-01-01 00:00:00' WHERE id=1"
        )
        connection.commit()

    with pytest.raises(RuntimeError, match="certificate expiry"):
        migrate_database(f"sqlite:///{database}", identity_dir=identity_dir)

    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == ("0009",)


def test_migrate_database_keeps_source_when_candidate_checkpoint_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "commissioning.db"
    identity_dir = _create_real_v030_registering_shape(database)
    inode_before = database.stat().st_ino
    with closing(sqlite3.connect(database)) as connection:
        identity_before = connection.execute("SELECT * FROM edge_identity WHERE id=1").fetchone()

    original_checkpoint = legacy_upgrade._checkpoint_to_delete

    def fail_candidate_checkpoint(connection, label):
        if label == "legacy Edge candidate":
            raise RuntimeError("injected candidate checkpoint failure")
        return original_checkpoint(connection, label)

    monkeypatch.setattr(legacy_upgrade, "_checkpoint_to_delete", fail_candidate_checkpoint)
    with pytest.raises(RuntimeError, match="candidate checkpoint failure"):
        migrate_database(f"sqlite:///{database}", identity_dir=identity_dir)

    assert database.stat().st_ino == inode_before
    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == ("0009",)
        assert (
            connection.execute("SELECT * FROM edge_identity WHERE id=1").fetchone()
            == identity_before
        )
    assert not list(tmp_path.glob(".commissioning.db.*legacy-upgrade*"))


def test_migrate_database_refuses_counterfeit_predecessor_catalog(tmp_path: Path) -> None:
    database = tmp_path / "commissioning.db"
    identity_dir = _create_real_v030_registering_shape(database)
    with closing(sqlite3.connect(database)) as connection:
        connection.execute("DROP INDEX uq_active_binding")
        connection.commit()

    with pytest.raises(RuntimeError, match="catalog"):
        migrate_database(f"sqlite:///{database}", identity_dir=identity_dir)

    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == ("0009",)
        indexes = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='index'")
        }
    assert "uq_active_binding" not in indexes


def test_migrate_database_refuses_reordered_predecessor_columns(tmp_path: Path) -> None:
    database = tmp_path / "commissioning.db"
    identity_dir = _create_real_v030_registering_shape(database)
    with closing(sqlite3.connect(database)) as connection:
        connection.execute("PRAGMA foreign_keys=OFF")
        original_sql = connection.execute(
            "SELECT sql FROM sqlite_schema WHERE type='table' AND name='structures'"
        ).fetchone()[0]
        reordered_sql, replacements = re.subn(
            r"name VARCHAR NOT NULL,\s+source_key VARCHAR NOT NULL",
            "source_key VARCHAR NOT NULL, name VARCHAR NOT NULL",
            original_sql,
            count=1,
        )
        assert replacements == 1
        connection.execute("PRAGMA writable_schema=ON")
        connection.execute(
            "UPDATE sqlite_schema SET sql=? WHERE type='table' AND name='structures'",
            (reordered_sql,),
        )
        connection.execute("PRAGMA writable_schema=OFF")
        schema_version = connection.execute("PRAGMA schema_version").fetchone()[0]
        connection.execute(f"PRAGMA schema_version={schema_version + 1}")  # noqa: S608
        connection.commit()

    with pytest.raises(RuntimeError, match="catalog"):
        migrate_database(f"sqlite:///{database}", identity_dir=identity_dir)


def test_migrate_database_refuses_registering_pairing_credential_tuple(tmp_path: Path) -> None:
    database = tmp_path / "commissioning.db"
    identity_dir = _create_real_v030_registering_shape(database)
    with closing(sqlite3.connect(database)) as connection:
        connection.execute(
            "UPDATE edge_pairing SET credential_id='unexpected', "
            "certificate_sha256=?, installation_revision=1 WHERE id=1",
            ("U" * 43,),
        )
        connection.commit()

    with pytest.raises(RuntimeError, match="registering"):
        migrate_database(f"sqlite:///{database}", identity_dir=identity_dir)


def test_migrate_database_refuses_intermediate_legacy_lifecycle(tmp_path: Path) -> None:
    database = tmp_path / "commissioning.db"
    identity_dir = _create_real_v030_registering_shape(database)
    with closing(sqlite3.connect(database)) as connection:
        connection.execute("UPDATE edge_identity SET status='registered'")
        connection.execute("UPDATE edge_pairing SET status='registered'")
        connection.commit()

    with pytest.raises(RuntimeError, match="eligible"):
        migrate_database(f"sqlite:///{database}", identity_dir=identity_dir)


def test_migrate_database_refuses_registering_state_without_private_candidate(
    tmp_path: Path,
) -> None:
    database = tmp_path / "commissioning.db"
    _create_real_v030_registering_shape(database)

    with pytest.raises(RuntimeError, match="identity"):
        migrate_database(f"sqlite:///{database}", identity_dir=tmp_path / "missing-identity")


def test_migrate_database_locks_published_inode_until_migration_boundary_closes(
    tmp_path: Path, monkeypatch
) -> None:
    database = tmp_path / "commissioning.db"
    identity_dir = _create_real_v030_registering_shape(database)
    original_replace = legacy_upgrade.os.replace
    writer_committed = False
    writer_rejected = False

    def raced_replace(source, destination):
        nonlocal writer_committed, writer_rejected
        original_replace(source, destination)
        try:
            with closing(sqlite3.connect(database, timeout=0.1)) as writer:
                writer.execute("PRAGMA busy_timeout=100")
                writer.execute("UPDATE edge_identity SET updated_at='post-verify-concurrent-write'")
                writer.commit()
                writer_committed = True
        except sqlite3.OperationalError:
            writer_rejected = True

    monkeypatch.setattr(legacy_upgrade.os, "replace", raced_replace)

    migrate_database(f"sqlite:///{database}", identity_dir=identity_dir)
    assert writer_rejected is True
    assert writer_committed is False
    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute("PRAGMA quick_check").fetchone() == ("ok",)
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == ("0021",)
        assert connection.execute("SELECT updated_at FROM edge_identity WHERE id=1").fetchone() != (
            "post-verify-concurrent-write",
        )


def test_migrate_database_rejects_wal_writer_at_checkpoint_lock_boundary(
    tmp_path: Path, monkeypatch
) -> None:
    database = tmp_path / "commissioning.db"
    identity_dir = _create_real_v030_registering_shape(database)
    original_checkpoint = legacy_upgrade._checkpoint_to_delete
    writer_committed = False
    writer_rejected = False

    def raced_checkpoint(connection, label):
        nonlocal writer_committed, writer_rejected
        original_checkpoint(connection, label)
        if label != "legacy Edge source":
            return
        try:
            with closing(sqlite3.connect(database, timeout=0.1)) as writer:
                writer.execute("PRAGMA busy_timeout=100")
                writer.execute("PRAGMA journal_mode=WAL")
                writer.execute("UPDATE edge_identity SET updated_at='concurrent-write'")
                writer.commit()
                writer_committed = True
        except sqlite3.OperationalError:
            writer_rejected = True

    monkeypatch.setattr(legacy_upgrade, "_checkpoint_to_delete", raced_checkpoint)

    migrate_database(f"sqlite:///{database}", identity_dir=identity_dir)
    assert writer_rejected is True
    assert writer_committed is False
    assert not Path(f"{database}-wal").exists()
    assert not Path(f"{database}-shm").exists()
    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute("PRAGMA quick_check").fetchone() == ("ok",)
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == ("0021",)
        assert connection.execute("SELECT updated_at FROM edge_identity WHERE id=1").fetchone() != (
            "concurrent-write",
        )


def test_migrate_database_holds_exclusive_source_boundary_until_publish(
    tmp_path: Path, monkeypatch
) -> None:
    database = tmp_path / "commissioning.db"
    identity_dir = _create_real_v030_registering_shape(database)
    reached_candidate = threading.Event()
    release_candidate = threading.Event()
    original_upgrade = legacy_upgrade.command.upgrade

    def paused_upgrade(config, revision):
        if revision == "0014":
            reached_candidate.set()
            assert release_candidate.wait(timeout=10)
        return original_upgrade(config, revision)

    monkeypatch.setattr(legacy_upgrade.command, "upgrade", paused_upgrade)
    failures: list[BaseException] = []

    def run_upgrade() -> None:
        try:
            migrate_database(f"sqlite:///{database}", identity_dir=identity_dir)
        except BaseException as error:  # pragma: no cover - surfaced below
            failures.append(error)

    thread = threading.Thread(target=run_upgrade)
    thread.start()
    assert reached_candidate.wait(timeout=10)
    try:
        with closing(sqlite3.connect(database, timeout=0.1)) as writer:
            with pytest.raises(sqlite3.OperationalError, match="locked"):
                writer.execute("UPDATE edge_identity SET updated_at='concurrent-write'")
                writer.commit()
    finally:
        release_candidate.set()
        thread.join(timeout=20)
    assert not thread.is_alive()
    assert failures == []
