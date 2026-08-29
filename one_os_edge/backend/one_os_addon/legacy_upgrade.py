from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import os
import shutil
import sqlite3
import tempfile
from contextlib import ExitStack, closing, contextmanager
from datetime import UTC, datetime
from pathlib import Path

from alembic import command
from alembic.config import Config
from cryptography.hazmat.primitives import serialization
from sqlalchemy.engine import make_url

from .pairing_backend import PairingError, validate_issued_credential
from .pairing_storage import IdentityStore, UnsafeIdentityStorage

_LEGACY_REVISIONS = {"0009", "0010", "0011", "0012", "0013", "0014"}
_EMPTY_LEGACY_TELEMETRY_TABLES = (
    "telemetry_streams",
    "telemetry_outbox_segments",
    "telemetry_outbox_records",
    "telemetry_gaps",
    "telemetry_batches",
    "telemetry_batch_records",
    "telemetry_batch_gaps",
    "telemetry_ingest_state",
)
_IDENTITY_FIELDS = (
    "status",
    "revision",
    "active_spki_sha256",
    "credential_id",
    "certificate_sha256",
    "certificate_not_after",
    "installation_revision",
    "renewal_status",
    "renewal_request_id",
    "renewal_issuance_expires_at",
    "renewal_ack_expires_at",
    "updated_at",
)


def _b64u(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _revision(connection: sqlite3.Connection) -> str | None:
    if (
        connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='alembic_version'"
        ).fetchone()
        is None
    ):
        return None
    rows = connection.execute("SELECT version_num FROM alembic_version").fetchall()
    if len(rows) != 1:
        raise RuntimeError("legacy Edge database has an invalid Alembic revision cardinality")
    return str(rows[0][0])


def _alembic_config(config_path: Path, database: Path) -> Config:
    config = Config(str(config_path))
    config.set_main_option("sqlalchemy.url", f"sqlite:///{database}")
    config.attributes["explicit_database_url"] = True
    return config


def _normalize_catalog_sql(sql: str) -> str:
    normalized = " ".join(sql.split())
    if not normalized.upper().startswith("CREATE TABLE") or "(" not in normalized:
        return normalized
    prefix, body = normalized.split("(", 1)
    body = body.rsplit(")", 1)[0]
    clauses: list[str] = []
    start = 0
    depth = 0
    for index, character in enumerate(body):
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
        elif character == "," and depth == 0:
            clauses.append(body[start:index].strip())
            start = index + 1
    clauses.append(body[start:].strip())
    return f"{prefix.strip()} ({','.join(sorted(clauses))})"


def _catalog(connection: sqlite3.Connection) -> tuple[tuple[object, ...], ...]:
    entries: list[tuple[object, ...]] = [
        (kind, name, table, _normalize_catalog_sql(sql))
        for kind, name, table, sql in connection.execute(
            "SELECT type, name, tbl_name, COALESCE(sql, '') FROM sqlite_schema "
            "WHERE name NOT LIKE 'sqlite_stat%' ORDER BY type, name, tbl_name"
        ).fetchall()
    ]
    tables = connection.execute(
        "SELECT name FROM sqlite_schema WHERE type='table' "
        "AND name NOT LIKE 'sqlite_stat%' ORDER BY name"
    ).fetchall()
    for (table,) in tables:
        columns = connection.execute(
            'SELECT cid, name, type, "notnull", dflt_value, pk '
            "FROM pragma_table_info(?) ORDER BY cid",
            (table,),
        ).fetchall()
        entries.extend(("column", table, *column) for column in columns)
    return tuple(entries)


def _assert_database_valid(connection: sqlite3.Connection, label: str) -> None:
    if connection.execute("PRAGMA integrity_check").fetchone() != ("ok",):
        raise RuntimeError(f"{label} failed SQLite integrity check")
    if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
        raise RuntimeError(f"{label} failed SQLite foreign-key check")


def _assert_catalog(
    connection: sqlite3.Connection,
    expected: tuple[tuple[object, ...], ...],
    label: str,
) -> None:
    if _catalog(connection) != expected:
        raise RuntimeError(f"{label} catalog does not match the canonical migration catalog")


def _assert_empty_legacy_telemetry(connection: sqlite3.Connection) -> None:
    tables = {
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        )
    }
    for table in _EMPTY_LEGACY_TELEMETRY_TABLES:
        query = f"SELECT 1 FROM {table} LIMIT 1"  # noqa: S608 - fixed internal allowlist
        if table in tables and connection.execute(query).fetchone():
            raise RuntimeError(f"legacy telemetry compatibility requires empty state: {table}")


def _snapshot_identity(connection: sqlite3.Connection) -> tuple[object, ...]:
    query = (
        "SELECT "  # noqa: S608 - fixed internal field allowlist
        + ",".join(_IDENTITY_FIELDS)
        + " FROM edge_identity WHERE id=1"
    )
    rows = connection.execute(query).fetchall()
    if len(rows) != 1:
        raise RuntimeError("legacy Edge identity singleton is missing")
    return rows[0]


def _validate_cross_store_identity(
    connection: sqlite3.Connection, identity_dir: Path | None
) -> None:
    if identity_dir is None:
        raise RuntimeError("legacy Edge identity directory is required for compatibility upgrade")
    identity = connection.execute(
        "SELECT installation_id, status, revision, active_spki_sha256, credential_id, "
        "certificate_sha256, certificate_not_after, installation_revision "
        "FROM edge_identity WHERE id=1"
    ).fetchone()
    if identity is None:
        raise RuntimeError("legacy Edge identity singleton is missing")
    (
        installation_id,
        status,
        revision,
        active_spki,
        credential,
        certificate,
        not_after,
        install_rev,
    ) = identity
    if status not in {"registering", "paired"}:
        raise RuntimeError("legacy Edge identity is not eligible for compatibility upgrade")
    pairing = connection.execute(
        "SELECT status, revision, registration_request_id, session_id, candidate_spki_sha256, "
        "credential_id, certificate_sha256, installation_revision, tenant_id, site_id "
        "FROM edge_pairing WHERE id=1"
    ).fetchone()
    if pairing is None or pairing[0] != status or pairing[1] != revision:
        raise RuntimeError("legacy Edge identity/pairing lifecycle binding mismatch")

    store = IdentityStore(identity_dir)
    try:
        if status == "registering":
            if any(
                value is not None
                for value in (active_spki, credential, certificate, not_after, install_rev)
            ) or pairing[5:8] != (None, None, None):
                raise RuntimeError("legacy registering identity contains paired credential state")
            candidate_spki = pairing[4]
            if not isinstance(candidate_spki, str):
                raise RuntimeError("legacy registering identity lacks candidate binding")
            key = store.load_candidate()
            key_spki = key.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            if _b64u(hashlib.sha256(key_spki).digest()) != candidate_spki:
                raise RuntimeError("legacy registering candidate key identity binding mismatch")
            transient_bytes = store._read_private(  # noqa: SLF001 - strict read-only storage guard
                store.root / "transient", "pairing.json"
            )
            transient = json.loads(transient_bytes)
            expected = {
                "installationId": installation_id,
                "registrationRequestId": pairing[2],
                "spkiSha256": candidate_spki,
            }
            if pairing[3] is not None:
                expected["sessionId"] = pairing[3]
            if not isinstance(transient, dict) or any(
                transient.get(field) != value for field, value in expected.items()
            ):
                raise RuntimeError("legacy registering transient identity binding mismatch")
            if (
                not isinstance(transient.get("bootstrapToken"), str)
                or not transient["bootstrapToken"]
            ):
                raise RuntimeError("legacy registering transient bootstrap state is missing")
            return

        if not all(
            value is not None
            for value in (active_spki, credential, certificate, not_after, install_rev)
        ) or pairing[5:8] != (credential, certificate, install_rev):
            raise RuntimeError("legacy paired identity binding mismatch")
        if not all(isinstance(value, str) for value in (pairing[8], pairing[9])):
            raise RuntimeError("legacy paired tenant/site binding is missing")
        private_key = store.load_identity()
        certificate_pem, chain_pem = store.read_identity_credential()
        leaf = validate_issued_credential(
            private_key,
            certificate_pem,
            chain_pem,
            certificate,
            installation_id,
            pairing[8],
            pairing[9],
            datetime.now(UTC),
        )
        stored_not_after = datetime.fromisoformat(str(not_after).replace("Z", "+00:00"))
        if stored_not_after.tzinfo is None:
            stored_not_after = stored_not_after.replace(tzinfo=UTC)
        if stored_not_after.astimezone(UTC) != leaf.not_valid_after_utc:
            raise RuntimeError("legacy paired certificate expiry binding mismatch")
        leaf_spki = leaf.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        if _b64u(hashlib.sha256(leaf_spki).digest()) != active_spki:
            raise RuntimeError("legacy paired certificate SPKI binding mismatch")
    except (
        OSError,
        UnicodeError,
        ValueError,
        json.JSONDecodeError,
        UnsafeIdentityStorage,
        PairingError,
    ) as error:
        raise RuntimeError("legacy Edge private identity verification failed") from error


def _requires_compatibility(connection: sqlite3.Connection) -> bool:
    revision = _revision(connection)
    if revision not in _LEGACY_REVISIONS:
        return False
    rows = connection.execute(
        "SELECT status, revision, active_spki_sha256, credential_id, certificate_sha256, "
        "certificate_not_after, installation_revision, renewal_status, renewal_request_id, "
        "renewal_issuance_expires_at, renewal_ack_expires_at FROM edge_identity"
    ).fetchall()
    if len(rows) > 1:
        raise RuntimeError("legacy Edge identity singleton is violated")
    if not rows:
        return False
    return rows[0] != ("unpaired", 0, None, None, None, None, None, None, None, None, None)


def _neutralize_identity(connection: sqlite3.Connection) -> None:
    connection.execute(
        "UPDATE edge_identity SET status='unpaired', revision=0, "
        "active_spki_sha256=NULL, credential_id=NULL, certificate_sha256=NULL, "
        "certificate_not_after=NULL, installation_revision=NULL, renewal_status=NULL, "
        "renewal_request_id=NULL, renewal_issuance_expires_at=NULL, renewal_ack_expires_at=NULL "
        "WHERE id=1"
    )
    connection.commit()


def _restore_identity(connection: sqlite3.Connection, values: tuple[object, ...]) -> None:
    assignments = ",".join(f"{field}=?" for field in _IDENTITY_FIELDS)
    query = f"UPDATE edge_identity SET {assignments} WHERE id=1"  # noqa: S608
    connection.execute(query, values)
    connection.commit()


def _verify_candidate(
    connection: sqlite3.Connection,
    expected_identity: tuple[object, ...],
    expected_catalog: tuple[tuple[object, ...], ...],
) -> None:
    _assert_database_valid(connection, "legacy Edge upgrade candidate")
    _assert_catalog(connection, expected_catalog, "legacy Edge upgrade candidate")
    if _revision(connection) != "0021":
        raise RuntimeError("legacy Edge upgrade candidate did not reach schema head")
    if _snapshot_identity(connection) != expected_identity:
        raise RuntimeError("legacy Edge identity changed during compatibility upgrade")
    installation_id = connection.execute(
        "SELECT installation_id FROM edge_identity WHERE id=1"
    ).fetchone()[0]
    if connection.execute(
        "SELECT telemetry_authorization_revision, lineage_id FROM edge_identity WHERE id=1"
    ).fetchone() != (1, installation_id):
        raise RuntimeError("legacy Edge telemetry authority baseline is invalid")
    _assert_empty_legacy_telemetry(connection)
    if connection.execute("SELECT last_journal_id FROM telemetry_journal_state").fetchone() != (0,):
        raise RuntimeError("legacy Edge telemetry journal is not at baseline")
    for table in ("telemetry_authority_cuts", "telemetry_authority_activation"):
        query = f"SELECT 1 FROM {table} LIMIT 1"  # noqa: S608 - fixed internal allowlist
        if connection.execute(query).fetchone():
            raise RuntimeError(f"legacy Edge upgrade unexpectedly activated {table}")


def _checkpoint_to_delete(connection: sqlite3.Connection, label: str) -> None:
    checkpoint = connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
    if checkpoint is None or checkpoint[0] != 0:
        raise RuntimeError(f"{label} WAL checkpoint did not complete")
    mode = connection.execute("PRAGMA journal_mode=DELETE").fetchone()
    if mode is None or str(mode[0]).lower() != "delete":
        raise RuntimeError(f"{label} could not leave WAL mode safely")


def _fsync_file(path: Path) -> None:
    with path.open("rb") as handle:
        os.fsync(handle.fileno())


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _remove_private_upgrade_artifacts(path: Path) -> None:
    path.unlink(missing_ok=True)
    Path(f"{path}-wal").unlink(missing_ok=True)
    Path(f"{path}-shm").unlink(missing_ok=True)


@contextmanager
def _migration_lock(database: Path):
    lock_path = database.parent / ".one-os-edge-legacy-upgrade.lock"
    descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def upgrade_legacy_sqlite(
    database_url: str, config_path: Path, identity_dir: Path | None = None
) -> bool:
    url = make_url(database_url)
    if not url.drivername.startswith("sqlite") or not url.database or url.database == ":memory:":
        return False
    database = Path(url.database).resolve()
    if not database.is_file():
        return False

    temporary: Path | None = None
    reference: Path | None = None
    committed = False
    with ExitStack() as cleanup, _migration_lock(database):
        with closing(sqlite3.connect(database, timeout=30)) as source:
            source.execute("PRAGMA busy_timeout=30000")
            if not _requires_compatibility(source):
                return False
            locking = source.execute("PRAGMA locking_mode=EXCLUSIVE").fetchone()
            if locking is None or str(locking[0]).lower() != "exclusive":
                raise RuntimeError("legacy Edge source could not retain exclusive locking")
            source.execute("BEGIN EXCLUSIVE")
            source.commit()
            _checkpoint_to_delete(source, "legacy Edge source")
            source.execute("BEGIN EXCLUSIVE")
            try:
                revision = _revision(source)
                assert revision in _LEGACY_REVISIONS
                _assert_database_valid(source, "legacy Edge source")
                _assert_empty_legacy_telemetry(source)

                ref_fd, ref_name = tempfile.mkstemp(
                    prefix=f".{database.name}.canonical-", suffix=".tmp", dir=database.parent
                )
                os.close(ref_fd)
                reference = Path(ref_name)
                cleanup.callback(_remove_private_upgrade_artifacts, reference)
                os.chmod(reference, 0o600)
                reference_config = _alembic_config(config_path, reference)
                command.upgrade(reference_config, revision)
                with closing(sqlite3.connect(reference)) as canonical:
                    canonical_catalog = _catalog(canonical)
                _assert_catalog(source, canonical_catalog, "legacy Edge predecessor")
                _validate_cross_store_identity(source, identity_dir)

                tmp_fd, tmp_name = tempfile.mkstemp(
                    prefix=f".{database.name}.legacy-upgrade-", suffix=".tmp", dir=database.parent
                )
                os.close(tmp_fd)
                temporary = Path(tmp_name)
                cleanup.callback(_remove_private_upgrade_artifacts, temporary)
                os.chmod(temporary, 0o600)
                shutil.copyfile(database, temporary)
                os.chmod(temporary, 0o600)

                config = _alembic_config(config_path, temporary)
                command.upgrade(config, "0014")
                with closing(sqlite3.connect(temporary)) as candidate:
                    _assert_empty_legacy_telemetry(candidate)
                    identity = _snapshot_identity(candidate)
                    _neutralize_identity(candidate)
                command.upgrade(config, "head")
                command.upgrade(reference_config, "head")
                with closing(sqlite3.connect(reference)) as canonical:
                    head_catalog = _catalog(canonical)
                publication = cleanup.enter_context(closing(sqlite3.connect(temporary, timeout=30)))
                publication.execute("PRAGMA busy_timeout=30000")
                _restore_identity(publication, identity)
                _verify_candidate(publication, identity, head_catalog)
                _checkpoint_to_delete(publication, "legacy Edge candidate")
                locking = publication.execute("PRAGMA locking_mode=EXCLUSIVE").fetchone()
                if locking is None or str(locking[0]).lower() != "exclusive":
                    raise RuntimeError("legacy Edge candidate could not retain exclusive locking")
                publication.execute("BEGIN EXCLUSIVE")
                publication.commit()
                for sidecar in (Path(f"{temporary}-wal"), Path(f"{temporary}-shm")):
                    if sidecar.exists():
                        raise RuntimeError("legacy Edge candidate retained SQLite sidecars")
                os.chmod(temporary, 0o600)
                _fsync_file(temporary)
                os.replace(temporary, database)
                committed = True
                _fsync_directory(database.parent)
            finally:
                source.rollback()

    for path in (temporary, reference):
        if path is not None:
            path.unlink(missing_ok=True)
            Path(f"{path}-wal").unlink(missing_ok=True)
            Path(f"{path}-shm").unlink(missing_ok=True)
    if committed:
        return True
    return False
