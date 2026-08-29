from __future__ import annotations

import base64
import binascii
import fcntl
import hashlib
import json
import os
import shutil
import sqlite3
import stat
import tempfile
from contextlib import ExitStack, closing, contextmanager
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

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


def _is_canonical_uuid4(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = UUID(value)
    except (ValueError, TypeError, AttributeError):
        return False
    return parsed.version == 4 and str(parsed) == value


def _is_canonical_b64u_sha256(value: object) -> bool:
    if not isinstance(value, str) or len(value) != 43 or "=" in value:
        return False
    try:
        decoded = base64.b64decode(value + "=", altchars=b"-_", validate=True)
    except (ValueError, binascii.Error):
        return False
    return (
        len(decoded) == 32
        and base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") == value
    )


def _assert_open_identity_recovery_directory(identity_dir: Path, descriptor: int) -> None:
    opened = os.fstat(descriptor)
    try:
        current = identity_dir.lstat()
    except FileNotFoundError as error:
        raise RuntimeError(
            "legacy Edge identity recovery requires a stable private identity directory"
        ) from error
    if (
        not stat.S_ISDIR(opened.st_mode)
        or not stat.S_ISDIR(current.st_mode)
        or opened.st_uid != os.geteuid()
        or current.st_uid != os.geteuid()
        or stat.S_IMODE(opened.st_mode) != 0o700
        or stat.S_IMODE(current.st_mode) != 0o700
        or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
    ):
        raise RuntimeError(
            "legacy Edge identity recovery requires a stable private identity directory"
        )
    if os.listdir(descriptor):
        raise RuntimeError("legacy Edge identity recovery requires an empty identity directory")


def _open_identity_recovery_directory(identity_dir: Path) -> int:
    try:
        descriptor = os.open(
            identity_dir,
            os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
    except OSError as error:
        raise RuntimeError(
            "legacy Edge identity recovery requires a safe private identity directory"
        ) from error
    try:
        _assert_open_identity_recovery_directory(identity_dir, descriptor)
    except (OSError, RuntimeError):
        os.close(descriptor)
        raise
    return descriptor


def _validate_identity_recovery_state(
    connection: sqlite3.Connection, identity_dir: Path | None
) -> int | None:
    if _revision(connection) != "0009":
        raise RuntimeError("legacy Edge identity recovery requires revision 0009")
    if identity_dir is None:
        raise RuntimeError("legacy Edge identity directory is required for identity recovery")

    identities = connection.execute(
        "SELECT installation_id, status, revision, active_spki_sha256, credential_id, "
        "certificate_sha256, certificate_not_after, installation_revision, renewal_status, "
        "renewal_request_id, renewal_issuance_expires_at, renewal_ack_expires_at "
        "FROM edge_identity"
    ).fetchall()
    if len(identities) != 1:
        raise RuntimeError("legacy Edge identity recovery requires one identity singleton")
    identity = identities[0]
    if not _is_canonical_uuid4(identity[0]) or identity[1:] != (
        "identity_missing_after_restore",
        2,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    ):
        raise RuntimeError("legacy Edge identity recovery state is not eligible")

    pairings = connection.execute(
        "SELECT mode, status, revision, registration_request_id, session_id, "
        "token_generation, candidate_spki_sha256, csr_sha256, tenant_id, site_id, "
        "claim_revision, installation_revision, credential_id, certificate_sha256, "
        "registration_expires_at, code_expires_at, claim_expires_at, issuance_expires_at, "
        "ack_expires_at, central_session_revision, last_error FROM edge_pairing"
    ).fetchall()
    if len(pairings) != 1:
        raise RuntimeError("legacy Edge identity recovery requires one pairing singleton")
    pairing = pairings[0]
    if (
        pairing[:3] != ("initial", "identity_missing_after_restore", 2)
        or not _is_canonical_uuid4(pairing[3])
        or not _is_canonical_b64u_sha256(pairing[6])
        or not _is_canonical_b64u_sha256(pairing[7])
        or pairing[4] is not None
        or pairing[5] != 0
        or any(value is not None for value in pairing[8:21])
    ):
        raise RuntimeError("legacy Edge pairing recovery state is not eligible")
    try:
        identity_dir.lstat()
    except FileNotFoundError:
        return None
    return _open_identity_recovery_directory(identity_dir)


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


def _prepare_identity_recovery_candidate(connection: sqlite3.Connection) -> tuple[object, ...]:
    _neutralize_identity(connection)
    connection.execute("DELETE FROM edge_pairing")
    connection.commit()
    return _snapshot_identity(connection)


def _record_identity_recovery_audit(connection: sqlite3.Connection) -> None:
    installation_id = connection.execute(
        "SELECT installation_id FROM edge_identity WHERE id=1"
    ).fetchone()[0]
    connection.execute(
        "INSERT INTO audit (id, actor_id, at, action, object_id, revision, fields_json) "
        "VALUES (?, 'system', ?, 'identity_recovery_authorized', 'edge_identity', 0, ?)",
        (
            f"audit:identity-recovery:{installation_id}",
            datetime.now(UTC).isoformat(),
            '["pairing_state","credential_binding","private_identity"]',
        ),
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


def _copy_private_preflight_state(database: Path, target: Path) -> None:
    source_sidecars = {
        suffix for suffix in ("-wal", "-shm") if Path(f"{database}{suffix}").exists()
    }
    for suffix in ("", "-wal"):
        source_path = database if not suffix else Path(f"{database}{suffix}")
        if suffix and suffix not in source_sidecars:
            continue
        metadata = source_path.lstat()
        if not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError("legacy Edge preflight source is not a regular file")
        source_descriptor = os.open(source_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            opened = os.fstat(source_descriptor)
            if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                raise RuntimeError("legacy Edge preflight source changed while opening")
            target_path = target if not suffix else Path(f"{target}{suffix}")
            target_descriptor = os.open(target_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with (
                os.fdopen(target_descriptor, "wb") as destination,
                os.fdopen(source_descriptor, "rb", closefd=False) as source,
            ):
                shutil.copyfileobj(source, destination)
                destination.flush()
                os.fsync(destination.fileno())
            after = os.fstat(source_descriptor)
            current = source_path.lstat()
            expected = (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns)
            if (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
            ) != expected or (
                current.st_dev,
                current.st_ino,
                current.st_size,
                current.st_mtime_ns,
            ) != expected:
                raise RuntimeError("legacy Edge preflight source changed while copying")
        finally:
            os.close(source_descriptor)
    if {
        suffix for suffix in ("-wal", "-shm") if Path(f"{database}{suffix}").exists()
    } != source_sidecars:
        raise RuntimeError("legacy Edge preflight sidecar set changed while copying")


def _assert_identity_recovery_single_file_source(database: Path) -> None:
    if any(Path(f"{database}{suffix}").exists() for suffix in ("-wal", "-shm")):
        raise RuntimeError(
            "legacy Edge identity recovery requires a clean single-file SQLite source"
        )


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
    database_url: str,
    config_path: Path,
    identity_dir: Path | None = None,
    identity_recovery_authorized: bool = False,
) -> bool:
    url = make_url(database_url)
    if not url.drivername.startswith("sqlite") or not url.database or url.database == ":memory:":
        return False
    database = Path(url.database).resolve()
    if not database.is_file():
        return False

    temporary: Path | None = None
    reference: Path | None = None
    identity_directory_descriptor: int | None = None
    committed = False
    with ExitStack() as cleanup, _migration_lock(database):
        if identity_recovery_authorized:
            _assert_identity_recovery_single_file_source(database)
        preflight_fd, preflight_name = tempfile.mkstemp(
            prefix=f".{database.name}.preflight-", suffix=".tmp", dir=database.parent
        )
        os.close(preflight_fd)
        preflight_database = Path(preflight_name)
        preflight_database.unlink()
        cleanup.callback(_remove_private_upgrade_artifacts, preflight_database)
        _copy_private_preflight_state(database, preflight_database)
        with closing(sqlite3.connect(preflight_database, timeout=30)) as preflight:
            preflight.execute("PRAGMA busy_timeout=30000")
            if not _requires_compatibility(preflight):
                return False
            revision = _revision(preflight)
            assert revision in _LEGACY_REVISIONS
            _assert_database_valid(preflight, "legacy Edge source")
            _assert_empty_legacy_telemetry(preflight)

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
            _assert_catalog(preflight, canonical_catalog, "legacy Edge predecessor")
            if identity_recovery_authorized:
                identity_directory_descriptor = _validate_identity_recovery_state(
                    preflight, identity_dir
                )
                if identity_directory_descriptor is not None:
                    cleanup.callback(os.close, identity_directory_descriptor)
            else:
                _validate_cross_store_identity(preflight, identity_dir)
            _checkpoint_to_delete(preflight, "legacy Edge private preflight")

        for sidecar in (
            Path(f"{preflight_database}-wal"),
            Path(f"{preflight_database}-shm"),
        ):
            if sidecar.exists():
                raise RuntimeError("legacy Edge private preflight retained SQLite sidecars")
        if identity_recovery_authorized:
            _assert_identity_recovery_single_file_source(database)

        with closing(sqlite3.connect(database, timeout=30)) as source:
            source.execute("PRAGMA busy_timeout=30000")
            if not _requires_compatibility(source):
                raise RuntimeError("legacy Edge source changed after recovery preflight")
            locking = source.execute("PRAGMA locking_mode=EXCLUSIVE").fetchone()
            if locking is None or str(locking[0]).lower() != "exclusive":
                raise RuntimeError("legacy Edge source could not retain exclusive locking")
            source.execute("BEGIN EXCLUSIVE")
            try:
                if _revision(source) != revision:
                    raise RuntimeError("legacy Edge source changed before exclusive validation")
                _assert_database_valid(source, "legacy Edge source")
                _assert_empty_legacy_telemetry(source)
                _assert_catalog(source, canonical_catalog, "legacy Edge predecessor")
                if identity_recovery_authorized:
                    repeated_descriptor = _validate_identity_recovery_state(source, identity_dir)
                    if repeated_descriptor is not None:
                        os.close(repeated_descriptor)
                    if identity_directory_descriptor is not None:
                        assert identity_dir is not None
                        _assert_open_identity_recovery_directory(
                            identity_dir, identity_directory_descriptor
                        )
                else:
                    _validate_cross_store_identity(source, identity_dir)

                tmp_fd, tmp_name = tempfile.mkstemp(
                    prefix=f".{database.name}.legacy-upgrade-", suffix=".tmp", dir=database.parent
                )
                os.close(tmp_fd)
                temporary = Path(tmp_name)
                cleanup.callback(_remove_private_upgrade_artifacts, temporary)
                os.chmod(temporary, 0o600)
                shutil.copyfile(preflight_database, temporary)
                os.chmod(temporary, 0o600)

                config = _alembic_config(config_path, temporary)
                command.upgrade(config, "0014")
                with closing(sqlite3.connect(temporary)) as candidate:
                    _assert_empty_legacy_telemetry(candidate)
                    if identity_recovery_authorized:
                        identity = _prepare_identity_recovery_candidate(candidate)
                    else:
                        identity = _snapshot_identity(candidate)
                        _neutralize_identity(candidate)
                command.upgrade(config, "head")
                command.upgrade(reference_config, "head")
                with closing(sqlite3.connect(reference)) as canonical:
                    head_catalog = _catalog(canonical)
                publication = cleanup.enter_context(closing(sqlite3.connect(temporary, timeout=30)))
                publication.execute("PRAGMA busy_timeout=30000")
                if not identity_recovery_authorized:
                    _restore_identity(publication, identity)
                else:
                    _record_identity_recovery_audit(publication)
                _verify_candidate(publication, identity, head_catalog)
                if (
                    identity_recovery_authorized
                    and publication.execute("SELECT 1 FROM edge_pairing LIMIT 1").fetchone()
                ):
                    raise RuntimeError("legacy Edge identity recovery retained pairing state")
                if identity_recovery_authorized and identity_directory_descriptor is None:
                    assert identity_dir is not None
                    try:
                        identity_dir.mkdir(mode=0o700)
                    except FileExistsError:
                        pass
                    identity_directory_descriptor = _open_identity_recovery_directory(identity_dir)
                    cleanup.callback(os.close, identity_directory_descriptor)
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
                if identity_recovery_authorized:
                    assert identity_dir is not None
                    assert identity_directory_descriptor is not None
                    _assert_open_identity_recovery_directory(
                        identity_dir, identity_directory_descriptor
                    )
                source.commit()
                _checkpoint_to_delete(source, "legacy Edge source")
                source.execute("BEGIN EXCLUSIVE")
                if identity_recovery_authorized:
                    _assert_identity_recovery_single_file_source(database)
                    assert identity_dir is not None
                    assert identity_directory_descriptor is not None
                    _assert_open_identity_recovery_directory(
                        identity_dir, identity_directory_descriptor
                    )
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
