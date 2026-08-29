"""Side-effect-free public status projection for the dedicated mTLS probe."""

from __future__ import annotations

import os
import sqlite3
import stat
from contextlib import closing
from pathlib import Path

from .version import DATABASE_REVISION, RELEASE_VERSION

EXPECTED_DATABASE_REVISION = DATABASE_REVISION
DELIVERY_STATUSES = ("pending", "leased", "acked", "quarantined")


class ProbeError(RuntimeError):
    pass


def _open_database(path: Path) -> tuple[int, sqlite3.Connection]:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as error:
        raise ProbeError("database_open") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ProbeError("database_open")
        uri = f"file:/proc/self/fd/{descriptor}?mode=ro"
        connection = sqlite3.connect(uri, uri=True, timeout=2)
    except (OSError, sqlite3.Error, ProbeError) as error:
        os.close(descriptor)
        if isinstance(error, ProbeError):
            raise
        raise ProbeError("database_open") from error
    return descriptor, connection


def collect_status(path: Path) -> dict[str, object]:
    descriptor, connection = _open_database(path)
    try:
        with closing(connection):
            connection.execute("PRAGMA query_only=ON")
            if connection.execute("PRAGMA query_only").fetchone() != (1,):
                raise ProbeError("database_read_only")
            revisions = connection.execute("SELECT version_num FROM alembic_version").fetchall()
            if revisions != [(EXPECTED_DATABASE_REVISION,)]:
                raise ProbeError("database_revision")
            rows = connection.execute(
                "SELECT status, COUNT(*) FROM telemetry_batches GROUP BY status"
            ).fetchall()
            counts = {status: 0 for status in DELIVERY_STATUSES}
            for status_value, count_value in rows:
                if status_value not in counts or type(count_value) is not int or count_value < 0:
                    raise ProbeError("delivery_status")
                counts[status_value] = count_value
            oldest = connection.execute(
                "SELECT MIN(quarantined_at) FROM telemetry_batches WHERE status = 'quarantined'"
            ).fetchone()
            if (
                type(oldest) is not tuple
                or len(oldest) != 1
                or (oldest[0] is not None and type(oldest[0]) is not str)
            ):
                raise ProbeError("delivery_status")
    except sqlite3.Error as error:
        raise ProbeError("database_query") from error
    finally:
        os.close(descriptor)
    return {
        "softwareVersion": RELEASE_VERSION,
        "databaseRevision": EXPECTED_DATABASE_REVISION,
        "telemetryDelivery": {**counts, "oldestQuarantine": oldest[0]},
    }
