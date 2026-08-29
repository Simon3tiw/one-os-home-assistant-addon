from __future__ import annotations

import sqlite3
from contextlib import closing
from pathlib import Path

import pytest
from one_os_addon.soak_probe import ProbeError, collect_status


def database(path: Path, *, revision: str = "0021", unknown: bool = False) -> None:
    with closing(sqlite3.connect(path)) as connection:
        connection.executescript(
            "CREATE TABLE alembic_version(version_num TEXT NOT NULL);"
            "CREATE TABLE telemetry_batches(status TEXT NOT NULL, quarantined_at TEXT);"
        )
        connection.execute("INSERT INTO alembic_version VALUES (?)", (revision,))
        rows = [
            ("pending", None),
            ("leased", None),
            ("acked", None),
            ("quarantined", "2026-08-13T12:00:00Z"),
        ]
        if unknown:
            rows.append(("invented", None))
        connection.executemany("INSERT INTO telemetry_batches VALUES (?, ?)", rows)
        connection.commit()


def test_collects_exact_public_projection_from_read_only_sqlite(tmp_path: Path) -> None:
    path = tmp_path / "commissioning.db"
    database(path)
    result = collect_status(path)
    assert result == {
        "softwareVersion": "0.4.0",
        "databaseRevision": "0021",
        "telemetryDelivery": {
            "pending": 1,
            "leased": 1,
            "acked": 1,
            "quarantined": 1,
            "oldestQuarantine": "2026-08-13T12:00:00Z",
        },
    }


def test_missing_wrong_revision_unknown_status_and_symlink_fail_closed(tmp_path: Path) -> None:
    with pytest.raises(ProbeError, match="database_open"):
        collect_status(tmp_path / "missing.db")
    wrong = tmp_path / "wrong.db"
    database(wrong, revision="0012")
    with pytest.raises(ProbeError, match="database_revision"):
        collect_status(wrong)
    unknown = tmp_path / "unknown.db"
    database(unknown, unknown=True)
    with pytest.raises(ProbeError, match="delivery_status"):
        collect_status(unknown)
    target = tmp_path / "target.db"
    database(target)
    link = tmp_path / "link.db"
    link.symlink_to(target)
    with pytest.raises(ProbeError, match="database_open"):
        collect_status(link)


def test_collects_from_current_production_alembic_head(tmp_path: Path) -> None:
    from alembic import command
    from alembic.config import Config

    path = tmp_path / "production-head.db"
    config = Config("one_os_edge/alembic.ini")
    config.set_main_option("sqlalchemy.url", f"sqlite:///{path}")
    config.attributes["explicit_database_url"] = True
    command.upgrade(config, "head")

    result = collect_status(path)
    assert result["databaseRevision"] == "0021"


def test_collector_is_stdlib_only_and_side_effect_free() -> None:
    source = (Path(__file__).parents[1] / "one_os_addon/soak_probe.py").read_text()
    for forbidden in (
        "sqlalchemy",
        "fastapi",
        "SUPERVISOR_TOKEN",
        "requests",
        "httpx",
        "INSERT ",
        "UPDATE ",
        "DELETE ",
        "CREATE ",
    ):
        assert forbidden not in source
    assert "mode=ro" in source
    assert "PRAGMA query_only=ON" in source
