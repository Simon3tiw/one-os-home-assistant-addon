import pytest


def test_v1_to_v2_migration_preserves_property_and_adds_constraints(tmp_path):
    import sqlite3
    from contextlib import closing

    from alembic import command
    from alembic.config import Config

    database = tmp_path / "upgrade.db"
    config = Config("one_os_edge/alembic.ini")
    config.set_main_option("sqlalchemy.url", f"sqlite:///{database}")
    config.attributes["explicit_database_url"] = True
    command.upgrade(config, "0001")
    with closing(sqlite3.connect(database)) as connection:
        connection.execute(
            "INSERT INTO sites(id,installation_id,name) "
            "VALUES('site_v1','installation_v1','Legacy site')"
        )
        connection.execute(
            "INSERT INTO properties(id,object_id,key,value_type,value_json) "
            "VALUES('prop_v1','site_v1','legacy_note','string','\"preserve me\"')"
        )
        connection.commit()

    command.upgrade(config, "head")
    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute(
            "SELECT site_id,key,value_json,revision FROM properties WHERE id='prop_v1'"
        ).fetchone() == ("site_v1", "legacy_note", '"preserve me"', 1)
        structure_sql = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='structures'"
        ).fetchone()[0]
        assert "ck_structure_exactly_one_parent" in structure_sql
        assert {row[3] for row in connection.execute("PRAGMA foreign_key_list(assets)")} >= {
            "space_id",
            "source_space_id",
        }
        assert {row[3] for row in connection.execute("PRAGMA foreign_key_list(points)")} >= {
            "asset_id",
            "source_asset_id",
        }


def test_v2_to_v3_migration_backfills_ontology_provenance_and_downgrades(tmp_path):
    import sqlite3
    from contextlib import closing

    from alembic import command
    from alembic.config import Config

    database = tmp_path / "ontology-upgrade.db"
    config = Config("one_os_edge/alembic.ini")
    config.set_main_option("sqlalchemy.url", f"sqlite:///{database}")
    config.attributes["explicit_database_url"] = True
    command.upgrade(config, "0002")
    with closing(sqlite3.connect(database)) as connection:
        connection.execute(
            "INSERT INTO points("
            "id,asset_id,source_key,registry_id,current_entity_id,source_name,ontology_class"
            ") "
            "VALUES(?,?,?,?,?,?,?)",
            (
                "point_v2",
                "legacy_asset",
                "ha:entity:sensor.legacy",
                "sensor.legacy",
                "sensor.legacy",
                "Legacy sensor",
                "https://brickschema.org/schema/Brick#Temperature_Sensor",
            ),
        )
        connection.commit()

    command.upgrade(config, "head")
    command.upgrade(config, "head")
    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute(
            "SELECT ontology_class, ontology_class_source FROM points WHERE id='point_v2'"
        ).fetchone() == (
            "https://brickschema.org/schema/Brick#Temperature_Sensor",
            "one_os_override",
        )

    command.downgrade(config, "0002")
    with closing(sqlite3.connect(database)) as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(points)")}
        assert "ontology_class_source" not in columns
        assert connection.execute(
            "SELECT ontology_class FROM points WHERE id='point_v2'"
        ).fetchone() == ("https://brickschema.org/schema/Brick#Temperature_Sensor",)


def test_diagnostics_is_allowlist_only_and_audit_is_safe(client, auth, fake_ha):
    from datetime import datetime

    from one_os_addon.models import TelemetryBatch

    fake_ha.states["sensor.room_temperature"]["state"] = "CANARY_SECRET_STATE"
    client.post("/api/v1/reconcile", headers=auth)
    with client.app.state.session() as session:
        session.add(
            TelemetryBatch(
                batch_id="99999999-9999-4999-8999-999999999999",
                installation_id="88888888-8888-4888-8888-888888888888",
                installation_revision=1,
                batch_authorization_revision=1,
                journal_id=1,
                credential_id="77777777-7777-4777-8777-777777777777",
                payload_sha256="DO_NOT_EXPORT_PAYLOAD_HASH",
                request_sha256="DO_NOT_EXPORT_REQUEST_HASH",
                request_bytes=b"DO_NOT_EXPORT_TELEMETRY_BYTES",
                sample_count=1,
                quality_event_count=0,
                gap_count=0,
                status="quarantined",
                lease_owner=None,
                lease_until=None,
                attempt_count=1,
                last_attempt_at=datetime(2030, 1, 1, 12, 0),
                next_attempt_at=None,
                ack_bytes=None,
                ingest_cursor=None,
                acked_at=None,
                terminal_reason="immutable_conflict",
                quarantined_at=datetime(2030, 1, 1, 12, 1),
                created_at=datetime(2030, 1, 1, 12, 0),
            )
        )
        session.commit()
    diag = client.get("/api/v1/diagnostics/export", headers=auth)
    assert set(diag.json()) == {
        "schemaVersion",
        "softwareVersion",
        "architecture",
        "installationHash",
        "databaseRevision",
        "connectorPresence",
        "lastSync",
        "counts",
        "storage",
        "telemetryDelivery",
    }
    assert diag.json()["softwareVersion"] == "0.4.1"
    assert diag.json()["databaseRevision"] == "0021"
    assert diag.json()["telemetryDelivery"] == {
        "pending": 0,
        "leased": 0,
        "acked": 0,
        "quarantined": 1,
        "oldestQuarantine": {
            "at": "2030-01-01T12:01:00",
            "reason": "immutable_conflict",
        },
    }
    assert "CANARY" not in diag.text and "sensor.room_temperature" not in diag.text
    assert "99999999" not in diag.text and "DO_NOT_EXPORT" not in diag.text
    assert all(
        set(row) <= {"actorId", "at", "action", "objectId", "revision", "fields"}
        for row in client.get("/api/v1/audit", headers=auth).json()
    )


def test_database_persists_stable_ids_and_overrides(tmp_path, fake_ha):
    from conftest import admin_headers
    from fastapi.testclient import TestClient
    from one_os_addon.app import create_app

    db = f"sqlite:///{tmp_path / 'persist.db'}"
    h = admin_headers()
    app = create_app(
        database_url=db,
        ha_client=fake_ha,
        ingress_proxies={"testclient"},
        allowed_origins={"http://testserver"},
    )
    with TestClient(app) as c:
        token = c.get("/api/v1/session", headers=h).json()["csrfToken"]
        mut = h | {
            "Origin": "http://testserver",
            "Sec-Fetch-Site": "same-origin",
            "Content-Type": "application/json",
            "X-CSRF-Token": token,
        }
        c.post("/api/v1/reconcile", headers=mut)
        p = c.get("/api/v1/inventory", headers=h).json()["flatPoints"][0]
        c.patch(
            f"/api/v1/points/{p['id']}/overrides",
            headers=mut,
            json={"revision": p["revision"], "displayName": "Persistent"},
        )
    app.state.engine.dispose()
    app2 = create_app(
        database_url=db,
        ha_client=fake_ha,
        ingress_proxies={"testclient"},
        allowed_origins={"http://testserver"},
    )
    with TestClient(app2) as c:
        d = c.get(f"/api/v1/points/{p['id']}", headers=h).json()
        assert d["id"] == p["id"] and d["display"]["name"]["value"] == "Persistent"
    app2.state.engine.dispose()


def test_fake_records_zero_mutations(client, auth, fake_ha):
    client.post("/api/v1/reconcile", headers=auth)
    assert fake_ha.mutation_attempts == []


def test_cold_backup_restore_preserves_complete_commissioning_state(tmp_path, fake_ha):
    import fnmatch
    import sqlite3
    import tarfile
    from contextlib import closing
    from pathlib import Path

    import yaml
    from conftest import admin_headers
    from fastapi.testclient import TestClient
    from one_os_addon.app import create_app
    from one_os_addon.configuration_snapshot import ConfigurationSnapshotRepository
    from one_os_addon.models import EdgeIdentity

    source_data = tmp_path / "source-data"
    restore_data = tmp_path / "restore-data"
    source_identity = source_data / "identity"
    restored_identity = restore_data / "identity"
    source_data.mkdir()
    restore_data.mkdir()
    source = source_data / "one-os.db"
    bundle = tmp_path / "cold-backup.tar.gz"
    headers = admin_headers()
    app = create_app(
        database_url=f"sqlite:///{source}",
        ha_client=fake_ha,
        ingress_proxies={"testclient"},
        allowed_origins={"http://testserver"},
        identity_dir=source_identity,
    )
    with TestClient(app) as client:
        token = client.get("/api/v1/session", headers=headers).json()["csrfToken"]
        mutation = headers | {
            "Origin": "http://testserver",
            "Sec-Fetch-Site": "same-origin",
            "Content-Type": "application/json",
            "X-CSRF-Token": token,
        }
        assert client.post("/api/v1/reconcile", headers=mutation).status_code == 200
        inventory = client.get("/api/v1/inventory", headers=headers).json()
        asset = next(
            item
            for structure in inventory["structures"]
            for space in structure["spaces"]
            for item in space["assets"]
            if len(item["points"]) == 2
        )
        point = asset["points"][0]
        overridden = client.patch(
            f"/api/v1/points/{point['id']}/overrides",
            headers=mutation,
            json={"revision": point["revision"], "displayName": "Backup persistent"},
        ).json()
        assert (
            client.post(
                f"/api/v1/selection/point/{point['id']}",
                headers=mutation,
                json={"intent": "include", "review": True},
            ).status_code
            == 200
        )
        created_property = client.post(
            f"/api/v1/properties/point/{point['id']}",
            headers=mutation,
            json={"key": "backup_marker", "valueType": "string", "value": "preserved"},
        ).json()
        split = client.post(
            f"/api/v1/assets/{asset['id']}/split",
            headers=mutation,
            json={
                "revision": asset["revision"],
                "name": "Backup split asset",
                "pointIds": [asset["points"][1]["id"]],
            },
        )
        assert split.status_code == 200
        expected_inventory = client.get("/api/v1/inventory", headers=headers).json()
        expected_ids = {
            "structures": {item["id"] for item in expected_inventory["structures"]},
            "spaces": {
                item["id"]
                for structure in expected_inventory["structures"]
                for item in structure["spaces"]
            },
            "assets": {
                item["id"]
                for structure in expected_inventory["structures"]
                for space in structure["spaces"]
                for item in space["assets"]
            },
            "points": {item["id"] for item in expected_inventory["flatPoints"]},
        }
        with app.state.session() as session:
            installation_id = session.get(EdgeIdentity, 1).installation_id
        pending = ConfigurationSnapshotRepository(app.state.session).prepare(installation_id)
        assert pending is not None
        expected_audit_actions = {
            row["action"] for row in client.get("/api/v1/audit", headers=headers).json()
        }
        expected_pending = {
            "snapshot_id": pending.snapshot_id,
            "installation_id": pending.installation_id,
            "config_version": pending.config_version,
            "projection_sha256": pending.projection_sha256,
            "request_sha256": pending.request_sha256,
            "payload": pending.payload,
            "status": pending.status,
        }
        source_identity.mkdir(parents=True, exist_ok=True)
        (source_identity / "identity-private-key.pem").write_text("DO-NOT-BACK-UP-IDENTITY")
        (source_identity / "transient").mkdir()
        (source_identity / "transient" / "candidate-key.pem").write_text("DO-NOT-BACK-UP-CANDIDATE")
        assert overridden["revision"] >= 2

    app.state.engine.dispose()
    with closing(sqlite3.connect(source)) as connection:
        assert connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0] == 0
        assert connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)
    manifest = yaml.safe_load(
        (Path(__file__).resolve().parents[2] / "config.yaml").read_text(encoding="utf-8")
    )
    exclusions = manifest["backup_exclude"]
    with tarfile.open(bundle, "w:gz") as archive:
        for item in sorted(source_data.rglob("*")):
            relative = item.relative_to(source_data).as_posix()
            if any(
                relative == pattern or fnmatch.fnmatch(relative, pattern) for pattern in exclusions
            ):
                continue
            archive.add(item, arcname=relative, recursive=False)
    with tarfile.open(bundle, "r:gz") as archive:
        assert archive.getnames() == ["one-os.db"]
        assert b"DO-NOT-BACK-UP-IDENTITY" not in bundle.read_bytes()
        assert b"DO-NOT-BACK-UP-CANDIDATE" not in bundle.read_bytes()
        archive.extractall(restore_data, filter="data")

    restored = restore_data / "one-os.db"
    restored_app = create_app(
        database_url=f"sqlite:///{restored}",
        ha_client=fake_ha,
        ingress_proxies={"testclient"},
        allowed_origins={"http://testserver"},
        identity_dir=restored_identity,
    )
    with TestClient(restored_app) as client:
        restored_inventory = client.get("/api/v1/inventory", headers=headers).json()
        actual_ids = {
            "structures": {item["id"] for item in restored_inventory["structures"]},
            "spaces": {
                item["id"]
                for structure in restored_inventory["structures"]
                for item in structure["spaces"]
            },
            "assets": {
                item["id"]
                for structure in restored_inventory["structures"]
                for space in structure["spaces"]
                for item in space["assets"]
            },
            "points": {item["id"] for item in restored_inventory["flatPoints"]},
        }
        assert actual_ids == expected_ids
        restored_point = client.get(f"/api/v1/points/{point['id']}", headers=headers).json()
        assert restored_point["display"]["name"]["value"] == "Backup persistent"
        assert restored_point["effectiveSelected"] is True
        assert client.get(f"/api/v1/properties/point/{point['id']}", headers=headers).json() == [
            created_property
        ]
        assert {
            row["action"] for row in client.get("/api/v1/audit", headers=headers).json()
        } == expected_audit_actions
        restored_pending = ConfigurationSnapshotRepository(restored_app.state.session).pending()
        assert restored_pending is not None
        assert {
            "snapshot_id": restored_pending.snapshot_id,
            "installation_id": restored_pending.installation_id,
            "config_version": restored_pending.config_version,
            "projection_sha256": restored_pending.projection_sha256,
            "request_sha256": restored_pending.request_sha256,
            "payload": restored_pending.payload,
            "status": restored_pending.status,
        } == expected_pending
        assert not (restored_identity / "identity-private-key.pem").exists()
    restored_app.state.engine.dispose()
    with closing(sqlite3.connect(restored)) as connection:
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == ("0021",)


def test_app_database_is_migrated_to_alembic_head(tmp_path, fake_ha):
    import sqlite3
    from contextlib import closing

    from one_os_addon.app import create_app

    database = tmp_path / "migrated.db"
    app = create_app(database_url=f"sqlite:///{database}", ha_client=fake_ha)
    app.state.engine.dispose()
    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == ("0021",)


def test_explicit_database_url_wins_over_ambient_database_url(tmp_path, fake_ha, monkeypatch):
    import sqlite3
    from contextlib import closing

    from one_os_addon.app import create_app

    explicit = tmp_path / "explicit.db"
    ambient = tmp_path / "ambient.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{ambient}")

    app = create_app(database_url=f"sqlite:///{explicit}", ha_client=fake_ha)
    app.state.engine.dispose()

    with closing(sqlite3.connect(explicit)) as connection:
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == ("0021",)
        assert connection.execute("SELECT COUNT(*) FROM edge_identity").fetchone() == (1,)
    assert not ambient.exists()


def test_credential_renewal_migration_cycles_empty_and_refuses_data_loss(tmp_path):
    import sqlite3
    from contextlib import closing

    import pytest
    from alembic import command
    from alembic.config import Config

    database = tmp_path / "renewal-migration.db"
    config = Config("one_os_edge/alembic.ini")
    config.set_main_option("sqlalchemy.url", f"sqlite:///{database}")
    config.attributes["explicit_database_url"] = True

    command.upgrade(config, "0007")
    command.downgrade(config, "0006")
    command.upgrade(config, "0007")
    with closing(sqlite3.connect(database)) as connection:
        connection.execute(
            "INSERT INTO edge_identity("
            "id,installation_id,status,revision,updated_at,installation_revision,renewal_status"
            ") VALUES(?,?,?,?,?,?,?)",
            (
                1,
                "00000000-0000-4000-8000-000000000001",
                "paired",
                1,
                "2026-08-07T12:00:00Z",
                7,
                "pending",
            ),
        )
        connection.commit()

    with pytest.raises(RuntimeError, match="renewal data; downgrade refused"):
        command.downgrade(config, "0006")
    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute("SELECT renewal_status FROM edge_identity").fetchone() == (
            "pending",
        )
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == ("0007",)


def test_pairing_deadline_and_revision_migrations_cycle_empty_deterministically(tmp_path):
    import sqlite3
    from contextlib import closing

    from alembic import command
    from alembic.config import Config

    database = tmp_path / "pairing-0008-0009-empty.db"
    config = Config("one_os_edge/alembic.ini")
    config.set_main_option("sqlalchemy.url", f"sqlite:///{database}")
    config.attributes["explicit_database_url"] = True

    command.upgrade(config, "0007")
    command.upgrade(config, "0009")
    command.downgrade(config, "0007")
    command.upgrade(config, "0009")

    with closing(sqlite3.connect(database)) as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(edge_pairing)")}
        assert {"issuance_expires_at", "central_session_revision"} <= columns
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == ("0009",)


@pytest.mark.parametrize(
    ("column", "value", "target", "message", "retained_revision"),
    [
        (
            "issuance_expires_at",
            "2026-08-07T12:05:00Z",
            "0007",
            "issuance deadlines; downgrade refused",
            "0008",
        ),
        (
            "central_session_revision",
            4,
            "0008",
            "session revisions; downgrade refused",
            "0009",
        ),
    ],
)
def test_pairing_deadline_and_revision_migrations_refuse_populated_downgrade(
    tmp_path, column, value, target, message, retained_revision
):
    import sqlite3
    from contextlib import closing

    from alembic import command
    from alembic.config import Config

    database = tmp_path / f"pairing-{column}.db"
    config = Config("one_os_edge/alembic.ini")
    config.set_main_option("sqlalchemy.url", f"sqlite:///{database}")
    config.attributes["explicit_database_url"] = True
    command.upgrade(config, "0009")
    with closing(sqlite3.connect(database)) as connection:
        connection.execute(
            "INSERT INTO edge_pairing("
            "id,revision,mode,status,registration_request_id,token_generation,"
            "candidate_spki_sha256,csr_sha256,updated_at," + column + ") "
            "VALUES(1,1,'initial','registered','request',1,'spki','csr',?,?)",
            ("2026-08-07T12:00:00Z", value),
        )
        connection.commit()

    with pytest.raises(RuntimeError, match=message):
        command.downgrade(config, target)

    with closing(sqlite3.connect(database)) as connection:
        query = {
            "issuance_expires_at": ("SELECT issuance_expires_at FROM edge_pairing WHERE id = 1"),
            "central_session_revision": (
                "SELECT central_session_revision FROM edge_pairing WHERE id = 1"
            ),
        }[column]
        assert connection.execute(query).fetchone() == (value,)
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == (
            retained_revision,
        )


def test_configuration_snapshot_migration_cycles_empty_and_refuses_data_loss(tmp_path):
    import sqlite3
    from contextlib import closing

    import pytest
    from alembic import command
    from alembic.config import Config

    database = tmp_path / "snapshot-migration.db"
    config = Config("one_os_edge/alembic.ini")
    config.set_main_option("sqlalchemy.url", f"sqlite:///{database}")
    config.attributes["explicit_database_url"] = True

    command.upgrade(config, "0006")
    command.downgrade(config, "0005")
    command.upgrade(config, "0006")
    with closing(sqlite3.connect(database)) as connection:
        connection.execute(
            "INSERT INTO configuration_snapshots("
            "snapshot_id,installation_id,config_version,projection_sha256,request_sha256,"
            "payload,status,created_at,attempt_count,last_attempt_at,needs_status_check,acked_at"
            ") VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                "00000000-0000-4000-8000-000000000001",
                "00000000-0000-4000-8000-000000000002",
                1,
                "a" * 43,
                "b" * 43,
                b"{}",
                "pending",
                "2026-08-07T12:00:00Z",
                0,
                None,
                0,
                None,
            ),
        )
        connection.commit()

    with pytest.raises(RuntimeError, match="refusing to drop non-empty"):
        command.downgrade(config, "0005")
    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute("SELECT COUNT(*) FROM configuration_snapshots").fetchone() == (1,)
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == ("0006",)
