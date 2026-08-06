def test_v1_to_v2_migration_preserves_property_and_adds_constraints(tmp_path):
    import sqlite3
    from contextlib import closing

    from alembic import command
    from alembic.config import Config

    database = tmp_path / "upgrade.db"
    config = Config("one_os_edge/alembic.ini")
    config.set_main_option("sqlalchemy.url", f"sqlite:///{database}")
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
    fake_ha.states["sensor.room_temperature"]["state"] = "CANARY_SECRET_STATE"
    client.post("/api/v1/reconcile", headers=auth)
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
    }
    assert diag.json()["softwareVersion"] == "0.2.2"
    assert "CANARY" not in diag.text and "sensor.room_temperature" not in diag.text
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
    import sqlite3
    import tarfile
    from contextlib import closing

    from conftest import admin_headers
    from fastapi.testclient import TestClient
    from one_os_addon.app import create_app

    source_data = tmp_path / "source-data"
    restore_data = tmp_path / "restore-data"
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
        expected_audit_actions = {
            row["action"] for row in client.get("/api/v1/audit", headers=headers).json()
        }
        assert overridden["revision"] >= 2

    app.state.engine.dispose()
    with closing(sqlite3.connect(source)) as connection:
        assert connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0] == 0
        assert connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)
    with tarfile.open(bundle, "w:gz") as archive:
        archive.add(source, arcname="one-os.db")
    with tarfile.open(bundle, "r:gz") as archive:
        assert archive.getnames() == ["one-os.db"]
        archive.extractall(restore_data, filter="data")

    restored = restore_data / "one-os.db"
    restored_app = create_app(
        database_url=f"sqlite:///{restored}",
        ha_client=fake_ha,
        ingress_proxies={"testclient"},
        allowed_origins={"http://testserver"},
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
    restored_app.state.engine.dispose()
    with closing(sqlite3.connect(restored)) as connection:
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == ("0004",)


def test_app_database_is_migrated_to_alembic_head(tmp_path, fake_ha):
    import sqlite3
    from contextlib import closing

    from one_os_addon.app import create_app

    database = tmp_path / "migrated.db"
    app = create_app(database_url=f"sqlite:///{database}", ha_client=fake_ha)
    app.state.engine.dispose()
    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == ("0004",)
