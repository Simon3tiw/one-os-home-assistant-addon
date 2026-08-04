def imported(client, auth):
    assert client.post("/api/v1/reconcile", headers=auth).status_code == 200
    return client.get("/api/v1/inventory", headers=auth).json()


def all_assets(inventory):
    return [
        asset
        for structure in inventory["structures"]
        for space in structure["spaces"]
        for asset in space["assets"]
    ]


def test_asset_move_and_rename_survive_reconciliation(client, auth):
    inventory = imported(client, auth)
    asset = next(asset for asset in all_assets(inventory) if asset["name"] == "Office multisensor")
    unassigned_space = next(
        space
        for structure in inventory["structures"]
        for space in structure["spaces"]
        if structure["type"] == "Unassigned"
    )

    response = client.patch(
        f"/api/v1/assets/{asset['id']}",
        headers=auth,
        json={
            "revision": asset["revision"],
            "name": "Commissioned multisensor",
            "spaceId": unassigned_space["id"],
        },
    )
    assert response.status_code == 200
    assert client.post("/api/v1/reconcile", headers=auth).status_code == 200

    moved = next(
        asset
        for asset in all_assets(client.get("/api/v1/inventory", headers=auth).json())
        if asset["id"] == response.json()["id"]
    )
    assert moved["name"] == "Commissioned multisensor"
    assert moved["placementOverride"] is True


def test_typed_property_crud_is_owner_bound_and_audited(client, auth):
    point = imported(client, auth)["flatPoints"][0]
    created = client.post(
        f"/api/v1/properties/point/{point['id']}",
        headers=auth,
        json={"key": "maintenance_interval_days", "valueType": "integer", "value": 90},
    )
    assert created.status_code == 200
    property_id = created.json()["id"]

    listed = client.get(f"/api/v1/properties/point/{point['id']}", headers=auth).json()
    assert listed == [created.json()]
    updated = client.patch(
        f"/api/v1/properties/{property_id}",
        headers=auth,
        json={"revision": created.json()["revision"], "valueType": "integer", "value": 120},
    )
    assert updated.status_code == 200 and updated.json()["value"] == 120
    deleted = client.delete(
        f"/api/v1/properties/{property_id}?revision={updated.json()['revision']}", headers=auth
    )
    assert deleted.status_code == 200


def test_point_move_survives_reconciliation(client, auth):
    inventory = imported(client, auth)
    assets = all_assets(inventory)
    source = next(asset for asset in assets if len(asset["points"]) == 2)
    target = next(asset for asset in assets if asset["id"] != source["id"])
    point = source["points"][0]
    moved = client.patch(
        f"/api/v1/points/{point['id']}/placement",
        headers=auth,
        json={"revision": point["revision"], "assetId": target["id"]},
    )
    assert moved.status_code == 200
    assert client.post("/api/v1/reconcile", headers=auth).status_code == 200
    assert (
        client.get(f"/api/v1/points/{point['id']}", headers=auth).json()["assetId"] == target["id"]
    )


def test_missing_point_replacement_preserves_one_os_id(client, auth, fake_ha):
    original = next(
        point
        for point in imported(client, auth)["flatPoints"]
        if point["source"]["registryId"] == "sensor.room_temperature"
    )
    fake_ha.entities = [
        entity for entity in fake_ha.entities if entity["entity_id"] != "sensor.room_temperature"
    ]
    fake_ha.states.pop("sensor.room_temperature")
    client.post("/api/v1/reconcile", headers=auth)

    fake_ha.entities.append(
        {
            "entity_id": "sensor.replacement_temperature",
            "unique_id": "temp-002",
            "platform": "demo",
            "config_entry_id": "entry-1",
            "device_id": "device-1",
            "area_id": None,
            "name": "Replacement temperature",
            "entity_category": None,
        }
    )
    fake_ha.states["sensor.replacement_temperature"] = {
        "state": "22",
        "last_updated": "2026-08-04T12:30:00Z",
        "attributes": {"unit_of_measurement": "°C"},
    }
    replacement = next(
        point
        for point in imported(client, auth)["flatPoints"]
        if point["source"]["registryId"] == "sensor.replacement_temperature"
    )
    missing = client.get(f"/api/v1/points/{original['id']}", headers=auth).json()

    response = client.post(
        f"/api/v1/lifecycle/points/{original['id']}/replace",
        headers=auth,
        json={
            "revision": missing["revision"],
            "replacementPointId": replacement["id"],
            "confirmSemanticMatch": True,
        },
    )
    assert response.status_code == 200
    assert response.json()["id"] == original["id"]
    assert response.json()["sourceLifecycle"] == "active"
    assert response.json()["reviewStatus"] == "unreviewed"
    assert response.json()["source"]["registryId"] == "sensor.replacement_temperature"


def test_archive_requires_preview_and_explicit_descendant_action(client, auth):
    asset = next(asset for asset in all_assets(imported(client, auth)) if len(asset["points"]) == 2)
    preview = client.get(f"/api/v1/lifecycle/assets/{asset['id']}/archive-preview", headers=auth)
    assert preview.status_code == 200
    assert preview.json()["activeDescendants"] == 2
    assert set(preview.json()["allowedActions"]) == {"rehome", "cascade"}

    archived = client.post(
        f"/api/v1/lifecycle/assets/{asset['id']}/archive",
        headers=auth,
        json={"revision": asset["revision"], "action": "rehome"},
    )
    assert archived.status_code == 200
    inventory = client.get("/api/v1/inventory", headers=auth).json()
    assert all(item["id"] != asset["id"] for item in all_assets(inventory))
    assert all(point["sourceLifecycle"] == "active" for point in inventory["flatPoints"])
