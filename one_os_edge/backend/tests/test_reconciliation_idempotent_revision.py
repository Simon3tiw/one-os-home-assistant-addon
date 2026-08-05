from one_os_addon.models import Point
from sqlalchemy import select
from sqlalchemy.orm import Session


def test_repeated_reconciliation_without_upstream_changes_does_not_bump_point_revision(
    client, auth
):
    assert client.post("/api/v1/reconcile", headers=auth).status_code == 200
    first = client.get("/api/v1/inventory", headers=auth).json()["flatPoints"][0]
    assert client.post("/api/v1/reconcile", headers=auth).status_code == 200
    second = client.get("/api/v1/inventory", headers=auth).json()["flatPoints"][0]
    assert second["revision"] == first["revision"]


def test_reconciliation_bumps_asset_and_point_revisions_for_source_metadata_changes(
    client, auth, fake_ha
):
    assert client.post("/api/v1/reconcile", headers=auth).status_code == 200
    first_inventory = client.get("/api/v1/inventory", headers=auth).json()
    first_point = next(
        point
        for point in first_inventory["flatPoints"]
        if point["source"]["registryId"] == "sensor.room_temperature"
    )
    first_asset = next(
        asset
        for structure in first_inventory["structures"]
        for space in structure["spaces"]
        for asset in space["assets"]
        if asset["id"] == first_point["assetId"]
    )
    outside_point = next(
        point
        for point in first_inventory["flatPoints"]
        if point["source"]["registryId"] == "sensor.outside"
    )
    outside_asset = next(
        asset
        for structure in first_inventory["structures"]
        for space in structure["spaces"]
        for asset in space["assets"]
        if asset["id"] == outside_point["assetId"]
    )

    entity = next(
        item for item in fake_ha.entities if item["entity_id"] == "sensor.room_temperature"
    )
    device = next(item for item in fake_ha.devices if item["id"] == entity["device_id"])
    fake_ha.areas.append({"area_id": "area-2", "name": "Plant room", "floor_id": "floor-1"})
    device["name"] = "Renamed multisensor"
    device["area_id"] = "area-2"
    fake_ha.states["sensor.room_temperature"]["attributes"]["friendly_name"] = "Renamed temp"
    fake_ha.states["sensor.room_temperature"]["attributes"]["unit_of_measurement"] = "K"
    next(item for item in fake_ha.entities if item["entity_id"] == "sensor.outside")["name"] = (
        "Renamed outside sensor"
    )

    assert client.post("/api/v1/reconcile", headers=auth).status_code == 200
    second_inventory = client.get("/api/v1/inventory", headers=auth).json()
    second_point = next(
        point for point in second_inventory["flatPoints"] if point["id"] == first_point["id"]
    )
    second_asset = next(
        asset
        for structure in second_inventory["structures"]
        for space in structure["spaces"]
        for asset in space["assets"]
        if asset["id"] == first_asset["id"]
    )
    second_outside_asset = next(
        asset
        for structure in second_inventory["structures"]
        for space in structure["spaces"]
        for asset in space["assets"]
        if asset["id"] == outside_asset["id"]
    )
    assert second_asset["name"] == "Renamed multisensor"
    assert second_asset["spaceId"] != first_asset["spaceId"]
    assert second_asset["revision"] == first_asset["revision"] + 1
    assert second_outside_asset["name"] == "Renamed outside sensor"
    assert second_outside_asset["revision"] == outside_asset["revision"] + 1
    assert second_point["display"]["name"]["value"] == "Renamed temp"
    assert second_point["display"]["unit"]["value"] == "K"
    assert second_point["revision"] == first_point["revision"] + 1

    assert (
        client.patch(
            f"/api/v1/assets/{first_asset['id']}",
            headers=auth,
            json={"revision": first_asset["revision"], "name": "stale"},
        ).status_code
        == 409
    )
    assert (
        client.patch(
            f"/api/v1/points/{first_point['id']}/overrides",
            headers=auth,
            json={"revision": first_point["revision"], "displayName": "stale"},
        ).status_code
        == 409
    )

    assert client.post("/api/v1/reconcile", headers=auth).status_code == 200
    third_inventory = client.get("/api/v1/inventory", headers=auth).json()
    third_point = next(
        point for point in third_inventory["flatPoints"] if point["id"] == first_point["id"]
    )
    third_asset = next(
        asset
        for structure in third_inventory["structures"]
        for space in structure["spaces"]
        for asset in space["assets"]
        if asset["id"] == first_asset["id"]
    )
    third_outside_asset = next(
        asset
        for structure in third_inventory["structures"]
        for space in structure["spaces"]
        for asset in space["assets"]
        if asset["id"] == outside_asset["id"]
    )
    assert third_asset["revision"] == second_asset["revision"]
    assert third_outside_asset["revision"] == second_outside_asset["revision"]
    assert third_point["revision"] == second_point["revision"]


def test_reconciliation_keeps_archived_point_archived_and_revision_stable(client, auth):
    assert client.post("/api/v1/reconcile", headers=auth).status_code == 200
    with Session(client.app.state.engine) as session:
        point = session.scalar(
            select(Point).where(Point.current_entity_id == "sensor.room_temperature")
        )
        point.lifecycle = "archived"
        point.revision += 1
        archived_revision = point.revision
        point_id = point.id
        session.commit()

    assert client.post("/api/v1/reconcile", headers=auth).status_code == 200
    assert client.post("/api/v1/reconcile", headers=auth).status_code == 200
    archived = client.get(f"/api/v1/points/{point_id}", headers=auth).json()
    assert archived["sourceLifecycle"] == "archived"
    assert archived["revision"] == archived_revision
