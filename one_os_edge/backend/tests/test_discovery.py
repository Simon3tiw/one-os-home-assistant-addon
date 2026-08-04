def test_reconciliation_imports_canonical_tree_idempotently(client, auth):
    assert client.post("/api/v1/reconcile", headers=auth).status_code == 200
    tree = client.get("/api/v1/inventory", headers=auth).json()
    assert tree["counts"] == {
        "structures": 2,
        "spaces": 2,
        "physicalDevices": 1,
        "assets": 2,
        "points": 3,
    }
    ids = {p["source"]["registryId"]: p["id"] for p in tree["flatPoints"]}
    client.post("/api/v1/reconcile", headers=auth)
    again = client.get("/api/v1/inventory", headers=auth).json()
    assert ids == {p["source"]["registryId"]: p["id"] for p in again["flatPoints"]}


def test_live_values_defaults_and_nl_be_preview(client, auth):
    client.post("/api/v1/reconcile", headers=auth)
    point = next(
        p
        for p in client.get("/api/v1/inventory", headers=auth).json()["flatPoints"]
        if p["source"]["registryId"] == "sensor.room_temperature"
    )
    detail = client.get(f"/api/v1/points/{point['id']}", headers=auth).json()
    assert detail["value"]["raw"] == "21.236"
    assert detail["value"]["formatted"] == "21,24 °C"
    assert detail["value"]["quality"] == "good"
    assert detail["display"]["name"] == {
        "value": "Room temperature",
        "provenance": "home_assistant",
    }


def test_missing_is_distinct_from_unavailable(client, auth, fake_ha):
    client.post("/api/v1/reconcile", headers=auth)
    fake_ha.states["sensor.room_temperature"]["state"] = "unavailable"
    client.post("/api/v1/reconcile", headers=auth)
    temp = next(
        p
        for p in client.get("/api/v1/inventory", headers=auth).json()["flatPoints"]
        if p["source"]["registryId"] == "sensor.room_temperature"
    )
    assert temp["sourceLifecycle"] == "active" and temp["valueQuality"] == "unavailable"
    fake_ha.entities = [e for e in fake_ha.entities if e["entity_id"] != "sensor.room_temperature"]
    fake_ha.states.pop("sensor.room_temperature")
    client.post("/api/v1/reconcile", headers=auth)
    assert (
        client.get(f"/api/v1/points/{temp['id']}", headers=auth).json()["sourceLifecycle"]
        == "missing"
    )


def test_state_only_object_is_idempotent(client, auth, fake_ha):
    fake_ha.states["sensor.state_only"] = {
        "state": "7",
        "last_updated": "2026-08-04T10:01:00Z",
        "attributes": {"friendly_name": "State only"},
    }

    assert client.post("/api/v1/reconcile", headers=auth).status_code == 200
    assert client.post("/api/v1/reconcile", headers=auth).status_code == 200

    points = client.get("/api/v1/inventory", headers=auth).json()["flatPoints"]
    matching = [point for point in points if point["source"]["registryId"] == "sensor.state_only"]
    assert len(matching) == 1
