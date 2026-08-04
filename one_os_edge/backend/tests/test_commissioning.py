def imported(client, auth):
    client.post("/api/v1/reconcile", headers=auth)
    return client.get("/api/v1/inventory", headers=auth).json()


def test_override_validation_reset_and_optimistic_concurrency(client, auth):
    p = next(
        x
        for x in imported(client, auth)["flatPoints"]
        if x["source"]["registryId"] == "sensor.room_temperature"
    )
    response = client.patch(
        f"/api/v1/points/{p['id']}/overrides",
        headers=auth,
        json={
            "revision": p["revision"],
            "displayName": "Supply temp",
            "decimals": 1,
            "displayUnit": "°F",
        },
    )
    assert response.status_code == 200 and response.json()["value"]["formatted"] == "70,2 °F"
    assert (
        client.patch(
            f"/api/v1/points/{p['id']}/overrides",
            headers=auth,
            json={"revision": response.json()["revision"], "displayUnit": "kW"},
        ).status_code
        == 422
    )
    assert (
        client.patch(
            f"/api/v1/points/{p['id']}/overrides",
            headers=auth,
            json={"revision": p["revision"], "displayName": "stale"},
        ).status_code
        == 409
    )
    rev = response.json()["revision"]
    reset = client.delete(
        f"/api/v1/points/{p['id']}/overrides/displayName?revision={rev}", headers=auth
    )
    assert reset.json()["display"]["name"]["provenance"] == "home_assistant"


def test_selection_requires_review_and_control_remains_separate(client, auth):
    data = imported(client, auth)
    asset = next(
        a for s in data["structures"] for sp in s["spaces"] for a in sp["assets"] if a["points"]
    )
    assert (
        client.post(
            f"/api/v1/selection/asset/{asset['id']}",
            headers=auth,
            json={"intent": "include", "review": False},
        ).status_code
        == 422
    )
    assert (
        client.post(
            f"/api/v1/selection/asset/{asset['id']}",
            headers=auth,
            json={"intent": "include", "review": True},
        ).json()["state"]
        == "selected"
    )
    p = client.get(f"/api/v1/points/{asset['points'][0]['id']}", headers=auth).json()
    assert p["effectiveSelected"] is True and p["cloudControlEnabled"] is False
    assert (
        client.post(
            f"/api/v1/selection/point/{p['id']}",
            headers=auth,
            json={"intent": "exclude", "review": False},
        ).json()["state"]
        == "unselected"
    )


def test_capability_is_evidence_bounded_and_drift_disables_control(client, auth, fake_ha):
    p = next(
        x
        for x in imported(client, auth)["flatPoints"]
        if x["source"]["registryId"] == "light.office"
    )
    detail = client.get(f"/api/v1/points/{p['id']}", headers=auth).json()
    assert (
        detail["capability"]["actions"] == ["set_power"]
        and detail["capability"]["immutable"] is True
    )
    assert (
        client.patch(
            f"/api/v1/points/{p['id']}/control",
            headers=auth,
            json={"revision": detail["revision"], "enabled": True},
        ).json()["cloudControlEnabled"]
        is True
    )
    fake_ha.states["light.office"]["attributes"]["supported_features"] = 1
    client.post("/api/v1/reconcile", headers=auth)
    drift = client.get(f"/api/v1/points/{p['id']}", headers=auth).json()
    assert drift["cloudControlEnabled"] is False and drift["capabilityReviewRequired"] is True


def test_split_and_merge_preserve_point_ids(client, auth):
    data = imported(client, auth)
    asset = next(
        a
        for s in data["structures"]
        for sp in s["spaces"]
        for a in sp["assets"]
        if len(a["points"]) == 2
    )
    moved = asset["points"][0]["id"]
    split = client.post(
        f"/api/v1/assets/{asset['id']}/split",
        headers=auth,
        json={"revision": asset["revision"], "name": "Temperature function", "pointIds": [moved]},
    )
    assert split.status_code == 200
    merge = client.post(
        f"/api/v1/assets/{asset['id']}/merge",
        headers=auth,
        json={"revision": split.json()["sourceRevision"], "otherAssetId": split.json()["assetId"]},
    )
    assert merge.status_code == 200 and moved in merge.json()["pointIds"]


def test_split_placement_survives_reconciliation(client, auth):
    data = imported(client, auth)
    asset = next(
        asset
        for structure in data["structures"]
        for space in structure["spaces"]
        for asset in space["assets"]
        if len(asset["points"]) == 2
    )
    point_id = asset["points"][0]["id"]
    split = client.post(
        f"/api/v1/assets/{asset['id']}/split",
        headers=auth,
        json={"revision": asset["revision"], "name": "Persistent split", "pointIds": [point_id]},
    )
    assert split.status_code == 200

    assert client.post("/api/v1/reconcile", headers=auth).status_code == 200
    inventory = client.get("/api/v1/inventory", headers=auth).json()
    placed = next(
        asset
        for structure in inventory["structures"]
        for space in structure["spaces"]
        for asset in space["assets"]
        if any(point["id"] == point_id for point in asset["points"])
    )
    assert placed["id"] == split.json()["assetId"]


def test_missing_parents_are_retained_and_inherited_children_rehomed(client, auth, fake_ha):
    imported(client, auth)
    fake_ha.floors.clear()
    fake_ha.areas.clear()
    fake_ha.devices.clear()

    assert client.post("/api/v1/reconcile", headers=auth).status_code == 200
    inventory = client.get("/api/v1/inventory", headers=auth).json()

    floor = next(
        structure for structure in inventory["structures"] if structure["name"] == "Ground floor"
    )
    office = next(
        space
        for structure in inventory["structures"]
        for space in structure["spaces"]
        if space["name"] == "Office"
    )
    device_asset = next(
        asset
        for structure in inventory["structures"]
        for space in structure["spaces"]
        for asset in space["assets"]
        if asset["name"] == "Office multisensor"
    )
    assert floor["sourceLifecycle"] == "missing"
    assert office["sourceLifecycle"] == "missing"
    assert device_asset["sourceLifecycle"] == "missing"


def test_structure_and_space_selection_are_explicit_bulk_mutations(client, auth):
    data = imported(client, auth)
    structure = next(item for item in data["structures"] if item["type"] == "Floor")
    space = structure["spaces"][0]

    selected = client.post(
        f"/api/v1/selection/structure/{structure['id']}",
        headers=auth,
        json={"intent": "include", "review": True},
    )
    assert selected.status_code == 200 and selected.json()["state"] == "selected"
    excluded = client.post(
        f"/api/v1/selection/space/{space['id']}",
        headers=auth,
        json={"intent": "exclude", "review": False},
    )
    assert excluded.status_code == 200 and excluded.json()["state"] == "unselected"


def test_state_only_point_cannot_be_selected(client, auth, fake_ha):
    fake_ha.states["sensor.state_only"] = {
        "state": "7",
        "last_updated": "2026-08-04T10:01:00Z",
        "attributes": {},
    }
    point = next(
        point
        for point in imported(client, auth)["flatPoints"]
        if point["source"]["registryId"] == "sensor.state_only"
    )
    response = client.post(
        f"/api/v1/selection/point/{point['id']}",
        headers=auth,
        json={"intent": "include", "review": True},
    )
    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "temporary_binding_not_accepted"

    accepted = client.post(
        f"/api/v1/points/{point['id']}/accept-temporary-binding",
        headers=auth,
        json={"revision": point["revision"]},
    )
    assert accepted.status_code == 200
    selected = client.post(
        f"/api/v1/selection/point/{point['id']}",
        headers=auth,
        json={"intent": "include", "review": True},
    )
    assert selected.status_code == 200

    fake_ha.entities.append(
        {
            "entity_id": "sensor.state_only",
            "unique_id": "state-only-001",
            "platform": "demo",
            "config_entry_id": "entry-1",
            "device_id": None,
            "area_id": None,
            "name": "State only",
            "entity_category": None,
        }
    )
    assert client.post("/api/v1/reconcile", headers=auth).status_code == 200
    promoted = client.get(f"/api/v1/points/{point['id']}", headers=auth).json()
    assert promoted["bindingStability"] == "stable"
    assert promoted["temporaryAccepted"] is False
    assert promoted["reviewStatus"] == "unreviewed"
