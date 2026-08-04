def test_repeated_reconciliation_without_upstream_changes_does_not_bump_point_revision(
    client, auth
):
    assert client.post("/api/v1/reconcile", headers=auth).status_code == 200
    first = client.get("/api/v1/inventory", headers=auth).json()["flatPoints"][0]
    assert client.post("/api/v1/reconcile", headers=auth).status_code == 200
    second = client.get("/api/v1/inventory", headers=auth).json()["flatPoints"][0]
    assert second["revision"] == first["revision"]
