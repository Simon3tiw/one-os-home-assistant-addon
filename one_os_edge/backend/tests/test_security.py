from conftest import admin_headers


def test_health_is_the_only_anonymous_route(client):
    assert client.get("/health").json() == {"status": "ok"}
    assert client.get("/api/v1/overview").status_code == 401


def test_admin_is_verified_and_csrf_is_required_for_mutation(client):
    assert client.get("/api/v1/overview", headers=admin_headers()).status_code == 200
    assert client.post("/api/v1/reconcile", headers=admin_headers()).status_code == 403


def test_non_admin_lookup_failure_and_spoofed_proxy_fail_closed(client, fake_ha):
    assert (
        client.get("/api/v1/overview", headers={"X-Remote-User-Id": "viewer-1"}).status_code == 403
    )
    fake_ha.auth_available = False
    assert client.get("/api/v1/overview", headers=admin_headers()).status_code == 503
    fake_ha.auth_available = True
    client.app.state.ingress_proxies = {"172.30.32.2"}
    assert client.get("/api/v1/overview", headers=admin_headers()).status_code == 403


def test_cross_origin_and_non_json_mutations_are_rejected(client, auth):
    assert (
        client.post(
            "/api/v1/reconcile", headers=auth | {"Origin": "https://evil.invalid"}
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/api/v1/reconcile", headers=auth | {"Sec-Fetch-Site": "cross-site"}
        ).status_code
        == 403
    )
    bad = {k: v for k, v in auth.items() if k != "Content-Type"}
    assert client.post("/api/v1/reconcile", headers=bad, content="x").status_code == 415


def test_missing_supervisor_token_fails_closed(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from one_os_addon.app import create_app

    monkeypatch.delenv("SUPERVISOR_TOKEN", raising=False)
    app = create_app(
        database_url=f"sqlite:///{tmp_path / 'no-token.db'}",
        ingress_proxies={"testclient"},
        allowed_origins={"http://testserver"},
    )
    with TestClient(app) as client:
        response = client.get("/api/v1/session", headers={"X-Remote-User-Id": "admin-1"})
    app.state.engine.dispose()
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "incompatible_home_assistant"


def test_mutation_origin_is_derived_from_home_assistant_config(tmp_path, fake_ha):
    from fastapi.testclient import TestClient
    from one_os_addon.app import create_app

    app = create_app(
        database_url=f"sqlite:///{tmp_path / 'dynamic-origin.db'}",
        ha_client=fake_ha,
        ingress_proxies={"testclient"},
    )
    headers = {"X-Remote-User-Id": "admin-1"}
    with TestClient(app) as client:
        token = client.get("/api/v1/session", headers=headers).json()["csrfToken"]
        response = client.post(
            "/api/v1/reconcile",
            headers=headers
            | {
                "Origin": "http://testserver",
                "Sec-Fetch-Site": "same-origin",
                "Content-Type": "application/json",
                "X-CSRF-Token": token,
            },
        )
    app.state.engine.dispose()
    assert response.status_code == 200


def test_same_origin_mutation_works_when_home_assistant_urls_are_unset(
    tmp_path, fake_ha, monkeypatch
):
    """HA commonly leaves internal_url/external_url unset; ingress remains same-origin."""
    from unittest.mock import AsyncMock

    from fastapi.testclient import TestClient
    from one_os_addon.app import create_app

    monkeypatch.setattr(fake_ha, "trusted_origins", AsyncMock(return_value=set()))
    app = create_app(
        database_url=f"sqlite:///{tmp_path / 'empty-origins.db'}",
        ha_client=fake_ha,
        ingress_proxies={"testclient"},
    )
    headers = {"X-Remote-User-Id": "admin-1"}
    with TestClient(app) as client:
        token = client.get("/api/v1/session", headers=headers).json()["csrfToken"]
        response = client.post(
            "/api/v1/reconcile",
            headers=headers
            | {
                "Origin": "http://testserver",
                "Sec-Fetch-Site": "same-origin",
                "Content-Type": "application/json",
                "X-CSRF-Token": token,
            },
        )
        cross_site = client.post(
            "/api/v1/reconcile",
            headers=headers
            | {
                "Origin": "https://evil.invalid",
                "Sec-Fetch-Site": "cross-site",
                "Content-Type": "application/json",
                "X-CSRF-Token": token,
            },
        )
    app.state.engine.dispose()
    assert response.status_code == 200
    assert cross_site.status_code == 403


def test_ingress_mutation_without_fetch_metadata_uses_csrf_bound_browser_origin(
    tmp_path, fake_ha, monkeypatch
):
    """Origin stays verifiable when Supervisor strips Fetch Metadata and rewrites Host."""
    from unittest.mock import AsyncMock

    from fastapi.testclient import TestClient
    from one_os_addon.app import create_app

    monkeypatch.setattr(fake_ha, "trusted_origins", AsyncMock(return_value=set()))
    app = create_app(
        database_url=f"sqlite:///{tmp_path / 'ingress-origin.db'}",
        ha_client=fake_ha,
        ingress_proxies={"testclient"},
    )
    headers = {"X-Remote-User-Id": "admin-1"}
    with TestClient(
        app, base_url="http://internal-addon:8099", raise_server_exceptions=False
    ) as client:
        malformed_session = client.get(
            "/api/v1/session?browserOrigin=http%3A%2F%2F%5B%3A%3A1",
            headers=headers,
        )
        path_session = client.get(
            "/api/v1/session?browserOrigin=https%3A%2F%2Fha.local%2Fpath",
            headers=headers,
        )
        token = client.get(
            "/api/v1/session?browserOrigin=http%3A%2F%2Ftestserver",
            headers=headers,
        ).json()["csrfToken"]
        mutation_headers = headers | {
            "Origin": "http://testserver",
            "X-Forwarded-Host": "evil.invalid",
            "Content-Type": "application/json",
            "X-CSRF-Token": token,
        }
        same_origin = client.post("/api/v1/reconcile", headers=mutation_headers)
        same_site = client.post(
            "/api/v1/reconcile",
            headers=mutation_headers | {"Sec-Fetch-Site": "same-site"},
        )
        explicit_cross_site = client.post(
            "/api/v1/reconcile",
            headers=mutation_headers | {"Sec-Fetch-Site": "cross-site"},
        )
        malformed_origin = client.post(
            "/api/v1/reconcile",
            headers=mutation_headers | {"Origin": "http://[::1", "Sec-Fetch-Site": "same-origin"},
        )
        path_origin = client.post(
            "/api/v1/reconcile",
            headers=mutation_headers
            | {
                "Origin": "http://testserver/path",
                "Sec-Fetch-Site": "same-origin",
            },
        )
        cross_origin = client.post(
            "/api/v1/reconcile",
            headers=mutation_headers
            | {
                "Origin": "https://evil.invalid",
                "X-Forwarded-Host": "evil.invalid",
            },
        )
    app.state.engine.dispose()

    assert malformed_session.status_code == 400
    assert malformed_session.json()["detail"]["code"] == "invalid_browser_origin"
    assert path_session.status_code == 400
    assert same_origin.status_code == 200
    assert same_site.status_code == 200
    assert explicit_cross_site.status_code == 403
    assert malformed_origin.status_code == 403
    assert path_origin.status_code == 403
    assert cross_origin.status_code == 403
    assert cross_origin.json()["error"]["code"] == "same_origin_required"


def test_expired_csrf_token_is_rejected(tmp_path, fake_ha):
    from fastapi.testclient import TestClient
    from one_os_addon.app import create_app

    app = create_app(
        database_url=f"sqlite:///{tmp_path / 'expired-csrf.db'}",
        ha_client=fake_ha,
        ingress_proxies={"testclient"},
        allowed_origins={"http://testserver"},
        csrf_ttl_seconds=-1,
    )
    headers = {"X-Remote-User-Id": "admin-1"}
    with TestClient(app) as client:
        token = client.get("/api/v1/session", headers=headers).json()["csrfToken"]
        response = client.post(
            "/api/v1/reconcile",
            headers=headers
            | {
                "Origin": "http://testserver",
                "Sec-Fetch-Site": "same-origin",
                "Content-Type": "application/json",
                "X-CSRF-Token": token,
            },
        )
    app.state.engine.dispose()
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "csrf_invalid"


def test_runtime_preserves_ingress_transport_peer():
    from pathlib import Path

    run_script = (Path(__file__).parents[2] / "rootfs/etc/services.d/one-os/run").read_text()
    assert "--no-proxy-headers" in run_script
