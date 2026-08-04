from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from one_os_addon.app import create_app
from one_os_addon.ha.fake import FakeHomeAssistant


@pytest.fixture
def fake_ha():
    return FakeHomeAssistant.standard()


@pytest.fixture
def client(tmp_path: Path, fake_ha):
    app = create_app(
        database_url=f"sqlite:///{tmp_path / 'commissioning.db'}",
        ha_client=fake_ha,
        ingress_proxies={"testclient"},
        allowed_origins={"http://testserver"},
    )
    with TestClient(app) as c:
        yield c
    app.state.engine.dispose()


def admin_headers():
    return {"X-Remote-User-Id": "admin-1"}


@pytest.fixture
def auth(client):
    headers = admin_headers()
    response = client.get("/api/v1/session", headers=headers)
    assert response.status_code == 200
    token = response.json()["csrfToken"]
    return headers | {
        "Origin": "http://testserver",
        "Sec-Fetch-Site": "same-origin",
        "Content-Type": "application/json",
        "X-CSRF-Token": token,
    }
