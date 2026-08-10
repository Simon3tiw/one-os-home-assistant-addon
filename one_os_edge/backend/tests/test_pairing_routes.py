from conftest import admin_headers
from one_os_addon.app import create_app
from one_os_addon.pairing_backend import PairingBackend, PairingError
from one_os_addon.pairing_repository import PairingRepository
from one_os_addon.pairing_storage import IdentityStore
from test_pairing_backend import LossyCentral


class StubPairing:
    def __init__(self):
        self.state = {"status": "pop_verified", "installationId": "id", "codeExpiresAt": "later"}
        self.calls = []
        self.actors = []

    def status(self):
        return self.state.copy()

    def code(self):
        return {"code": "0123-4567-89AB-CDEF-GHJK", "expiresAt": "later"}

    def start(self, mode, installation_id, actor_id=None):
        self.actors.append(actor_id)
        self.calls.append(("start", mode, installation_id))
        return self.status()

    def refresh(self, actor_id=None):
        self.actors.append(actor_id)
        self.calls.append(("refresh",))
        return self.status()

    def reset(self, actor_id=None):
        self.actors.append(actor_id)
        if self.state.get("credentialId"):
            raise PairingError("identity_repair_required")
        self.calls.append(("reset",))

    def cancel(self, actor_id=None):
        self.actors.append(actor_id)
        self.calls.append(("cancel",))
        return self.status()

    def rotate_key(self, actor_id=None):
        self.actors.append(actor_id)
        self.calls.append(("rotate_key",))
        return self.status()


def test_pairing_routes_are_admin_only_no_store_and_reuse_browser_security(tmp_path, fake_ha):
    stub = StubPairing()
    app = create_app(
        database_url=f"sqlite:///{tmp_path / 'db.sqlite'}",
        ha_client=fake_ha,
        ingress_proxies={"testclient"},
        allowed_origins={"http://testserver"},
        identity_dir=tmp_path / "identity",
        pairing_backend=stub,
    )
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        status = client.get("/api/v1/pairing/status", headers=admin_headers())
        code = client.get("/api/v1/pairing/code", headers=admin_headers())
        assert status.status_code == code.status_code == 200
        assert status.headers["cache-control"] == code.headers["cache-control"] == "no-store"
        assert "code" not in status.json()
        assert code.json()["code"] == "0123-4567-89AB-CDEF-GHJK"

        unauthenticated = client.post("/api/v1/pairing/refresh", headers=admin_headers(), json={})
        assert unauthenticated.status_code == 403
        token = client.get("/api/v1/session", headers=admin_headers()).json()["csrfToken"]
        auth = admin_headers() | {
            "Origin": "http://testserver",
            "Sec-Fetch-Site": "same-origin",
            "Content-Type": "application/json",
            "X-CSRF-Token": token,
        }
        assert client.post("/api/v1/pairing/refresh", headers=auth, json={}).status_code == 200
        assert client.post("/api/v1/pairing/start", headers=auth, json={}).status_code == 200
        assert (
            client.post(
                "/api/v1/pairing/cancel", headers=auth, json={"confirmed": True}
            ).status_code
            == 200
        )
        assert (
            client.post(
                "/api/v1/pairing/rotate-key", headers=auth, json={"confirmed": True}
            ).status_code
            == 200
        )
        assert (
            client.post(
                "/api/v1/pairing/cancel", headers=auth, json={"confirmed": False}
            ).status_code
            == 422
        )
        unknown_field = client.post("/api/v1/pairing/start", headers=auth, json={"secret": "x"})
        assert unknown_field.status_code == 422
        assert ("cancel",) in stub.calls
        assert ("rotate_key",) in stub.calls
        assert stub.actors == ["ha:admin-1"] * 4

        stub.state = {
            "status": "compromised",
            "installationId": "id",
            "credentialId": "credential",
        }
        repair = client.post("/api/v1/pairing/rotate-key", headers=auth, json={"confirmed": True})
        assert repair.status_code == 200
        assert stub.calls[-1] == ("rotate_key",)
        reset = client.post("/api/v1/pairing/reset", headers=auth, json={})
        assert reset.status_code == 409
        assert reset.json()["detail"]["code"] == "identity_repair_required"

        fake_ha.users[0]["group_ids"] = ["system-users"]
        assert client.get("/api/v1/pairing/status", headers=admin_headers()).status_code == 403
    app.state.engine.dispose()


def test_restore_replacement_route_is_repair_only(tmp_path, fake_ha):
    stub = StubPairing()
    stub.state = {"status": "identity_missing_after_restore", "installationId": "stable-id"}
    app = create_app(
        database_url=f"sqlite:///{tmp_path / 'db.sqlite'}",
        ha_client=fake_ha,
        ingress_proxies={"testclient"},
        allowed_origins={"http://testserver"},
        identity_dir=tmp_path / "identity",
        pairing_backend=stub,
    )
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        token = client.get("/api/v1/session", headers=admin_headers()).json()["csrfToken"]
        auth = admin_headers() | {
            "Origin": "http://testserver",
            "Sec-Fetch-Site": "same-origin",
            "Content-Type": "application/json",
            "X-CSRF-Token": token,
        }
        response = client.post(
            "/api/v1/pairing/replace-identity-after-restore",
            headers=auth,
            json={"confirmed": True},
        )
        assert response.status_code == 200
        assert stub.calls == [("rotate_key",)]
    app.state.engine.dispose()


def test_expired_pairing_must_be_reset_via_real_route_before_initial_restart(tmp_path, fake_ha):
    app = create_app(
        database_url=f"sqlite:///{tmp_path / 'expiry.db'}",
        ha_client=fake_ha,
        ingress_proxies={"testclient"},
        allowed_origins={"http://testserver"},
        identity_dir=tmp_path / "identity",
        pairing_backend=False,
    )
    repository = PairingRepository(app.state.session)
    expired = repository.save(
        repository.load() | {"status": "expired"},
        actor_id="system:edge-worker",
        action="pairing.reset",
    )
    app.state.pairing = PairingBackend(
        IdentityStore(tmp_path / "identity"), LossyCentral(), repository=repository
    )
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        token = client.get("/api/v1/session", headers=admin_headers()).json()["csrfToken"]
        auth = admin_headers() | {
            "Origin": "http://testserver",
            "Sec-Fetch-Site": "same-origin",
            "Content-Type": "application/json",
            "X-CSRF-Token": token,
        }
        rejected = client.post("/api/v1/pairing/start", headers=auth, json={})
        assert rejected.status_code == 409
        assert rejected.json()["detail"]["code"] == "initial_pairing_not_allowed"
        assert repository.load() == expired
        assert not (tmp_path / "identity").exists()

        reset = client.post("/api/v1/pairing/reset", headers=auth, json={})
        assert reset.status_code == 200
        assert reset.json()["status"] == "unpaired"
        started = client.post("/api/v1/pairing/start", headers=auth, json={})
        assert started.status_code == 503
        assert started.json()["detail"]["code"] == "central_registration_unreachable"
        assert repository.load()["status"] == "registering"
    app.state.engine.dispose()
