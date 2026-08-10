from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from one_os_addon.app import create_app
from one_os_addon.models import EdgeIdentity, EdgePairing
from one_os_addon.pairing_backend import PairingBackend, PairingError
from one_os_addon.pairing_repository import PairingRepository
from one_os_addon.pairing_storage import IdentityStore, UnsafeIdentityStorage
from one_os_addon.pairing_worker import PairingWorker
from test_pairing_backend import LossyCentral


def _rfc3339(seconds: int) -> str:
    return datetime.fromtimestamp(seconds, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def test_repository_persists_every_public_transition_and_restores_it(tmp_path) -> None:
    database = tmp_path / "state.db"
    app = create_app(
        database_url=f"sqlite:///{database}",
        identity_dir=tmp_path / "identity",
        pairing_backend=False,
    )
    repository = PairingRepository(app.state.session)
    installation_id = repository.load()["installationId"]
    central = LossyCentral()
    central.lose_registration_once = False
    now = int(datetime.now(UTC).timestamp())

    original_register = central.register

    def registration(body):
        response = original_register(body)
        response["registrationExpiresAt"] = _rfc3339(now + 120)
        return response

    central.register = registration
    backend = PairingBackend(IdentityStore(tmp_path / "identity"), central, repository=repository)
    backend.start("initial", installation_id)

    with app.state.session() as session:
        identity = session.get(EdgeIdentity, 1)
        pairing = session.get(EdgePairing, 1)
        assert identity.installation_id == installation_id
        assert pairing.status == "pop_verified"
        assert pairing.session_id == central.session_id
        assert (
            PairingRepository(app.state.session).load()["registrationExpiresAt"].endswith("+00:00")
        )

    restarted = PairingBackend(
        IdentityStore(tmp_path / "identity"),
        central,
        repository=PairingRepository(app.state.session),
    )
    assert restarted.status()["status"] == "pop_verified"
    assert restarted.code()["code"].count("-") == 4
    app.state.engine.dispose()


def test_repository_persists_issuance_deadline_for_restart_terminalization(tmp_path) -> None:
    app = create_app(
        database_url=f"sqlite:///{tmp_path / 'state.db'}",
        identity_dir=tmp_path / "identity",
        pairing_backend=False,
    )
    repository = PairingRepository(app.state.session)
    installation_id = repository.load()["installationId"]
    deadline = datetime.now(UTC).isoformat()
    persisted = repository.save(
        {
            "installationId": installation_id,
            "mode": "initial",
            "status": "claim_proved",
            "registrationRequestId": str(uuid4()),
            "candidateSpkiSha256": "A" * 43,
            "csrSha256": "B" * 43,
            "issuanceExpiresAt": deadline,
        }
    )

    assert persisted["issuanceExpiresAt"] == deadline
    app.state.engine.dispose()


def test_missing_excluded_identity_is_persisted_fail_closed_and_never_polls(tmp_path) -> None:
    database = tmp_path / "state.db"
    app = create_app(
        database_url=f"sqlite:///{database}",
        identity_dir=tmp_path / "identity",
        pairing_backend=False,
    )
    repository = PairingRepository(app.state.session)
    with app.state.session() as session:
        identity = session.get(EdgeIdentity, 1)
        identity.status = "paired"
        identity.credential_id = str(uuid4())
        session.commit()

    central = LossyCentral()
    backend = PairingBackend(IdentityStore(tmp_path / "identity"), central, repository=repository)

    assert backend.status()["status"] == "identity_missing_after_restore"
    with pytest.raises(PairingError, match="identity_missing_after_restore"):
        backend.refresh()
    assert central.registration_calls == []
    assert central.proof_calls == []
    assert central.ack_calls == []
    assert PairingRepository(app.state.session).load()["status"] == "identity_missing_after_restore"
    app.state.engine.dispose()


def test_startup_cleans_candidate_and_pre_network_intent_orphans(tmp_path, monkeypatch) -> None:
    app = create_app(
        database_url=f"sqlite:///{tmp_path / 'state.db'}",
        identity_dir=tmp_path / "identity",
        pairing_backend=False,
    )
    repository = PairingRepository(app.state.session)
    store = IdentityStore(tmp_path / "identity")
    backend = PairingBackend(store, LossyCentral(), repository=repository)
    original_save = repository.save

    def crash_before_public_state(_state, *, actor_id, action):
        assert actor_id == "system:edge-worker"
        assert action == "pairing.initial.start"
        raise RuntimeError("crashpoint_after_transient_write")

    monkeypatch.setattr(repository, "save", crash_before_public_state)
    with pytest.raises(RuntimeError, match="crashpoint_after_transient_write"):
        backend.start("initial", repository.load()["installationId"])
    monkeypatch.setattr(repository, "save", original_save)

    restarted = PairingBackend(store, LossyCentral(), repository=repository)

    assert restarted.status()["status"] == "unpaired"
    assert store.read_transient() is None
    with pytest.raises(UnsafeIdentityStorage):
        store.load_candidate()
    app.state.engine.dispose()


def test_startup_recovers_post_registration_intent_when_public_write_crashes(
    tmp_path, monkeypatch
) -> None:
    app = create_app(
        database_url=f"sqlite:///{tmp_path / 'state.db'}",
        identity_dir=tmp_path / "identity",
        pairing_backend=False,
    )
    repository = PairingRepository(app.state.session)
    central = LossyCentral()
    central.lose_registration_once = False
    now = int(datetime.now(UTC).timestamp())
    original_register = central.register

    def registration(body):
        response = original_register(body)
        response["registrationExpiresAt"] = _rfc3339(now + 120)
        return response

    central.register = registration
    original_save = repository.save
    saves = 0

    def crash_after_registration(state, *, actor_id, action):
        nonlocal saves
        saves += 1
        if saves == 2:
            raise RuntimeError("crashpoint_after_registration_secret")
        return original_save(state, actor_id=actor_id, action=action)

    monkeypatch.setattr(repository, "save", crash_after_registration)
    backend = PairingBackend(IdentityStore(tmp_path / "identity"), central, repository=repository)
    with pytest.raises(RuntimeError, match="crashpoint_after_registration_secret"):
        backend.start("initial", repository.load()["installationId"])
    monkeypatch.setattr(repository, "save", original_save)

    restarted = PairingBackend(IdentityStore(tmp_path / "identity"), central, repository=repository)

    assert restarted.status()["status"] == "registered"
    assert restarted.status()["sessionId"] == central.session_id
    app.state.engine.dispose()


def test_startup_recovers_pop_response_committed_before_public_state(tmp_path, monkeypatch) -> None:
    app = create_app(
        database_url=f"sqlite:///{tmp_path / 'state.db'}",
        identity_dir=tmp_path / "identity",
        pairing_backend=False,
    )
    repository = PairingRepository(app.state.session)
    central = LossyCentral()
    central.lose_registration_once = False
    original_save = repository.save

    def crash_after_proof_secret(state, *, actor_id, action):
        if state.get("status") == "pop_verified":
            raise RuntimeError("crashpoint_after_proof_secret")
        return original_save(state, actor_id=actor_id, action=action)

    monkeypatch.setattr(repository, "save", crash_after_proof_secret)
    store = IdentityStore(tmp_path / "identity")
    backend = PairingBackend(store, central, repository=repository)
    with pytest.raises(RuntimeError, match="crashpoint_after_proof_secret"):
        backend.start("initial", repository.load()["installationId"])
    monkeypatch.setattr(repository, "save", original_save)

    restarted = PairingBackend(store, central, repository=repository)

    assert restarted.status()["status"] == "pop_verified"
    assert restarted.status()["codeExpiresAt"] == store.read_transient()["codeExpiresAt"]
    assert len(central.registration_calls) == 1
    assert len(central.proof_calls) == 1
    app.state.engine.dispose()


def test_create_app_wires_operational_pairing_backend_by_default(tmp_path, fake_ha) -> None:
    app = create_app(
        database_url=f"sqlite:///{tmp_path / 'db.sqlite'}",
        ha_client=fake_ha,
        ingress_proxies={"testclient"},
        allowed_origins={"http://testserver"},
        identity_dir=tmp_path / "identity",
        start_pairing_worker=False,
    )
    with TestClient(app) as client:
        response = client.get("/api/v1/pairing/status", headers={"X-Remote-User-Id": "admin-1"})
        assert response.status_code == 200
        assert response.json()["status"] == "unpaired"
        assert app.state.pairing is not None
        assert app.state.pairing_worker is None
        assert app.state.configuration_snapshot_repository is not None
        assert app.state.configuration_sync is not None
    app.state.engine.dispose()


async def _eventually(predicate, timeout: float = 1.0) -> None:
    deadline = asyncio.get_running_loop().time() + timeout
    while not predicate():
        if asyncio.get_running_loop().time() >= deadline:
            raise AssertionError("condition was not reached")
        await asyncio.sleep(0.001)


@pytest.mark.asyncio
async def test_initial_issued_ack_timeout_worker_removes_all_candidate_and_db_intent(
    tmp_path,
) -> None:
    app = create_app(
        database_url=f"sqlite:///{tmp_path / 'state.db'}",
        identity_dir=tmp_path / "identity",
        pairing_backend=False,
    )
    repository = PairingRepository(app.state.session)
    installation_id = repository.load()["installationId"]
    store = IdentityStore(tmp_path / "identity")
    store.create_candidate()
    store.write_candidate_credential("candidate-cert", "candidate-chain")
    request_id = str(uuid4())
    transient = {
        "installationId": installation_id,
        "mode": "initial",
        "registrationRequestId": request_id,
        "sessionId": str(uuid4()),
        "bootstrapToken": "secret",
        "spkiSha256": "A" * 43,
        "csrSha256": "B" * 43,
        "ackRequest": {"installationRevision": 11},
    }
    store.write_transient(transient)
    repository.save(
        {
            "installationId": installation_id,
            "mode": "initial",
            "status": "issued",
            "registrationRequestId": request_id,
            "sessionId": transient["sessionId"],
            "candidateSpkiSha256": transient["spkiSha256"],
            "csrSha256": transient["csrSha256"],
            "claimRevision": 3,
            "installationRevision": 11,
            "credentialId": str(uuid4()),
            "certificateSha256": "C" * 43,
            "ackExpiresAt": (datetime.now(UTC) - timedelta(seconds=1)).isoformat(),
        }
    )
    backend = PairingBackend(store, LossyCentral(), repository=repository)
    worker = PairingWorker(backend, poll_interval=0.001)

    await worker.start()
    await _eventually(lambda: backend.status()["status"] == "expired")
    await worker.stop()

    assert {key: value for key, value in backend.status().items() if key != "revision"} == {
        "installationId": installation_id,
        "status": "expired",
    }
    with app.state.session() as session:
        assert session.get(EdgePairing, 1) is None
    assert store.read_transient() is None
    for name in (
        "candidate-key.pem",
        "candidate-certificate.pem",
        "candidate-chain.pem",
        "candidate-promotion.json",
    ):
        assert not (store.root / name).exists()

    restarted = PairingBackend(store, LossyCentral(), repository=repository)
    restarted.reset()
    assert restarted.status()["status"] == "unpaired"
    with pytest.raises(PairingError, match="central_registration_unreachable"):
        restarted.start("initial", installation_id)
    assert restarted.status()["mode"] == "initial"
    assert restarted.status()["status"] == "registering"
    app.state.engine.dispose()


def test_repair_terminalization_preserves_old_identity_pointer_but_clears_replacement(
    tmp_path,
) -> None:
    app = create_app(
        database_url=f"sqlite:///{tmp_path / 'state.db'}",
        identity_dir=tmp_path / "identity",
        pairing_backend=False,
    )
    repository = PairingRepository(app.state.session)
    installation_id = repository.load()["installationId"]
    store = IdentityStore(tmp_path / "identity")
    old_key = store.load_or_create_identity().private_numbers()
    store.write_identity_credential("old-cert", "old-chain")
    store.create_candidate()
    store.write_candidate_credential("candidate-cert", "candidate-chain")
    request_id = str(uuid4())
    transient = {
        "installationId": installation_id,
        "mode": "repair",
        "registrationRequestId": request_id,
        "sessionId": str(uuid4()),
        "bootstrapToken": "secret",
        "spkiSha256": "N" * 43,
        "csrSha256": "R" * 43,
        "ackRequest": {"installationRevision": 11},
    }
    store.write_transient(transient)
    old_public = {
        "credentialId": str(uuid4()),
        "certificateSha256": "O" * 43,
        "activeSpkiSha256": "P" * 43,
        "certificateNotAfter": (datetime.now(UTC) + timedelta(days=5)).isoformat(),
        "installationRevision": 11,
    }
    repository.save(
        {
            "installationId": installation_id,
            "mode": "repair",
            "status": "issued",
            "registrationRequestId": request_id,
            "sessionId": transient["sessionId"],
            "candidateSpkiSha256": transient["spkiSha256"],
            "csrSha256": transient["csrSha256"],
            "tenantId": "tenant-1",
            "siteId": "site-1",
            "claimRevision": 3,
            "ackExpiresAt": (datetime.now(UTC) - timedelta(seconds=1)).isoformat(),
        }
        | old_public
    )
    backend = PairingBackend(store, LossyCentral(), repository=repository)

    backend.reset(local_only=True, terminal="expired")

    expected = {"installationId": installation_id, "status": "expired"} | old_public
    assert {key: value for key, value in backend.status().items() if key != "revision"} == expected
    assert store.load_identity().private_numbers() == old_key
    assert store.read_identity_credential() == ("old-cert", "old-chain")
    assert store.read_transient() is None
    with pytest.raises(UnsafeIdentityStorage):
        store.load_candidate()
    restarted = PairingBackend(store, LossyCentral(), repository=repository)
    assert restarted.store.load_identity().private_numbers() == old_key
    with pytest.raises(PairingError, match="central_registration_unreachable"):
        restarted.rotate_key()
    assert restarted.status()["mode"] == "repair"
    assert restarted.store.load_identity().private_numbers() == old_key
    app.state.engine.dispose()
