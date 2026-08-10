from __future__ import annotations

import json

import pytest
from one_os_addon.app import create_app
from one_os_addon.configuration_snapshot import ConfigurationSnapshotRepository
from one_os_addon.models import Audit, ConfigurationSnapshot, EdgeIdentity
from one_os_addon.pairing_backend import PairingBackend, PairingError
from one_os_addon.pairing_repository import PairingRepository
from one_os_addon.pairing_storage import IdentityStore
from sqlalchemy import event, select
from test_pairing_backend import LossyCentral


def test_pairing_state_and_secret_free_actor_audit_commit_together(tmp_path) -> None:
    app = create_app(database_url=f"sqlite:///{tmp_path / 'audit.db'}", pairing_backend=False)
    repository = PairingRepository(app.state.session)
    installation_id = repository.load()["installationId"]
    backend = PairingBackend(
        IdentityStore(tmp_path / "identity"), LossyCentral(), repository=repository
    )

    with pytest.raises(PairingError, match="central_registration_unreachable"):
        backend.start("initial", installation_id, actor_id="ha:admin-1")

    with app.state.session() as session:
        records = session.scalars(select(Audit).order_by(Audit.at, Audit.id)).all()
    assert records
    assert {record.actor_id for record in records} == {"ha:admin-1"}
    assert records[0].action == "pairing.initial.start"
    assert records[-1].revision == backend.status()["revision"]
    serialized = "\n".join(record.fields_json for record in records)
    assert "registering" in serialized
    for forbidden in ("bootstrapToken", "recoverySecret", "normalizedCode", "PRIVATE KEY"):
        assert forbidden not in serialized
    app.state.engine.dispose()


def test_audit_insert_failure_rolls_back_pairing_state_revision(tmp_path) -> None:
    app = create_app(database_url=f"sqlite:///{tmp_path / 'rollback.db'}", pairing_backend=False)
    repository = PairingRepository(app.state.session)
    before = repository.load()

    def reject_audit(_mapper, _connection, _target):
        raise RuntimeError("injected audit failure")

    event.listen(Audit, "before_insert", reject_audit)
    try:
        with pytest.raises(RuntimeError, match="injected audit failure"):
            repository.save(
                before | {"status": "cancelled"},
                actor_id="ha:admin-1",
                action="pairing.reset",
            )
    finally:
        event.remove(Audit, "before_insert", reject_audit)

    assert repository.load() == before
    with app.state.session() as session:
        assert session.scalars(select(Audit)).all() == []
    app.state.engine.dispose()


def test_audit_insert_failure_rolls_back_backend_state_and_pairing_material(tmp_path) -> None:
    app = create_app(
        database_url=f"sqlite:///{tmp_path / 'backend-rollback.db'}", pairing_backend=False
    )
    repository = PairingRepository(app.state.session)
    before = repository.load()
    central = LossyCentral()
    store = IdentityStore(tmp_path / "identity")
    backend = PairingBackend(store, central, repository=repository)

    def reject_audit(_mapper, _connection, _target):
        raise RuntimeError("injected audit failure")

    event.listen(Audit, "before_insert", reject_audit)
    try:
        with pytest.raises(RuntimeError, match="injected audit failure"):
            backend.start("initial", before["installationId"], actor_id="ha:admin-1")
    finally:
        event.remove(Audit, "before_insert", reject_audit)

    assert repository.load() == before
    assert backend.status() == before
    assert central.registration_calls == []
    assert store.read_transient() is None
    assert not store.has_pairing_material()
    with app.state.session() as session:
        assert session.scalars(select(Audit)).all() == []
    app.state.engine.dispose()


def test_repair_audit_failure_preserves_active_identity_and_allows_same_process_retry(
    tmp_path,
) -> None:
    app = create_app(
        database_url=f"sqlite:///{tmp_path / 'repair-rollback.db'}", pairing_backend=False
    )
    repository = PairingRepository(app.state.session)
    central = LossyCentral()
    central.lose_registration_once = False
    central.lose_ack_once = False
    store = IdentityStore(tmp_path / "identity")
    backend = PairingBackend(store, central, repository=repository)
    installation_id = repository.load()["installationId"]
    backend.start("initial", installation_id)
    central.claimed = True
    backend.refresh()
    central.prepare_issued(backend)
    backend.refresh()
    assert backend.status()["status"] == "paired"
    before = repository.load()
    active_key = store.load_identity().private_numbers()
    store.create_renewal_candidate()
    store.write_renewal(
        {
            "status": "pending",
            "installationId": installation_id,
            "credentialId": before["credentialId"],
        }
    )
    registration_calls = len(central.registration_calls)

    def reject_audit(_mapper, _connection, _target):
        raise RuntimeError("injected repair audit failure")

    event.listen(Audit, "before_insert", reject_audit)
    try:
        with pytest.raises(RuntimeError, match="injected repair audit failure"):
            backend.start("repair", installation_id, actor_id="ha:admin-1")
    finally:
        event.remove(Audit, "before_insert", reject_audit)

    assert repository.load() == before
    assert backend.status() == before
    assert len(central.registration_calls) == registration_calls
    assert store.load_identity().private_numbers() == active_key
    assert store.read_transient() is None
    assert not (store.root / "candidate-key.pem").exists()
    assert store.read_renewal() is None
    assert not (store.root / "renewal-key.pem").exists()
    central.proof_committed = False
    central.claimed = False
    central.issued = False
    backend.start("repair", installation_id, actor_id="ha:admin-1")
    assert len(central.registration_calls) == registration_calls + 1
    app.state.engine.dispose()


def test_pairing_audit_reconstructs_public_status_without_retry_spam(tmp_path) -> None:
    app = create_app(database_url=f"sqlite:///{tmp_path / 'reconstruct.db'}", pairing_backend=False)
    repository = PairingRepository(app.state.session)
    initial = repository.load()
    changed = repository.save(
        initial | {"status": "cancelled"},
        actor_id="system:edge-worker",
        action="pairing.cancel",
    )
    retried = repository.save(
        changed,
        actor_id="system:edge-worker",
        action="pairing.cancel",
    )

    with app.state.session() as session:
        records = session.scalars(select(Audit).order_by(Audit.at, Audit.id)).all()
    assert retried["revision"] == changed["revision"]
    assert len(records) == 1
    detail = json.loads(records[0].fields_json)
    assert detail == {"changed": ["status"], "fromStatus": "unpaired", "toStatus": "cancelled"}
    assert records[0].revision == changed["revision"]
    app.state.engine.dispose()


def test_snapshot_prepare_attempt_and_ack_are_audited_once_with_system_actor(tmp_path) -> None:
    app = create_app(database_url=f"sqlite:///{tmp_path / 'snapshot.db'}", pairing_backend=False)
    with app.state.session() as session:
        installation_id = session.get(EdgeIdentity, 1).installation_id
    repository = ConfigurationSnapshotRepository(app.state.session)

    pending = repository.prepare(installation_id)
    assert repository.prepare(installation_id).snapshot_id == pending.snapshot_id
    repository.record_attempt(pending.snapshot_id)
    repository.ack(pending.snapshot_id)
    repository.ack(pending.snapshot_id)

    with app.state.session() as session:
        records = session.scalars(
            select(Audit).where(Audit.object_id == pending.snapshot_id).order_by(Audit.at, Audit.id)
        ).all()
    assert [record.action for record in records] == [
        "configuration_snapshot.prepare",
        "configuration_snapshot.attempt",
        "configuration_snapshot.ack",
    ]
    assert {record.actor_id for record in records} == {"system:edge-worker"}
    detail = "\n".join(record.fields_json for record in records)
    assert "PRIVATE" not in detail and "payload" not in detail
    app.state.engine.dispose()


def test_snapshot_audit_failure_rolls_back_snapshot_prepare(tmp_path) -> None:
    app = create_app(
        database_url=f"sqlite:///{tmp_path / 'snapshot-rollback.db'}", pairing_backend=False
    )
    with app.state.session() as session:
        installation_id = session.get(EdgeIdentity, 1).installation_id
    repository = ConfigurationSnapshotRepository(app.state.session)

    def reject_audit(_mapper, _connection, _target):
        raise RuntimeError("injected snapshot audit failure")

    event.listen(Audit, "before_insert", reject_audit)
    try:
        with pytest.raises(RuntimeError, match="injected snapshot audit failure"):
            repository.prepare(installation_id)
    finally:
        event.remove(Audit, "before_insert", reject_audit)

    with app.state.session() as session:
        assert session.scalars(select(ConfigurationSnapshot)).all() == []
        assert session.scalars(select(Audit)).all() == []
    app.state.engine.dispose()
