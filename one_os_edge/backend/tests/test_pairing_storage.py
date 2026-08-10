import json
import os
import stat

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from one_os_addon.app import create_app
from one_os_addon.pairing_storage import IdentityStore, UnsafeIdentityStorage
from sqlalchemy import inspect, text


def test_alembic_0005_contains_only_public_pairing_metadata(tmp_path, fake_ha) -> None:
    app = create_app(
        database_url=f"sqlite:///{tmp_path / 'db.sqlite'}",
        ha_client=fake_ha,
        ingress_proxies={"testclient"},
        allowed_origins={"http://testserver"},
        identity_dir=tmp_path / "identity",
    )
    inspector = inspect(app.state.engine)
    assert {"edge_identity", "edge_pairing"} <= set(inspector.get_table_names())
    identity_columns = {item["name"] for item in inspector.get_columns("edge_identity")}
    assert {
        "installation_revision",
        "renewal_status",
        "renewal_request_id",
        "renewal_issuance_expires_at",
        "renewal_ack_expires_at",
    } <= identity_columns
    pairing_columns = {item["name"] for item in inspector.get_columns("edge_pairing")}
    forbidden = {"private_key", "pairing_code", "bootstrap_token", "recovery_secret"}
    assert forbidden.isdisjoint(identity_columns | pairing_columns)
    with app.state.engine.connect() as connection:
        installation_id = connection.scalar(text("SELECT installation_id FROM edge_identity"))
    app.state.engine.dispose()

    restarted = create_app(
        database_url=f"sqlite:///{tmp_path / 'db.sqlite'}",
        ha_client=fake_ha,
        ingress_proxies={"testclient"},
        allowed_origins={"http://testserver"},
        identity_dir=tmp_path / "identity",
    )
    with restarted.state.engine.connect() as connection:
        restored_installation_id = connection.scalar(
            text("SELECT installation_id FROM edge_identity")
        )
        assert restored_installation_id == installation_id
    restarted.state.engine.dispose()


def test_identity_and_transient_files_are_pkcs8_atomic_and_private(tmp_path) -> None:
    root = tmp_path / "identity"
    store = IdentityStore(root)

    key = store.load_or_create_identity()
    store.write_transient({"registrationRequestId": "public", "recoverySecret": "secret"})

    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    assert stat.S_IMODE((root / "identity-key.pem").stat().st_mode) == 0o600
    assert stat.S_IMODE((root / "transient").stat().st_mode) == 0o700
    assert stat.S_IMODE((root / "transient" / "pairing.json").stat().st_mode) == 0o600
    loaded = serialization.load_pem_private_key((root / "identity-key.pem").read_bytes(), None)
    assert isinstance(loaded, ec.EllipticCurvePrivateKey)
    assert loaded.private_numbers() == key.private_numbers()
    assert store.read_transient()["recoverySecret"] == "secret"
    assert not list(root.rglob("*.tmp"))


def test_unsafe_or_missing_restored_identity_fails_closed(tmp_path) -> None:
    root = tmp_path / "identity"
    store = IdentityStore(root)
    store.load_or_create_identity()
    os.chmod(root / "identity-key.pem", 0o644)
    with pytest.raises(UnsafeIdentityStorage):
        store.load_identity()

    (root / "identity-key.pem").unlink()
    outside = tmp_path / "outside"
    outside.write_text("not a key", encoding="utf-8")
    (root / "identity-key.pem").symlink_to(outside)
    with pytest.raises(UnsafeIdentityStorage):
        store.load_identity()


def test_transient_mismatch_is_destroyed_at_secret_boundary(tmp_path) -> None:
    store = IdentityStore(tmp_path / "identity")
    store.write_transient({"installationId": "one", "recoverySecret": "secret"})

    assert store.read_transient(expected={"installationId": "two"}) is None
    assert not (store.root / "transient" / "pairing.json").exists()
    assert "secret" not in json.dumps({"status": "identity_missing_after_restore"})


def test_candidate_promotion_resumes_after_process_crash_between_renames(
    tmp_path, monkeypatch
) -> None:
    store = IdentityStore(tmp_path / "identity")
    candidate = store.create_candidate()
    store.write_candidate_credential("candidate-cert", "candidate-chain")
    real_replace = os.replace
    moves = 0

    def crash_during_second_move(source, destination, **kwargs):
        nonlocal moves
        if str(source).startswith("candidate-"):
            moves += 1
            if moves == 2:
                raise OSError("simulated process crash")
        return real_replace(source, destination, **kwargs)

    monkeypatch.setattr(os, "replace", crash_during_second_move)
    with pytest.raises(UnsafeIdentityStorage):
        store.promote_candidate()
    assert store.promotion_in_progress()

    monkeypatch.setattr(os, "replace", real_replace)
    store.promote_candidate()

    assert store.load_identity().private_numbers() == candidate.private_numbers()
    assert store.read_identity_credential() == ("candidate-cert", "candidate-chain")
    assert not store.promotion_in_progress()
