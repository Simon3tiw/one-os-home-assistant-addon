from __future__ import annotations

import asyncio
import base64
import hashlib
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import one_os_addon.pairing_storage as pairing_storage_module
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from one_os_addon.pairing_backend import PairingBackend, PairingError, validate_issued_credential
from one_os_addon.pairing_storage import IdentityStore
from one_os_addon.pairing_worker import PairingWorker


def b64u(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def issue_client_certificate(public_key, installation_id, tenant="tenant-1", site="site-1"):
    now = datetime.now(UTC)
    root_key = ec.generate_private_key(ec.SECP256R1())
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Pairing test CA")])
    root = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=90))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(root_key, hashes.SHA256())
    )
    uri = f"spiffe://one-os/tenants/{tenant}/sites/{site}/installations/{installation_id}"
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([]))
        .issuer_name(root.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(uri)]), critical=True
        )
        .sign(root_key, hashes.SHA256())
    )
    leaf_pem = leaf.public_bytes(serialization.Encoding.PEM).decode()
    chain_pem = root.public_bytes(serialization.Encoding.PEM).decode()
    return leaf, leaf_pem, chain_pem


def test_strict_issued_certificate_validation_rejects_wrong_san_and_fingerprint() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    installation_id = str(uuid4())
    leaf, leaf_pem, chain_pem = issue_client_certificate(key.public_key(), installation_id)

    validated = validate_issued_credential(
        key,
        leaf_pem,
        chain_pem,
        b64u(hashlib.sha256(leaf.public_bytes(serialization.Encoding.DER)).digest()),
        installation_id,
        "tenant-1",
        "site-1",
        datetime.now(UTC),
    )
    assert validated.serial_number == leaf.serial_number

    with pytest.raises(PairingError):
        validate_issued_credential(
            key,
            leaf_pem,
            chain_pem,
            b64u(b"x" * 32),
            installation_id,
            "tenant-1",
            "other-site",
            datetime.now(UTC),
        )


class LossyCentral:
    def __init__(self):
        self.registration_calls = []
        self.proof_calls = []
        self.claim_proof_calls = []
        self.ack_calls = []
        self.lose_registration_once = True
        self.lose_proof_once = False
        self.lose_ack_once = True
        self.lose_issued_result_once = False
        self.proof_committed = False
        self.ack_response_overrides = {}
        self.registration_session_revision = 0
        self.session_id = str(uuid4())
        self.credential_id = str(uuid4())
        self.claimed = False
        self.issued = False
        self.leaf_pem = None
        self.chain_pem = None
        self.cert_digest = None
        self.cancel_calls = []

    def register(self, body):
        if self.proof_committed:
            raise AssertionError("registration retried after proof was committed")
        self.registration_calls.append(body.copy())
        response = {
            "sessionId": self.session_id,
            "serverNonce": b64u(b"s" * 32),
            "bootstrapToken": b64u(b"b" * 32),
            "tokenGeneration": len(self.registration_calls),
            "registrationExpiresAt": int(datetime.now(UTC).timestamp()) + 120,
            "sessionRevision": self.registration_session_revision,
        }
        if self.lose_registration_once:
            self.lose_registration_once = False
            raise ConnectionError("response lost")
        return response

    def proof(self, session_id, bootstrap_token, body):
        self.proof_calls.append((session_id, bootstrap_token, body.copy()))
        response = {
            "sessionId": session_id,
            "status": "pop_verified",
            "codeExpiresAt": (datetime.now(UTC) + timedelta(minutes=10)).isoformat(),
            "sessionRevision": 2,
        }
        self.proof_committed = True
        if self.lose_proof_once:
            self.lose_proof_once = False
            raise ConnectionError("proof response lost")
        return response

    def result(self, session_id, bootstrap_token):
        if not self.claimed:
            return {"sessionId": session_id, "status": "pop_verified", "sessionRevision": 2}
        if not self.issued:
            return {
                "sessionId": session_id,
                "status": "claimed",
                "tenantId": "tenant-1",
                "siteId": "site-1",
                "claimNonce": b64u(b"n" * 32),
                "claimExpiresAt": int(datetime.now(UTC).timestamp()) + 120,
                "claimRevision": 7,
                "installationRevision": 11,
                "sessionRevision": 3,
            }
        if self.lose_issued_result_once:
            self.lose_issued_result_once = False
            raise ConnectionError("issued response lost")
        return self.issued_result

    def claim_proof(self, session_id, bootstrap_token, body):
        self.claim_proof_calls.append((session_id, bootstrap_token, body.copy()))
        self.issued = True
        return {
            "sessionId": session_id,
            "status": "claim_proved",
            "claimRevision": 7,
            "installationRevision": 11,
            "issuanceExpiresAt": (datetime.now(UTC) + timedelta(minutes=5)).isoformat(),
            "sessionRevision": 4,
        }

    def cancel(self, session_id, bootstrap_token, expected_session_revision):
        self.cancel_calls.append((session_id, bootstrap_token, expected_session_revision))
        return {"sessionId": session_id, "status": "cancelled"}

    def prepare_issued(self, backend):
        secret = backend.store.read_transient()
        key = backend.store.load_candidate()
        leaf, self.leaf_pem, self.chain_pem = issue_client_certificate(
            key.public_key(), secret["installationId"]
        )
        self.cert_digest = b64u(
            hashlib.sha256(leaf.public_bytes(serialization.Encoding.DER)).digest()
        )
        self.issued_result = {
            "sessionId": self.session_id,
            "installationId": secret["installationId"],
            "status": "issued",
            "claimRevision": 7,
            "installationRevision": 11,
            "credentialId": self.credential_id,
            "certificatePem": self.leaf_pem,
            "certificateSha256": self.cert_digest,
            "caChainPem": self.chain_pem,
            "ackExpiresAt": (datetime.now(UTC) + timedelta(minutes=10)).isoformat(),
            "sessionRevision": 5,
        }

    def ack(self, body, certificate_pem, private_key_pem, bootstrap_token):
        self.ack_calls.append((body.copy(), certificate_pem, private_key_pem, bootstrap_token))
        if self.lose_ack_once:
            self.lose_ack_once = False
            raise ConnectionError("ACK response lost")
        return {
            "sessionId": body["sessionId"],
            "installationId": body["installationId"],
            "status": "acked",
            "installationRevision": body["installationRevision"],
            "credentialId": body["credentialId"],
            "certificateSha256": body["certificateSha256"],
        } | self.ack_response_overrides


def test_registration_response_loss_restart_and_generation_cas(tmp_path) -> None:
    central = LossyCentral()
    state = {}
    backend = PairingBackend(IdentityStore(tmp_path / "identity"), central, state)

    with pytest.raises(PairingError):
        backend.start("initial", str(uuid4()))
    request = central.registration_calls[0]
    assert backend.store.read_transient()["tokenGeneration"] == 0

    backend = PairingBackend(IdentityStore(tmp_path / "identity"), central, state)
    backend.refresh()

    assert central.registration_calls[1] == request
    assert state["status"] == "pop_verified"
    assert backend.code()["code"].count("-") == 4
    assert backend.store.read_transient()["tokenGeneration"] == 2
    backend.apply_registration_response(
        {
            "sessionId": central.session_id,
            "serverNonce": b64u(b"s" * 32),
            "bootstrapToken": b64u(b"old".ljust(32, b"!")),
            "tokenGeneration": 1,
            "registrationExpiresAt": int(datetime.now(UTC).timestamp()) + 120,
            "sessionRevision": 1,
        }
    )
    assert backend.store.read_transient()["tokenGeneration"] == 2


def test_registration_accepts_zero_revision_and_rejects_negative_revision(tmp_path) -> None:
    central = LossyCentral()
    central.lose_registration_once = False
    central.registration_session_revision = -1
    backend = PairingBackend(IdentityStore(tmp_path / "identity"), central, {})

    with pytest.raises(PairingError, match="invalid_registration_response"):
        backend.start("initial", str(uuid4()))
    assert central.proof_calls == []


def test_first_proof_response_loss_retries_exact_proof_without_registration(tmp_path) -> None:
    central = LossyCentral()
    central.lose_registration_once = False
    central.lose_proof_once = True
    state = {}
    backend = PairingBackend(IdentityStore(tmp_path / "identity"), central, state)

    with pytest.raises(PairingError, match="central_proof_unreachable"):
        backend.start("initial", str(uuid4()))
    persisted = backend.store.read_transient()
    first_proof = central.proof_calls[0]
    assert persisted["proofRequest"] == first_proof[2]

    restarted = PairingBackend(IdentityStore(tmp_path / "identity"), central, state)
    restarted.refresh()

    assert len(central.registration_calls) == 1
    assert central.proof_calls == [first_proof, first_proof]
    assert restarted.status()["status"] == "pop_verified"
    assert restarted.store.read_transient()["codeExpiresAt"] == restarted.status()["codeExpiresAt"]


def test_cancel_uses_persisted_central_session_revision_and_is_retry_safe(tmp_path) -> None:
    central = LossyCentral()
    central.lose_registration_once = False
    state = {}
    backend = PairingBackend(IdentityStore(tmp_path / "identity"), central, state)
    backend.start("initial", str(uuid4()))

    backend.cancel()

    assert central.cancel_calls == [(central.session_id, b64u(b"b" * 32), 2)]
    assert state["status"] == "cancelled"
    assert backend.store.read_transient() is None


def test_claim_proof_persists_central_issuance_deadline(tmp_path) -> None:
    central = LossyCentral()
    central.lose_registration_once = False
    state = {}
    backend = PairingBackend(IdentityStore(tmp_path / "identity"), central, state)
    backend.start("initial", str(uuid4()))
    central.claimed = True

    backend.refresh()

    assert state["status"] == "claim_proved"
    assert datetime.fromisoformat(state["issuanceExpiresAt"]) > datetime.now(UTC)
    assert state["centralSessionRevision"] == 4


def test_claim_secret_boundary_pending_candidate_and_mtls_ack_retry_after_restart(tmp_path) -> None:
    central = LossyCentral()
    central.lose_registration_once = False
    state = {}
    backend = PairingBackend(IdentityStore(tmp_path / "identity"), central, state)
    backend.start("initial", str(uuid4()))
    central.claimed = True

    backend.refresh()
    assert "normalizedCode" not in backend.store.read_transient()
    assert central.claim_proof_calls
    central.prepare_issued(backend)

    with pytest.raises(PairingError):
        backend.refresh()
    transient = backend.store.read_transient()
    first_ack = central.ack_calls[0][0]
    assert central.leaf_pem is not None
    assert central.chain_pem is not None
    assert transient["ackRequest"] == first_ack
    assert central.ack_calls[0][1] == central.leaf_pem + central.chain_pem
    assert (backend.store.root / "candidate-certificate.pem").exists()
    assert not (backend.store.root / "identity-key.pem").exists()

    restarted = PairingBackend(IdentityStore(tmp_path / "identity"), central, state)
    restarted.refresh()

    assert central.ack_calls[1][0] == first_ack
    assert central.ack_calls[1][1] == central.leaf_pem + central.chain_pem
    assert state["status"] == "paired"
    assert (restarted.store.root / "identity-key.pem").exists()
    assert not (restarted.store.root / "candidate-key.pem").exists()
    assert restarted.store.read_transient() is None


def test_issued_result_response_loss_retries_without_losing_or_duplicating_candidate(
    tmp_path,
) -> None:
    central = LossyCentral()
    central.lose_registration_once = False
    central.lose_ack_once = False
    backend = PairingBackend(IdentityStore(tmp_path / "identity"), central, {})
    backend.start("initial", str(uuid4()))
    central.claimed = True
    backend.refresh()
    central.prepare_issued(backend)
    central.lose_issued_result_once = True
    candidate = backend.store.load_candidate().private_numbers()

    with pytest.raises(PairingError, match="central_result_unreachable"):
        backend.refresh()

    assert backend.status()["status"] == "claim_proved"
    assert backend.store.load_candidate().private_numbers() == candidate
    assert not (backend.store.root / "candidate-certificate.pem").exists()

    backend.refresh()

    assert backend.status()["status"] == "paired"
    assert backend.store.load_identity().private_numbers() == candidate
    assert not (backend.store.root / "candidate-key.pem").exists()
    assert backend.store.read_transient() is None


@pytest.mark.parametrize("issued_session_revision", [0, 4, "5", None])
def test_issued_result_rejects_non_monotone_or_malformed_session_revision(
    tmp_path, issued_session_revision
) -> None:
    central = LossyCentral()
    central.lose_registration_once = False
    central.lose_ack_once = False
    backend = PairingBackend(IdentityStore(tmp_path / "identity"), central, {})
    backend.start("initial", str(uuid4()))
    central.claimed = True
    backend.refresh()
    central.prepare_issued(backend)
    central.issued_result["sessionRevision"] = issued_session_revision

    with pytest.raises(PairingError, match="invalid_issued_session_revision"):
        backend.refresh()

    assert backend.status()["status"] == "claim_proved"
    assert backend.status()["centralSessionRevision"] == 4
    assert central.ack_calls == []
    assert not (backend.store.root / "candidate-certificate.pem").exists()


@pytest.mark.asyncio
async def test_running_worker_reconciles_mid_promotion_io_failure_without_restart(
    tmp_path, monkeypatch
) -> None:
    central = LossyCentral()
    central.lose_registration_once = False
    central.lose_ack_once = False
    backend = PairingBackend(IdentityStore(tmp_path / "identity"), central, {})
    backend.start("initial", str(uuid4()))
    central.claimed = True
    backend.refresh()
    central.prepare_issued(backend)
    candidate = backend.store.load_candidate().private_numbers()
    real_replace = pairing_storage_module.os.replace
    failed = False

    def fail_mid_promotion(source, destination, *args, **kwargs):
        nonlocal failed
        if source == "candidate-certificate.pem" and not failed:
            failed = True
            raise OSError("injected nonfatal promotion failure")
        return real_replace(source, destination, *args, **kwargs)

    monkeypatch.setattr(pairing_storage_module.os, "replace", fail_mid_promotion)
    worker = PairingWorker(
        backend,
        poll_interval=0.001,
        base_backoff=0.001,
        max_backoff=0.001,
    )
    await worker.start()
    deadline = asyncio.get_running_loop().time() + 1
    while backend.status()["status"] != "paired":
        if asyncio.get_running_loop().time() >= deadline:
            await worker.stop()
            raise AssertionError("same-process promotion did not reconcile")
        await asyncio.sleep(0.001)
    await worker.stop()

    assert failed is True
    assert len(central.ack_calls) == 1
    assert backend.store.load_identity().private_numbers() == candidate
    assert backend.store.read_identity_credential() == (central.leaf_pem, central.chain_pem)
    assert backend.store.read_transient() is None
    assert not backend.store.promotion_in_progress()
    assert not [path for path in backend.store.root.iterdir() if path.name.startswith("candidate-")]


@pytest.mark.parametrize(
    ("field", "wrong"),
    [
        ("sessionId", str(uuid4())),
        ("installationId", str(uuid4())),
        ("status", "issued"),
        ("installationRevision", 12),
        ("credentialId", str(uuid4())),
        ("certificateSha256", b64u(b"x" * 32)),
    ],
)
def test_initial_ack_mismatch_never_promotes_candidate(tmp_path, field, wrong) -> None:
    central = LossyCentral()
    central.lose_registration_once = False
    central.lose_ack_once = False
    state = {}
    backend = PairingBackend(IdentityStore(tmp_path / "identity"), central, state)
    backend.start("initial", str(uuid4()))
    central.claimed = True
    backend.refresh()
    central.prepare_issued(backend)
    candidate = backend.store.load_candidate().private_numbers()
    central.ack_response_overrides = {field: wrong}

    with pytest.raises(PairingError, match="invalid_ack_response"):
        backend.refresh()

    assert backend.store.load_candidate().private_numbers() == candidate
    assert (backend.store.root / "candidate-certificate.pem").exists()
    assert not (backend.store.root / "identity-key.pem").exists()


def test_repair_keeps_old_identity_until_candidate_mtls_ack_succeeds(tmp_path) -> None:
    central = LossyCentral()
    central.lose_registration_once = False
    installation_id = str(uuid4())
    store = IdentityStore(tmp_path / "identity")
    old_key = store.load_or_create_identity().private_numbers()
    _leaf, old_pem, old_chain = issue_client_certificate(
        store.load_identity().public_key(), installation_id
    )
    store.write_identity_credential(old_pem, old_chain)
    state = {
        "installationId": installation_id,
        "status": "compromised",
        "credentialId": str(uuid4()),
        "certificateSha256": b64u(b"o" * 32),
        "certificateNotAfter": (datetime.now(UTC) + timedelta(days=5)).isoformat(),
        "installationRevision": 11,
        "tenantId": "tenant-1",
        "siteId": "site-1",
    }
    backend = PairingBackend(store, central, state)
    backend.rotate_key()
    central.claimed = True
    backend.refresh()
    central.prepare_issued(backend)

    with pytest.raises(PairingError, match="central_ack_unreachable"):
        backend.refresh()

    assert store.load_identity().private_numbers() == old_key
    assert store.read_identity_credential() == (old_pem, old_chain)
    assert store.read_candidate_credential()[0] == central.leaf_pem

    restarted = PairingBackend(store, central, state)
    restarted.refresh()

    assert restarted.status()["status"] == "paired"
    assert store.load_identity().private_numbers() != old_key
    assert store.read_identity_credential()[0] == central.leaf_pem


@pytest.mark.parametrize(
    "state",
    [
        {"status": "paired", "credentialId": "credential"},
        {"status": "revoked", "credentialId": "credential"},
        {"status": "compromised", "credentialId": "credential"},
        {"status": "expired", "credentialId": "credential"},
        {"status": "identity_missing_after_restore", "credentialId": "credential"},
    ],
)
def test_manual_reset_refuses_identity_bearing_states(tmp_path, state) -> None:
    backend = PairingBackend(
        IdentityStore(tmp_path / "identity"),
        LossyCentral(),
        {"installationId": str(uuid4())} | state,
    )

    with pytest.raises(PairingError, match="identity_repair_required"):
        backend.reset()


@pytest.mark.parametrize("status", ["unpaired", "cancelled", "expired"])
def test_manual_reset_returns_only_non_identity_state_to_unpaired(tmp_path, status) -> None:
    installation_id = str(uuid4())
    backend = PairingBackend(
        IdentityStore(tmp_path / "identity"),
        LossyCentral(),
        {"installationId": installation_id, "status": status},
    )

    backend.reset()

    assert backend.status() == {"installationId": installation_id, "status": "unpaired"}


@pytest.mark.parametrize("status", ["paired", "revoked", "repairing", "cancelled", "expired"])
def test_initial_start_requires_exactly_unpaired_public_state_without_mutation(
    tmp_path, status
) -> None:
    installation_id = str(uuid4())
    state = {
        "installationId": installation_id,
        "status": status,
        "credentialId": str(uuid4()),
    }
    original = state.copy()
    store = IdentityStore(tmp_path / "identity")
    backend = PairingBackend(store, LossyCentral(), state)

    with pytest.raises(PairingError, match="initial_pairing_not_allowed"):
        backend.start("initial", installation_id)

    assert state == original
    assert not store.root.exists()


@pytest.mark.parametrize("material", ["active", "candidate", "renewal", "transient"])
def test_initial_start_rejects_any_existing_identity_material_without_deleting_it(
    tmp_path, material
) -> None:
    installation_id = str(uuid4())
    store = IdentityStore(tmp_path / "identity")
    if material == "active":
        store.load_or_create_identity()
    elif material == "candidate":
        store.create_candidate()
    elif material == "renewal":
        store.create_renewal_candidate()
    else:
        store.write_transient({"installationId": installation_id, "bootstrapToken": "keep"})
    before = {
        path.relative_to(store.root): path.read_bytes()
        for path in store.root.rglob("*")
        if path.is_file()
    }
    state = {"installationId": installation_id, "status": "unpaired"}

    with pytest.raises(PairingError, match="initial_pairing_not_allowed"):
        PairingBackend(store, LossyCentral(), state).start("initial", installation_id)

    after = {
        path.relative_to(store.root): path.read_bytes()
        for path in store.root.rglob("*")
        if path.is_file()
    }
    assert after == before
    assert state == {"installationId": installation_id, "status": "unpaired"}
