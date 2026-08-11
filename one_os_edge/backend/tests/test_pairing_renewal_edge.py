from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from one_os_addon.central_pairing_client import CentralDeviceRevokedError
from one_os_addon.pairing_backend import (
    PairingBackend,
    PairingError,
    build_renewal_ack_preimage,
    build_renewal_proof_preimage,
)
from one_os_addon.pairing_storage import IdentityStore


def b64u(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def test_renewal_preimages_match_committed_central_vectors() -> None:
    contract = json.loads(
        (
            Path(__file__).resolve().parents[3]
            / "docs/reference/contracts/pairing/v1/signing-vectors.json"
        ).read_text()
    )
    values = contract["inputs"]
    proof = build_renewal_proof_preimage(
        protocol=values["protocol"],
        request_id=values["renewalRequestId"],
        installation_id=values["installationId"],
        current_credential_id=values["credentialId"],
        current_certificate_sha256=base64.urlsafe_b64decode(values["certificateSha256"] + "="),
        csr_sha256=base64.urlsafe_b64decode(values["csrSha256"] + "="),
        edge_nonce=base64.urlsafe_b64decode(values["edgeNonce"] + "="),
        epoch_minute=values["renewalEpochMinute"],
        installation_revision=values["installationRevision"],
    )
    ack = build_renewal_ack_preimage(
        protocol=values["protocol"],
        installation_id=values["installationId"],
        old_credential_id=values["credentialId"],
        old_certificate_sha256=base64.urlsafe_b64decode(values["certificateSha256"] + "="),
        new_credential_id=values["newCredentialId"],
        new_certificate_sha256=base64.urlsafe_b64decode(values["newCertificateSha256"] + "="),
        request_id=values["renewalRequestId"],
        ack_expires_epoch_seconds=values["renewalAckExpiresEpochSeconds"],
        installation_revision=values["installationRevision"],
    )
    assert b64u(proof) == contract["vectors"]["renewalProof"]["preimageBase64url"]
    assert b64u(ack) == contract["vectors"]["renewalAck"]["preimageBase64url"]


def issue(public_key, installation_id: str, *, days: int = 5):
    now = datetime.now(UTC)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "renewal ca")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=90))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([]))
        .issuer_name(ca.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(True, False, False, False, False, False, False, False, False),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.UniformResourceIdentifier(
                        "spiffe://one-os/tenants/tenant-1/sites/site-1/installations/"
                        + installation_id
                    )
                ]
            ),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return (
        leaf,
        leaf.public_bytes(serialization.Encoding.PEM).decode(),
        ca.public_bytes(serialization.Encoding.PEM).decode(),
    )


class RenewalCentral:
    def __init__(self, store: IdentityStore, installation_id: str, old_id: str, old_hash: str):
        self.store = store
        self.installation_id = installation_id
        self.old_id = old_id
        self.old_hash = old_hash
        self.request_body = None
        self.ack_body = None
        self.new_id = str(uuid4())
        self.revision = 11
        self.ack_response_overrides = {}

    def device_status(self, certificate, private_key):
        leaf, chain = self.store.read_identity_credential()
        assert certificate == leaf + chain
        assert private_key == self.store.identity_private_pem()
        return {
            "installationId": self.installation_id,
            "status": "paired",
            "installationRevision": self.revision,
            "credentialId": self.old_id if self.revision == 11 else self.new_id,
            "certificateSha256": self.old_hash
            if self.revision == 11
            else self.ack_body["newCertificateSha256"],
        }

    def start_renewal(self, body, certificate, private_key):
        self.request_body = json.loads(json.dumps(body, sort_keys=True, separators=(",", ":")))
        leaf, chain = self.store.read_identity_credential()
        assert certificate == leaf + chain
        assert private_key == self.store.identity_private_pem()
        return {
            "requestId": body["requestId"],
            "installationId": self.installation_id,
            "status": "pending",
            "installationRevision": 11,
            "issuanceExpiresAt": (datetime.now(UTC) + timedelta(minutes=5)).isoformat(),
        }

    def renewal_result(self, request_id, certificate, private_key):
        assert request_id == self.request_body["requestId"]
        leaf, chain = self.store.read_identity_credential()
        assert certificate == leaf + chain
        assert private_key == self.store.identity_private_pem()
        key = self.store.load_renewal_candidate()
        leaf, pem, chain = issue(key.public_key(), self.installation_id, days=30)
        digest = b64u(hashlib.sha256(leaf.public_bytes(serialization.Encoding.DER)).digest())
        return {
            "requestId": request_id,
            "installationId": self.installation_id,
            "status": "issued",
            "installationRevision": 11,
            "oldCredentialId": self.old_id,
            "oldCertificateSha256": self.old_hash,
            "newCredentialId": self.new_id,
            "newCertificateSha256": digest,
            "certificatePem": pem,
            "caChainPem": chain,
            "ackExpiresAt": (datetime.now(UTC) + timedelta(hours=1))
            .replace(microsecond=0)
            .isoformat(),
        }

    def ack_renewal(self, request_id, body, certificate, private_key):
        leaf, chain = self.store.read_renewal_credential()
        assert certificate == leaf + chain
        assert private_key == self.store.renewal_private_pem()
        self.ack_body = json.loads(json.dumps(body, sort_keys=True, separators=(",", ":")))
        self.revision = 12
        return {
            "requestId": request_id,
            "installationId": self.installation_id,
            "status": "acked",
            "installationRevision": 12,
            "oldCredentialId": self.old_id,
            "oldCertificateSha256": self.old_hash,
            "newCredentialId": self.new_id,
            "newCertificateSha256": body["newCertificateSha256"],
        } | self.ack_response_overrides


def paired_backend(tmp_path):
    installation_id = str(uuid4())
    old_id = str(uuid4())
    store = IdentityStore(tmp_path / "identity")
    key = store.load_or_create_identity()
    leaf, pem, chain = issue(key.public_key(), installation_id)
    store.write_identity_credential(pem, chain)
    digest = b64u(hashlib.sha256(leaf.public_bytes(serialization.Encoding.DER)).digest())
    spki = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    state = {
        "installationId": installation_id,
        "status": "paired",
        "credentialId": old_id,
        "certificateSha256": digest,
        "activeSpkiSha256": b64u(hashlib.sha256(spki).digest()),
        "certificateNotAfter": leaf.not_valid_after_utc.isoformat(),
        "installationRevision": 11,
        "tenantId": "tenant-1",
        "siteId": "site-1",
        "revision": 1,
    }
    central = RenewalCentral(store, installation_id, old_id, digest)
    return PairingBackend(store, central, state), central


def test_renewal_happy_path_is_restart_safe_and_promotes_only_after_ack(tmp_path) -> None:
    backend, central = paired_backend(tmp_path)
    old_spki = backend.state["activeSpkiSha256"]
    backend.maintain_device()
    first = backend.store.read_renewal()
    assert first["startRequest"] == central.request_body
    old_key = backend.store.load_identity().private_numbers()

    restarted = PairingBackend(backend.store, central, backend.state)
    restarted.maintain_device()
    assert restarted.status()["renewalStatus"] == "ack_ready"
    assert restarted.store.load_identity().private_numbers() == old_key

    restarted = PairingBackend(backend.store, central, backend.state)
    restarted.maintain_device()
    assert restarted.status()["status"] == "paired"
    assert restarted.status()["credentialId"] == central.new_id
    assert restarted.store.read_renewal() is None
    assert restarted.store.load_identity().private_numbers() != old_key
    identity = restarted.active_transport_identity()
    assert identity["credentialId"] == central.new_id
    assert identity["activeSpkiSha256"] == restarted.state["activeSpkiSha256"]
    assert identity["activeSpkiSha256"] != old_spki
    assert identity["certificateSha256"] == restarted.state["certificateSha256"]
    assert identity["certificateNotAfter"] == restarted.state["certificateNotAfter"]
    assert identity["revision"] == restarted.state["revision"]


@pytest.mark.parametrize(
    ("field", "wrong"),
    [
        ("requestId", str(uuid4())),
        ("installationId", str(uuid4())),
        ("status", "issued"),
        ("installationRevision", 999),
        ("oldCredentialId", str(uuid4())),
        ("oldCertificateSha256", b64u(b"x" * 32)),
        ("newCredentialId", str(uuid4())),
        ("newCertificateSha256", b64u(b"y" * 32)),
    ],
)
def test_renewal_ack_mismatch_keeps_old_and_candidate_identities(tmp_path, field, wrong) -> None:
    backend, central = paired_backend(tmp_path)
    backend.maintain_device()
    backend.maintain_device()
    old_key = backend.store.load_identity().private_numbers()
    candidate_key = backend.store.load_renewal_candidate().private_numbers()
    old_credential = backend.store.read_identity_credential()
    candidate_credential = backend.store.read_renewal_credential()
    central.ack_response_overrides = {field: wrong}

    with pytest.raises(PairingError, match="invalid_renewal_ack_response"):
        backend.maintain_device()

    assert backend.store.load_identity().private_numbers() == old_key
    assert backend.store.load_renewal_candidate().private_numbers() == candidate_key
    assert backend.store.read_identity_credential() == old_credential
    assert backend.store.read_renewal_credential() == candidate_credential


def test_device_generation_drift_fails_closed_before_other_work(tmp_path) -> None:
    backend, central = paired_backend(tmp_path)
    central.revision = 12
    central.new_id = str(uuid4())
    central.ack_body = {"newCertificateSha256": b64u(b"x" * 32)}
    with pytest.raises(PairingError, match="device_generation_drift"):
        backend.maintain_device()
    assert backend.status()["status"] == "compromised"
    assert central.request_body is None


class StateRepository:
    def __init__(self, state):
        self.state = state.copy()

    def load(self):
        return self.state.copy()

    def save(self, state):
        self.state = state.copy()
        return self.state.copy()


@pytest.mark.parametrize("cause", ["generation_drift", "renewal_window_missed"])
def test_compromised_identity_survives_restart_and_can_start_confirmed_repair(
    tmp_path, cause
) -> None:
    backend, central = paired_backend(tmp_path)
    old_key = backend.store.load_identity().private_numbers()
    old_credential = backend.store.read_identity_credential()
    if cause == "generation_drift":
        central.revision = 12
        central.new_id = str(uuid4())
        central.ack_body = {"newCertificateSha256": b64u(b"x" * 32)}
        expected_error = "device_generation_drift"
    else:
        backend.state["certificateNotAfter"] = (datetime.now(UTC) + timedelta(hours=47)).isoformat()
        expected_error = "renewal_safety_window_missed"

    with pytest.raises(PairingError, match=expected_error):
        backend.maintain_device()
    repository = StateRepository(backend.state)
    restarted = PairingBackend(backend.store, central, repository=repository)

    assert restarted.status()["status"] == "compromised"
    assert restarted.store.load_identity().private_numbers() == old_key
    assert restarted.store.read_identity_credential() == old_credential

    with pytest.raises(PairingError, match="central_registration_unreachable"):
        restarted.rotate_key()

    assert restarted.status()["mode"] == "repair"
    assert restarted.status()["status"] == "registering"
    assert restarted.store.load_identity().private_numbers() == old_key
    assert restarted.store.read_identity_credential() == old_credential
    assert restarted.store.load_candidate().private_numbers() != old_key


def test_revoked_current_is_retained_until_repair_ack(tmp_path) -> None:
    backend, central = paired_backend(tmp_path)

    def revoked(_certificate, _key):
        raise CentralDeviceRevokedError("revoked")

    central.device_status = revoked
    with pytest.raises(PairingError, match="device_revoked"):
        backend.maintain_device()

    assert backend.status()["status"] == "revoked"
    assert (backend.store.root / "identity-key.pem").exists()
    assert (backend.store.root / "certificate.pem").exists()
    assert backend.store.read_renewal() is None


def test_revoked_during_renewal_ack_stops_retries_survives_restart_and_allows_repair(
    tmp_path,
) -> None:
    backend, central = paired_backend(tmp_path)
    repository = StateRepository(backend.state)
    backend.repository = repository
    backend.maintain_device()
    backend.maintain_device()
    old_key = backend.store.load_identity().private_numbers()
    old_credential = backend.store.read_identity_credential()
    ack_calls = 0

    def revoked(*_args):
        nonlocal ack_calls
        ack_calls += 1
        raise CentralDeviceRevokedError("revoked")

    central.ack_renewal = revoked

    with pytest.raises(PairingError, match="device_revoked"):
        backend.maintain_device()

    assert backend.status()["status"] == "revoked"
    assert backend.status().get("renewalStatus") is None
    assert backend.status().get("renewalRequestId") is None
    assert backend.status().get("renewalIssuanceExpiresAt") is None
    assert backend.status().get("renewalAckExpiresAt") is None
    assert backend.store.read_renewal() is None
    assert backend.store.load_identity().private_numbers() == old_key
    assert backend.store.read_identity_credential() == old_credential
    with pytest.raises(PairingError, match="device_not_paired"):
        backend.maintain_device()
    assert ack_calls == 1

    restarted = PairingBackend(backend.store, central, repository=repository)
    assert restarted.status()["status"] == "revoked"
    assert restarted.store.load_identity().private_numbers() == old_key
    with pytest.raises(PairingError, match="device_not_paired"):
        restarted.maintain_device()
    assert ack_calls == 1
    with pytest.raises(PairingError, match="central_registration_unreachable"):
        restarted.rotate_key()
    assert restarted.status()["mode"] == "repair"
    assert restarted.store.load_identity().private_numbers() == old_key
