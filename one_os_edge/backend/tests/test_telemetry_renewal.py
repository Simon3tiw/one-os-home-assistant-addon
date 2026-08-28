from __future__ import annotations

import base64
import hashlib
import json
import threading
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    encode_dss_signature,
)
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from one_os_addon.app import create_app
from one_os_addon.central_pairing_client import CentralPairingHTTPClient
from one_os_addon.models import (
    EdgeIdentity,
    TelemetryAuthorityCut,
    TelemetryBatch,
    TelemetryJournalState,
    TelemetryRenewalOperation,
)
from one_os_addon.pairing_storage import IdentityStore, UnsafeIdentityStorage
from one_os_addon.telemetry_contract_v2 import canonical_json
from one_os_addon.telemetry_renewal import TelemetryRenewalError, TelemetryRenewalManager


def test_renewal_service_is_default_off_and_never_auto_starts(tmp_path) -> None:
    disabled = create_app(
        database_url=f"sqlite:///{tmp_path / 'disabled.db'}",
        pairing_backend=False,
        telemetry_enabled=True,
    )
    assert disabled.state.telemetry_renewal is None

    enabled = create_app(
        database_url=f"sqlite:///{tmp_path / 'enabled.db'}",
        identity_dir=tmp_path / "enabled-identity",
        telemetry_enabled=True,
        telemetry_authority_enabled=True,
        start_pairing_worker=False,
    )
    assert isinstance(enabled.state.telemetry_renewal, TelemetryRenewalManager)
    assert enabled.state.pairing.renewal_v2_status() is None
    with enabled.state.session() as session:
        assert session.get(TelemetryRenewalOperation, 1) is None


INSTALLATION = "00000000-0000-4000-8000-000000000002"
LINEAGE = "00000000-0000-4000-8000-000000000003"
OLD_CREDENTIAL = "00000000-0000-4000-8000-000000000004"
REQUEST = "00000000-0000-4000-8000-000000000005"
PENDING = "00000000-0000-4000-8000-000000000006"
CUT = "00000000-0000-4000-8000-000000000007"
CANCEL = "00000000-0000-4000-8000-000000000008"
BATCH = "00000000-0000-4000-8000-000000000009"
NOW = datetime(2030, 1, 1, 12, 0, 1, tzinfo=UTC)
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _certificate(key: ec.EllipticCurvePrivateKey) -> tuple[str, str]:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, OLD_CREDENTIAL)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode(), _b64(
        hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).digest()
    )


def _seed(app, store: IdentityStore, *, backlog: bool = True) -> dict:
    key = store.load_or_create_identity()
    certificate, certificate_hash = _certificate(key)
    store.write_identity_credential(certificate, certificate)
    spki = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    request = b'{"durable":"batch"}'
    with app.state.session() as session:
        identity = session.get(EdgeIdentity, 1)
        identity.installation_id = INSTALLATION
        identity.lineage_id = LINEAGE
        identity.status = "paired"
        identity.credential_id = OLD_CREDENTIAL
        identity.certificate_sha256 = certificate_hash
        identity.active_spki_sha256 = _b64(hashlib.sha256(spki).digest())
        identity.installation_revision = 5
        identity.telemetry_authorization_revision = 7
        journal = session.get(TelemetryJournalState, 1)
        journal.last_journal_id = 1 if backlog else 0
        if backlog:
            session.add(
                TelemetryBatch(
                    batch_id=BATCH,
                    installation_id=INSTALLATION,
                    installation_revision=5,
                    batch_authorization_revision=7,
                    journal_id=1,
                    credential_id=OLD_CREDENTIAL,
                    payload_sha256="a" * 43,
                    request_sha256=_b64(hashlib.sha256(request).digest()),
                    request_bytes=request,
                    sample_count=1,
                    quality_event_count=0,
                    gap_count=0,
                    status="pending",
                    attempt_count=0,
                    created_at=NOW,
                )
            )
        session.commit()
    return {
        "status": "paired",
        "installationId": INSTALLATION,
        "credentialId": OLD_CREDENTIAL,
        "certificateSha256": certificate_hash,
        "activeSpkiSha256": _b64(hashlib.sha256(spki).digest()),
        "certificatePem": certificate,
        "privateKeyPem": store.identity_private_pem(),
    }


class _Central:
    def __init__(self, mismatch: str | None = None, *, lose_start: bool = False) -> None:
        self.start_requests: list[bytes] = []
        self.cancel_requests: list[bytes] = []
        self.mismatch = mismatch
        self.lose_start = lose_start
        self.start_response: bytes | None = None
        self.cancel_response: bytes | None = None
        self.lose_cancel = False
        self.issued_response: bytes | None = None
        self.ack_response: bytes | None = None
        self.ack_requests: list[bytes] = []
        self.lose_ack = False

    def start_renewal_v2(self, raw: bytes, _certificate: str, _key: str) -> bytes:
        self.start_requests.append(raw)
        if self.start_response is None:
            request = json.loads(raw)
            manifest = request["backlogManifest"]
            mode = request["backlogMode"]
            response = {
                "backlogManifestSha256": request["backlogManifestSha256"],
                "backlogMode": mode,
                "csrSha256": request["csrSha256"],
                "csrSpkiSha256": request["csrSpkiSha256"],
                "installationId": INSTALLATION,
                "installationRevisionBefore": request["installationRevisionBefore"],
                "issuanceExpiresAt": "2030-01-01T12:10:01Z",
                "lineageId": LINEAGE,
                "newCredentialId": PENDING,
                "oldCertificateSha256": request["oldCertificateSha256"],
                "oldCertificateSpkiSha256": request["oldCertificateSpkiSha256"],
                "oldCredentialId": OLD_CREDENTIAL,
                "protocol": "2.0",
                "requestId": REQUEST,
                "status": "pending",
                "telemetryAuthorizationRevisionAfter": 8,
                "telemetryAuthorizationRevisionBefore": 7,
            }
            receipt = {
                "allowedTransportCredentialIds": sorted([OLD_CREDENTIAL, PENDING]),
                "backlogManifestSha256": request["backlogManifestSha256"],
                "cutJournalMaxId": 1,
                "cutMarkerId": CUT,
                "entries": manifest["entries"],
                "entryCount": 1,
                "expiresAt": "2030-01-02T12:00:01Z",
                "historicalAuthorizationRevision": 7,
                "ingestAuthorizationRevision": 8,
                "installationId": INSTALLATION,
                "lineageId": LINEAGE,
                "notBefore": "2030-01-01T12:00:01Z",
                "receiptNonce": "a" * 64,
                "renewalOperationId": REQUEST,
                "renewalRequestSha256": _b64(hashlib.sha256(raw).digest()),
                "schemaVersion": "one-os-historical-authorization-receipt/v2",
                "totalRequestBytes": len(b'{"durable":"batch"}'),
            }
            if mode == "historical":
                receipt_hash = _b64(hashlib.sha256(canonical_json(receipt)).digest())
                response["historicalAuthorizationReceipt"] = receipt
                response["historicalAuthorizationReceiptSha256"] = receipt_hash
            if self.mismatch:
                response[self.mismatch] = LINEAGE if self.mismatch != "lineageId" else INSTALLATION
            self.start_response = canonical_json(response)
        if self.lose_start and len(self.start_requests) == 1:
            raise ConnectionError("response dropped after Central commit")
        return self.start_response

    def renewal_status_v2(self, _request_id: str, _certificate: str, _key: str) -> bytes:
        assert self.issued_response is not None
        return self.issued_response

    def ack_renewal_v2(self, _request_id: str, raw: bytes, _certificate: str, _key: str) -> bytes:
        self.ack_requests.append(raw)
        if self.ack_response is None:
            ack = json.loads(raw)
            response = {key: value for key, value in ack.items() if key != "signature"}
            response["installationRevisionAfter"] = response["installationRevisionBefore"] + 1
            response["status"] = "acked"
            self.ack_response = canonical_json(response)
        if self.lose_ack and len(self.ack_requests) == 1:
            raise ConnectionError("ack response dropped")
        return self.ack_response

    def cancel_renewal_v2(
        self, _request_id: str, raw: bytes, _certificate: str, _key: str
    ) -> bytes:
        self.cancel_requests.append(raw)
        request = json.loads(raw)
        if self.cancel_response is None:
            self.cancel_response = canonical_json(
                {
                    "backlogManifestSha256": request["backlogManifestSha256"],
                    "cancelRequestId": CANCEL,
                    "cancelRequestSha256": _b64(hashlib.sha256(raw).digest()),
                    "currentCertificateSha256": request["currentCertificateSha256"],
                    "currentCredentialId": OLD_CREDENTIAL,
                    "decidedAt": "2030-01-01T12:00:02Z",
                    "installationId": INSTALLATION,
                    "lineageId": LINEAGE,
                    "protocol": "2.0",
                    "status": "cancelled_no_reservation",
                    "targetRenewalRequestSha256": request["targetRenewalRequestSha256"],
                    "targetRequestId": REQUEST,
                    "telemetryAuthorizationRevision": 7,
                }
            )
        if self.lose_cancel and len(self.cancel_requests) == 1:
            raise ConnectionError("cancel response dropped")
        return self.cancel_response

    def cancel_status_v2(self, _cancel_id: str, _certificate: str, _key: str) -> bytes:
        assert self.cancel_response is not None
        return self.cancel_response


class _ProductRouteCentral(_Central):
    def __init__(self) -> None:
        super().__init__(lose_start=True)
        self.status_paths: list[str] = []

    def _raw_device_request(
        self,
        method: str,
        path: str,
        request_bytes: bytes | None,
        _certificate: str,
        _key: str,
    ) -> bytes:
        assert method == "GET"
        assert request_bytes is None
        self.status_paths.append(path)
        assert self.cancel_response is not None
        return self.cancel_response

    def cancel_status_v2(self, cancel_id: str, certificate: str, key: str) -> bytes:
        return CentralPairingHTTPClient.cancel_status_v2(
            self,
            cancel_id,
            certificate,
            key,  # type: ignore[arg-type]
        )


def _manager(app, store, central) -> TelemetryRenewalManager:
    values = iter((REQUEST, PENDING, CUT, CANCEL))

    def identity_provider():
        with app.state.session() as session:
            identity = session.get(EdgeIdentity, 1)
            certificate, chain = store.read_identity_credential()
            return {
                "status": identity.status,
                "installationId": identity.installation_id,
                "credentialId": identity.credential_id,
                "certificateSha256": identity.certificate_sha256,
                "activeSpkiSha256": identity.active_spki_sha256,
                "certificatePem": certificate + chain,
                "privateKeyPem": store.identity_private_pem(),
            }

    return TelemetryRenewalManager(
        app.state.session,
        store,
        central,
        identity_provider,
        lambda _preimage: b"s" * 64,
        uuid_factory=lambda: next(values),
        nonce_factory=lambda: b"n" * 32,
        clock=lambda: NOW,
    )


def _setup(tmp_path, central, *, backlog: bool = True):
    app = create_app(database_url=f"sqlite:///{tmp_path / 'renewal.db'}", pairing_backend=False)
    store = IdentityStore(tmp_path / "identity")
    _seed(app, store, backlog=backlog)
    return app, store, _manager(app, store, central)


def _method1_ski(key) -> bytes:
    point = key.public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    return hashlib.sha1(point[1:]).digest()  # noqa: S324 - X.509 SKI method 1


def _issue(central: _Central) -> None:
    request = json.loads(central.start_requests[0])
    csr_raw = base64.urlsafe_b64decode(request["csrDer"] + "==")
    csr = x509.load_der_x509_csr(csr_raw)
    root_key = ec.generate_private_key(ec.SECP256R1())
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ONE.OS Draft-4 Test Root")])
    root = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_key.public_key())
        .serial_number(10)
        .not_valid_before(NOW - timedelta(days=2))
        .not_valid_after(NOW + timedelta(days=800))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier(_method1_ski(root_key.public_key())), critical=False
        )
        .sign(root_key, hashes.SHA256())
    )
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, PENDING)]))
        .issuer_name(root.subject)
        .public_key(csr.public_key())
        .serial_number(11)
        .not_valid_before(NOW - timedelta(seconds=1))
        .not_valid_after(NOW - timedelta(seconds=1) + timedelta(days=366))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(True, False, False, False, False, False, False, False, False),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=True)
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.UniformResourceIdentifier(
                        f"urn:one-os:installation:{INSTALLATION}:credential:{PENDING}"
                    )
                ]
            ),
            critical=False,
        )
        .add_extension(x509.SubjectKeyIdentifier(_method1_ski(csr.public_key())), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier(_method1_ski(root_key.public_key()), None, None),
            critical=False,
        )
        .sign(root_key, hashes.SHA256())
    )
    assert central.start_response is not None
    pending = json.loads(central.start_response)
    leaf_der = leaf.public_bytes(serialization.Encoding.DER)
    leaf_spki = leaf.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    issued = pending | {
        "ackExpiresAt": "2030-01-01T12:20:01Z",
        "caChainPem": root.public_bytes(serialization.Encoding.PEM).decode(),
        "certificatePem": leaf.public_bytes(serialization.Encoding.PEM).decode(),
        "newCertificateSha256": _b64(hashlib.sha256(leaf_der).digest()),
        "newCertificateSpkiSha256": _b64(hashlib.sha256(leaf_spki).digest()),
        "status": "issued",
    }
    issued.pop("issuanceExpiresAt")
    central.issued_response = canonical_json(issued)


def test_start_is_dynamic_strict_and_persists_only_public_pending_key_material(tmp_path) -> None:
    central = _Central()
    app, store, manager = _setup(tmp_path, central)
    response = manager.start()
    request = json.loads(central.start_requests[0])
    encoded_csr = request["csrDer"]
    csr = x509.load_der_x509_csr(
        base64.urlsafe_b64decode(encoded_csr + "=" * ((4 - len(encoded_csr) % 4) % 4))
    )
    assert csr.subject == x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, PENDING)])
    assert csr.extensions.get_extension_for_class(
        x509.SubjectAlternativeName
    ).value == x509.SubjectAlternativeName(
        [
            x509.UniformResourceIdentifier(
                f"urn:one-os:installation:{INSTALLATION}:credential:{PENDING}"
            )
        ]
    )
    assert response == central.start_response
    with app.state.session() as session:
        row = session.get(TelemetryRenewalOperation, 1)
        assert row.status == "pending"
        assert row.start_request_bytes == central.start_requests[0]
        assert row.pending_response_bytes == response
        assert row.receipt_bytes == canonical_json(
            json.loads(response)["historicalAuthorizationReceipt"]
        )
        assert b"PRIVATE" not in b"".join(
            value for value in row.__dict__.values() if isinstance(value, bytes)
        )
        assert session.get(TelemetryAuthorityCut, CUT).milestone == "receipt_stored"
    assert b"PRIVATE KEY" in store.renewal_private_pem().encode()


def test_restart_after_start_response_loss_replays_exact_request(tmp_path) -> None:
    central = _Central(lose_start=True)
    app, store, manager = _setup(tmp_path, central)
    with pytest.raises(ConnectionError, match="response dropped"):
        manager.start()
    restarted = _manager(app, store, central)
    assert restarted.start() == central.start_response
    assert central.start_requests[0] == central.start_requests[1]


def test_start_validation_failures_leave_no_renewal_key(tmp_path) -> None:
    central = _Central()
    app, store, manager = _setup(tmp_path, central)
    store.write_identity_credential("not a certificate", "not a certificate")

    with pytest.raises((TelemetryRenewalError, ValueError)):
        manager.start()

    with pytest.raises(UnsafeIdentityStorage):
        store.load_renewal_candidate()
    with app.state.session() as session:
        assert session.get(TelemetryRenewalOperation, 1) is None


def test_clock_and_manifest_failures_leave_no_renewal_key(tmp_path, monkeypatch) -> None:
    central = _Central()
    _app, store, manager = _setup(tmp_path, central)
    manager._clock = lambda: (_ for _ in ()).throw(RuntimeError("clock failed"))
    with pytest.raises(RuntimeError, match="clock failed"):
        manager.start()
    with pytest.raises(UnsafeIdentityStorage):
        store.load_renewal_candidate()

    import one_os_addon.telemetry_renewal as renewal_module

    manager = _manager(_app, store, central)
    manager._clock = lambda: NOW
    monkeypatch.setattr(
        renewal_module,
        "parse_backlog_manifest",
        lambda _value: (_ for _ in ()).throw(ValueError("manifest failed")),
    )
    with pytest.raises(ValueError, match="manifest failed"):
        manager.start()
    with pytest.raises(UnsafeIdentityStorage):
        store.load_renewal_candidate()


def test_failed_prevalidation_does_not_overwrite_existing_renewal_key(tmp_path) -> None:
    central = _Central()
    _app, store, manager = _setup(tmp_path, central)
    original = store.create_renewal_candidate().private_numbers()
    store.write_identity_credential("not a certificate", "not a certificate")

    with pytest.raises((TelemetryRenewalError, ValueError)):
        manager.start()

    assert store.load_renewal_candidate().private_numbers() == original


def test_partial_pending_alias_mismatch_refuses_progression(tmp_path) -> None:
    central = _Central(mismatch="lineageId")
    app, _store, manager = _setup(tmp_path, central)
    with pytest.raises(TelemetryRenewalError, match="pending_response_conflict"):
        manager.start()
    with app.state.session() as session:
        row = session.get(TelemetryRenewalOperation, 1)
        assert row.status == "start_requested"
        assert row.pending_response_bytes is None


def test_cancel_persists_before_http_and_restart_uses_status_response(tmp_path) -> None:
    central = _ProductRouteCentral()
    app, store, manager = _setup(tmp_path, central)
    with pytest.raises(ConnectionError):
        manager.start()
    central.lose_cancel = True
    with pytest.raises(ConnectionError, match="cancel response dropped"):
        manager.cancel()
    restarted = _manager(app, store, central)
    response = restarted.cancel()
    assert response == central.cancel_response
    assert central.status_paths == [f"/api/v1/edge/device/renewal-cancellations/{CANCEL}"]
    with app.state.session() as session:
        row = session.get(TelemetryRenewalOperation, 1)
        assert row.status == "cancelled"
        assert row.cancel_request_bytes == central.cancel_requests[0]
        assert row.cancel_response_bytes == response
        assert session.get(TelemetryAuthorityCut, CUT) is None


def test_issued_drain_signed_ack_response_loss_and_local_promotion_are_restart_safe(
    tmp_path,
) -> None:
    central = _Central()
    app, store, manager = _setup(tmp_path, central)
    manager.start()
    pending_key = store.load_renewal_candidate().public_key()
    _issue(central)

    assert manager.poll() == central.issued_response
    with app.state.session() as session:
        row = session.get(TelemetryRenewalOperation, 1)
        identity = session.get(EdgeIdentity, 1)
        assert row.status == "issued"
        assert row.issued_response_bytes == central.issued_response
        assert identity.credential_id == OLD_CREDENTIAL
        assert session.get(TelemetryAuthorityCut, CUT).milestone == "receipt_stored"

    with pytest.raises(TelemetryRenewalError, match="historical_backlog_not_drained"):
        manager.finalize()
    assert central.ack_requests == []

    with app.state.session() as session:
        batch = session.get(TelemetryBatch, BATCH)
        batch.status = "acked"
        batch.ack_bytes = b"{}"
        batch.ingest_cursor = 1
        batch.acked_at = NOW
        session.commit()

    central.lose_ack = True
    with pytest.raises(ConnectionError, match="ack response dropped"):
        manager.finalize()
    ack = json.loads(central.ack_requests[0])
    raw_signature = base64.urlsafe_b64decode(ack["signature"] + "==")
    r = int.from_bytes(raw_signature[:32], "big")
    s = int.from_bytes(raw_signature[32:], "big")
    assert 1 <= s <= P256_N // 2
    unsigned = dict(ack)
    unsigned.pop("signature")
    from one_os_addon.telemetry_renewal import build_ack_preimage

    pending_key.verify(
        encode_dss_signature(r, s),
        build_ack_preimage(unsigned),
        ec.ECDSA(hashes.SHA256()),
    )
    with app.state.session() as session:
        row = session.get(TelemetryRenewalOperation, 1)
        assert row.status == "ack_requested"
        assert row.ack_request_bytes == central.ack_requests[0]
        assert session.get(EdgeIdentity, 1).credential_id == OLD_CREDENTIAL

    restarted = _manager(app, store, central)
    valid_ack_response = central.ack_response
    wrong_ack = json.loads(valid_ack_response)
    wrong_ack["newCredentialId"] = OLD_CREDENTIAL
    central.ack_response = canonical_json(wrong_ack)
    with pytest.raises(TelemetryRenewalError, match="ack_response_conflict"):
        restarted.finalize()
    with app.state.session() as session:
        assert session.get(EdgeIdentity, 1).credential_id == OLD_CREDENTIAL
        assert session.get(TelemetryRenewalOperation, 1).status == "ack_requested"
    central.ack_response = valid_ack_response
    assert restarted.finalize() == central.ack_response
    assert central.ack_requests[0] == central.ack_requests[1] == central.ack_requests[2]
    with app.state.session() as session:
        row = session.get(TelemetryRenewalOperation, 1)
        identity = session.get(EdgeIdentity, 1)
        cut = session.get(TelemetryAuthorityCut, CUT)
        assert row.status == "terminal"
        assert row.ack_response_bytes == central.ack_response
        assert identity.credential_id == PENDING
        assert identity.installation_revision == 6
        assert identity.telemetry_authorization_revision == 8
        assert cut.milestone == "terminal"
    assert store.load_identity().public_key().public_numbers() == pending_key.public_numbers()


def test_terminalize_cannot_race_between_filesystem_and_database_promotion(
    tmp_path, monkeypatch
) -> None:
    central = _Central()
    app, store, manager = _setup(tmp_path, central, backlog=False)
    manager.start()
    _issue(central)
    manager.poll()

    original_promote = store.promote_renewal
    import one_os_addon.telemetry_renewal as renewal_module

    original_begin = renewal_module._begin
    terminalizer_entered = threading.Event()
    terminalizer_done = threading.Event()
    terminalizer_thread: list[threading.Thread] = []

    def observed_begin(session):
        if threading.current_thread().name == "renewal-terminalizer":
            terminalizer_entered.set()
        return original_begin(session)

    def racing_promote():
        original_promote()

        def terminalize():
            try:
                manager.terminalize("repair")
            finally:
                terminalizer_done.set()

        thread = threading.Thread(target=terminalize, name="renewal-terminalizer")
        terminalizer_thread.append(thread)
        thread.start()
        assert terminalizer_entered.wait(2)
        terminalizer_done.wait(0.2)

    monkeypatch.setattr(renewal_module, "_begin", observed_begin)
    monkeypatch.setattr(store, "promote_renewal", racing_promote)
    manager.finalize()
    assert terminalizer_done.wait(2)
    terminalizer_thread[0].join(timeout=2)

    with app.state.session() as session:
        assert session.get(EdgeIdentity, 1).credential_id == PENDING
        assert session.get(TelemetryRenewalOperation, 1).status == "terminal"
        assert session.get(TelemetryAuthorityCut, CUT).milestone == "terminal"


def test_wrong_issued_certificate_fails_before_mutation(tmp_path) -> None:
    central = _Central()
    app, store, manager = _setup(tmp_path, central)
    manager.start()
    _issue(central)
    issued = json.loads(central.issued_response)
    issued["newCredentialId"] = OLD_CREDENTIAL
    central.issued_response = canonical_json(issued)
    with pytest.raises(TelemetryRenewalError, match="issued_response_conflict"):
        manager.poll()
    with app.state.session() as session:
        assert session.get(TelemetryRenewalOperation, 1).status == "pending"
    with pytest.raises(UnsafeIdentityStorage):
        store.read_renewal_credential()


def test_wrong_historical_receipt_fails_before_receipt_storage(tmp_path) -> None:
    central = _Central()
    app, _store, manager = _setup(tmp_path, central)
    with pytest.raises(ConnectionError):
        central.lose_start = True
        manager.start()
    assert central.start_response is not None
    response = json.loads(central.start_response)
    response["historicalAuthorizationReceipt"]["entries"][0]["requestSha256"] = "B" * 43
    receipt_bytes = canonical_json(response["historicalAuthorizationReceipt"])
    response["historicalAuthorizationReceiptSha256"] = _b64(hashlib.sha256(receipt_bytes).digest())
    central.start_response = canonical_json(response)
    central.lose_start = False
    with pytest.raises(TelemetryRenewalError, match="pending_response_conflict"):
        manager.start()
    with app.state.session() as session:
        row = session.get(TelemetryRenewalOperation, 1)
        assert row.status == "start_requested"
        assert row.receipt_bytes is None
        assert session.get(TelemetryAuthorityCut, CUT).milestone == "cut_open"


def test_repair_terminalizes_local_operation_and_retains_cut_as_fail_closed_quarantine(
    tmp_path,
) -> None:
    central = _Central()
    app, store, manager = _setup(tmp_path, central)
    manager.start()
    manager.terminalize("repair")
    restarted = _manager(app, store, central)
    restarted.terminalize("repair")
    with app.state.session() as session:
        assert session.get(TelemetryRenewalOperation, 1).status == "quarantined"
        cut = session.get(TelemetryAuthorityCut, CUT)
        assert cut.milestone == "terminal"
        terminal_at = cut.terminal_at
        if terminal_at.tzinfo is None:
            terminal_at = terminal_at.replace(tzinfo=UTC)
        assert terminal_at == NOW
        batch = session.get(TelemetryBatch, BATCH)
        assert batch.status == "quarantined"
        assert batch.terminal_reason == "authority_terminalized"
        assert session.get(EdgeIdentity, 1).credential_id == OLD_CREDENTIAL
    with pytest.raises(UnsafeIdentityStorage):
        store.renewal_private_pem()
    with pytest.raises(TelemetryRenewalError, match="renewal_operation_conflict"):
        manager.finalize()


def test_zero_backlog_start_replay_restart_and_finalize_use_none_without_receipt(tmp_path) -> None:
    central = _Central(lose_start=True)
    app, store, manager = _setup(tmp_path, central, backlog=False)
    with pytest.raises(ConnectionError, match="response dropped"):
        manager.start()
    request = json.loads(central.start_requests[0])
    assert request["backlogMode"] == "none"
    assert request["backlogManifest"] == {
        "batchAuthorizationRevision": 0,
        "createdAt": "2030-01-01T12:00:01Z",
        "cutJournalMaxId": 0,
        "cutMarkerId": CUT,
        "entries": [],
        "entryCount": 0,
        "firstJournalId": 0,
        "installationId": INSTALLATION,
        "lastJournalId": 0,
        "lineageId": LINEAGE,
        "renewalOperationId": REQUEST,
        "schemaVersion": "one-os-telemetry-backlog-manifest/v2",
        "totalRequestBytes": 0,
    }

    central.lose_start = False
    restarted = _manager(app, store, central)
    pending = json.loads(restarted.start())
    assert central.start_requests[0] == central.start_requests[1]
    assert pending["backlogMode"] == "none"
    assert "historicalAuthorizationReceipt" not in pending
    assert "historicalAuthorizationReceiptSha256" not in pending
    with app.state.session() as session:
        row = session.get(TelemetryRenewalOperation, 1)
        cut = session.get(TelemetryAuthorityCut, CUT)
        assert row.cut_journal_max_id == 0
        assert row.receipt_bytes is None
        assert cut.backlog_mode == "none"
        assert cut.cut_journal_max_id == 0
        assert cut.receipt_bytes is None
        assert cut.milestone == "receipt_stored"

    _issue(central)
    issued = json.loads(restarted.poll())
    assert issued["backlogMode"] == "none"
    assert "historicalAuthorizationReceipt" not in issued
    assert "historicalAuthorizationReceiptSha256" not in issued
    response = json.loads(restarted.finalize())
    assert response["backlogMode"] == "none"
    assert "historicalAuthorizationReceiptSha256" not in response
    with app.state.session() as session:
        assert session.get(TelemetryRenewalOperation, 1).status == "terminal"
        cut = session.get(TelemetryAuthorityCut, CUT)
        assert cut.milestone == "terminal"
        assert cut.receipt_bytes is None
        assert cut.backlog_drained_at is None


@pytest.mark.parametrize("installation_revision", [2**63 - 1])
def test_installation_revision_saturation_refuses_before_any_mutation(
    tmp_path, installation_revision
) -> None:
    central = _Central()
    app, store, manager = _setup(tmp_path, central, backlog=False)
    with app.state.session() as session:
        session.get(EdgeIdentity, 1).installation_revision = installation_revision
        session.commit()

    with pytest.raises(TelemetryRenewalError, match="identity_not_eligible"):
        manager.start()

    assert central.start_requests == []
    with app.state.session() as session:
        assert session.get(TelemetryRenewalOperation, 1) is None
        assert session.query(TelemetryAuthorityCut).count() == 0
    with pytest.raises(UnsafeIdentityStorage):
        store.load_renewal_candidate()


def test_installation_revision_max_minus_one_is_renewable(tmp_path) -> None:
    central = _Central()
    app, _store, manager = _setup(tmp_path, central, backlog=False)
    with app.state.session() as session:
        session.get(EdgeIdentity, 1).installation_revision = 2**63 - 2
        session.commit()

    manager.start()
    assert json.loads(central.start_requests[0])["installationRevisionBefore"] == 2**63 - 2
