from __future__ import annotations

import base64
import hashlib
import json
import ssl
import threading
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from fastapi.testclient import TestClient
from one_os_addon.app import create_app
from one_os_addon.central_pairing_client import PairingRequestGate
from one_os_addon.ha.fake import FakeHomeAssistant
from one_os_addon.models import Audit, CentralDestination, ConfigurationSnapshot, EdgeIdentity
from sqlalchemy import select


def _b64u(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _private_pem(key) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _ca(key) -> x509.Certificate:
    moment = datetime.now(UTC)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Phase 2B lifecycle CA")])
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(moment - timedelta(minutes=1))
        .not_valid_after(moment + timedelta(days=90))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )


def _server_certificate(key, ca, ca_key) -> x509.Certificate:
    moment = datetime.now(UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
        .issuer_name(ca.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(moment - timedelta(minutes=1))
        .not_valid_after(moment + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=True)
        .add_extension(
            x509.KeyUsage(True, False, False, False, False, False, False, False, False),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=True)
        .sign(ca_key, hashes.SHA256())
    )


class _CentralState:
    def __init__(self, ca: x509.Certificate, ca_key) -> None:
        self.ca = ca
        self.ca_key = ca_key
        self.installation_id: str | None = None
        self.installation_revision = 11
        self.session_id: str | None = None
        self.bootstrap = _b64u(b"b" * 32)
        self.csr: x509.CertificateSigningRequest | None = None
        self.claimable = False
        self.issued = False
        self.revoked = False
        self.credential_id: str | None = None
        self.certificate_sha256: str | None = None
        self.renewal: dict | None = None
        self.events: list[tuple[str, bool]] = []
        self.snapshot: dict | None = None

    def issue(self, csr_der: str, days: int) -> tuple[str, str, str]:
        csr = x509.load_der_x509_csr(base64.urlsafe_b64decode(csr_der + "=" * (-len(csr_der) % 4)))
        moment = datetime.now(UTC)
        uri = f"spiffe://one-os/tenants/tenant-1/sites/site-1/installations/{self.installation_id}"
        leaf = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([]))
            .issuer_name(self.ca.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(moment - timedelta(minutes=1))
            .not_valid_after(moment + timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(True, False, False, False, False, False, False, False, False),
                critical=True,
            )
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=True)
            .add_extension(
                x509.SubjectAlternativeName([x509.UniformResourceIdentifier(uri)]), critical=True
            )
            .sign(self.ca_key, hashes.SHA256())
        )
        pem = leaf.public_bytes(serialization.Encoding.PEM).decode("ascii")
        chain = self.ca.public_bytes(serialization.Encoding.PEM).decode("ascii")
        digest = _b64u(hashlib.sha256(leaf.public_bytes(serialization.Encoding.DER)).digest())
        return pem, chain, digest


class _LifecycleServer(ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        del request, client_address


@contextmanager
def _central_server(tmp_path: Path):
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = _ca(ca_key)
    server_key = ec.generate_private_key(ec.SECP256R1())
    server_cert = _server_certificate(server_key, ca, ca_key)
    state = _CentralState(ca, ca_key)

    class Handler(BaseHTTPRequestHandler):
        def _body(self) -> dict:
            length = int(self.headers.get("Content-Length", "0"))
            return json.loads(self.rfile.read(length) or b"{}")

        def _send(self, status: int, body: dict, *, no_store: bool = False) -> None:
            payload = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            if no_store:
                self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(payload)

        def _peer(self) -> bool:
            return bool(self.connection.getpeercert(binary_form=True))

        def _require_device(self) -> bool:
            peer = self._peer()
            state.events.append((self.path, peer))
            if state.revoked or not peer:
                self._send(401, {"status": "revoked"})
                return False
            return True

        def do_GET(self):
            if self.path == "/api/v1/edge/discovery":
                self._send(
                    200,
                    {
                        "schemaVersion": "1.0",
                        "service": "one-os-central",
                        "pairingSupported": True,
                        "phase": "2B.3-selected-configuration-sync",
                    },
                )
                return
            if self.path.endswith("/result"):
                state.events.append((self.path, self._peer()))
                if state.claimable and not state.issued:
                    self._send(
                        200,
                        {
                            "sessionId": state.session_id,
                            "status": "claimed",
                            "tenantId": "tenant-1",
                            "siteId": "site-1",
                            "claimNonce": _b64u(b"n" * 32),
                            "claimExpiresAt": int(datetime.now(UTC).timestamp()) + 120,
                            "claimRevision": 7,
                            "installationRevision": state.installation_revision,
                            "sessionRevision": 3,
                        },
                        no_store=True,
                    )
                    return
                pem, chain, digest = state.issue(
                    _b64u(state.csr.public_bytes(serialization.Encoding.DER)), 5
                )
                state.credential_id = str(uuid4())
                state.certificate_sha256 = digest
                self._send(
                    200,
                    {
                        "sessionId": state.session_id,
                        "installationId": state.installation_id,
                        "status": "issued",
                        "claimRevision": 7,
                        "installationRevision": state.installation_revision,
                        "credentialId": state.credential_id,
                        "certificatePem": pem,
                        "certificateSha256": digest,
                        "caChainPem": chain,
                        "ackExpiresAt": (datetime.now(UTC) + timedelta(minutes=5)).isoformat(),
                        "sessionRevision": 5,
                    },
                    no_store=True,
                )
                return
            if self.path == "/api/v1/edge/device/status":
                if not self._require_device():
                    return
                self._send(
                    200,
                    {
                        "installationId": state.installation_id,
                        "status": "paired",
                        "installationRevision": state.installation_revision,
                        "credentialId": state.credential_id,
                        "certificateSha256": state.certificate_sha256,
                    },
                    no_store=True,
                )
                return
            if self.path.startswith("/api/v1/edge/device/renewals/"):
                if not self._require_device():
                    return
                renewal = state.renewal
                pem, chain, digest = state.issue(renewal["csrDer"], 30)
                renewal.update(
                    newCredentialId=str(uuid4()),
                    newCertificateSha256=digest,
                    certificatePem=pem,
                    caChainPem=chain,
                )
                self._send(
                    200,
                    {
                        "requestId": renewal["requestId"],
                        "installationId": state.installation_id,
                        "status": "issued",
                        "installationRevision": state.installation_revision,
                        "oldCredentialId": state.credential_id,
                        "oldCertificateSha256": state.certificate_sha256,
                        "newCredentialId": renewal["newCredentialId"],
                        "newCertificateSha256": digest,
                        "certificatePem": pem,
                        "caChainPem": chain,
                        "ackExpiresAt": (datetime.now(UTC) + timedelta(minutes=5))
                        .replace(microsecond=0)
                        .isoformat(),
                    },
                    no_store=True,
                )
                return
            self._send(404, {"status": "missing"})

        def do_POST(self):
            body = self._body()
            if self.path == "/api/v1/edge/pairing/sessions":
                state.events.append((self.path, self._peer()))
                state.installation_id = body["installationId"]
                state.session_id = str(uuid4())
                state.csr = x509.load_der_x509_csr(
                    base64.urlsafe_b64decode(body["csrDer"] + "=" * (-len(body["csrDer"]) % 4))
                )
                state.claimable = False
                state.issued = False
                self._send(
                    201,
                    {
                        "sessionId": state.session_id,
                        "serverNonce": _b64u(b"s" * 32),
                        "bootstrapToken": state.bootstrap,
                        "tokenGeneration": 1,
                        "registrationExpiresAt": int(datetime.now(UTC).timestamp()) + 120,
                        "sessionRevision": 0,
                    },
                )
                return
            if self.path.endswith("/proof"):
                state.events.append((self.path, self._peer()))
                self._send(
                    200,
                    {
                        "sessionId": state.session_id,
                        "status": "pop_verified",
                        "codeExpiresAt": (datetime.now(UTC) + timedelta(minutes=5)).isoformat(),
                        "sessionRevision": 2,
                    },
                )
                return
            if self.path.endswith("/claim-proof"):
                state.events.append((self.path, self._peer()))
                state.issued = True
                self._send(
                    200,
                    {
                        "sessionId": state.session_id,
                        "status": "claim_proved",
                        "claimRevision": 7,
                        "installationRevision": state.installation_revision,
                        "issuanceExpiresAt": (datetime.now(UTC) + timedelta(minutes=5)).isoformat(),
                        "sessionRevision": 4,
                    },
                )
                return
            if self.path == "/api/v1/edge/device/ack":
                if not self._require_device():
                    return
                self._send(
                    200,
                    {
                        "sessionId": body["sessionId"],
                        "installationId": body["installationId"],
                        "status": "acked",
                        "installationRevision": body["installationRevision"],
                        "credentialId": body["credentialId"],
                        "certificateSha256": body["certificateSha256"],
                    },
                )
                return
            if self.path == "/api/v1/edge/device/configuration-snapshots":
                if not self._require_device():
                    return
                state.snapshot = body
                self._send(
                    201,
                    {
                        "status": "accepted",
                        "snapshotId": body["snapshotId"],
                        "installationId": body["installationId"],
                        "configVersion": body["configVersion"],
                        "projectionSha256": body["projectionSha256"],
                        "acceptedAt": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                        "activePointCount": len(body["points"]),
                    },
                    no_store=True,
                )
                return
            if self.path == "/api/v1/edge/device/renewal":
                if not self._require_device():
                    return
                state.renewal = body
                self._send(
                    202,
                    {
                        "requestId": body["requestId"],
                        "installationId": state.installation_id,
                        "status": "pending",
                        "installationRevision": state.installation_revision,
                        "issuanceExpiresAt": (datetime.now(UTC) + timedelta(minutes=5)).isoformat(),
                    },
                    no_store=True,
                )
                return
            if self.path.endswith("/ack") and "/renewals/" in self.path:
                if not self._require_device():
                    return
                renewal = state.renewal
                old_id, old_hash = state.credential_id, state.certificate_sha256
                state.credential_id = renewal["newCredentialId"]
                state.certificate_sha256 = renewal["newCertificateSha256"]
                state.installation_revision += 1
                self._send(
                    200,
                    {
                        "requestId": body["requestId"],
                        "installationId": state.installation_id,
                        "status": "acked",
                        "installationRevision": state.installation_revision,
                        "oldCredentialId": old_id,
                        "oldCertificateSha256": old_hash,
                        "newCredentialId": state.credential_id,
                        "newCertificateSha256": state.certificate_sha256,
                    },
                    no_store=True,
                )
                return
            self._send(404, {"status": "missing"})

        def log_message(self, _format, *_args):
            pass

    key_path = tmp_path / "central-key.pem"
    cert_path = tmp_path / "central-cert.pem"
    ca_path = tmp_path / "client-ca.pem"
    key_path.write_bytes(_private_pem(server_key))
    cert_path.write_bytes(server_cert.public_bytes(serialization.Encoding.PEM))
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    server = _LifecycleServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    context.verify_mode = ssl.CERT_OPTIONAL
    context.load_verify_locations(cafile=ca_path)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, name="phase2b-fake-central", daemon=True)
    thread.start()
    origin = f"https://localhost:{server.server_port}"
    fingerprint = hashlib.sha256(server_cert.public_bytes(serialization.Encoding.DER)).hexdigest()
    try:
        yield state, origin, fingerprint
    finally:
        server.shutdown()
        thread.join(timeout=3)
        server.server_close()


def _auth(client: TestClient) -> dict[str, str]:
    base = {"X-Remote-User-Id": "admin-1"}
    token = client.get("/api/v1/session", headers=base).json()["csrfToken"]
    return base | {
        "Origin": "http://testserver",
        "Sec-Fetch-Site": "same-origin",
        "Content-Type": "application/json",
        "X-CSRF-Token": token,
    }


def test_real_phase2b_route_tls_pairing_snapshot_renew_revoke_repair_lifecycle(tmp_path) -> None:
    with _central_server(tmp_path) as (central, origin, fingerprint):
        app = create_app(
            database_url=f"sqlite:///{tmp_path / 'edge.db'}",
            ha_client=FakeHomeAssistant.standard(),
            ingress_proxies={"testclient"},
            allowed_origins={"http://testserver"},
            identity_dir=tmp_path / "identity",
            start_pairing_worker=False,
        )
        app.state.pairing.central._gate = PairingRequestGate(interval=0.0)
        with TestClient(app) as client:
            auth = _auth(client)
            configured = client.put(
                "/api/v1/central-destination",
                headers=auth,
                json={"revision": 0, "origin": origin, "certificateFingerprint": fingerprint},
            )
            assert configured.status_code == 200
            discovery = client.post("/api/v1/central-destination/test", headers=auth, json={})
            assert discovery.status_code == 200
            assert discovery.json()["phase"] == "2B.3-selected-configuration-sync"

            started = client.post("/api/v1/pairing/start", headers=auth, json={})
            assert started.status_code == 200
            assert started.json()["status"] == "pop_verified"
            assert client.get("/api/v1/pairing/code", headers=auth).status_code == 200
            central.claimable = True
            assert (
                client.post("/api/v1/pairing/refresh", headers=auth, json={}).json()["status"]
                == "claim_proved"
            )
            paired = client.post("/api/v1/pairing/refresh", headers=auth, json={})
            assert paired.status_code == 200
            assert paired.json()["status"] == "paired"

            assert app.state.configuration_sync.run_once() == "acked"
            assert central.snapshot is not None
            app.state.pairing.maintain_device()
            app.state.pairing.maintain_device()
            app.state.pairing.maintain_device()
            renewed = app.state.pairing.status()
            assert renewed["status"] == "paired"
            assert renewed["installationRevision"] == 12

            central.revoked = True
            try:
                app.state.pairing.maintain_device()
            except Exception as error:
                assert str(error) == "device_revoked"
            else:
                raise AssertionError("revocation must fail closed")
            assert app.state.pairing.status()["status"] == "revoked"

            central.revoked = False
            repaired = client.post(
                "/api/v1/pairing/rotate-key", headers=auth, json={"confirmed": True}
            )
            assert repaired.status_code == 200
            assert repaired.json()["status"] == "pop_verified"
            central.claimable = True
            client.post("/api/v1/pairing/refresh", headers=auth, json={})
            repaired = client.post("/api/v1/pairing/refresh", headers=auth, json={})
            assert repaired.status_code == 200
            assert repaired.json()["status"] == "paired"

        with app.state.session() as session:
            assert session.get(CentralDestination, 1) is not None
            assert session.get(EdgeIdentity, 1).status == "paired"
            assert session.scalars(select(ConfigurationSnapshot)).one().status == "acked"
            actions = {row.action for row in session.scalars(select(Audit)).all()}
            assert "pairing.initial.start" in actions
            assert "pairing.renewal" in actions
            assert "pairing.rotate" in actions
            assert "configuration_snapshot.ack" in actions
        assert all(peer for path, peer in central.events if path.startswith("/api/v1/edge/device/"))
        app.state.engine.dispose()
