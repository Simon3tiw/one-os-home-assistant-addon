from __future__ import annotations

import hashlib
import json
import ssl
import threading
import time
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from uuid import uuid4

import one_os_addon.central_pairing_client as pairing_client_module
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from one_os_addon.central_pairing_client import CentralPairingHTTPClient, CentralProtocolError


def _certificate(
    key,
    subject: str,
    *,
    issuer_cert=None,
    issuer_key=None,
    san_dns: str | None = None,
    client=False,
):
    now = datetime.now(UTC)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)])
    issuer_cert = issuer_cert or None
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer_cert.subject if issuer_cert else name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(
            x509.BasicConstraints(ca=issuer_cert is None, path_length=None), critical=True
        )
    )
    if san_dns:
        certificate = certificate.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(san_dns)]), critical=True
        )
    if client:
        certificate = certificate.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=True
        )
    return certificate.sign(issuer_key or key, hashes.SHA256())


def _pem_private(key) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")


class PairingHandler(BaseHTTPRequestHandler):
    body = b"{}"
    status = 200
    content_type = "application/json"
    duplicate_length = False
    transfer_encoding: str | None = None
    cache_control: str | None = None
    duplicate_content_type = False
    duplicate_cache_control = False
    delay = 0.0
    header_drip_delay = 0.0
    body_drip_delay = 0.0
    requests: list[tuple[str, dict[str, str], bytes, bool]] = []

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        request_body = self.rfile.read(length)
        peer = self.connection.getpeercert(binary_form=True)
        type(self).requests.append((self.path, dict(self.headers), request_body, bool(peer)))
        if type(self).header_drip_delay:
            self.wfile.write(f"HTTP/1.1 {type(self).status} OK\r\n".encode("ascii"))
            self.wfile.flush()
            for header in (
                f"Content-Type: {type(self).content_type}\r\n",
                f"Content-Length: {len(type(self).body)}\r\n",
                "\r\n",
            ):
                time.sleep(type(self).header_drip_delay)
                self.wfile.write(header.encode("ascii"))
                self.wfile.flush()
            return
        self.send_response(type(self).status)
        content_type = type(self).content_type
        if content_type is not None:
            self.send_header("Content-Type", content_type)
            if type(self).duplicate_content_type:
                self.send_header("Content-Type", content_type)
        if type(self).cache_control:
            self.send_header("Cache-Control", type(self).cache_control)
            if type(self).duplicate_cache_control:
                self.send_header("Cache-Control", type(self).cache_control)
        if type(self).transfer_encoding:
            self.send_header("Transfer-Encoding", type(self).transfer_encoding)
        else:
            self.send_header("Content-Length", str(len(type(self).body)))
            if type(self).duplicate_length:
                self.send_header("Content-Length", str(len(type(self).body)))
        self.end_headers()
        if type(self).delay:
            time.sleep(type(self).delay)
        if type(self).body_drip_delay:
            for byte in type(self).body:
                self.wfile.write(bytes([byte]))
                self.wfile.flush()
                time.sleep(type(self).body_drip_delay)
        else:
            self.wfile.write(type(self).body)

    def do_GET(self):
        self.do_POST()

    def log_message(self, _format, *_args):
        pass


class QuietServer(ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        del request, client_address


@pytest.fixture
def pairing_tls_server(tmp_path: Path):
    server_key = ec.generate_private_key(ec.SECP256R1())
    server_cert = _certificate(server_key, "central", san_dns="localhost")
    client_ca_key = ec.generate_private_key(ec.SECP256R1())
    client_ca = _certificate(client_ca_key, "client-ca")
    client_key = ec.generate_private_key(ec.SECP256R1())
    client_cert = _certificate(
        client_key,
        "edge",
        issuer_cert=client_ca,
        issuer_key=client_ca_key,
        client=True,
    )
    server_key_path = tmp_path / "server-key.pem"
    server_cert_path = tmp_path / "server-cert.pem"
    client_ca_path = tmp_path / "client-ca.pem"
    server_key_path.write_text(_pem_private(server_key))
    server_cert_path.write_bytes(server_cert.public_bytes(serialization.Encoding.PEM))
    client_ca_path.write_bytes(client_ca.public_bytes(serialization.Encoding.PEM))
    PairingHandler.requests = []
    PairingHandler.status = 200
    PairingHandler.content_type = "application/json"
    PairingHandler.duplicate_length = False
    PairingHandler.transfer_encoding = None
    PairingHandler.cache_control = None
    PairingHandler.duplicate_content_type = False
    PairingHandler.duplicate_cache_control = False
    PairingHandler.delay = 0
    PairingHandler.header_drip_delay = 0
    PairingHandler.body_drip_delay = 0
    server = QuietServer(("127.0.0.1", 0), PairingHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(server_cert_path, server_key_path)
    context.verify_mode = ssl.CERT_OPTIONAL
    context.load_verify_locations(cafile=client_ca_path)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    fingerprint = hashlib.sha256(server_cert.public_bytes(serialization.Encoding.DER)).hexdigest()
    try:
        yield (
            f"https://localhost:{server.server_port}",
            fingerprint,
            client_cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
            _pem_private(client_key),
        )
    finally:
        server.shutdown()
        thread.join()
        server.server_close()


def _registration_response() -> dict:
    return {
        "sessionId": str(uuid4()),
        "sessionRevision": 1,
        "serverNonce": "cw" + "A" * 41,
        "bootstrapToken": "Yg" + "A" * 41,
        "tokenGeneration": 1,
        "registrationExpiresAt": "2026-08-07T12:00:00Z",
    }


def test_real_client_uses_fixed_path_host_sni_pin_strict_json_and_no_redirect(
    pairing_tls_server,
) -> None:
    origin, fingerprint, _cert, _key = pairing_tls_server
    PairingHandler.status = 201
    PairingHandler.body = json.dumps(_registration_response()).encode()
    client = CentralPairingHTTPClient(lambda: (origin, fingerprint), timeout=2)
    body = {"protocol": "1.0", "registrationRequestId": str(uuid4())}

    assert client.register(body)["tokenGeneration"] == 1
    path, headers, wire_body, had_client_cert = PairingHandler.requests[-1]
    assert path == "/api/v1/edge/pairing/sessions"
    assert headers["Host"] == f"localhost:{origin.rsplit(':', 1)[1]}"
    assert headers["Content-Type"] == "application/json"
    assert json.loads(wire_body) == body
    assert had_client_cert is False

    PairingHandler.status = 200
    with pytest.raises(CentralProtocolError, match="protocol_error"):
        client.register(body)

    PairingHandler.status = 302
    PairingHandler.body = b"{}"
    with pytest.raises(CentralProtocolError, match="protocol_error"):
        client.register(body)
    assert len(PairingHandler.requests) == 3


def test_real_client_result_rejects_non_contract_legacy_shape(pairing_tls_server) -> None:
    origin, fingerprint, _certificate_pem, _private_key = pairing_tls_server
    session_id = str(uuid4())
    bootstrap = "bootstrap-secret"
    claimed = {
        "sessionId": session_id,
        "sessionRevision": 2,
        "status": "claimed",
        "tenantId": "tenant-a",
        "siteId": "site-a",
        "claimNonce": "A" * 43,
        "claimExpiresAt": "2026-08-07T12:05:00Z",
        "claimRevision": 1,
        "installationRevision": 1,
    }
    PairingHandler.body = json.dumps(claimed, separators=(",", ":")).encode()
    PairingHandler.cache_control = "no-store"
    client = CentralPairingHTTPClient(lambda: (origin, fingerprint), timeout=2)

    assert client.result(session_id, bootstrap) == claimed

    PairingHandler.body = json.dumps({"sessionId": session_id, "status": "pop_verified"}).encode()
    with pytest.raises(CentralProtocolError, match="protocol_error"):
        client.result(session_id, bootstrap)


@pytest.mark.parametrize(
    ("content_type", "duplicate_content_type", "cache_control", "duplicate_cache_control"),
    [
        (None, False, "no-store", False),
        ("application/json", True, "no-store", False),
        ("application/json; charset=utf-8", False, "no-store", False),
        ("text/json", False, "no-store", False),
        ("application/json", False, None, False),
        ("application/json", False, "private", False),
        ("application/json", False, "no-store", True),
    ],
)
def test_issued_result_get_requires_exact_json_and_one_no_store(
    pairing_tls_server,
    content_type,
    duplicate_content_type,
    cache_control,
    duplicate_cache_control,
) -> None:
    origin, fingerprint, _certificate_pem, _private_key = pairing_tls_server
    session_id = str(uuid4())
    PairingHandler.body = json.dumps(
        {
            "sessionId": session_id,
            "installationId": str(uuid4()),
            "sessionRevision": 5,
            "status": "issued",
            "claimRevision": 1,
            "installationRevision": 1,
            "credentialId": str(uuid4()),
            "certificatePem": "certificate",
            "certificateSha256": "A" * 43,
            "caChainPem": "chain",
            "ackExpiresAt": "2026-08-07T12:05:00Z",
        },
        separators=(",", ":"),
    ).encode()
    PairingHandler.content_type = content_type
    PairingHandler.duplicate_content_type = duplicate_content_type
    PairingHandler.cache_control = cache_control
    PairingHandler.duplicate_cache_control = duplicate_cache_control
    client = CentralPairingHTTPClient(lambda: (origin, fingerprint), timeout=2)

    with pytest.raises(CentralProtocolError, match="protocol_error"):
        client.result(session_id, "bootstrap")


def test_issued_result_get_accepts_exact_json_and_one_no_store(pairing_tls_server) -> None:
    origin, fingerprint, _certificate_pem, _private_key = pairing_tls_server
    session_id = str(uuid4())
    result = {"sessionId": session_id, "sessionRevision": 2, "status": "pop_verified"}
    PairingHandler.body = json.dumps(result, separators=(",", ":")).encode()
    PairingHandler.cache_control = "no-store"
    client = CentralPairingHTTPClient(lambda: (origin, fingerprint), timeout=2)

    assert client.result(session_id, "bootstrap") == result


def test_real_client_claim_proof_requires_the_exact_central_response(pairing_tls_server) -> None:
    origin, fingerprint, _certificate_pem, _private_key = pairing_tls_server
    session_id = str(uuid4())
    bootstrap = "bootstrap-secret"
    response = {
        "sessionId": session_id,
        "sessionRevision": 3,
        "status": "claim_proved",
        "claimRevision": 1,
        "installationRevision": 1,
        "issuanceExpiresAt": "2026-08-07T12:05:00Z",
    }
    PairingHandler.body = json.dumps(response, separators=(",", ":")).encode()
    client = CentralPairingHTTPClient(lambda: (origin, fingerprint), timeout=2)

    assert client.claim_proof(session_id, bootstrap, {"claimRevision": 1}) == response
    path, headers, _wire_body, had_client_cert = PairingHandler.requests[-1]
    assert path == f"/api/v1/edge/pairing/sessions/{session_id}/claim-proof"
    assert headers["Authorization"] == f"PairingBootstrap {bootstrap}"
    assert had_client_cert is False

    PairingHandler.body = json.dumps(response | {"unexpected": True}).encode()
    with pytest.raises(CentralProtocolError, match="protocol_error"):
        client.claim_proof(session_id, bootstrap, {"claimRevision": 1})


def test_real_client_ack_presents_candidate_mtls_and_bootstrap_is_not_logged(
    pairing_tls_server, caplog
) -> None:
    origin, fingerprint, certificate, private_key = pairing_tls_server
    session_id = str(uuid4())
    installation_id = str(uuid4())
    credential_id = str(uuid4())
    certificate_sha256 = "A" * 43
    PairingHandler.body = json.dumps(
        {
            "sessionId": session_id,
            "installationId": installation_id,
            "status": "acked",
            "installationRevision": 2,
            "credentialId": credential_id,
            "certificateSha256": certificate_sha256,
        }
    ).encode()
    client = CentralPairingHTTPClient(lambda: (origin, fingerprint), timeout=2)
    bootstrap = "secret-bootstrap-never-log"

    response = client.ack({"credentialId": credential_id}, certificate, private_key, bootstrap)

    assert response["status"] == "acked"
    path, headers, _body, had_client_cert = PairingHandler.requests[-1]
    assert path == "/api/v1/edge/device/ack"
    assert had_client_cert is True
    assert headers["Authorization"] == f"PairingBootstrap {bootstrap}"
    assert bootstrap not in caplog.text

    PairingHandler.body = json.dumps({"status": "acked", "credentialId": credential_id}).encode()
    with pytest.raises(CentralProtocolError, match="protocol_error"):
        client.ack({"credentialId": credential_id}, certificate, private_key, bootstrap)


def test_wrong_pin_never_loads_or_offers_client_identity(pairing_tls_server, monkeypatch) -> None:
    origin, _fingerprint, certificate, private_key = pairing_tls_server
    loaded_chains = 0
    original = pairing_client_module._loaded_client_chain

    def counted(context, material):
        nonlocal loaded_chains
        if material is not None:
            loaded_chains += 1
        return original(context, material)

    monkeypatch.setattr(pairing_client_module, "_loaded_client_chain", counted)
    client = CentralPairingHTTPClient(lambda: (origin, "00" * 32), timeout=2)

    with pytest.raises(CentralProtocolError, match="trust_error"):
        client.device_status(certificate, private_key)

    assert loaded_chains == 0


def test_real_client_rejects_pin_san_rebinding_framing_oversize_slow_and_unreachable(
    pairing_tls_server, monkeypatch
) -> None:
    origin, fingerprint, _certificate_pem, _private_key = pairing_tls_server
    PairingHandler.status = 201
    PairingHandler.body = json.dumps(_registration_response()).encode()
    client = CentralPairingHTTPClient(lambda: (origin, fingerprint), timeout=0.1, max_body=1024)
    body = {"protocol": "1.0"}

    with pytest.raises(CentralProtocolError, match="trust_error"):
        CentralPairingHTTPClient(lambda: (origin, "00" * 32), timeout=1).register(body)

    real_resolve = pairing_client_module._resolve_once_hard
    calls = 0

    def one_dns_set(host, port, deadline):
        nonlocal calls
        calls += 1
        return real_resolve(host, port, deadline)

    monkeypatch.setattr(pairing_client_module, "_resolve_once_hard", one_dns_set)
    assert client.register(body)["tokenGeneration"] == 1
    assert calls == 1

    PairingHandler.duplicate_length = True
    with pytest.raises(CentralProtocolError, match="protocol_error"):
        client.register(body)
    PairingHandler.duplicate_length = False
    PairingHandler.transfer_encoding = "chunked"
    with pytest.raises(CentralProtocolError, match="protocol_error"):
        client.register(body)
    PairingHandler.transfer_encoding = None
    PairingHandler.body = b"x" * 1025
    with pytest.raises(CentralProtocolError, match="protocol_error"):
        client.register(body)
    PairingHandler.body = json.dumps(_registration_response()).encode()
    PairingHandler.delay = 0.2
    with pytest.raises(CentralProtocolError, match="unreachable"):
        client.register(body)

    port = origin.rsplit(":", 1)[1]
    unreachable = CentralPairingHTTPClient(
        lambda: (f"https://localhost:{int(port) + 1}", fingerprint), timeout=0.05
    )
    with pytest.raises(CentralProtocolError, match="unreachable"):
        unreachable.register(body)


@pytest.mark.parametrize("drip", ["headers", "body"])
def test_total_deadline_stops_real_slow_drip_without_leftover_workers(
    pairing_tls_server, drip
) -> None:
    origin, fingerprint, _certificate_pem, _private_key = pairing_tls_server
    PairingHandler.status = 201
    PairingHandler.body = json.dumps(_registration_response()).encode()
    if drip == "headers":
        PairingHandler.header_drip_delay = 0.04
    else:
        PairingHandler.body_drip_delay = 0.01
    client = CentralPairingHTTPClient(lambda: (origin, fingerprint), timeout=0.08)
    started = time.monotonic()
    with pytest.raises(CentralProtocolError, match="unreachable"):
        client.register({"protocol": "1.0"})
    elapsed = time.monotonic() - started

    assert elapsed < 0.25
    assert not [
        thread for thread in threading.enumerate() if thread.name == "central-pairing-deadline"
    ]


def test_real_client_rejects_wrong_san_and_non_json_or_unknown_response_fields(
    tmp_path: Path, pairing_tls_server
) -> None:
    origin, fingerprint, _certificate_pem, _private_key = pairing_tls_server
    PairingHandler.status = 201
    PairingHandler.body = json.dumps(_registration_response() | {"unexpected": True}).encode()
    client = CentralPairingHTTPClient(lambda: (origin, fingerprint), timeout=1)
    with pytest.raises(CentralProtocolError, match="protocol_error"):
        client.register({"protocol": "1.0"})

    PairingHandler.body = b"not-json"
    with pytest.raises(CentralProtocolError, match="protocol_error"):
        client.register({"protocol": "1.0"})
    PairingHandler.content_type = "text/plain"
    with pytest.raises(CentralProtocolError, match="protocol_error"):
        client.register({"protocol": "1.0"})


def test_configuration_snapshot_uses_exact_bytes_route_and_active_mtls(pairing_tls_server) -> None:
    origin, fingerprint, certificate, private_key = pairing_tls_server
    snapshot_id = str(uuid4())
    installation_id = str(uuid4())
    digest = "A" * 43
    payload = json.dumps(
        {
            "schemaVersion": "1.0",
            "snapshotId": snapshot_id,
            "installationId": installation_id,
            "configVersion": 7,
            "capturedAt": "2026-08-07T12:00:00Z",
            "projectionSha256": digest,
            "structures": [],
            "spaces": [],
            "assets": [],
            "points": [],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    accepted = {
        "status": "accepted",
        "snapshotId": snapshot_id,
        "installationId": installation_id,
        "configVersion": 7,
        "projectionSha256": digest,
        "acceptedAt": "2026-08-07T12:00:01Z",
        "activePointCount": 0,
    }
    PairingHandler.status = 201
    PairingHandler.cache_control = "no-store"
    PairingHandler.body = json.dumps(accepted, separators=(",", ":")).encode()
    client = CentralPairingHTTPClient(lambda: (origin, fingerprint), timeout=2)

    assert client.upload_configuration_snapshot(payload, certificate, private_key) == accepted
    path, headers, wire_body, had_client_cert = PairingHandler.requests[-1]
    assert path == "/api/v1/edge/device/configuration-snapshots"
    assert wire_body == payload
    assert had_client_cert is True
    assert headers["Content-Type"] == "application/json"
    assert "Authorization" not in headers

    status_body = {key: value for key, value in accepted.items() if key != "snapshotId"}
    PairingHandler.status = 200
    PairingHandler.body = json.dumps(status_body, separators=(",", ":")).encode()
    assert client.configuration_status(certificate, private_key) == status_body
    assert PairingHandler.requests[-1][0] == "/api/v1/edge/device/configuration-status"
    assert PairingHandler.requests[-1][3] is True


def test_configuration_snapshot_rejects_redirect_wrong_status_content_type_and_cache(
    pairing_tls_server,
) -> None:
    origin, fingerprint, certificate, private_key = pairing_tls_server
    client = CentralPairingHTTPClient(lambda: (origin, fingerprint), timeout=2)
    PairingHandler.body = b"{}"
    PairingHandler.cache_control = "no-store"
    for status in (200, 202, 302):
        PairingHandler.status = status
        with pytest.raises(CentralProtocolError, match="protocol_error"):
            client.upload_configuration_snapshot(b"{}", certificate, private_key)
    PairingHandler.status = 201
    PairingHandler.content_type = "application/json; charset=utf-8"
    with pytest.raises(CentralProtocolError, match="protocol_error"):
        client.upload_configuration_snapshot(b"{}", certificate, private_key)
    PairingHandler.content_type = "application/json"
    PairingHandler.cache_control = None
    with pytest.raises(CentralProtocolError, match="protocol_error"):
        client.upload_configuration_snapshot(b"{}", certificate, private_key)


def test_device_lifecycle_routes_are_strict_no_store_and_select_required_mtls(
    pairing_tls_server,
) -> None:
    origin, fingerprint, current_certificate, current_key = pairing_tls_server
    client = CentralPairingHTTPClient(lambda: (origin, fingerprint), timeout=2)
    installation_id = str(uuid4())
    request_id = str(uuid4())
    old_id = str(uuid4())
    new_id = str(uuid4())
    digest = "A" * 43
    PairingHandler.cache_control = "no-store"

    device = {
        "installationId": installation_id,
        "status": "paired",
        "installationRevision": 11,
        "credentialId": old_id,
        "certificateSha256": digest,
    }
    PairingHandler.body = json.dumps(device, separators=(",", ":")).encode()
    assert client.device_status(current_certificate, current_key) == device
    assert PairingHandler.requests[-1][0] == "/api/v1/edge/device/status"
    assert PairingHandler.requests[-1][3] is True

    pending = {
        "requestId": request_id,
        "installationId": installation_id,
        "status": "pending",
        "installationRevision": 11,
        "issuanceExpiresAt": "2026-08-07T12:05:00Z",
    }
    PairingHandler.status = 202
    PairingHandler.body = json.dumps(pending, separators=(",", ":")).encode()
    body = {"protocol": "1.0", "requestId": request_id}
    assert client.start_renewal(body, current_certificate, current_key) == pending
    assert PairingHandler.requests[-1][0] == "/api/v1/edge/device/renewal"

    issued = {
        "requestId": request_id,
        "installationId": installation_id,
        "status": "issued",
        "installationRevision": 11,
        "oldCredentialId": old_id,
        "oldCertificateSha256": digest,
        "newCredentialId": new_id,
        "newCertificateSha256": digest,
        "certificatePem": "certificate",
        "caChainPem": "chain",
        "ackExpiresAt": "2026-08-08T12:00:00Z",
    }
    PairingHandler.status = 200
    PairingHandler.body = json.dumps(issued, separators=(",", ":")).encode()
    assert client.renewal_result(request_id, current_certificate, current_key) == issued
    assert PairingHandler.requests[-1][0] == f"/api/v1/edge/device/renewals/{request_id}"

    acked = {
        "requestId": request_id,
        "installationId": installation_id,
        "status": "acked",
        "installationRevision": 12,
        "oldCredentialId": old_id,
        "oldCertificateSha256": digest,
        "newCredentialId": new_id,
        "newCertificateSha256": digest,
    }
    PairingHandler.body = json.dumps(acked, separators=(",", ":")).encode()
    assert (
        client.ack_renewal(request_id, {"protocol": "1.0"}, current_certificate, current_key)
        == acked
    )
    assert PairingHandler.requests[-1][0] == f"/api/v1/edge/device/renewals/{request_id}/ack"

    PairingHandler.content_type = "application/json; charset=utf-8"
    with pytest.raises(CentralProtocolError, match="protocol_error"):
        client.device_status(current_certificate, current_key)
    PairingHandler.content_type = "application/json"
    PairingHandler.cache_control = None
    with pytest.raises(CentralProtocolError, match="protocol_error"):
        client.device_status(current_certificate, current_key)


def test_draft4_renewal_client_preserves_exact_request_and_response_bytes(
    pairing_tls_server,
) -> None:
    origin, fingerprint, certificate, private_key = pairing_tls_server
    client = CentralPairingHTTPClient(lambda: (origin, fingerprint), timeout=2)
    request_id = str(uuid4())
    cancel_id = str(uuid4())
    request = b'{"protocol":"2.0","requestId":"' + request_id.encode() + b'"}'
    response = b'{"protocol":"2.0","status":"pending"}'
    PairingHandler.cache_control = "no-store"
    PairingHandler.body = response
    PairingHandler.status = 202

    assert client.start_renewal_v2(request, certificate, private_key) == response
    assert PairingHandler.requests[-1][0] == "/api/v1/edge/device/renewal"
    assert PairingHandler.requests[-1][1]["One-OS-Telemetry-Protocol"] == "2.0"
    assert PairingHandler.requests[-1][2] == request

    PairingHandler.status = 200
    assert client.renewal_status_v2(request_id, certificate, private_key) == response
    assert PairingHandler.requests[-1][0] == f"/api/v1/edge/device/renewals/{request_id}"
    assert client.ack_renewal_v2(request_id, request, certificate, private_key) == response
    assert PairingHandler.requests[-1][0] == f"/api/v1/edge/device/renewals/{request_id}/ack"
    assert PairingHandler.requests[-1][1]["One-OS-Telemetry-Protocol"] == "2.0"
    assert PairingHandler.requests[-1][2] == request
    assert client.cancel_renewal_v2(request_id, request, certificate, private_key) == response
    assert PairingHandler.requests[-1][0] == f"/api/v1/edge/device/renewals/{request_id}/cancel"
    assert PairingHandler.requests[-1][1]["One-OS-Telemetry-Protocol"] == "2.0"
    assert client.cancel_status_v2(cancel_id, certificate, private_key) == response
    assert PairingHandler.requests[-1][0] == (
        f"/api/v1/edge/device/renewal-cancellations/{cancel_id}"
    )
