from __future__ import annotations

import http.client
import socket
import ssl
import threading
import time
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from one_os_addon.soak_probe_server import (
    ProbeServerError,
    _encode_status,
    create_server,
    load_allowed_client_sha256,
)


def key_and_cert(
    tmp_path: Path, name: str, *, ca_key=None, ca_cert=None, server=False, client=False
):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    issuer = ca_cert.subject if ca_cert else subject
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(minutes=1))
        .not_valid_after(datetime.now(UTC) + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=ca_key is None, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                ca_key.public_key() if ca_key else key.public_key()
            ),
            critical=False,
        )
    )
    if ca_key is None:
        builder = builder.add_extension(
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
    else:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    if server:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ip_address("127.0.0.1"))]), critical=False
        )
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
    if client:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False
        )
    cert = builder.sign(private_key=ca_key or key, algorithm=hashes.SHA256())
    key_path, cert_path = tmp_path / f"{name}.key", tmp_path / f"{name}.crt"
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return key, cert, key_path, cert_path


def fixtures(tmp_path: Path):
    ca_key, ca_cert, _, ca_path = key_and_cert(tmp_path, "ca")
    _, _, server_key, server_cert = key_and_cert(
        tmp_path, "server", ca_key=ca_key, ca_cert=ca_cert, server=True
    )
    _, client_certificate, client_key, client_cert = key_and_cert(
        tmp_path, "client", ca_key=ca_key, ca_cert=ca_cert, client=True
    )
    _, _, other_client_key, other_client_cert = key_and_cert(
        tmp_path, "other-client", ca_key=ca_key, ca_cert=ca_cert, client=True
    )
    wrong_key, wrong_cert, _, wrong_ca = key_and_cert(tmp_path, "wrong-ca")
    _, _, wrong_client_key, wrong_client_cert = key_and_cert(
        tmp_path, "wrong-client", ca_key=wrong_key, ca_cert=wrong_cert, client=True
    )
    return (
        ca_path,
        server_cert,
        server_key,
        client_cert,
        client_key,
        client_certificate.fingerprint(hashes.SHA256()).hex(),
        other_client_cert,
        other_client_key,
        wrong_ca,
        wrong_client_cert,
        wrong_client_key,
    )


def context(ca: Path, cert: Path | None = None, key: Path | None = None) -> ssl.SSLContext:
    value = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(ca))
    value.minimum_version = ssl.TLSVersion.TLSv1_3
    if cert and key:
        value.load_cert_chain(cert, key)
    return value


def request(
    port: int,
    tls: ssl.SSLContext,
    method: str = "GET",
    path: str = "/v1/phase2c/status",
    timeout: float = 3,
    nonce: str | None = "1" * 64,
):
    connection = http.client.HTTPSConnection("127.0.0.1", port, context=tls, timeout=timeout)
    try:
        headers = {} if nonce is None else {"X-ONE-OS-Probe-Nonce": nonce}
        connection.request(method, path, headers=headers)
        response = connection.getresponse()
        body = response.read()
        return response.status, response.getheader("Content-Type"), body
    finally:
        connection.close()


def test_real_mtls_handshake_closed_route_and_no_client_rejected(tmp_path: Path) -> None:
    (
        ca,
        server_cert,
        server_key,
        client_cert,
        client_key,
        allowed_client_sha256,
        other_client_cert,
        other_client_key,
        wrong_ca,
        wrong_cert,
        wrong_key,
    ) = fixtures(tmp_path)
    payload = {
        "softwareVersion": "0.4.2",
        "databaseRevision": "0014",
        "telemetryDelivery": {
            "pending": 0,
            "leased": 0,
            "acked": 1,
            "quarantined": 0,
            "oldestQuarantine": None,
        },
    }
    server = create_server(
        "127.0.0.1",
        0,
        ca,
        server_cert,
        server_key,
        allowed_client_sha256,
        lambda: payload,
        process_start_id="2" * 32,
        clock=lambda: "2026-08-17T13:20:25Z",
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        status, content_type, body = request(port, context(ca, client_cert, client_key))
        assert status == 200
        assert content_type == "application/json"
        assert body == (
            b'{"databaseRevision":"0014","observedAt":"2026-08-17T13:20:25Z",'
            b'"probeNonce":"1111111111111111111111111111111111111111111111111111111111111111",'
            b'"processStartId":"22222222222222222222222222222222","softwareVersion":"0.4.2",'
            b'"telemetryDelivery":{"acked":1,"leased":0,"oldestQuarantine":null,'
            b'"pending":0,"quarantined":0}}\n'
        )
        assert request(port, context(ca, client_cert, client_key), nonce=None)[0] == 400
        assert request(port, context(ca, client_cert, client_key), nonce="A" * 64)[0] == 400
        assert request(port, context(ca, client_cert, client_key), path="/health")[0] == 404
        assert request(port, context(ca, client_cert, client_key), method="POST")[0] == 405
        assert request(port, context(ca, other_client_cert, other_client_key))[0] == 403
        with pytest.raises((ssl.SSLError, ConnectionError, OSError)):
            request(port, context(ca))
        with pytest.raises((ssl.SSLError, ConnectionError, OSError)):
            request(port, context(ca, wrong_cert, wrong_key))
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_server_source_has_no_ingress_admin_token_or_mutation_surface() -> None:
    source = (Path(__file__).parents[1] / "one_os_addon/soak_probe_server.py").read_text()
    for required in (
        "ssl.CERT_REQUIRED",
        "ssl.TLSVersion.TLSv1_3",
        "def do_GET",
        '"/v1/phase2c/status"',
    ):
        assert required in source
    for forbidden in (
        "SUPERVISOR_TOKEN",
        "X-Remote-User",
        "Ingress",
        "do_POST",
        "do_PUT",
        "do_DELETE",
        "verify_mode = ssl.CERT_OPTIONAL",
    ):
        assert forbidden not in source


def test_client_identity_file_is_canonical_nofollow_and_not_writable(tmp_path: Path) -> None:
    fingerprint = "a" * 64
    allowed = tmp_path / "allowed.sha256"
    allowed.write_text(f"{fingerprint}\n", encoding="ascii")
    allowed.chmod(0o644)
    assert load_allowed_client_sha256(allowed) == fingerprint

    for value in ("A" * 64 + "\n", "a" * 63 + "\n", "a" * 64, "g" * 64 + "\n"):
        allowed.write_text(value, encoding="ascii")
        with pytest.raises(ProbeServerError, match="client_identity"):
            load_allowed_client_sha256(allowed)

    allowed.write_text(f"{fingerprint}\n", encoding="ascii")
    allowed.chmod(0o666)
    with pytest.raises(ProbeServerError, match="client_identity"):
        load_allowed_client_sha256(allowed)

    target = tmp_path / "target.sha256"
    target.write_text(f"{fingerprint}\n", encoding="ascii")
    link = tmp_path / "link.sha256"
    link.symlink_to(target)
    with pytest.raises(ProbeServerError, match="client_identity"):
        load_allowed_client_sha256(link)

    with pytest.raises(ProbeServerError, match="client_identity"):
        load_allowed_client_sha256(tmp_path / "missing.sha256")


def test_slow_tls_handshake_is_closed_at_total_deadline(tmp_path: Path) -> None:
    (
        ca,
        server_cert,
        server_key,
        client_cert,
        client_key,
        allowed_client_sha256,
        _other_client_cert,
        _other_client_key,
        _wrong_ca,
        _wrong_cert,
        _wrong_key,
    ) = fixtures(tmp_path)
    payload = {
        "softwareVersion": "0.4.2",
        "databaseRevision": "0014",
        "telemetryDelivery": {
            "pending": 0,
            "leased": 0,
            "acked": 1,
            "quarantined": 0,
            "oldestQuarantine": None,
        },
    }
    server = create_server(
        "127.0.0.1",
        0,
        ca,
        server_cert,
        server_key,
        allowed_client_sha256,
        lambda: payload,
        request_deadline_seconds=0.2,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    slow = socket.create_connection(server.server_address, timeout=1)
    incoming = ssl.MemoryBIO()
    outgoing = ssl.MemoryBIO()
    slow_tls = context(ca, client_cert, client_key).wrap_bio(
        incoming,
        outgoing,
        server_side=False,
        server_hostname="127.0.0.1",
    )
    with pytest.raises(ssl.SSLWantReadError):
        slow_tls.do_handshake()
    client_hello = outgoing.read()
    stop = threading.Event()

    def drip() -> None:
        for byte in client_hello:
            if stop.wait(0.05):
                return
            try:
                slow.sendall(bytes((byte,)))
            except OSError:
                return

    drip_thread = threading.Thread(target=drip, daemon=True)
    drip_thread.start()
    try:
        time.sleep(0.35)
        assert (
            request(
                server.server_address[1],
                context(ca, client_cert, client_key),
                timeout=0.75,
            )[0]
            == 200
        )
    finally:
        stop.set()
        slow.close()
        drip_thread.join(timeout=1)
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_oversized_status_response_is_rejected() -> None:
    with pytest.raises(ProbeServerError, match="status_size"):
        _encode_status(
            {
                "softwareVersion": "x" * 20_000,
                "databaseRevision": "0014",
                "observedAt": "2026-08-17T13:20:25Z",
                "probeNonce": "1" * 64,
                "processStartId": "2" * 32,
                "telemetryDelivery": {
                    "pending": 0,
                    "leased": 0,
                    "acked": 0,
                    "quarantined": 0,
                    "oldestQuarantine": None,
                },
            }
        )
