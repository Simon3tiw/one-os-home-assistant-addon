from __future__ import annotations

import fcntl
import hashlib
import json
import os
import ssl
import threading
import time
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, cast

import one_os_addon.telemetry_transport as transport_module
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from one_os_addon.telemetry_transport import (
    TELEMETRY_PATH,
    TelemetryDestinationSnapshot,
    TelemetryTransportError,
    TelemetryUploadTransport,
    _upload_in_worker,
)

CONTRACT = Path(__file__).resolve().parents[3] / "docs/reference/contracts/telemetry/v1"


def _vectors() -> dict:
    return json.loads((CONTRACT / "canonical-vectors.json").read_text(encoding="utf-8"))


def _destination(origin: str, fingerprint: str) -> TelemetryDestinationSnapshot:
    return TelemetryDestinationSnapshot(1, origin, fingerprint)


def _certificate(
    key,
    subject: str,
    *,
    issuer_cert=None,
    issuer_key=None,
    san_dns: str | None = None,
    client: bool = False,
    not_valid_before=None,
    not_valid_after=None,
):
    now = datetime.now(UTC)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer_cert.subject if issuer_cert else name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_valid_before or now - timedelta(minutes=1))
        .not_valid_after(not_valid_after or now + timedelta(days=1))
        .add_extension(
            x509.BasicConstraints(ca=issuer_cert is None, path_length=None), critical=True
        )
    )
    if san_dns:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(san_dns)]), critical=True
        )
    if client:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=True
        )
    return builder.sign(issuer_key or key, hashes.SHA256())


def _pem_private(key) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")


class TelemetryHandler(BaseHTTPRequestHandler):
    body = b"{}"
    status = 201
    content_type: str | None = "application/json"
    cache_control: str | None = "no-store"
    duplicate_length = False
    transfer_encoding: str | None = None
    body_drip_delay = 0.0
    retry_after: str | None = None
    requests: list[tuple[str, dict[str, str], bytes, bool]] = []

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        request_body = self.rfile.read(length)
        peer = self.connection.getpeercert(binary_form=True)
        type(self).requests.append((self.path, dict(self.headers), request_body, bool(peer)))
        self.send_response(type(self).status)
        if type(self).content_type is not None:
            self.send_header("Content-Type", type(self).content_type)
        if type(self).cache_control is not None:
            self.send_header("Cache-Control", type(self).cache_control)
        if type(self).retry_after is not None:
            self.send_header("Retry-After", type(self).retry_after)
        if type(self).transfer_encoding is not None:
            self.send_header("Transfer-Encoding", type(self).transfer_encoding)
        else:
            self.send_header("Content-Length", str(len(type(self).body)))
            if type(self).duplicate_length:
                self.send_header("Content-Length", str(len(type(self).body)))
        self.end_headers()
        if type(self).body_drip_delay:
            for byte in type(self).body:
                self.wfile.write(bytes([byte]))
                self.wfile.flush()
                time.sleep(type(self).body_drip_delay)
        else:
            self.wfile.write(type(self).body)

    def log_message(self, _format, *_args):
        pass


class QuietServer(ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        del request, client_address


@pytest.fixture
def telemetry_tls_server(tmp_path: Path, request):
    server_key = ec.generate_private_key(ec.SECP256R1())
    variant = getattr(request, "param", "localhost")
    if variant == "expired":
        now = datetime.now(UTC)
        server_cert = _certificate(
            server_key,
            "central",
            san_dns="localhost",
            not_valid_before=now - timedelta(days=2),
            not_valid_after=now - timedelta(days=1),
        )
    else:
        server_cert = _certificate(server_key, "central", san_dns=variant)
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
    TelemetryHandler.requests = []
    TelemetryHandler.status = 201
    TelemetryHandler.content_type = "application/json"
    TelemetryHandler.cache_control = "no-store"
    TelemetryHandler.duplicate_length = False
    TelemetryHandler.transfer_encoding = None
    TelemetryHandler.body_drip_delay = 0.0
    TelemetryHandler.retry_after = None
    vectors = _vectors()
    TelemetryHandler.body = vectors["ackCanonical"].encode("utf-8")
    server = QuietServer(("127.0.0.1", 0), TelemetryHandler)
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


def test_worker_uploads_exact_immutable_bytes_and_returns_exact_ack(telemetry_tls_server):
    origin, fingerprint, certificate, private_key = telemetry_tls_server
    vectors = _vectors()
    request_bytes = vectors["batchCanonical"].encode("utf-8")
    expected_ack = vectors["ackCanonical"].encode("utf-8")

    ack = _upload_in_worker(
        origin,
        fingerprint,
        request_bytes,
        certificate,
        private_key,
        timeout=2,
    )

    assert ack == expected_ack
    path, headers, received, had_client_certificate = TelemetryHandler.requests[-1]
    assert path == TELEMETRY_PATH
    assert received == request_bytes
    assert had_client_certificate is True
    assert headers["Content-Type"] == "application/json"
    assert headers["Accept"] == "application/json"
    assert headers["Accept-Encoding"] == "identity"


def test_wrong_pin_never_loads_or_offers_client_identity(telemetry_tls_server, monkeypatch):
    origin, _fingerprint, certificate, private_key = telemetry_tls_server
    loaded = 0
    original = transport_module._loaded_client_chain

    def counted(context, material):
        nonlocal loaded
        loaded += 1
        return original(context, material)

    monkeypatch.setattr(transport_module, "_loaded_client_chain", counted)
    with pytest.raises(TelemetryTransportError, match="trust_error"):
        _upload_in_worker(
            origin,
            "00" * 32,
            _vectors()["batchCanonical"].encode(),
            certificate,
            private_key,
            timeout=2,
        )

    assert loaded == 0
    assert TelemetryHandler.requests == []


@pytest.mark.parametrize("telemetry_tls_server", ["wrong.example"], indirect=True)
def test_san_mismatch_never_loads_client_identity(telemetry_tls_server, monkeypatch):
    origin, fingerprint, certificate, private_key = telemetry_tls_server
    loaded = 0
    original = transport_module._loaded_client_chain

    def counted(context, material):
        nonlocal loaded
        loaded += 1
        return original(context, material)

    monkeypatch.setattr(transport_module, "_loaded_client_chain", counted)
    with pytest.raises(TelemetryTransportError, match="trust_error"):
        _upload_in_worker(
            origin,
            fingerprint,
            _vectors()["batchCanonical"].encode(),
            certificate,
            private_key,
            timeout=2,
        )

    assert loaded == 0
    assert TelemetryHandler.requests == []


@pytest.mark.parametrize("telemetry_tls_server", ["expired"], indirect=True)
def test_expired_server_certificate_never_loads_client_identity(telemetry_tls_server, monkeypatch):
    origin, fingerprint, certificate, private_key = telemetry_tls_server
    loaded = 0
    original = transport_module._loaded_client_chain

    def counted(context, material):
        nonlocal loaded
        loaded += 1
        return original(context, material)

    monkeypatch.setattr(transport_module, "_loaded_client_chain", counted)
    with pytest.raises(TelemetryTransportError, match="trust_error"):
        _upload_in_worker(
            origin,
            fingerprint,
            _vectors()["batchCanonical"].encode(),
            certificate,
            private_key,
            timeout=2,
        )

    assert loaded == 0
    assert TelemetryHandler.requests == []


@pytest.mark.parametrize(
    ("mutate", "error"),
    [
        (lambda: setattr(TelemetryHandler, "cache_control", None), "protocol_error"),
        (lambda: setattr(TelemetryHandler, "content_type", "text/plain"), "protocol_error"),
        (lambda: setattr(TelemetryHandler, "duplicate_length", True), "protocol_error"),
        (lambda: setattr(TelemetryHandler, "transfer_encoding", "chunked"), "protocol_error"),
        (lambda: setattr(TelemetryHandler, "status", 401), "revoked"),
        (lambda: setattr(TelemetryHandler, "status", 429), "rate_limited"),
    ],
)
def test_worker_rejects_bad_framing_and_maps_safe_statuses(telemetry_tls_server, mutate, error):
    origin, fingerprint, certificate, private_key = telemetry_tls_server
    mutate()
    if TelemetryHandler.status == 429:
        TelemetryHandler.retry_after = "5"

    with pytest.raises(TelemetryTransportError, match=error):
        _upload_in_worker(
            origin,
            fingerprint,
            _vectors()["batchCanonical"].encode(),
            certificate,
            private_key,
            timeout=2,
        )


def test_rate_limit_requires_exact_retry_after(telemetry_tls_server):
    origin, fingerprint, certificate, private_key = telemetry_tls_server
    TelemetryHandler.status = 429
    TelemetryHandler.retry_after = None

    with pytest.raises(TelemetryTransportError, match="protocol_error"):
        _upload_in_worker(
            origin,
            fingerprint,
            _vectors()["batchCanonical"].encode(),
            certificate,
            private_key,
            timeout=2,
        )


@pytest.mark.parametrize(
    "detail",
    [
        "Telemetry batch conflicts",
        "Telemetry snapshot binding conflicts",
        "Telemetry Point semantics conflict",
        "Telemetry stream continuity conflicts",
        "Telemetry record conflicts",
        "Telemetry gap conflicts",
        "Telemetry credential lineage conflicts",
        "Telemetry installation binding conflicts",
    ],
)
def test_permanent_central_conflict_is_mapped_to_immutable_conflict(telemetry_tls_server, detail):
    origin, fingerprint, certificate, private_key = telemetry_tls_server
    TelemetryHandler.status = 409
    TelemetryHandler.body = json.dumps(
        {"detail": detail}, separators=(",", ":"), sort_keys=True
    ).encode()

    with pytest.raises(TelemetryTransportError, match="^immutable_conflict$"):
        _upload_in_worker(
            origin,
            fingerprint,
            _vectors()["batchCanonical"].encode(),
            certificate,
            private_key,
            timeout=2,
        )


@pytest.mark.parametrize(
    "body",
    [
        b'{"detail":"Telemetry request already in flight"}',
        b'{"detail":"Telemetry request lease lost"}',
        b'{"detail":"unknown"}',
        b'{"detail":"Telemetry batch conflicts","extra":true}',
    ],
)
def test_transient_or_noncanonical_conflict_is_not_terminal(telemetry_tls_server, body):
    origin, fingerprint, certificate, private_key = telemetry_tls_server
    TelemetryHandler.status = 409
    TelemetryHandler.body = body

    with pytest.raises(TelemetryTransportError, match="^protocol_error$"):
        _upload_in_worker(
            origin,
            fingerprint,
            _vectors()["batchCanonical"].encode(),
            certificate,
            private_key,
            timeout=2,
        )


def test_expired_central_payload_is_terminal(telemetry_tls_server):
    origin, fingerprint, certificate, private_key = telemetry_tls_server
    TelemetryHandler.status = 422
    TelemetryHandler.body = b'{"detail":"Telemetry timestamp expired"}'

    with pytest.raises(TelemetryTransportError, match="^expired_payload$"):
        _upload_in_worker(
            origin,
            fingerprint,
            _vectors()["batchCanonical"].encode(),
            certificate,
            private_key,
            timeout=2,
        )


@pytest.mark.parametrize(
    "body",
    [
        b'{"detail":"Telemetry timestamp ahead of acceptance window"}',
        b'{"detail":"Telemetry timestamp expired","extra":true}',
    ],
)
def test_future_or_noncanonical_timestamp_rejection_is_not_terminal(telemetry_tls_server, body):
    origin, fingerprint, certificate, private_key = telemetry_tls_server
    TelemetryHandler.status = 422
    TelemetryHandler.body = body

    with pytest.raises(TelemetryTransportError, match="^protocol_error$"):
        _upload_in_worker(
            origin,
            fingerprint,
            _vectors()["batchCanonical"].encode(),
            certificate,
            private_key,
            timeout=2,
        )


def test_parent_transport_preserves_immutable_conflict(telemetry_tls_server):
    origin, fingerprint, certificate, private_key = telemetry_tls_server
    TelemetryHandler.status = 409
    TelemetryHandler.body = b'{"detail":"Telemetry batch conflicts"}'
    transport = TelemetryUploadTransport(_destination(origin, fingerprint), timeout=2)

    with pytest.raises(TelemetryTransportError, match="^immutable_conflict$"):
        transport.upload(_vectors()["batchCanonical"].encode(), certificate, private_key)


def test_parent_transport_preserves_expired_payload(telemetry_tls_server):
    origin, fingerprint, certificate, private_key = telemetry_tls_server
    TelemetryHandler.status = 422
    TelemetryHandler.body = b'{"detail":"Telemetry timestamp expired"}'
    transport = TelemetryUploadTransport(_destination(origin, fingerprint), timeout=2)

    with pytest.raises(TelemetryTransportError, match="^expired_payload$"):
        transport.upload(_vectors()["batchCanonical"].encode(), certificate, private_key)


def test_parent_deadline_kills_slow_drip_worker(telemetry_tls_server):
    origin, fingerprint, certificate, private_key = telemetry_tls_server
    TelemetryHandler.body_drip_delay = 0.02
    transport = TelemetryUploadTransport(_destination(origin, fingerprint), timeout=0.08)
    started = time.monotonic()

    with pytest.raises(TelemetryTransportError, match="unreachable"):
        transport.upload(_vectors()["batchCanonical"].encode(), certificate, private_key)

    assert time.monotonic() - started < 0.5


def test_parent_worker_round_trip_returns_exact_ack(telemetry_tls_server):
    origin, fingerprint, certificate, private_key = telemetry_tls_server
    vectors = _vectors()

    ack = TelemetryUploadTransport(_destination(origin, fingerprint), timeout=2).upload(
        vectors["batchCanonical"].encode(), certificate, private_key
    )

    assert ack == vectors["ackCanonical"].encode()


@pytest.mark.parametrize("timeout", [0, float("nan"), 61])
def test_transport_rejects_nonfinite_or_excessive_deadline(timeout):
    with pytest.raises(ValueError, match="invalid telemetry transport limits"):
        TelemetryUploadTransport(
            _destination("https://central.example", "00" * 32), timeout=timeout
        )


def test_transport_rejects_arbitrary_destination_callback_and_snapshot_updates_atomically():
    with pytest.raises(ValueError, match="invalid telemetry transport limits"):
        TelemetryUploadTransport(cast(Any, lambda: ("https://central.example", "00" * 32)))

    destination = _destination("https://old.example", "00" * 32)
    assert destination.read() == ("https://old.example", "00" * 32)
    assert destination.update(2, "https://new.example", "11" * 32) is True
    assert destination.update(1, "https://stale.example", "22" * 32) is False
    assert destination.read() == ("https://new.example", "11" * 32)
    assert destination.read_versioned() == (2, "https://new.example", "11" * 32)


def test_parent_maps_process_spawn_failure_to_fixed_unreachable(monkeypatch):
    def failed_spawn(*_args, **_kwargs):
        raise OSError("sensitive local process detail")

    monkeypatch.setattr(transport_module.subprocess, "Popen", failed_spawn)
    transport = TelemetryUploadTransport(
        _destination("https://central.example", "00" * 32), timeout=2
    )

    with pytest.raises(TelemetryTransportError) as raised:
        transport.upload(
            _vectors()["batchCanonical"].encode(),
            "certificate",
            "private-key",
        )

    assert str(raised.value) == "unreachable"


def test_parent_ipc_uses_only_sealed_memfds_and_nonsecret_metadata(monkeypatch):
    captured = {}

    class _Input:
        def close(self):
            pass

    class _MemfdWorker:
        def __init__(self, _argv, **kwargs):
            captured["kwargs"] = kwargs
            self.returncode = None
            self.stdin = _Input()

        def communicate(self, metadata, timeout=None):
            captured["metadata"] = metadata
            captured["timeout"] = timeout
            values = json.loads(metadata)
            for fd_name, size_name, expected in (
                ("requestFd", "requestBytes", _vectors()["batchCanonical"].encode()),
                ("certificateFd", "certificateBytes", b"CERTIFICATE_SECRET_ABC"),
                ("privateKeyFd", "privateKeyBytes", b"PRIVATE_KEY_SECRET_XYZ"),
            ):
                descriptor = values[fd_name]
                assert (
                    fcntl.fcntl(descriptor, fcntl.F_GET_SEALS) & transport_module._INPUT_SEALS
                    == transport_module._INPUT_SEALS
                )
                assert os.pread(descriptor, values[size_name], 0) == expected
            result_fd = values["resultFd"]
            os.write(result_fd, b"Aack")
            fcntl.fcntl(result_fd, fcntl.F_ADD_SEALS, transport_module._INPUT_SEALS)
            self.returncode = 0
            return None, None

        def poll(self):
            return self.returncode

        def kill(self):
            self.returncode = -9

        def wait(self):
            return self.returncode

    monkeypatch.setattr(transport_module.subprocess, "Popen", _MemfdWorker)
    transport = TelemetryUploadTransport(
        _destination("https://central.example", "00" * 32), timeout=2
    )

    assert (
        transport.upload(
            _vectors()["batchCanonical"].encode(),
            "CERTIFICATE_SECRET_ABC",
            "PRIVATE_KEY_SECRET_XYZ",
        )
        == b"ack"
    )
    assert captured["kwargs"]["stdout"] is transport_module.subprocess.DEVNULL
    assert len(captured["kwargs"]["pass_fds"]) == 4
    metadata = captured["metadata"]
    assert "PRIVATE_KEY_SECRET_XYZ" not in metadata
    assert "CERTIFICATE_SECRET_ABC" not in metadata
    assert _vectors()["batchCanonical"] not in metadata


@pytest.mark.parametrize(
    ("payload", "seal"),
    [(b"A" + b"x" * (16 * 1024 + 1), True), (b"Aack", False)],
)
def test_parent_rejects_oversized_or_unsealed_result_memfd(monkeypatch, payload, seal):
    class _Input:
        def close(self):
            pass

    class _BadWorker:
        def __init__(self, _argv, **_kwargs):
            self.returncode = None
            self.stdin = _Input()

        def communicate(self, metadata, timeout=None):
            del timeout
            result_fd = json.loads(metadata)["resultFd"]
            os.write(result_fd, payload)
            if seal:
                fcntl.fcntl(result_fd, fcntl.F_ADD_SEALS, transport_module._INPUT_SEALS)
            self.returncode = 0
            return None, None

        def poll(self):
            return self.returncode

        def kill(self):
            self.returncode = -9

        def wait(self):
            return self.returncode

    monkeypatch.setattr(transport_module.subprocess, "Popen", _BadWorker)
    transport = TelemetryUploadTransport(
        _destination("https://central.example", "00" * 32), timeout=2
    )

    with pytest.raises(TelemetryTransportError, match="protocol_error"):
        transport.upload(_vectors()["batchCanonical"].encode(), "certificate", "private-key")
