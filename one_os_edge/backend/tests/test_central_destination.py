from __future__ import annotations

import hashlib
import http.client
import socket
import ssl
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import one_os_addon.central_destination as destination_module
import pytest
from one_os_addon.central_destination import DiscoveryError, test_pinned_discovery
from one_os_addon.models import CentralDestination
from sqlalchemy import inspect, update

ORIGIN = "https://central.example:8443"
FINGERPRINT = "AA:" * 31 + "AA"


def test_destination_is_unconfigured_without_secrets(client):
    response = client.get("/api/v1/central-destination", headers={"X-Remote-User-Id": "admin-1"})

    assert response.status_code == 200
    assert response.json() == {
        "configured": False,
        "revision": 0,
        "origin": None,
        "certificateFingerprint": None,
        "configuredAt": None,
        "status": "not_configured",
    }
    assert "token" not in response.text.lower()
    assert "credential" not in response.text.lower()


def test_put_persists_normalized_revision_safe_destination(client, auth):
    response = client.put(
        "/api/v1/central-destination",
        headers=auth,
        json={"revision": 0, "origin": ORIGIN, "certificateFingerprint": FINGERPRINT},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["configured"] is True
    assert body["revision"] == 1
    assert body["origin"] == ORIGIN
    assert body["certificateFingerprint"] == "aa" * 32
    assert body["configuredAt"].endswith("+00:00")
    assert body["status"] == "configured"
    assert (
        client.put(
            "/api/v1/central-destination",
            headers=auth,
            json={"revision": 0, "origin": ORIGIN, "certificateFingerprint": "bb" * 32},
        ).status_code
        == 409
    )


def test_concurrent_initial_destination_create_has_exactly_one_winner(client, auth):
    def create(fingerprint: str):
        return client.put(
            "/api/v1/central-destination",
            headers=auth,
            json={"revision": 0, "origin": ORIGIN, "certificateFingerprint": fingerprint},
        ).status_code

    with ThreadPoolExecutor(max_workers=2) as executor:
        statuses = list(executor.map(create, ("aa" * 32, "bb" * 32)))

    assert sorted(statuses) == [200, 409]
    assert client.get("/api/v1/central-destination", headers=auth).json()["revision"] == 1


def test_concurrent_destination_update_has_exactly_one_winner(client, auth):
    assert (
        client.put(
            "/api/v1/central-destination",
            headers=auth,
            json={"revision": 0, "origin": ORIGIN, "certificateFingerprint": "aa" * 32},
        ).status_code
        == 200
    )

    def update_destination(fingerprint: str):
        return client.put(
            "/api/v1/central-destination",
            headers=auth,
            json={"revision": 1, "origin": ORIGIN, "certificateFingerprint": fingerprint},
        ).status_code

    with ThreadPoolExecutor(max_workers=2) as executor:
        statuses = list(executor.map(update_destination, ("bb" * 32, "cc" * 32)))

    assert sorted(statuses) == [200, 409]
    assert client.get("/api/v1/central-destination", headers=auth).json()["revision"] == 2


@pytest.mark.parametrize(
    "origin",
    [
        "http://central.example",
        "https://central.example/",
        "https://central.example/path",
        "https://central.example?q=1",
        "https://central.example#fragment",
        "https://user@central.example",
        "https://central.example:0",
        "https://central.example:65536",
        "https://central.example%2f.evil",
        "https://central example",
        " https://central.example",
        "https://central.example ",
    ],
)
def test_put_rejects_anything_except_exact_https_origin(client, auth, origin):
    response = client.put(
        "/api/v1/central-destination",
        headers=auth,
        json={"revision": 0, "origin": origin, "certificateFingerprint": "ab" * 32},
    )
    assert response.status_code == 422


@pytest.mark.parametrize("fingerprint", ["ab" * 31, "gg" * 32, "ab:cd", " ab" * 32])
def test_put_rejects_malformed_sha256_fingerprint(client, auth, fingerprint):
    response = client.put(
        "/api/v1/central-destination",
        headers=auth,
        json={"revision": 0, "origin": ORIGIN, "certificateFingerprint": fingerprint},
    )
    assert response.status_code == 422


def test_destination_mutations_keep_ingress_csrf_guards(client):
    assert (
        client.put(
            "/api/v1/central-destination",
            headers={"X-Remote-User-Id": "admin-1"},
            json={"revision": 0, "origin": ORIGIN, "certificateFingerprint": "ab" * 32},
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/api/v1/central-destination/test",
            headers={"X-Remote-User-Id": "admin-1"},
            json={},
        ).status_code
        == 403
    )


def test_connection_endpoint_uses_only_persisted_destination(client, auth):
    calls = []
    client.app.state.destination_tester = lambda origin, fingerprint: calls.append(
        (origin, fingerprint)
    ) or {
        "service": "one-os-central",
        "schemaVersion": "1.0",
        "pairingSupported": False,
        "phase": "2B.1-sandbox-foundation",
    }
    client.put(
        "/api/v1/central-destination",
        headers=auth,
        json={"revision": 0, "origin": ORIGIN, "certificateFingerprint": "ab" * 32},
    )

    response = client.post("/api/v1/central-destination/test", headers=auth, json={})

    assert response.status_code == 200
    assert response.json() == {
        "status": "reachable",
        "revision": 1,
        "service": "one-os-central",
        "schemaVersion": "1.0",
        "pairingSupported": False,
        "phase": "2B.1-sandbox-foundation",
    }
    assert calls == [(ORIGIN, "ab" * 32)]


def test_connection_endpoint_maps_trust_and_protocol_errors(client, auth):
    client.put(
        "/api/v1/central-destination",
        headers=auth,
        json={"revision": 0, "origin": ORIGIN, "certificateFingerprint": "ab" * 32},
    )
    for code, status in (("trust_error", 502), ("protocol_error", 502), ("unreachable", 503)):

        def fail(_origin, _fingerprint, error=code):
            raise DiscoveryError(error)

        client.app.state.destination_tester = fail
        response = client.post("/api/v1/central-destination/test", headers=auth, json={})
        assert response.status_code == status
        assert response.json()["detail"]["code"] == code


def test_migration_creates_singleton_without_credential_columns(client):
    columns = {
        column["name"]
        for column in inspect(client.app.state.engine).get_columns("central_destination")
    }
    assert columns == {"id", "revision", "origin", "certificate_fingerprint", "configured_at"}


class _DiscoveryHandler(BaseHTTPRequestHandler):
    seen_paths: list[str] = []
    response_body = (
        b'{"schemaVersion":"1.0","service":"one-os-central",'
        b'"pairingSupported":false,"phase":"2B.1-sandbox-foundation"}'
    )
    response_status = 200
    extra_content_length: int | None = None
    declared_content_length: int | None = None
    body_chunk_delay = 0.0

    def do_GET(self):
        type(self).seen_paths.append(self.path)
        self.send_response(type(self).response_status)
        self.send_header("Content-Type", "application/json")
        declared_length = type(self).declared_content_length
        self.send_header(
            "Content-Length",
            str(len(type(self).response_body) if declared_length is None else declared_length),
        )
        if type(self).extra_content_length is not None:
            self.send_header("Content-Length", str(type(self).extra_content_length))
        self.end_headers()
        if type(self).body_chunk_delay:
            for byte in type(self).response_body:
                self.wfile.write(bytes([byte]))
                self.wfile.flush()
                destination_module.time.sleep(type(self).body_chunk_delay)
        else:
            self.wfile.write(type(self).response_body)

    def log_message(self, _format, *_args):
        pass


class _QuietThreadingHTTPServer(ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        del request, client_address


@pytest.fixture
def tls_discovery_server(tmp_path: Path):
    key = tmp_path / "key.pem"
    cert = tmp_path / "cert.pem"
    config = tmp_path / "openssl.cnf"
    config.write_text(
        "[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n"
        "[dn]\nCN=localhost\n[ext]\nsubjectAltName=DNS:localhost\n"
        "basicConstraints=critical,CA:TRUE\n"
        "keyUsage=critical,digitalSignature,keyCertSign\n"
    )
    subprocess.run(  # noqa: S603 - fixed executable and test-controlled arguments
        [
            "/usr/bin/openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-config",
            str(config),
        ],
        check=True,
        capture_output=True,
    )
    _DiscoveryHandler.seen_paths = []
    _DiscoveryHandler.response_body = (
        b'{"schemaVersion":"1.0","service":"one-os-central",'
        b'"pairingSupported":false,"phase":"2B.1-sandbox-foundation"}'
    )
    _DiscoveryHandler.response_status = 200
    _DiscoveryHandler.extra_content_length = None
    _DiscoveryHandler.declared_content_length = None
    _DiscoveryHandler.body_chunk_delay = 0.0
    server = _QuietThreadingHTTPServer(("127.0.0.1", 0), _DiscoveryHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    der = ssl.PEM_cert_to_DER_cert(cert.read_text())
    try:
        yield f"https://localhost:{server.server_port}", hashlib.sha256(der).hexdigest()
    finally:
        server.shutdown()
        thread.join()
        server.server_close()


def test_real_pinned_discovery_verifies_self_signed_cert_and_fixed_path(tls_discovery_server):
    origin, fingerprint = tls_discovery_server
    result = test_pinned_discovery(origin, fingerprint, timeout=2, max_response_bytes=1024)
    assert result == {
        "service": "one-os-central",
        "schemaVersion": "1.0",
        "pairingSupported": False,
        "phase": "2B.1-sandbox-foundation",
    }
    assert _DiscoveryHandler.seen_paths == ["/api/v1/edge/discovery"]


def test_real_pinned_discovery_rejects_wrong_pin_before_http_data(tls_discovery_server):
    origin, _fingerprint = tls_discovery_server
    with pytest.raises(DiscoveryError, match="trust_error"):
        test_pinned_discovery(origin, "00" * 32, timeout=2)
    assert _DiscoveryHandler.seen_paths == []


def test_real_pinned_discovery_rejects_redirect_and_oversized_body(tls_discovery_server):
    origin, fingerprint = tls_discovery_server
    _DiscoveryHandler.response_status = 302
    with pytest.raises(DiscoveryError, match="protocol_error"):
        test_pinned_discovery(origin, fingerprint, timeout=2)
    assert _DiscoveryHandler.seen_paths == ["/api/v1/edge/discovery"]

    _DiscoveryHandler.seen_paths = []
    _DiscoveryHandler.response_status = 200
    _DiscoveryHandler.response_body = b"x" * 1025
    with pytest.raises(DiscoveryError, match="protocol_error"):
        test_pinned_discovery(origin, fingerprint, timeout=2, max_response_bytes=1024)
    assert _DiscoveryHandler.seen_paths == ["/api/v1/edge/discovery"]


def test_pinned_context_disables_legacy_common_name_fallback(tls_discovery_server):
    origin, fingerprint = tls_discovery_server
    port = int(origin.rsplit(":", 1)[1])
    deadline = destination_module.time.monotonic() + 2
    targets = destination_module._resolve_once("localhost", port, deadline)
    _chosen, certificate_der = destination_module._select_reachable_target(
        targets, "localhost", deadline
    )
    context = destination_module._pinned_context(certificate_der)

    assert context.check_hostname is True
    assert context.hostname_checks_common_name is False
    assert hashlib.sha256(certificate_der).hexdigest() == fingerprint


def test_real_cn_only_certificate_is_rejected(tmp_path: Path):
    key = tmp_path / "cn-only-key.pem"
    cert = tmp_path / "cn-only-cert.pem"
    subprocess.run(  # noqa: S603 - fixed executable and test-controlled arguments
        [
            "/usr/bin/openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-keyout",
            str(key),
            "-out",
            str(cert),
        ],
        check=True,
        capture_output=True,
    )
    _DiscoveryHandler.extra_content_length = None
    _DiscoveryHandler.declared_content_length = None
    _DiscoveryHandler.body_chunk_delay = 0.0
    server = _QuietThreadingHTTPServer(("127.0.0.1", 0), _DiscoveryHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    certificate_der = ssl.PEM_cert_to_DER_cert(cert.read_text())
    fingerprint = hashlib.sha256(certificate_der).hexdigest()
    try:
        with pytest.raises(DiscoveryError, match="trust_error"):
            test_pinned_discovery(f"https://localhost:{server.server_port}", fingerprint, timeout=2)
    finally:
        server.shutdown()
        thread.join()
        server.server_close()


def test_pinned_discovery_resolves_dns_only_once(tls_discovery_server, monkeypatch):
    origin, fingerprint = tls_discovery_server
    port = int(origin.rsplit(":", 1)[1])
    calls = 0

    def alternating_dns(_host, _port, *, type):
        nonlocal calls
        calls += 1
        address = ("127.0.0.1", port) if calls == 1 else ("127.0.0.2", port)
        return [(socket.AF_INET, type, socket.IPPROTO_TCP, "", address)]

    monkeypatch.setattr(socket, "getaddrinfo", alternating_dns)

    assert (
        destination_module._test_pinned_discovery_in_worker(origin, fingerprint, timeout=2)[
            "service"
        ]
        == "one-os-central"
    )
    assert calls == 1


def test_malformed_http_status_is_canonical_protocol_error(tls_discovery_server, monkeypatch):
    origin, fingerprint = tls_discovery_server

    def malformed_status(_self):
        raise http.client.BadStatusLine("not-http")

    monkeypatch.setattr(
        destination_module._ResolvedHTTPSConnection, "getresponse", malformed_status
    )

    with pytest.raises(DiscoveryError, match="protocol_error"):
        destination_module._test_pinned_discovery_in_worker(origin, fingerprint, timeout=2)


def test_conflicting_content_length_and_truncated_body_are_protocol_errors(
    tls_discovery_server,
):
    origin, fingerprint = tls_discovery_server

    _DiscoveryHandler.extra_content_length = len(_DiscoveryHandler.response_body) + 1
    with pytest.raises(DiscoveryError, match="protocol_error"):
        test_pinned_discovery(origin, fingerprint, timeout=2)

    _DiscoveryHandler.extra_content_length = None
    _DiscoveryHandler.declared_content_length = len(_DiscoveryHandler.response_body) + 100
    with pytest.raises(DiscoveryError, match="protocol_error"):
        test_pinned_discovery(origin, fingerprint, timeout=2)


def test_put_rejects_origin_longer_than_database_contract(client, auth):
    response = client.put(
        "/api/v1/central-destination",
        headers=auth,
        json={
            "revision": 0,
            "origin": "https://" + ("a" * 2041),
            "certificateFingerprint": "ab" * 32,
        },
    )
    assert response.status_code == 422


def test_connection_result_is_rejected_if_persisted_revision_changes(client, auth):
    client.put(
        "/api/v1/central-destination",
        headers=auth,
        json={"revision": 0, "origin": ORIGIN, "certificateFingerprint": "ab" * 32},
    )

    def mutate_during_test(_origin, _fingerprint):
        with client.app.state.engine.begin() as connection:
            connection.execute(
                update(CentralDestination).where(CentralDestination.id == 1).values(revision=2)
            )
        return {
            "service": "one-os-central",
            "schemaVersion": "1.0",
            "pairingSupported": False,
            "phase": "2B.1-sandbox-foundation",
        }

    client.app.state.destination_tester = mutate_during_test
    response = client.post("/api/v1/central-destination/test", headers=auth, json={})

    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "revision_conflict"


def test_total_deadline_stops_slow_drip_response_body(tls_discovery_server):
    origin, fingerprint = tls_discovery_server
    _DiscoveryHandler.body_chunk_delay = 0.02

    started = destination_module.time.monotonic()
    with pytest.raises(DiscoveryError, match="unreachable"):
        test_pinned_discovery(origin, fingerprint, timeout=0.05)
    elapsed = destination_module.time.monotonic() - started

    assert elapsed < 0.25
