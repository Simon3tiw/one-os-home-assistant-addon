"""Dedicated side-effect-free mTLS status server for ONE.OS Phase 2C."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import ssl
import stat
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import cast

_STATUS_PATH = "/v1/phase2c/status"
_ALLOWED_KEYS = {
    "softwareVersion",
    "databaseRevision",
    "telemetryDelivery",
    "probeNonce",
    "observedAt",
    "processStartId",
}
_ALLOWED_DELIVERY = {"pending", "leased", "acked", "quarantined", "oldestQuarantine"}
_MAX_RESPONSE = 4096


class ProbeServerError(RuntimeError):
    pass


class _DeadlineHTTPServer(HTTPServer):
    def __init__(
        self,
        server_address: tuple[str, int],
        handler,
        context: ssl.SSLContext,
        request_deadline_seconds: float,
    ) -> None:
        self._tls_context = context
        self._request_deadline_seconds = request_deadline_seconds
        super().__init__(server_address, handler, bind_and_activate=False)

    @staticmethod
    def _close_socket(value: socket.socket) -> None:
        try:
            value.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        value.close()

    def _deadline_timer(self, value: socket.socket) -> threading.Timer:
        timer = threading.Timer(
            self._request_deadline_seconds,
            self._close_socket,
            args=(value,),
        )
        timer.daemon = True
        timer.start()
        return timer

    @staticmethod
    def _cancel_timer(timer: threading.Timer) -> None:
        timer.cancel()
        timer.join()

    def get_request(self):
        raw, address = super().get_request()
        raw.settimeout(self._request_deadline_seconds)
        timer = self._deadline_timer(raw)
        try:
            secured = self._tls_context.wrap_socket(raw, server_side=True)
        except OSError:
            self._close_socket(raw)
            raise
        finally:
            self._cancel_timer(timer)
        secured.settimeout(self._request_deadline_seconds)
        return secured, address

    def finish_request(self, request, client_address) -> None:
        timer = self._deadline_timer(cast(socket.socket, request))
        try:
            super().finish_request(request, client_address)
        finally:
            self._cancel_timer(timer)


def _canonical_sha256(value: str) -> str:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise ProbeServerError("client_identity")
    return value


def _canonical_process_start_id(value: str) -> str:
    if len(value) != 32 or any(character not in "0123456789abcdef" for character in value):
        raise ProbeServerError("process_start_id")
    return value


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_allowed_client_sha256(path: Path) -> str:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as error:
        raise ProbeServerError("client_identity") from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size != 65
            or metadata.st_mode & 0o022
        ):
            raise ProbeServerError("client_identity")
        payload = os.read(descriptor, 66)
    finally:
        os.close(descriptor)
    try:
        value = payload.decode("ascii")
    except UnicodeDecodeError as error:
        raise ProbeServerError("client_identity") from error
    if not value.endswith("\n"):
        raise ProbeServerError("client_identity")
    return _canonical_sha256(value[:-1])


def _encode_status(value: dict[str, object]) -> bytes:
    if type(value) is not dict or set(value) != _ALLOWED_KEYS:
        raise ProbeServerError("status_shape")
    delivery = value.get("telemetryDelivery")
    observed_at = value.get("observedAt")
    probe_nonce = value.get("probeNonce")
    process_start_id = value.get("processStartId")
    if (
        type(value.get("softwareVersion")) is not str
        or type(value.get("databaseRevision")) is not str
        or type(observed_at) is not str
        or type(probe_nonce) is not str
        or type(process_start_id) is not str
    ):
        raise ProbeServerError("status_shape")
    _canonical_sha256(probe_nonce)
    _canonical_process_start_id(process_start_id)
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", observed_at) is None:
        raise ProbeServerError("status_shape")
    if type(delivery) is not dict or set(delivery) != _ALLOWED_DELIVERY:
        raise ProbeServerError("status_shape")
    for key in ("pending", "leased", "acked", "quarantined"):
        if type(delivery[key]) is not int or delivery[key] < 0:
            raise ProbeServerError("status_shape")
    if delivery["oldestQuarantine"] is not None and type(delivery["oldestQuarantine"]) is not str:
        raise ProbeServerError("status_shape")
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
    if len(encoded) > _MAX_RESPONSE:
        raise ProbeServerError("status_size")
    return encoded


def _handler(
    allowed_client_sha256: str,
    process_start_id: str,
    clock: Callable[[], str],
    collector: Callable[[], dict[str, object]],
):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, _format: str, *_arguments: object) -> None:
            return

        def _empty(self, status: int) -> None:
            self.send_response(status)
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()

        def _authorized(self) -> bool:
            certificate = self.connection.getpeercert(binary_form=True)
            if type(certificate) is not bytes:
                return False
            actual = hashlib.sha256(certificate).hexdigest()
            return hmac.compare_digest(actual, allowed_client_sha256)

        def do_GET(self) -> None:  # noqa: N802
            if not self._authorized():
                self._empty(403)
                return
            if self.path != _STATUS_PATH:
                self._empty(404)
                return
            try:
                nonce_values = self.headers.get_all("X-ONE-OS-Probe-Nonce", [])
                if len(nonce_values) != 1:
                    raise ProbeServerError("probe_nonce")
                nonce = _canonical_sha256(nonce_values[0])
                status = dict(collector())
                status.update(
                    {
                        "probeNonce": nonce,
                        "observedAt": clock(),
                        "processStartId": process_start_id,
                    }
                )
                body = _encode_status(status)
            except ProbeServerError:
                self._empty(400)
                return
            except Exception:
                self._empty(503)
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        def __getattr__(self, name: str):
            if name.startswith("do_"):
                return lambda: self._empty(405 if self._authorized() else 403)
            raise AttributeError(name)

    return Handler


def create_server(
    host: str,
    port: int,
    client_ca: Path,
    server_certificate: Path,
    server_key: Path,
    allowed_client_sha256: str,
    collector: Callable[[], dict[str, object]],
    *,
    request_deadline_seconds: float = 3.0,
    process_start_id: str | None = None,
    clock: Callable[[], str] = _utc_now,
) -> HTTPServer:
    if (
        host
        not in {
            "0.0.0.0",  # noqa: S104 - fixed add-on address; Supervisor controls mapping.
            "127.0.0.1",
            "::",
        }
        or not 0 <= port <= 65535
        or type(request_deadline_seconds) not in {int, float}
        or not 0.1 <= request_deadline_seconds <= 30.0
    ):
        raise ProbeServerError("listen_address")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=str(client_ca))
    context.load_cert_chain(certfile=str(server_certificate), keyfile=str(server_key))
    identity = _canonical_sha256(allowed_client_sha256)
    start_id = _canonical_process_start_id(process_start_id or secrets.token_hex(16))
    server = _DeadlineHTTPServer(
        (host, port),
        _handler(identity, start_id, clock, collector),
        context,
        float(request_deadline_seconds),
    )
    server.server_bind()
    server.server_activate()
    return server
