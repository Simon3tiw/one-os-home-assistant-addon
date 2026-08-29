from __future__ import annotations

import fcntl
import hashlib
import http.client
import json
import math
import os
import re
import secrets
import ssl
import subprocess
import sys
import threading
import time
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit

from .central_destination import (
    DiscoveryError,
    ResolvedTarget,
    _open_socket,
    _pinned_context,
    _remaining,
    _resolve_once,
    normalize_fingerprint,
    validate_https_origin,
)
from .central_pairing_client import (
    _DeadlineSocketGuard,
    _loaded_client_chain,
    _PinnedHTTPSConnection,
    _select_peer,
)
from .telemetry_contract_v1 import (
    MAX_BATCH_BYTES,
    TelemetryValidationError,
    parse_telemetry_batch,
)
from .telemetry_contract_v2 import (
    TelemetryValidationError as TelemetryValidationErrorV2,
)
from .telemetry_contract_v2 import (
    parse_telemetry_batch as parse_telemetry_batch_v2,
)

TELEMETRY_PATH = "/api/v1/edge/device/telemetry-batches"
DEFAULT_TIMEOUT_SECONDS = 10.0
MAX_TIMEOUT_SECONDS = 60.0
DEFAULT_MAX_ACK_BYTES = 16 * 1024
_MAX_ERROR_BYTES = 512
_MAX_MATERIAL_BYTES = 64 * 1024
_WORKER_SLOTS = threading.BoundedSemaphore(2)
_SAFE_ERRORS = frozenset(
    {
        "expired_payload",
        "immutable_conflict",
        "protocol_error",
        "rate_limited",
        "revoked",
        "trust_error",
        "unreachable",
    }
)
_IMMUTABLE_CONFLICT_BODIES = frozenset(
    json.dumps({"detail": detail}, separators=(",", ":"), sort_keys=True).encode()
    for detail in (
        "Telemetry batch conflicts",
        "Telemetry snapshot binding conflicts",
        "Telemetry Point semantics conflict",
        "Telemetry stream continuity conflicts",
        "Telemetry record conflicts",
        "Telemetry gap conflicts",
        "Telemetry credential lineage conflicts",
        "Telemetry installation binding conflicts",
    )
)
_EXPIRED_PAYLOAD_BODY = b'{"detail":"Telemetry timestamp expired"}'
_V2_ERROR_FIELDS = {
    "batchId",
    "code",
    "decidedAt",
    "requestSha256",
    "retryClass",
    "schemaVersion",
}


class TelemetryTransportError(RuntimeError):
    """A fixed, non-sensitive telemetry transport failure."""


_INPUT_SEALS = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE


def _input_memfd(label: str, payload: bytes) -> int:
    descriptor = os.memfd_create(label, os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("memfd write failed")
            view = view[written:]
        os.lseek(descriptor, 0, os.SEEK_SET)
        fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, _INPUT_SEALS)
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _result_memfd() -> int:
    return os.memfd_create("one-os-telemetry-result", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)


def _read_result(descriptor: int, max_ack_bytes: int) -> bytes:
    size = os.fstat(descriptor).st_size
    if size < 2 or size > max_ack_bytes + 1:
        raise TelemetryTransportError("protocol_error")
    seals = fcntl.fcntl(descriptor, fcntl.F_GET_SEALS)
    if seals & _INPUT_SEALS != _INPUT_SEALS:
        raise TelemetryTransportError("protocol_error")
    os.lseek(descriptor, 0, os.SEEK_SET)
    payload = bytearray()
    while len(payload) < size:
        chunk = os.read(descriptor, size - len(payload))
        if not chunk:
            raise TelemetryTransportError("protocol_error")
        payload.extend(chunk)
    kind, body = bytes(payload[:1]), bytes(payload[1:])
    if kind == b"A" and 1 <= len(body) <= max_ack_bytes:
        return body
    if kind == b"E":
        try:
            code = body.decode("ascii")
        except UnicodeDecodeError as error:
            raise TelemetryTransportError("protocol_error") from error
        if code not in _SAFE_ERRORS:
            code = "protocol_error"
        raise TelemetryTransportError(code)
    raise TelemetryTransportError("protocol_error")


def _strict_json(raw: str) -> dict[str, Any]:
    def unique_object(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate key")
            value[key] = item
        return value

    value = json.loads(raw, object_pairs_hook=unique_object)
    if not isinstance(value, dict):
        raise ValueError("not object")
    return value


def _is_exact_v2_terminal_error(
    payload: bytes, *, expected_batch_id: str, expected_request_sha256: str
) -> bool:
    try:
        document = _strict_json(payload.decode("utf-8", errors="strict"))
        datetime.strptime(document.get("decidedAt", ""), "%Y-%m-%dT%H:%M:%SZ")
    except (UnicodeDecodeError, ValueError, TypeError):
        return False
    if (
        set(document) != _V2_ERROR_FIELDS
        or document.get("schemaVersion") != "one-os-telemetry-error/v2"
        or document.get("batchId") != expected_batch_id
        or document.get("code") != "immutable_identity_conflict"
        or document.get("requestSha256") != expected_request_sha256
        or document.get("retryClass") != "terminal_quarantine"
        or re.fullmatch(
            r"[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])T"
            r"(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z",
            document["decidedAt"],
        )
        is None
    ):
        return False
    canonical = json.dumps(document, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return secrets.compare_digest(canonical, payload)


class TelemetryDestinationSnapshot:
    __slots__ = ("_update_lock", "_value")

    def __init__(
        self,
        revision: int | None = None,
        origin: str | None = None,
        fingerprint: str | None = None,
    ) -> None:
        self._update_lock = threading.Lock()
        self._value: tuple[int, str, str] | None = None
        if revision is not None or origin is not None or fingerprint is not None:
            self.update(revision, origin, fingerprint)

    def update(self, revision: int | None, origin: str | None, fingerprint: str | None) -> bool:
        if (
            type(revision) is not int
            or revision <= 0
            or not isinstance(origin, str)
            or not isinstance(fingerprint, str)
        ):
            raise ValueError("invalid telemetry destination")
        candidate = (
            revision,
            validate_https_origin(origin),
            normalize_fingerprint(fingerprint),
        )
        with self._update_lock:
            current = self._value
            if current is not None and revision <= current[0]:
                return False
            self._value = candidate
            return True

    def read(self) -> tuple[str, str]:
        value = self._value
        if value is None:
            raise LookupError("telemetry destination is not configured")
        return value[1], value[2]

    def read_versioned(self) -> tuple[int, str, str]:
        value = self._value
        if value is None:
            raise LookupError("telemetry destination is not configured")
        return value


def _normalize_material(certificate_pem: str, private_key_pem: str) -> tuple[str, str]:
    if not isinstance(certificate_pem, str) or not isinstance(private_key_pem, str):
        raise TelemetryTransportError("trust_error")
    try:
        certificate_size = len(certificate_pem.encode("ascii"))
        private_key_size = len(private_key_pem.encode("ascii"))
    except UnicodeError as error:
        raise TelemetryTransportError("trust_error") from error
    if not (1 <= certificate_size <= _MAX_MATERIAL_BYTES) or not (
        1 <= private_key_size <= _MAX_MATERIAL_BYTES
    ):
        raise TelemetryTransportError("trust_error")
    return certificate_pem, private_key_pem


def _verify_pinned_server_before_identity(
    target: ResolvedTarget,
    host: str,
    context: ssl.SSLContext,
    expected_pin: bytes,
    deadline: float,
    guard: _DeadlineSocketGuard,
) -> None:
    try:
        with _open_socket(target, _remaining(deadline)) as raw_socket:
            guard.set_socket(raw_socket)
            with context.wrap_socket(raw_socket, server_hostname=host) as tls_socket:
                guard.set_socket(tls_socket)
                peer_der = tls_socket.getpeercert(binary_form=True)
                _remaining(deadline)
            guard.set_socket(None)
    except ssl.SSLCertVerificationError as error:
        raise TelemetryTransportError("trust_error") from error
    except (OSError, ssl.SSLError, TimeoutError) as error:
        raise TelemetryTransportError("unreachable") from error
    if not peer_der or not secrets.compare_digest(hashlib.sha256(peer_der).digest(), expected_pin):
        raise TelemetryTransportError("trust_error")


def _read_framed_json(
    connection: _PinnedHTTPSConnection,
    response: http.client.HTTPResponse,
    *,
    deadline: float,
    maximum_bytes: int,
    require_no_store: bool,
) -> bytes:
    if response.getheader("Transfer-Encoding") is not None:
        raise TelemetryTransportError("protocol_error")
    if response.getheader("Content-Encoding") is not None:
        raise TelemetryTransportError("protocol_error")
    lengths = response.headers.get_all("Content-Length", failobj=[]) or []
    if len(lengths) != 1:
        raise TelemetryTransportError("protocol_error")
    if re.fullmatch(r"[1-9][0-9]*", lengths[0], re.ASCII) is None:
        raise TelemetryTransportError("protocol_error")
    try:
        declared = int(lengths[0])
    except ValueError as error:
        raise TelemetryTransportError("protocol_error") from error
    if declared < 1 or declared > maximum_bytes:
        raise TelemetryTransportError("protocol_error")
    content_types = response.headers.get_all("Content-Type", failobj=[]) or []
    if len(content_types) != 1 or content_types[0].strip().lower() != "application/json":
        raise TelemetryTransportError("protocol_error")
    if require_no_store:
        cache_controls = response.headers.get_all("Cache-Control", failobj=[]) or []
        if len(cache_controls) != 1 or cache_controls[0].strip().lower() != "no-store":
            raise TelemetryTransportError("protocol_error")
    if connection.sock:
        connection.sock.settimeout(_remaining(deadline))
    payload = response.read(maximum_bytes + 1)
    _remaining(deadline)
    if len(payload) != declared or len(payload) > maximum_bytes:
        raise TelemetryTransportError("protocol_error")
    return payload


def _read_ack(
    connection: _PinnedHTTPSConnection,
    *,
    deadline: float,
    max_ack_bytes: int,
    protocol: str,
    expected_batch_id: str | None,
    expected_request_sha256: str | None,
) -> bytes:
    if connection.sock:
        connection.sock.settimeout(_remaining(deadline))
    response = connection.getresponse()
    _remaining(deadline)
    if response.status == 401:
        raise TelemetryTransportError("revoked")
    if response.status == 429:
        retry_after = response.headers.get_all("Retry-After", failobj=[]) or []
        if retry_after != ["5"]:
            raise TelemetryTransportError("protocol_error")
        raise TelemetryTransportError("rate_limited")
    if response.status == 409:
        payload = _read_framed_json(
            connection,
            response,
            deadline=deadline,
            maximum_bytes=_MAX_ERROR_BYTES,
            require_no_store=False,
        )
        if protocol == "2.0":
            if (
                expected_batch_id is not None
                and expected_request_sha256 is not None
                and _is_exact_v2_terminal_error(
                    payload,
                    expected_batch_id=expected_batch_id,
                    expected_request_sha256=expected_request_sha256,
                )
            ):
                raise TelemetryTransportError("immutable_conflict")
            raise TelemetryTransportError("protocol_error")
        if payload in _IMMUTABLE_CONFLICT_BODIES:
            raise TelemetryTransportError("immutable_conflict")
        raise TelemetryTransportError("protocol_error")
    if response.status == 422:
        payload = _read_framed_json(
            connection,
            response,
            deadline=deadline,
            maximum_bytes=_MAX_ERROR_BYTES,
            require_no_store=False,
        )
        if protocol == "1.0" and payload == _EXPIRED_PAYLOAD_BODY:
            raise TelemetryTransportError("expired_payload")
        raise TelemetryTransportError("protocol_error")
    if response.status != 201:
        raise TelemetryTransportError("protocol_error")
    return _read_framed_json(
        connection,
        response,
        deadline=deadline,
        maximum_bytes=max_ack_bytes,
        require_no_store=True,
    )


def _upload_in_worker(
    origin: str,
    fingerprint: str,
    request_bytes: bytes,
    certificate_pem: str,
    private_key_pem: str,
    *,
    timeout: float,
    max_ack_bytes: int = DEFAULT_MAX_ACK_BYTES,
    protocol: str = "1.0",
    authorization_mode: str = "current",
    historical_receipt_sha256: str | None = None,
) -> bytes:
    if (
        protocol not in {"1.0", "2.0"}
        or authorization_mode not in {"current", "historical_backlog"}
        or (authorization_mode == "historical_backlog") != (historical_receipt_sha256 is not None)
        or (
            historical_receipt_sha256 is not None
            and re.fullmatch(r"[A-Za-z0-9_-]{43}", historical_receipt_sha256) is None
        )
        or (protocol != "2.0" and authorization_mode != "current")
        or not math.isfinite(timeout)
        or timeout <= 0
        or timeout > MAX_TIMEOUT_SECONDS
        or type(max_ack_bytes) is not int
        or max_ack_bytes <= 0
        or max_ack_bytes > DEFAULT_MAX_ACK_BYTES
    ):
        raise TelemetryTransportError("protocol_error")
    try:
        origin = validate_https_origin(origin)
        fingerprint = normalize_fingerprint(fingerprint)
    except (TypeError, ValueError) as error:
        raise TelemetryTransportError("protocol_error") from error
    try:
        if protocol == "2.0":
            parsed_request = parse_telemetry_batch_v2(request_bytes)
        else:
            parsed_request = parse_telemetry_batch(request_bytes)
    except (TelemetryValidationError, TelemetryValidationErrorV2) as error:
        raise TelemetryTransportError("protocol_error") from error
    certificate_pem, private_key_pem = _normalize_material(certificate_pem, private_key_pem)
    deadline = time.monotonic() + timeout
    parsed = urlsplit(origin)
    host = parsed.hostname
    if host is None:
        raise TelemetryTransportError("protocol_error")
    port = parsed.port or 443
    guard = _DeadlineSocketGuard(deadline)
    connection = None
    try:
        # DNS runs in this already killable worker process. Spawning the
        # pairing resolver worker here would create a grandchild that could
        # survive when the parent enforces the total deadline.
        targets = _resolve_once(host, port, deadline)
        target, certificate_der = _select_peer(targets, host, deadline, guard)
        expected_pin = bytes.fromhex(fingerprint)
        if not secrets.compare_digest(hashlib.sha256(certificate_der).digest(), expected_pin):
            raise TelemetryTransportError("trust_error")
        context = _pinned_context(certificate_der)
        _verify_pinned_server_before_identity(target, host, context, expected_pin, deadline, guard)
        with _loaded_client_chain(context, (certificate_pem, private_key_pem)):
            connection = _PinnedHTTPSConnection(host, port, target, _remaining(deadline), context)
            connection.connect()
            guard.set_socket(connection.sock)
            if connection.sock:
                connection.sock.settimeout(_remaining(deadline))
                peer_der = connection.sock.getpeercert(binary_form=True)
            else:
                peer_der = None
            if not peer_der or not secrets.compare_digest(
                hashlib.sha256(peer_der).digest(), expected_pin
            ):
                raise TelemetryTransportError("trust_error")
            headers = {
                "Accept": "application/json",
                "Accept-Encoding": "identity",
                "Content-Type": "application/json",
                "One-OS-Telemetry-Protocol": protocol,
            }
            if authorization_mode == "historical_backlog":
                if historical_receipt_sha256 is None:
                    raise TelemetryTransportError("protocol_error")
                headers.update(
                    {
                        "One-OS-Telemetry-Authorization-Mode": authorization_mode,
                        "One-OS-Historical-Authorization-Receipt-Sha256": (
                            historical_receipt_sha256
                        ),
                    }
                )
            connection.request(
                "POST",
                TELEMETRY_PATH,
                body=request_bytes,
                headers=headers,
            )
            return _read_ack(
                connection,
                deadline=deadline,
                max_ack_bytes=max_ack_bytes,
                protocol=protocol,
                expected_batch_id=parsed_request.document["batchId"],
                expected_request_sha256=(
                    parsed_request.request_sha256 if protocol == "2.0" else None
                ),
            )
    except TelemetryTransportError:
        raise
    except DiscoveryError as error:
        raise TelemetryTransportError(str(error)) from error
    except ssl.SSLCertVerificationError as error:
        raise TelemetryTransportError("trust_error") from error
    except http.client.HTTPException as error:
        raise TelemetryTransportError("protocol_error") from error
    except (OSError, ssl.SSLError, TimeoutError) as error:
        raise TelemetryTransportError("unreachable") from error
    finally:
        guard.set_socket(None)
        if connection is not None:
            connection.close()
        guard.close()


class TelemetryUploadTransport:
    """Run one immutable telemetry upload inside a bounded, killable subprocess."""

    def __init__(
        self,
        destination: TelemetryDestinationSnapshot,
        *,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        max_ack_bytes: int = DEFAULT_MAX_ACK_BYTES,
    ) -> None:
        if (
            type(destination) is not TelemetryDestinationSnapshot
            or not math.isfinite(timeout)
            or timeout <= 0
            or timeout > MAX_TIMEOUT_SECONDS
            or type(max_ack_bytes) is not int
            or max_ack_bytes <= 0
            or max_ack_bytes > DEFAULT_MAX_ACK_BYTES
        ):
            raise ValueError("invalid telemetry transport limits")
        self._destination = destination
        self._timeout = timeout
        self._max_ack_bytes = max_ack_bytes

    @property
    def timeout_seconds(self) -> float:
        return self._timeout

    def upload(
        self,
        request_bytes: bytes,
        certificate_pem: str,
        private_key_pem: str,
        *,
        protocol: str = "1.0",
        authorization_mode: str = "current",
        historical_receipt_sha256: str | None = None,
    ) -> bytes:
        deadline = time.monotonic() + self._timeout
        if (
            protocol not in {"1.0", "2.0"}
            or authorization_mode not in {"current", "historical_backlog"}
            or (authorization_mode == "historical_backlog")
            != (historical_receipt_sha256 is not None)
            or (
                historical_receipt_sha256 is not None
                and re.fullmatch(r"[A-Za-z0-9_-]{43}", historical_receipt_sha256) is None
            )
            or (protocol != "2.0" and authorization_mode != "current")
            or not isinstance(request_bytes, bytes)
            or not (1 <= len(request_bytes) <= MAX_BATCH_BYTES)
        ):
            raise TelemetryTransportError("protocol_error")
        try:
            origin, fingerprint = self._destination.read()
            origin = validate_https_origin(origin)
            fingerprint = normalize_fingerprint(fingerprint)
        except (LookupError, TypeError, ValueError) as error:
            raise TelemetryTransportError("trust_error") from error
        except OSError as error:
            raise TelemetryTransportError("unreachable") from error
        try:
            if protocol == "2.0":
                parse_telemetry_batch_v2(request_bytes)
            else:
                parse_telemetry_batch(request_bytes)
        except (TelemetryValidationError, TelemetryValidationErrorV2) as error:
            raise TelemetryTransportError("protocol_error") from error
        try:
            certificate_pem, private_key_pem = _normalize_material(certificate_pem, private_key_pem)
        except (TypeError, ValueError) as error:
            raise TelemetryTransportError("trust_error") from error
        remaining = _remaining(deadline)
        if not _WORKER_SLOTS.acquire(timeout=remaining):
            raise TelemetryTransportError("unreachable")
        process = None
        descriptors: list[int] = []
        try:
            request_fd = _input_memfd("one-os-telemetry-request", request_bytes)
            descriptors.append(request_fd)
            certificate_bytes = certificate_pem.encode("ascii")
            certificate_fd = _input_memfd("one-os-telemetry-certificate", certificate_bytes)
            descriptors.append(certificate_fd)
            private_key_bytes = private_key_pem.encode("ascii")
            private_key_fd = _input_memfd("one-os-telemetry-private-key", private_key_bytes)
            descriptors.append(private_key_fd)
            result_fd = _result_memfd()
            descriptors.append(result_fd)
            process = subprocess.Popen(  # noqa: S603 - fixed interpreter and module
                [sys.executable, "-m", "one_os_addon.telemetry_transport_worker"],
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                text=True,
                pass_fds=tuple(descriptors),
            )
            metadata = json.dumps(
                {
                    "origin": origin,
                    "fingerprint": fingerprint,
                    "timeout": _remaining(deadline),
                    "maxAckBytes": self._max_ack_bytes,
                    "protocol": protocol,
                    "authorizationMode": authorization_mode,
                    "historicalReceiptSha256": historical_receipt_sha256,
                    "requestFd": request_fd,
                    "requestBytes": len(request_bytes),
                    "certificateFd": certificate_fd,
                    "certificateBytes": len(certificate_bytes),
                    "privateKeyFd": private_key_fd,
                    "privateKeyBytes": len(private_key_bytes),
                    "resultFd": result_fd,
                },
                separators=(",", ":"),
            )
            try:
                process.communicate(metadata, timeout=_remaining(deadline))
            except subprocess.TimeoutExpired as error:
                process.kill()
                process.communicate()
                raise TelemetryTransportError("unreachable") from error
            if process.returncode != 0:
                raise TelemetryTransportError("unreachable")
            return _read_result(result_fd, self._max_ack_bytes)
        except TelemetryTransportError:
            raise
        except (OSError, TimeoutError, subprocess.SubprocessError) as error:
            raise TelemetryTransportError("unreachable") from error
        finally:
            if process is not None:
                if process.poll() is None:
                    process.kill()
                    process.wait()
                if process.stdin is not None:
                    process.stdin.close()
            for descriptor in descriptors:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            _WORKER_SLOTS.release()
