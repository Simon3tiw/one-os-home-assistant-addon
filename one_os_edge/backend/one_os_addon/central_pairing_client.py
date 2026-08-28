from __future__ import annotations

import hashlib
import http.client
import json
import os
import secrets
import socket
import ssl
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any
from urllib.parse import quote, urlsplit

from .central_destination import (
    DiscoveryError,
    ResolvedTarget,
    _open_socket,
    _pinned_context,
    _remaining,
    normalize_fingerprint,
    validate_https_origin,
)

DEFAULT_TIMEOUT_SECONDS = 5.0
DEFAULT_MAX_RESPONSE_BYTES = 64 * 1024
_PAIRING_PATH = "/api/v1/edge/pairing/sessions"
_ACK_PATH = "/api/v1/edge/device/ack"
_CONFIGURATION_SNAPSHOT_PATH = "/api/v1/edge/device/configuration-snapshots"
_CONFIGURATION_STATUS_PATH = "/api/v1/edge/device/configuration-status"
_DEVICE_STATUS_PATH = "/api/v1/edge/device/status"
_RENEWAL_PATH = "/api/v1/edge/device/renewal"
_MAX_CONFIGURATION_SNAPSHOT_BYTES = 2 * 1024 * 1024
_RESOLVER_SLOTS = threading.BoundedSemaphore(2)


class CentralProtocolError(RuntimeError):
    """A deliberately non-sensitive Central pairing transport failure."""


class CentralDeviceRevokedError(CentralProtocolError):
    """Central rejected the currently presented device credential."""


class PairingRequestGate:
    """Bound all pairing traffic to two operations and one request per second."""

    def __init__(self, *, interval: float = 1.0, slots: int = 2) -> None:
        self._interval = interval
        self._slots = threading.BoundedSemaphore(slots)
        self._lock = threading.Lock()
        self._next_request = 0.0

    @contextmanager
    def request(self, deadline: float) -> Iterator[None]:
        if not self._slots.acquire(timeout=_remaining(deadline)):
            raise CentralProtocolError("unreachable")
        try:
            with self._lock:
                delay = self._next_request - time.monotonic()
                if delay > 0:
                    if delay >= _remaining(deadline):
                        raise CentralProtocolError("unreachable")
                    time.sleep(delay)
                _remaining(deadline)
                self._next_request = time.monotonic() + self._interval
            yield
        finally:
            self._slots.release()


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(
        self,
        host: str,
        port: int,
        target: ResolvedTarget,
        timeout: float,
        context: ssl.SSLContext,
    ) -> None:
        super().__init__(host=host, port=port, timeout=timeout, context=context)
        self._target = target
        self._connect_timeout = timeout
        self._tls_context = context

    def connect(self) -> None:
        raw_socket = _open_socket(self._target, self._connect_timeout)
        try:
            self.sock = self._tls_context.wrap_socket(raw_socket, server_hostname=self.host)
        except BaseException:
            raw_socket.close()
            raise


class _DeadlineSocketGuard:
    """Close the current socket at one monotonic deadline and join cleanly."""

    def __init__(self, deadline: float) -> None:
        self._deadline = deadline
        self._finished = threading.Event()
        self._lock = threading.Lock()
        self._socket: socket.socket | None = None
        self._thread = threading.Thread(
            target=self._watch,
            name="central-pairing-deadline",
            daemon=True,
        )
        self._thread.start()

    def _watch(self) -> None:
        if self._finished.wait(max(0.0, self._deadline - time.monotonic())):
            return
        with self._lock:
            current = self._socket
        if current is not None:
            try:
                current.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def set_socket(self, current: socket.socket | None) -> None:
        with self._lock:
            self._socket = current

    def close(self) -> None:
        self._finished.set()
        self._thread.join()


def _resolve_once_hard(host: str, port: int, deadline: float) -> list[ResolvedTarget]:
    process = None
    acquired = False
    try:
        acquired = _RESOLVER_SLOTS.acquire(timeout=_remaining(deadline))
        if not acquired:
            raise CentralProtocolError("unreachable")
        process = subprocess.Popen(  # noqa: S603 - fixed interpreter and module
            [sys.executable, "-m", "one_os_addon.central_pairing_resolver_worker"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        request = json.dumps({"host": host, "port": port}, separators=(",", ":"))
        try:
            output, _stderr = process.communicate(request, timeout=_remaining(deadline))
        except subprocess.TimeoutExpired as error:
            process.kill()
            process.communicate()
            raise CentralProtocolError("unreachable") from error
        if process.returncode != 0 or len(output) > 8192:
            raise CentralProtocolError("unreachable")
        response = json.loads(output)
        if not isinstance(response, dict):
            raise ValueError("invalid resolver response")
        raw_targets = response.get("targets")
        if response.get("ok") is not True or not isinstance(raw_targets, list) or not raw_targets:
            raise CentralProtocolError("unreachable")
        targets = []
        for family, socket_type, protocol, address in raw_targets:
            if not all(type(value) is int for value in (family, socket_type, protocol)):
                raise ValueError("invalid resolver response")
            if not isinstance(address, list):
                raise ValueError("invalid resolver response")
            targets.append(ResolvedTarget(family, socket_type, protocol, tuple(address)))
        _remaining(deadline)
        return targets
    except (json.JSONDecodeError, TypeError, ValueError) as error:
        raise CentralProtocolError("unreachable") from error
    finally:
        if process is not None:
            if process.poll() is None:
                process.kill()
                process.wait()
            if process.stdin is not None:
                process.stdin.close()
            if process.stdout is not None:
                process.stdout.close()
        if acquired:
            _RESOLVER_SLOTS.release()


def _select_peer(
    targets: list[ResolvedTarget],
    host: str,
    deadline: float,
    guard: _DeadlineSocketGuard,
) -> tuple[ResolvedTarget, bytes]:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    for target in targets:
        try:
            with _open_socket(target, _remaining(deadline)) as raw_socket:
                guard.set_socket(raw_socket)
                with context.wrap_socket(raw_socket, server_hostname=host) as tls_socket:
                    guard.set_socket(tls_socket)
                    certificate = tls_socket.getpeercert(binary_form=True)
                guard.set_socket(None)
            if not certificate:
                raise CentralProtocolError("trust_error")
            return target, certificate
        except CentralProtocolError:
            raise
        except (OSError, ssl.SSLError, TimeoutError):
            continue
    raise CentralProtocolError("unreachable")


@contextmanager
def _loaded_client_chain(
    context: ssl.SSLContext, material: tuple[str, str] | None
) -> Iterator[None]:
    if material is None:
        yield
        return
    certificate_pem, private_key_pem = material
    descriptors: list[int] = []
    try:
        for name, value in (
            ("one-os-candidate-certificate", certificate_pem),
            ("one-os-candidate-private-key", private_key_pem),
        ):
            descriptor = os.memfd_create(name, flags=os.MFD_CLOEXEC)
            descriptors.append(descriptor)
            os.fchmod(descriptor, 0o600)
            remaining = memoryview(value.encode("ascii"))
            while remaining:
                written = os.write(descriptor, remaining)
                if written <= 0:
                    raise OSError("short mTLS material write")
                remaining = remaining[written:]
            os.lseek(descriptor, 0, os.SEEK_SET)
        context.load_cert_chain(
            f"/proc/self/fd/{descriptors[0]}", f"/proc/self/fd/{descriptors[1]}"
        )
        yield
    except (OSError, UnicodeError, ssl.SSLError, ValueError) as error:
        raise CentralProtocolError("trust_error") from error
    finally:
        for descriptor in descriptors:
            os.close(descriptor)


def _strict_object(payload: bytes, allowed_shapes: tuple[frozenset[str], ...]) -> dict[str, Any]:
    def unique_object(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise CentralProtocolError("protocol_error")
            value[key] = item
        return value

    try:
        value = json.loads(payload, object_pairs_hook=unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CentralProtocolError("protocol_error") from error
    if not isinstance(value, dict) or frozenset(value) not in allowed_shapes:
        raise CentralProtocolError("protocol_error")
    return value


_REGISTER_SHAPES = (
    frozenset(
        {
            "sessionId",
            "serverNonce",
            "bootstrapToken",
            "tokenGeneration",
            "registrationExpiresAt",
            "sessionRevision",
        }
    ),
)
_PROOF_SHAPES = (frozenset({"sessionId", "status", "codeExpiresAt", "sessionRevision"}),)
_CANCEL_SHAPES = (frozenset({"sessionId", "status"}),)
_CLAIM_PROOF_SHAPES = (
    frozenset(
        {
            "sessionId",
            "status",
            "claimRevision",
            "installationRevision",
            "issuanceExpiresAt",
            "sessionRevision",
        }
    ),
)
_ACK_SHAPES = (
    frozenset(
        {
            "sessionId",
            "installationId",
            "status",
            "installationRevision",
            "credentialId",
            "certificateSha256",
        }
    ),
)
_CONFIGURATION_ACCEPTED_SHAPES = (
    frozenset(
        {
            "status",
            "snapshotId",
            "installationId",
            "configVersion",
            "projectionSha256",
            "acceptedAt",
            "activePointCount",
        }
    ),
)
_CONFIGURATION_STATUS_SHAPES = (
    frozenset({"status", "installationId"}),
    frozenset(
        {
            "status",
            "installationId",
            "configVersion",
            "projectionSha256",
            "acceptedAt",
            "activePointCount",
        }
    ),
)
_DEVICE_STATUS_SHAPES = (
    frozenset(
        {"installationId", "status", "installationRevision", "credentialId", "certificateSha256"}
    ),
)
_RENEWAL_RESULT_SHAPES = (
    frozenset(
        {"requestId", "installationId", "status", "installationRevision", "issuanceExpiresAt"}
    ),
    frozenset(
        {
            "requestId",
            "installationId",
            "status",
            "installationRevision",
            "oldCredentialId",
            "oldCertificateSha256",
            "newCredentialId",
            "newCertificateSha256",
            "certificatePem",
            "caChainPem",
            "ackExpiresAt",
        }
    ),
    frozenset(
        {
            "requestId",
            "installationId",
            "status",
            "installationRevision",
            "oldCredentialId",
            "oldCertificateSha256",
            "newCredentialId",
            "newCertificateSha256",
        }
    ),
    frozenset(
        {
            "requestId",
            "installationId",
            "status",
            "installationRevision",
            "oldCredentialId",
            "oldCertificateSha256",
        }
    ),
)
_RESULT_SHAPES = (
    frozenset({"sessionId", "status", "sessionRevision"}),
    frozenset(
        {
            "sessionId",
            "status",
            "tenantId",
            "siteId",
            "claimNonce",
            "claimExpiresAt",
            "claimRevision",
            "installationRevision",
            "sessionRevision",
        }
    ),
    frozenset(
        {
            "sessionId",
            "installationId",
            "status",
            "claimRevision",
            "installationRevision",
            "issuanceExpiresAt",
            "sessionRevision",
        }
    ),
    frozenset(
        {
            "sessionId",
            "installationId",
            "status",
            "claimRevision",
            "installationRevision",
            "credentialId",
            "certificatePem",
            "certificateSha256",
            "caChainPem",
            "ackExpiresAt",
            "sessionRevision",
        }
    ),
)


class CentralPairingHTTPClient:
    """Strict pinned-HTTPS client for the Edge half of pairing V1."""

    def __init__(
        self,
        destination: Callable[[], tuple[str, str]],
        *,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        max_body: int = DEFAULT_MAX_RESPONSE_BYTES,
        gate: PairingRequestGate | None = None,
    ) -> None:
        if timeout <= 0 or max_body <= 0:
            raise ValueError("invalid pairing client limits")
        self._destination = destination
        self._timeout = timeout
        self._max_body = max_body
        # The background worker owns the 1 rps policy. The transport still
        # bounds concurrent sockets when interactive refreshes race it.
        self._gate = gate or PairingRequestGate(interval=0.0)
        self._resolution_lock = threading.Lock()
        self._resolved_destination: tuple[str, int, list[ResolvedTarget]] | None = None

    def register(self, body: dict[str, Any]) -> dict[str, Any]:
        return self._request(
            "POST",
            _PAIRING_PATH,
            body,
            _REGISTER_SHAPES,
            expected_status=201,
        )

    def proof(self, session_id: str, bootstrap_token: str, body: dict[str, Any]) -> dict[str, Any]:
        return self._request(
            "POST",
            f"{_PAIRING_PATH}/{quote(session_id, safe='')}/proof",
            body,
            _PROOF_SHAPES,
            bootstrap_token=bootstrap_token,
        )

    def result(self, session_id: str, bootstrap_token: str) -> dict[str, Any]:
        return self._request(
            "GET",
            f"{_PAIRING_PATH}/{quote(session_id, safe='')}/result",
            None,
            _RESULT_SHAPES,
            bootstrap_token=bootstrap_token,
            require_no_store=True,
            exact_content_type=True,
        )

    def cancel(
        self, session_id: str, bootstrap_token: str, expected_session_revision: int
    ) -> dict[str, Any]:
        return self._request(
            "POST",
            f"{_PAIRING_PATH}/{quote(session_id, safe='')}/cancel",
            {"expectedSessionRevision": expected_session_revision},
            _CANCEL_SHAPES,
            bootstrap_token=bootstrap_token,
        )

    def claim_proof(
        self, session_id: str, bootstrap_token: str, body: dict[str, Any]
    ) -> dict[str, Any]:
        return self._request(
            "POST",
            f"{_PAIRING_PATH}/{quote(session_id, safe='')}/claim-proof",
            body,
            _CLAIM_PROOF_SHAPES,
            bootstrap_token=bootstrap_token,
        )

    def ack(
        self,
        body: dict[str, Any],
        certificate_pem: str,
        private_key_pem: str,
        bootstrap_token: str,
    ) -> dict[str, Any]:
        return self._request(
            "POST",
            _ACK_PATH,
            body,
            _ACK_SHAPES,
            bootstrap_token=bootstrap_token,
            client_material=(certificate_pem, private_key_pem),
        )

    def upload_configuration_snapshot(
        self, payload: bytes, certificate_pem: str, private_key_pem: str
    ) -> dict[str, Any]:
        if (
            not isinstance(payload, bytes)
            or not payload
            or len(payload) > _MAX_CONFIGURATION_SNAPSHOT_BYTES
        ):
            raise CentralProtocolError("protocol_error")
        return self._request(
            "POST",
            _CONFIGURATION_SNAPSHOT_PATH,
            payload,
            _CONFIGURATION_ACCEPTED_SHAPES,
            client_material=(certificate_pem, private_key_pem),
            expected_status=201,
            require_no_store=True,
            exact_content_type=True,
        )

    def configuration_status(self, certificate_pem: str, private_key_pem: str) -> dict[str, Any]:
        return self._request(
            "GET",
            _CONFIGURATION_STATUS_PATH,
            None,
            _CONFIGURATION_STATUS_SHAPES,
            client_material=(certificate_pem, private_key_pem),
            require_no_store=True,
            exact_content_type=True,
        )

    def device_status(self, certificate_pem: str, private_key_pem: str) -> dict[str, Any]:
        return self._request(
            "GET",
            _DEVICE_STATUS_PATH,
            None,
            _DEVICE_STATUS_SHAPES,
            client_material=(certificate_pem, private_key_pem),
            require_no_store=True,
            exact_content_type=True,
        )

    def start_renewal(
        self, body: dict[str, Any], certificate_pem: str, private_key_pem: str
    ) -> dict[str, Any]:
        return self._request(
            "POST",
            _RENEWAL_PATH,
            body,
            _RENEWAL_RESULT_SHAPES,
            client_material=(certificate_pem, private_key_pem),
            expected_status=202,
            require_no_store=True,
            exact_content_type=True,
        )

    def renewal_result(
        self, request_id: str, certificate_pem: str, private_key_pem: str
    ) -> dict[str, Any]:
        return self._request(
            "GET",
            f"/api/v1/edge/device/renewals/{quote(request_id, safe='')}",
            None,
            _RENEWAL_RESULT_SHAPES,
            client_material=(certificate_pem, private_key_pem),
            require_no_store=True,
            exact_content_type=True,
        )

    def ack_renewal(
        self, request_id: str, body: dict[str, Any], certificate_pem: str, private_key_pem: str
    ) -> dict[str, Any]:
        return self._request(
            "POST",
            f"/api/v1/edge/device/renewals/{quote(request_id, safe='')}/ack",
            body,
            _RENEWAL_RESULT_SHAPES,
            client_material=(certificate_pem, private_key_pem),
            require_no_store=True,
            exact_content_type=True,
        )

    def _request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | bytes | None,
        response_shapes: tuple[frozenset[str], ...],
        *,
        bootstrap_token: str | None = None,
        client_material: tuple[str, str] | None = None,
        expected_status: int = 200,
        require_no_store: bool = False,
        exact_content_type: bool = False,
    ) -> dict[str, Any]:
        deadline = time.monotonic() + self._timeout
        try:
            origin, fingerprint = self._destination()
            origin = validate_https_origin(origin)
            fingerprint = normalize_fingerprint(fingerprint)
        except (LookupError, TypeError, ValueError) as error:
            raise CentralProtocolError("trust_error") from error
        parsed = urlsplit(origin)
        host = parsed.hostname
        if host is None:
            raise CentralProtocolError("protocol_error")
        port = parsed.port or 443

        with self._gate.request(deadline):
            guard = _DeadlineSocketGuard(deadline)
            try:
                with self._resolution_lock:
                    cached = self._resolved_destination
                    if cached is None:
                        targets = _resolve_once_hard(host, port, deadline)
                        self._resolved_destination = (host, port, targets)
                    elif cached[:2] == (host, port):
                        targets = cached[2]
                    else:
                        raise CentralProtocolError("trust_error")
                target, certificate_der = _select_peer(targets, host, deadline, guard)
                expected_pin = bytes.fromhex(fingerprint)
                if not secrets.compare_digest(
                    hashlib.sha256(certificate_der).digest(), expected_pin
                ):
                    raise CentralProtocolError("trust_error")
                context = _pinned_context(certificate_der)
                with _loaded_client_chain(context, client_material):
                    return self._exchange(
                        context,
                        target,
                        host,
                        port,
                        deadline,
                        method,
                        path,
                        body,
                        response_shapes,
                        fingerprint,
                        bootstrap_token,
                        expected_status,
                        require_no_store,
                        exact_content_type,
                        guard,
                    )
            except CentralProtocolError:
                raise
            except DiscoveryError as error:
                raise CentralProtocolError(str(error)) from error
            except ssl.SSLCertVerificationError as error:
                raise CentralProtocolError("trust_error") from error
            except http.client.HTTPException as error:
                raise CentralProtocolError("protocol_error") from error
            except (OSError, ssl.SSLError, TimeoutError) as error:
                raise CentralProtocolError("unreachable") from error
            finally:
                guard.close()

    def _exchange(
        self,
        context: ssl.SSLContext,
        target: ResolvedTarget,
        host: str,
        port: int,
        deadline: float,
        method: str,
        path: str,
        body: dict[str, Any] | bytes | None,
        response_shapes: tuple[frozenset[str], ...],
        fingerprint: str,
        bootstrap_token: str | None,
        expected_status: int,
        require_no_store: bool,
        exact_content_type: bool,
        guard: _DeadlineSocketGuard,
    ) -> dict[str, Any]:
        connection = _PinnedHTTPSConnection(host, port, target, _remaining(deadline), context)
        wire_body = (
            body
            if isinstance(body, bytes)
            else json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
            if body is not None
            else None
        )
        headers = {"Accept": "application/json", "Accept-Encoding": "identity"}
        if wire_body is not None:
            headers["Content-Type"] = "application/json"
        if bootstrap_token is not None:
            headers["Authorization"] = f"PairingBootstrap {bootstrap_token}"
        try:
            connection.connect()
            guard.set_socket(connection.sock)
            if connection.sock:
                connection.sock.settimeout(_remaining(deadline))
                peer_der = connection.sock.getpeercert(binary_form=True)
            else:
                peer_der = None
            if not peer_der or not secrets.compare_digest(
                hashlib.sha256(peer_der).digest(), bytes.fromhex(fingerprint)
            ):
                raise CentralProtocolError("trust_error")
            connection.request(method, path, body=wire_body, headers=headers)
            if connection.sock:
                connection.sock.settimeout(_remaining(deadline))
            response = connection.getresponse()
            _remaining(deadline)
            if response.status == 401 and path.startswith("/api/v1/edge/device/"):
                raise CentralDeviceRevokedError("revoked")
            if response.status != expected_status:
                raise CentralProtocolError("protocol_error")
            if response.getheader("Transfer-Encoding") is not None:
                raise CentralProtocolError("protocol_error")
            if response.getheader("Content-Encoding") is not None:
                raise CentralProtocolError("protocol_error")
            lengths = response.headers.get_all("Content-Length", failobj=[]) or []
            if len(lengths) != 1:
                raise CentralProtocolError("protocol_error")
            try:
                declared = int(lengths[0])
            except ValueError as error:
                raise CentralProtocolError("protocol_error") from error
            if declared < 0 or declared > self._max_body:
                raise CentralProtocolError("protocol_error")
            content_types = response.headers.get_all("Content-Type", failobj=[]) or []
            if len(content_types) != 1:
                raise CentralProtocolError("protocol_error")
            content_type = content_types[0].strip().lower()
            if exact_content_type:
                if content_type != "application/json":
                    raise CentralProtocolError("protocol_error")
            elif content_type.split(";", 1)[0].strip() != "application/json":
                raise CentralProtocolError("protocol_error")
            if require_no_store:
                cache_controls = response.headers.get_all("Cache-Control", failobj=[]) or []
                if len(cache_controls) != 1 or cache_controls[0].strip().lower() != "no-store":
                    raise CentralProtocolError("protocol_error")
            if connection.sock:
                connection.sock.settimeout(_remaining(deadline))
            payload = response.read(self._max_body + 1)
            _remaining(deadline)
            if len(payload) != declared or len(payload) > self._max_body:
                raise CentralProtocolError("protocol_error")
            return _strict_object(payload, response_shapes)
        finally:
            guard.set_socket(None)
            connection.close()
