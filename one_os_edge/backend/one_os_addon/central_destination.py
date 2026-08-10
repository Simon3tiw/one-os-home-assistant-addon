from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import socket
import ssl
import subprocess
import sys
import threading
import time
from typing import NamedTuple
from urllib.parse import urlsplit

DISCOVERY_PATH = "/api/v1/edge/discovery"
DEFAULT_TIMEOUT_SECONDS = 5.0
DEFAULT_MAX_RESPONSE_BYTES = 64 * 1024
_WORKER_SLOTS = threading.BoundedSemaphore(2)


class DiscoveryError(Exception):
    """A safe, non-sensitive destination connection-test failure."""


class ResolvedTarget(NamedTuple):
    family: int
    socket_type: int
    protocol: int
    address: tuple


def normalize_fingerprint(value: str) -> str:
    compact = value.replace(":", "")
    if len(compact) != 64 or any(
        character not in "0123456789abcdefABCDEF" for character in compact
    ):
        raise ValueError("invalid_certificate_fingerprint")
    return compact.lower()


def validate_https_origin(value: str) -> str:
    if not value or any(character.isspace() for character in value) or "%" in value:
        raise ValueError("invalid_central_origin")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise ValueError("invalid_central_origin") from error
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or not parsed.netloc
        or (port is not None and not 1 <= port <= 65535)
    ):
        raise ValueError("invalid_central_origin")
    host = parsed.hostname
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if not host.isascii() or host.endswith(".") or all(c in "0123456789." for c in host):
            raise ValueError("invalid_central_origin") from None
        try:
            canonical_host = host.encode("idna").decode("ascii").lower()
        except UnicodeError as error:
            raise ValueError("invalid_central_origin") from error
        if (
            not canonical_host
            or len(canonical_host) > 253
            or any(not label or len(label) > 63 for label in canonical_host.split("."))
        ):
            raise ValueError("invalid_central_origin") from None
    else:
        canonical_host = address.compressed
        if address.version == 6:
            canonical_host = f"[{canonical_host}]"
    canonical = f"https://{canonical_host}" + (f":{port}" if port is not None else "")
    if value != canonical:
        raise ValueError("invalid_central_origin")
    return value


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise DiscoveryError("unreachable")
    return remaining


def _resolve_once(host: str, port: int, deadline: float) -> list[ResolvedTarget]:
    try:
        targets = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as error:
        raise DiscoveryError("unreachable") from error
    _remaining(deadline)
    if not targets:
        raise DiscoveryError("unreachable")
    resolved = []
    seen_addresses = set()
    for family, socket_type, protocol, _canonical_name, address in targets:
        key = (family, socket_type, protocol, address)
        if key not in seen_addresses:
            seen_addresses.add(key)
            resolved.append(ResolvedTarget(family, socket_type, protocol, address))
        if len(resolved) == 4:
            break
    return resolved


def _select_reachable_target(
    targets: list[ResolvedTarget],
    host: str,
    deadline: float,
) -> tuple[ResolvedTarget, bytes]:
    for target in targets:
        try:
            return target, _peer_certificate_der(target, host, _remaining(deadline))
        except DiscoveryError as error:
            if str(error) != "unreachable":
                raise
    raise DiscoveryError("unreachable")


def _open_socket(target: ResolvedTarget, timeout: float) -> socket.socket:
    raw_socket = socket.socket(target.family, target.socket_type, target.protocol)
    try:
        raw_socket.settimeout(timeout)
        raw_socket.connect(target.address)
        return raw_socket
    except BaseException:
        raw_socket.close()
        raise


def _peer_certificate_der(
    target: ResolvedTarget,
    host: str,
    timeout: float,
) -> bytes:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with _open_socket(target, timeout) as raw_socket:
            with context.wrap_socket(raw_socket, server_hostname=host) as tls_socket:
                certificate = tls_socket.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError, TimeoutError) as error:
        raise DiscoveryError("unreachable") from error
    if not certificate:
        raise DiscoveryError("trust_error")
    return certificate


def _pinned_context(certificate_der: bytes) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = True
    context.hostname_checks_common_name = False
    context.verify_mode = ssl.CERT_REQUIRED
    certificate_pem = ssl.DER_cert_to_PEM_cert(certificate_der)
    context.load_verify_locations(cadata=certificate_pem)
    if hasattr(ssl, "VERIFY_X509_PARTIAL_CHAIN"):
        context.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    return context


class _ResolvedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(
        self,
        host: str,
        port: int,
        target: ResolvedTarget,
        timeout: float,
        context: ssl.SSLContext,
    ) -> None:
        super().__init__(host=host, port=port, timeout=timeout, context=context)
        self._resolved_target = target
        self._connection_timeout = timeout
        self._tls_context = context

    def connect(self) -> None:
        raw_socket = _open_socket(self._resolved_target, self._connection_timeout)
        try:
            self.sock = self._tls_context.wrap_socket(raw_socket, server_hostname=self.host)
        except BaseException:
            raw_socket.close()
            raise


def _test_pinned_discovery_in_worker(
    origin: str,
    fingerprint: str,
    *,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
) -> dict[str, str | bool]:
    """Fetch only the pinned Central discovery resource over verified TLS."""
    try:
        validated_origin = validate_https_origin(origin)
        expected_fingerprint = normalize_fingerprint(fingerprint)
    except ValueError as error:
        raise DiscoveryError("protocol_error") from error
    if timeout <= 0 or max_response_bytes <= 0:
        raise DiscoveryError("protocol_error")
    deadline = time.monotonic() + timeout
    parsed = urlsplit(validated_origin)
    host = parsed.hostname
    if host is None:
        raise DiscoveryError("protocol_error")
    port = parsed.port or 443
    targets = _resolve_once(host, port, deadline)
    target, certificate_der = _select_reachable_target(targets, host, deadline)
    if hashlib.sha256(certificate_der).hexdigest() != expected_fingerprint:
        raise DiscoveryError("trust_error")

    connection = _ResolvedHTTPSConnection(
        host=host,
        port=port,
        target=target,
        timeout=_remaining(deadline),
        context=_pinned_context(certificate_der),
    )
    try:
        connection.connect()
        if connection.sock:
            connection.sock.settimeout(_remaining(deadline))
        peer_der = connection.sock.getpeercert(binary_form=True) if connection.sock else None
        if not peer_der or hashlib.sha256(peer_der).hexdigest() != expected_fingerprint:
            raise DiscoveryError("trust_error")
        connection.request("GET", DISCOVERY_PATH, headers={"Accept": "application/json"})
        if connection.sock:
            connection.sock.settimeout(_remaining(deadline))
        response = connection.getresponse()
        if response.status != 200:
            raise DiscoveryError("protocol_error")
        if response.getheader("Transfer-Encoding") is not None:
            raise DiscoveryError("protocol_error")
        content_lengths = response.headers.get_all("Content-Length", failobj=[]) or []
        if len(content_lengths) > 1:
            raise DiscoveryError("protocol_error")
        declared_content_length = None
        if content_lengths:
            try:
                declared_content_length = int(content_lengths[0])
            except ValueError as error:
                raise DiscoveryError("protocol_error") from error
            if declared_content_length < 0 or declared_content_length > max_response_bytes:
                raise DiscoveryError("protocol_error")
        content_type = response.getheader("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            raise DiscoveryError("protocol_error")
        if connection.sock:
            connection.sock.settimeout(_remaining(deadline))
        payload = response.read(max_response_bytes + 1)
        if len(payload) > max_response_bytes or (
            declared_content_length is not None and len(payload) != declared_content_length
        ):
            raise DiscoveryError("protocol_error")
    except DiscoveryError:
        raise
    except ssl.SSLCertVerificationError as error:
        raise DiscoveryError("trust_error") from error
    except http.client.HTTPException as error:
        raise DiscoveryError("protocol_error") from error
    except (OSError, ssl.SSLError, TimeoutError) as error:
        raise DiscoveryError("unreachable") from error
    finally:
        connection.close()

    try:
        document = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DiscoveryError("protocol_error") from error
    valid_capability_tuples = {
        (False, "2B.1-sandbox-foundation"),
        (True, "2B.2-secure-pairing"),
        (True, "2B.3-selected-configuration-sync"),
    }
    if (
        not isinstance(document, dict)
        or set(document) != {"service", "schemaVersion", "pairingSupported", "phase"}
        or document.get("service") != "one-os-central"
        or document.get("schemaVersion") != "1.0"
        or not isinstance(document.get("pairingSupported"), bool)
        or (document.get("pairingSupported"), document.get("phase")) not in valid_capability_tuples
    ):
        raise DiscoveryError("protocol_error")
    return {
        "service": document["service"],
        "schemaVersion": document["schemaVersion"],
        "pairingSupported": document["pairingSupported"],
        "phase": document["phase"],
    }


def test_pinned_discovery(
    origin: str,
    fingerprint: str,
    *,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
) -> dict[str, str | bool]:
    """Run the entire pinned request in a killable, concurrency-bounded worker."""
    try:
        validated_origin = validate_https_origin(origin)
        expected_fingerprint = normalize_fingerprint(fingerprint)
    except ValueError as error:
        raise DiscoveryError("protocol_error") from error
    if timeout <= 0 or max_response_bytes <= 0:
        raise DiscoveryError("protocol_error")

    deadline = time.monotonic() + timeout
    if not _WORKER_SLOTS.acquire(timeout=_remaining(deadline)):
        raise DiscoveryError("unreachable")
    process = None
    try:
        process = subprocess.Popen(  # noqa: S603 - fixed interpreter and module
            [sys.executable, "-m", "one_os_addon.central_destination_worker"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        request = json.dumps(
            {
                "origin": validated_origin,
                "fingerprint": expected_fingerprint,
                "timeout": _remaining(deadline),
                "maxResponseBytes": max_response_bytes,
            }
        )
        try:
            output, _stderr = process.communicate(request, timeout=_remaining(deadline))
        except subprocess.TimeoutExpired as error:
            process.kill()
            process.communicate()
            raise DiscoveryError("unreachable") from error
        if process.returncode != 0 or len(output) > 4096:
            raise DiscoveryError("unreachable")
        try:
            response = json.loads(output)
        except json.JSONDecodeError as error:
            raise DiscoveryError("protocol_error") from error
        if not isinstance(response, dict) or response.get("ok") is not True:
            code = response.get("error") if isinstance(response, dict) else None
            if code not in {"trust_error", "protocol_error", "unreachable"}:
                code = "protocol_error"
            raise DiscoveryError(code)
        result = response.get("result")
        if not isinstance(result, dict):
            raise DiscoveryError("protocol_error")
        return result
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        _WORKER_SLOTS.release()


# Prevent pytest from collecting this imported public function as a test.
test_pinned_discovery.__test__ = False
