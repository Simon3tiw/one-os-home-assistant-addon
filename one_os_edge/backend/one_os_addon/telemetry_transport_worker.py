from __future__ import annotations

import fcntl
import json
import os
import sys

from .telemetry_contract_v1 import MAX_BATCH_BYTES
from .telemetry_transport import (
    _INPUT_SEALS,
    DEFAULT_MAX_ACK_BYTES,
    TelemetryTransportError,
    _strict_json,
    _upload_in_worker,
)

_MAX_INPUT_CHARS = 4096
_MAX_MATERIAL_BYTES = 64 * 1024
_SAFE_ERRORS = frozenset(
    {
        "immutable_conflict",
        "protocol_error",
        "rate_limited",
        "revoked",
        "trust_error",
        "unreachable",
    }
)
_METADATA_FIELDS = {
    "origin",
    "fingerprint",
    "timeout",
    "maxAckBytes",
    "requestFd",
    "requestBytes",
    "certificateFd",
    "certificateBytes",
    "privateKeyFd",
    "privateKeyBytes",
    "resultFd",
}


def _read_sealed(descriptor: int, expected_size: int, maximum_size: int) -> bytes:
    if type(descriptor) is not int or descriptor < 3:
        raise ValueError("invalid descriptor")
    if type(expected_size) is not int or not 1 <= expected_size <= maximum_size:
        raise ValueError("invalid size")
    stat = os.fstat(descriptor)
    if stat.st_size != expected_size:
        raise ValueError("invalid descriptor size")
    seals = fcntl.fcntl(descriptor, fcntl.F_GET_SEALS)
    if seals & _INPUT_SEALS != _INPUT_SEALS:
        raise ValueError("unsealed input")
    os.lseek(descriptor, 0, os.SEEK_SET)
    value = bytearray()
    while len(value) < expected_size:
        chunk = os.read(descriptor, expected_size - len(value))
        if not chunk:
            raise ValueError("truncated descriptor")
        value.extend(chunk)
    return bytes(value)


def _emit(descriptor: int, payload: bytes) -> None:
    if type(descriptor) is not int or descriptor < 3:
        raise ValueError("invalid result descriptor")
    if os.fstat(descriptor).st_size != 0:
        raise ValueError("non-empty result descriptor")
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("result write failed")
        view = view[written:]
    fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, _INPUT_SEALS)


def main() -> int:
    result_fd: int | None = None
    descriptors: set[int] = set()
    try:
        raw = sys.stdin.read(_MAX_INPUT_CHARS + 1)
        if len(raw) > _MAX_INPUT_CHARS:
            raise ValueError("oversized input")
        metadata = _strict_json(raw)
        if set(metadata) != _METADATA_FIELDS:
            raise ValueError("invalid input shape")
        if (
            type(metadata["timeout"]) not in {int, float}
            or type(metadata["maxAckBytes"]) is not int
        ):
            raise ValueError("invalid limits")
        if not isinstance(metadata["origin"], str) or not isinstance(metadata["fingerprint"], str):
            raise ValueError("invalid strings")
        descriptor_names = ("requestFd", "certificateFd", "privateKeyFd", "resultFd")
        descriptors = {metadata[name] for name in descriptor_names}
        if len(descriptors) != len(descriptor_names) or any(
            type(descriptor) is not int or descriptor < 3 for descriptor in descriptors
        ):
            raise ValueError("invalid descriptors")
        result_fd = metadata["resultFd"]
        assert isinstance(result_fd, int)
        request_bytes = _read_sealed(
            metadata["requestFd"], metadata["requestBytes"], MAX_BATCH_BYTES
        )
        certificate_pem = _read_sealed(
            metadata["certificateFd"], metadata["certificateBytes"], _MAX_MATERIAL_BYTES
        ).decode("ascii")
        private_key_pem = _read_sealed(
            metadata["privateKeyFd"], metadata["privateKeyBytes"], _MAX_MATERIAL_BYTES
        ).decode("ascii")
        max_ack_bytes = metadata["maxAckBytes"]
        if not 1 <= max_ack_bytes <= DEFAULT_MAX_ACK_BYTES:
            raise ValueError("invalid ack size")
        ack = _upload_in_worker(
            metadata["origin"],
            metadata["fingerprint"],
            request_bytes,
            certificate_pem,
            private_key_pem,
            timeout=float(metadata["timeout"]),
            max_ack_bytes=max_ack_bytes,
        )
        _emit(result_fd, b"A" + ack)
    except TelemetryTransportError as error:
        code = str(error)
        if result_fd is None:
            return 1
        _emit(
            result_fd, b"E" + (code if code in _SAFE_ERRORS else "protocol_error").encode("ascii")
        )
    except (TypeError, ValueError, UnicodeError, json.JSONDecodeError):
        if result_fd is None:
            return 1
        _emit(result_fd, b"Eprotocol_error")
    except Exception:
        if result_fd is None:
            return 1
        _emit(result_fd, b"Eunreachable")
    finally:
        for descriptor in descriptors:
            try:
                os.close(descriptor)
            except OSError:
                pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
