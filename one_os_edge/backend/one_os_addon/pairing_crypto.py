from __future__ import annotations

import base64
import re
import secrets
import struct
from collections.abc import Callable, Mapping
from typing import Any
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

PAIRING_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_CODE_PLAIN = re.compile(r"[0-9A-HJKMNP-TV-Z]{20}", re.ASCII)
_CODE_SHOWN = re.compile(r"[0-9A-HJKMNP-TV-Z]{4}(?:-[0-9A-HJKMNP-TV-Z]{4}){4}", re.ASCII)


def _b64u(value: str, length: int) -> bytes:
    if "=" in value or not re.fullmatch(r"[A-Za-z0-9_-]+", value, re.ASCII):
        raise ValueError("invalid base64url")
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except ValueError as error:
        raise ValueError("invalid base64url") from error
    if len(decoded) != length:
        raise ValueError("invalid decoded length")
    return decoded


def _uuid(value: str) -> bytes:
    parsed = UUID(value)
    if parsed.version != 4 or str(parsed) != value:
        raise ValueError("invalid UUIDv4")
    return parsed.bytes


def _uint64(value: int) -> bytes:
    if type(value) is not int or not 0 <= value < 1 << 64:
        raise ValueError("invalid uint64")
    return struct.pack(">Q", value)


def _text(value: str, pattern: str | None = None) -> bytes:
    if not isinstance(value, str) or "\x00" in value or value.startswith("\ufeff"):
        raise ValueError("invalid text")
    encoded = value.encode("utf-8", errors="strict")
    if pattern and not re.fullmatch(pattern, value, re.ASCII):
        raise ValueError("invalid identifier")
    return encoded


def _preimage(domain: str, fields: list[bytes]) -> bytes:
    output = bytearray(domain.encode("ascii") + b"\0")
    for tag, value in enumerate(fields, 1):
        output.extend(struct.pack(">HI", tag, len(value)))
        output.extend(value)
    return bytes(output)


def build_first_pop_preimage(values: Mapping[str, Any]) -> bytes:
    return _preimage(
        "ONE.OS-PAIRING-SESSION-PROOF-V1",
        [
            _text(values["protocol"]),
            _uuid(values["sessionId"]),
            _uuid(values["installationId"]),
            _b64u(values["spkiSha256"], 32),
            _b64u(values["csrSha256"], 32),
            _b64u(values["edgeNonce"], 32),
            _b64u(values["serverNonce"], 32),
            _uint64(values["registrationExpiresEpochSeconds"]),
            _b64u(values["codeSha256"], 32),
        ],
    )


def build_claim_pop_preimage(values: Mapping[str, Any]) -> bytes:
    return _preimage(
        "ONE.OS-PAIRING-CLAIM-PROOF-V1",
        [
            _text(values["protocol"]),
            _uuid(values["sessionId"]),
            _uuid(values["installationId"]),
            _b64u(values["spkiSha256"], 32),
            _text(values["tenantId"], r"[a-z0-9][a-z0-9._-]{0,35}"),
            _text(values["siteId"], r"[a-z0-9][a-z0-9._-]{0,119}"),
            _b64u(values["claimNonce"], 32),
            _uint64(values["claimExpiresEpochSeconds"]),
            _uint64(values["claimRevision"]),
            _b64u(values["csrSha256"], 32),
            _uint64(values["installationRevision"]),
        ],
    )


def build_certificate_ack_preimage(values: Mapping[str, Any]) -> bytes:
    return _preimage(
        "ONE.OS-PAIRING-CERT-ACK-V1",
        [
            _text(values["protocol"]),
            _uuid(values["sessionId"]),
            _uuid(values["installationId"]),
            _uuid(values["credentialId"]),
            _b64u(values["certificateSha256"], 32),
            _uint64(values["claimRevision"]),
            _uint64(values["installationRevision"]),
        ],
    )


def sign_low_s(private_key: ec.EllipticCurvePrivateKey, preimage: bytes) -> bytes:
    if not isinstance(private_key.curve, ec.SECP256R1):
        raise ValueError("P-256 key required")
    der = private_key.sign(preimage, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    s = min(s, P256_ORDER - s)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def verify_raw_low_s(
    public_key: ec.EllipticCurvePublicKey, preimage: bytes, signature: bytes
) -> None:
    if not isinstance(public_key.curve, ec.SECP256R1) or len(signature) != 64:
        raise ValueError("invalid signature")
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    if not 1 <= r < P256_ORDER or not 1 <= s <= P256_ORDER // 2:
        raise ValueError("invalid signature")
    try:
        public_key.verify(encode_dss_signature(r, s), preimage, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as error:
        raise ValueError("invalid signature") from error


def generate_pairing_code(randbits: Callable[[int], int] = secrets.randbits) -> str:
    value = randbits(100)
    if type(value) is not int or not 0 <= value < 1 << 100:
        raise ValueError("random source returned invalid value")
    normalized = "".join(PAIRING_ALPHABET[(value >> shift) & 31] for shift in range(95, -1, -5))
    return "-".join(normalized[index : index + 4] for index in range(0, 20, 4))


def normalize_pairing_code(value: str) -> str:
    if not isinstance(value, str) or not value.isascii():
        raise ValueError("invalid pairing code")
    upper = value.upper()
    if _CODE_PLAIN.fullmatch(upper):
        return upper
    if _CODE_SHOWN.fullmatch(upper):
        return upper.replace("-", "")
    raise ValueError("invalid pairing code")
