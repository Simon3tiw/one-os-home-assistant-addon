#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import json
import struct
from pathlib import Path
from uuid import UUID


def b64u_decode(value: str) -> bytes:
    if not isinstance(value, str) or "=" in value:
        raise ValueError("non-canonical base64url")
    decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != value:
        raise ValueError("non-canonical base64url")
    return decoded


def encode(domain: str, fields: list[tuple[int, bytes]]) -> bytes:
    return domain.encode("ascii") + b"\0" + b"".join(
        struct.pack(">HI", tag, len(value)) + value for tag, value in fields
    )


def uuid_bytes(value: str) -> bytes:
    parsed = UUID(value)
    if parsed.version != 4 or str(parsed) != value:
        raise ValueError("UUID must be canonical v4")
    return parsed.bytes


def u64(value: int) -> bytes:
    if type(value) is not int or not 0 <= value < 2**64:
        raise ValueError("uint64 out of range")
    return value.to_bytes(8, "big")


def check(vector: dict[str, str], preimage: bytes) -> None:
    if b64u_decode(vector["preimageBase64url"]) != preimage:
        raise ValueError("preimage mismatch")
    if b64u_decode(vector["sha256Base64url"]) != hashlib.sha256(preimage).digest():
        raise ValueError("digest mismatch")


def main() -> None:
    source = Path(__file__).with_name("signing-vectors.json")
    document = json.loads(source.read_text(encoding="utf-8"))
    values = document["inputs"]
    vectors = document["vectors"]
    first = encode(
        "ONE.OS-PAIRING-SESSION-PROOF-V1",
        [
            (1, values["protocol"].encode("ascii")),
            (2, uuid_bytes(values["sessionId"])),
            (3, uuid_bytes(values["installationId"])),
            (4, b64u_decode(values["spkiSha256"])),
            (5, b64u_decode(values["csrSha256"])),
            (6, b64u_decode(values["edgeNonce"])),
            (7, b64u_decode(values["serverNonce"])),
            (8, u64(values["registrationExpiresEpochSeconds"])),
            (9, b64u_decode(values["codeSha256"])),
        ],
    )
    claim = encode(
        "ONE.OS-PAIRING-CLAIM-PROOF-V1",
        [
            (1, values["protocol"].encode("ascii")),
            (2, uuid_bytes(values["sessionId"])),
            (3, uuid_bytes(values["installationId"])),
            (4, b64u_decode(values["spkiSha256"])),
            (5, values["tenantId"].encode("utf-8")),
            (6, values["siteId"].encode("utf-8")),
            (7, b64u_decode(values["claimNonce"])),
            (8, u64(values["claimExpiresEpochSeconds"])),
            (9, u64(values["claimRevision"])),
            (10, b64u_decode(values["csrSha256"])),
            (11, u64(values["installationRevision"])),
        ],
    )
    ack = encode(
        "ONE.OS-PAIRING-CERT-ACK-V1",
        [
            (1, values["protocol"].encode("ascii")),
            (2, uuid_bytes(values["sessionId"])),
            (3, uuid_bytes(values["installationId"])),
            (4, uuid_bytes(values["credentialId"])),
            (5, b64u_decode(values["certificateSha256"])),
            (6, u64(values["claimRevision"])),
            (7, u64(values["installationRevision"])),
        ],
    )
    renewal = encode(
        "ONE.OS-DEVICE-RENEW-V1",
        [
            (1, values["protocol"].encode("ascii")),
            (2, uuid_bytes(values["installationId"])),
            (3, uuid_bytes(values["credentialId"])),
            (4, b64u_decode(values["certificateSha256"])),
            (5, uuid_bytes(values["renewalRequestId"])),
            (6, b64u_decode(values["csrSha256"])),
            (7, b64u_decode(values["edgeNonce"])),
            (8, u64(values["renewalEpochMinute"])),
            (9, u64(values["installationRevision"])),
        ],
    )
    renewal_ack = encode(
        "ONE.OS-DEVICE-RENEW-ACK-V1",
        [
            (1, values["protocol"].encode("ascii")),
            (2, uuid_bytes(values["installationId"])),
            (3, uuid_bytes(values["credentialId"])),
            (4, b64u_decode(values["certificateSha256"])),
            (5, uuid_bytes(values["newCredentialId"])),
            (6, b64u_decode(values["newCertificateSha256"])),
            (7, uuid_bytes(values["renewalRequestId"])),
            (8, u64(values["renewalAckExpiresEpochSeconds"])),
            (9, u64(values["installationRevision"])),
        ],
    )
    check(vectors["firstPop"], first)
    check(vectors["claimPop"], claim)
    check(vectors["certificateAck"], ack)
    check(vectors["renewalProof"], renewal)
    check(vectors["renewalAck"], renewal_ack)
    print("pairing_v1_vectors=exact")


if __name__ == "__main__":
    main()
