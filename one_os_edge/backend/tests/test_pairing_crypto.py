import base64
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec
from one_os_addon.pairing_crypto import (
    P256_ORDER,
    build_certificate_ack_preimage,
    build_claim_pop_preimage,
    build_first_pop_preimage,
    generate_pairing_code,
    normalize_pairing_code,
    sign_low_s,
    verify_raw_low_s,
)

VECTORS = (
    Path(__file__).resolve().parents[3] / "docs/reference/contracts/pairing/v1/signing-vectors.json"
)


def b64u(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def test_canonical_pairing_preimages_match_immutable_local_vectors() -> None:
    fixture = json.loads(VECTORS.read_text(encoding="utf-8"))
    inputs = fixture["inputs"]

    actual = {
        "firstPop": build_first_pop_preimage(inputs),
        "claimPop": build_claim_pop_preimage(inputs),
        "certificateAck": build_certificate_ack_preimage(inputs),
    }

    for name, preimage in actual.items():
        assert preimage == b64u(fixture["vectors"][name]["preimageBase64url"])


def test_pairing_code_is_exactly_100_bits_and_normalization_is_strict() -> None:
    assert generate_pairing_code(lambda _: 0) == "0000-0000-0000-0000-0000"
    assert generate_pairing_code(lambda _: (1 << 100) - 1) == "ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ"
    assert normalize_pairing_code("0123-4567-89ab-cdef-ghjk") == "0123456789ABCDEFGHJK"
    assert normalize_pairing_code("0123456789ABCDEFGHJK") == "0123456789ABCDEFGHJK"

    for invalid in (
        " 0123456789ABCDEFGHJK",
        "01234-5678-9ABC-DEFG-HJK",
        "0123456789ABCDEFGHJI",
        "0123456789ABCDEFGHJO",
        "０123456789ABCDEFGHJK",
    ):
        try:
            normalize_pairing_code(invalid)
        except ValueError:
            pass
        else:
            raise AssertionError(f"accepted invalid code: {invalid!r}")


def test_p256_signatures_are_raw_low_s_and_high_s_is_rejected() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    preimage = b"canonical bytes"

    signature = sign_low_s(key, preimage)

    assert len(signature) == 64
    s = int.from_bytes(signature[32:], "big")
    assert 1 <= s <= P256_ORDER // 2
    verify_raw_low_s(key.public_key(), preimage, signature)
    high_s = signature[:32] + (P256_ORDER - s).to_bytes(32, "big")
    try:
        verify_raw_low_s(key.public_key(), preimage, high_s)
    except ValueError:
        pass
    else:
        raise AssertionError("high-S signature accepted")
