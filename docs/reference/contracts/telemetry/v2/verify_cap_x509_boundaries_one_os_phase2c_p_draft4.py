#!/usr/bin/env python3
"""Read-only verifier for stopped public Draft-4 cap/X.509 boundary evidence."""
from __future__ import annotations

BUNDLE_ID = 'phase2c-p-telemetry-authority-v2-draft4-20260825'
ROLE_ID = 'cap_x509_boundary_verifier'
GENERATION = 4
CANDIDATE_STATUS = 'UNFROZEN_STAGING'
ROLE_API_VERSION = 1

import base64
from datetime import datetime, timezone

import json
from pathlib import Path
import sys
from typing import Any, Callable

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from strict_wire_one_os_phase2c_p_draft4 import Reject, canonical_json_bytes, strict_decode_canonical, validate_exact_schema
from protocol_helpers_one_os_phase2c_p_draft4 import ProtocolError, der_spki, method1_ski, register_issuer_serial, sha, start_preimage, unb64, verify_csr, verify_leaf, verify_leaf_profile, verify_raw, verify_root
from verify_semantics_one_os_phase2c_p_draft4 import parse_utctime
from protocol_helpers_one_os_phase2c_p_draft4 import parse_time

HERE = Path(__file__).resolve().parent
EVIDENCE = HERE / "one-os-phase2c-p-cap-x509-boundaries-v2-draft4-20260825.json"

SCHEMA = HERE / "one-os-phase2c-p-renewal-control-v2-draft4-20260825.schema.json"
BATCH_SCHEMA = HERE / "one-os-phase2c-p-telemetry-batch-v2-draft4-20260825.schema.json"
MAX_SERIAL = 2**159 - 1
ISSUANCE = datetime(2030, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


class CapReject(Exception):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def require(condition: bool, code: str) -> None:
    if not condition:
        raise CapReject(code)


def exact_keys(value: dict[str, Any], keys: set[str], code: str) -> None:
    require(type(value) is dict and set(value) == keys, code)


def expect_reject(label: str, exc_type: type[BaseException], code: str | None, fn: Callable[[], Any], got: list[str]) -> None:
    try:
        fn()
    except exc_type as exc:
        observed = exc.code if isinstance(exc, CapReject) else str(exc)
        require(code is None or observed == code, "D4C_NEGATIVE_WRONG_GUARD")
        got.append(label)
        return
    raise CapReject("D4C_NEGATIVE_ACCEPTED")


def builder_reject(serial: int, code: str) -> None:
    try: x509.CertificateBuilder().serial_number(serial)
    except ValueError as exc: raise CapReject(code) from exc
    raise CapReject("D4C_NEGATIVE_ACCEPTED")


def malformed_private_csr_reject(raw: bytes, installation: str, credential: str) -> None:
    try: verify_csr(raw, installation, credential)
    except ValueError as exc: raise CapReject("D4C_CSR_ASN1") from exc


def exact_schema(obj: dict[str, Any], schema: dict[str, Any]) -> None:
    try:
        validate_exact_schema(obj, schema, schema_registry={schema["$id"]: schema})
    except Reject as exc:
        raise CapReject("D4C_SECTION_SCHEMA") from exc


def envelope(raw: bytes, cap: int, schema: dict[str, Any]) -> dict[str, Any]:
    if len(raw) > cap:
        raise ProtocolError("D4S_OBJECT_BYTE_CAP")
    obj = strict_decode_canonical(raw, max_bytes=cap, expected_root=dict)
    exact_schema(obj, schema)
    return obj


def bound_section(section: dict[str, Any], schema: dict[str, Any]) -> tuple[bytes, dict[str, Any]]:
    exact_keys(section, {"canonicalUtf8", "length", "object", "sha256"}, "D4C_SECTION_SHAPE")
    raw = section["canonicalUtf8"].encode("utf-8")
    require(len(raw) == section["length"] and sha(raw) == section["sha256"], "D4C_SECTION_BINDING")
    obj = strict_decode_canonical(raw, max_bytes=len(raw), expected_root=dict)
    require(obj == section["object"], "D4C_SECTION_BINDING")
    exact_schema(obj, schema)
    return raw, obj


def public_only(node: Any) -> None:
    if type(node) is dict:
        for value in node.values():
            public_only(value)
    elif type(node) is list:
        for value in node:
            public_only(value)
    elif type(node) is str and 40 <= len(node) <= 2_000_000:
        try:
            candidate = base64.urlsafe_b64decode(node + "=" * ((4 - len(node) % 4) % 4))
            serialization.load_der_private_key(candidate, password=None)
        except (ValueError, TypeError):
            return
        raise CapReject("D4C_PRIVATE_FIXTURE_MATERIAL")


def verify_batch_semantics(obj: dict[str, Any]) -> None:
    payload = {key: obj[key] for key in ("batchAuthorizationRevision", "gaps", "qualityEvents", "samples")}
    expected = sha(b"ONE.OS-TELEMETRY-BATCH-PAYLOAD-V2\0" + canonical_json_bytes(payload))
    require(obj["payloadSha256"] == expected, "D4C_PARENT_PAYLOAD_HASH")


def p384_root_like(root: x509.Certificate) -> x509.Certificate:
    """Runtime-only negative: preserve the root profile except for its curve."""
    key = ec.generate_private_key(ec.SECP384R1())
    builder = (x509.CertificateBuilder().subject_name(root.subject).issuer_name(root.issuer)
               .public_key(key.public_key()).serial_number(root.serial_number)
               .not_valid_before(root.not_valid_before_utc).not_valid_after(root.not_valid_after_utc))
    for extension in root.extensions:
        value = extension.value
        if extension.oid == x509.ExtensionOID.SUBJECT_KEY_IDENTIFIER:
            value = x509.SubjectKeyIdentifier(method1_ski(key.public_key()))
        builder = builder.add_extension(value, critical=extension.critical)
    return builder.sign(key, hashes.SHA256())


def verify() -> None:
    raw_evidence = EVIDENCE.read_bytes()
    forbidden = (b"BEGIN " + b"PRIVATE" + b" KEY", b"BEGIN EC " + b"PRIVATE" + b" KEY")
    require(not any(marker in raw_evidence for marker in forbidden), "D4C_PUBLIC_ONLY")
    data = strict_decode_canonical(raw_evidence, max_bytes=2_000_000, expected_root=dict)
    exact_keys(data, {"capVectors", "cryptoFixtures", "generationBoundary", "proposedCaps", "schemaVersion", "x-one-os-role"}, "D4C_EVIDENCE_SHAPE")
    require(data["schemaVersion"] == "one-os-phase2c-p-cap-x509-boundary-evidence/v1", "D4C_EVIDENCE_SHAPE")
    public_only(data)

    require(data["generationBoundary"] == {"temporaryDirectoryMode": "0700", "privateFilesMode": "0600", "privateDirectoryRemovedBeforeWrite": True}, "D4C_GENERATION_BOUNDARY")

    schema = strict_decode_canonical(SCHEMA.read_bytes(), max_bytes=2_000_000, expected_root=dict)
    batch_schema = strict_decode_canonical(BATCH_SCHEMA.read_bytes(), max_bytes=2_000_000, expected_root=dict)
    caps = data["proposedCaps"]
    exact_keys(caps, {"manifestCanonicalBytes", "receiptCanonicalBytes", "renewalStartCanonicalBytes", "issuedResponseCanonicalBytes", "csrBase64urlChars", "leafPemAsciiBytes", "caChainPemAsciiBytes"}, "D4C_CAP_SHAPE")
    cap_fields = {"manifest": "manifestCanonicalBytes", "receipt": "receiptCanonicalBytes", "renewalStart": "renewalStartCanonicalBytes", "issuedResponse": "issuedResponseCanonicalBytes"}
    for name, cap_field in cap_fields.items():
        pair = data["capVectors"][name]
        exact_keys(pair, {"exact", "capPlusOne", "changedParentExact", "changedParentCapPlusOne"} if name == "manifest" else {"exact", "capPlusOne"}, "D4C_CAP_SHAPE")
        cap = caps[cap_field]
        for disposition, key in (("accept", "exact"), ("reject", "capPlusOne")):
            section = pair[key]
            raw, _ = bound_section(section, schema)
            if disposition == "accept":
                require(envelope(raw, cap, schema) == section["object"], "D4C_CAP_BOUNDARY")
            else:
                try:
                    envelope(raw, cap, schema)
                except ProtocolError as exc:
                    require(str(exc) == "D4S_OBJECT_BYTE_CAP", "D4C_CAP_BOUNDARY")
                else:
                    raise CapReject("D4C_CAP_BOUNDARY")
        require(pair["capPlusOne"]["length"] == pair["exact"]["length"] + 1 == cap + 1, "D4C_CAP_BOUNDARY")
        require(pair["exact"]["length"] == cap, "D4C_CAP_BOUNDARY")

    for key in ("exact", "capPlusOne"):
        suffix = "Exact" if key == "exact" else "CapPlusOne"
        manifest = data["capVectors"]["manifest"][key]
        parent = data["capVectors"]["manifest"]["changedParent" + suffix]
        _, parent_object = bound_section(parent, batch_schema)
        verify_batch_semantics(parent_object)
        entry = manifest["object"]["entries"][0]
        require(entry["requestLength"] == parent["length"] and entry["requestSha256"] == parent["sha256"], "D4C_DAG_BINDING")
        require((entry["batchId"], entry["credentialId"], entry["batchAuthorizationRevision"]) ==
                (parent_object["batchId"], parent_object["credentialId"], parent_object["batchAuthorizationRevision"]), "D4C_DAG_BINDING")
        require(manifest["object"]["totalRequestBytes"] == sum(e["requestLength"] for e in manifest["object"]["entries"]), "D4C_DAG_BINDING")
        start = data["capVectors"]["renewalStart"][key]
        receipt = data["capVectors"]["receipt"][key]
        issued = data["capVectors"]["issuedResponse"][key]
        require(start["object"]["backlogManifest"] == manifest["object"] and start["object"]["backlogManifestSha256"] == manifest["sha256"], "D4C_DAG_BINDING")
        require(receipt["object"]["entries"] == manifest["object"]["entries"] and receipt["object"]["backlogManifestSha256"] == manifest["sha256"] and receipt["object"]["renewalRequestSha256"] == start["sha256"], "D4C_DAG_BINDING")
        require(issued["object"]["historicalAuthorizationReceipt"] == receipt["object"] and issued["object"]["historicalAuthorizationReceiptSha256"] == receipt["sha256"], "D4C_DAG_BINDING")

        start_object = start["object"]
        issued_object = issued["object"]
        pair_root = x509.load_pem_x509_certificate(issued_object["caChainPem"].encode("ascii"))
        pair_leaf = x509.load_pem_x509_certificate(issued_object["certificatePem"].encode("ascii"))
        require(pair_root.public_bytes(serialization.Encoding.PEM).decode("ascii") == issued_object["caChainPem"], "D4C_PAIR_CRYPTO_BINDING")
        require(pair_leaf.public_bytes(serialization.Encoding.PEM).decode("ascii") == issued_object["certificatePem"], "D4C_PAIR_CRYPTO_BINDING")
        require(issued_object["caChainPem"] == data["cryptoFixtures"]["rootCertificatePem"], "D4C_PAIR_CRYPTO_BINDING")
        pair_csr_raw = unb64(start_object["csrDer"])
        pair_csr = verify_csr(pair_csr_raw, start_object["installationId"], start_object["pendingCredentialId"])
        pair_leaf_der = pair_leaf.public_bytes(serialization.Encoding.DER)
        verify_leaf(pair_leaf_der, pair_root, pair_csr, start_object["installationId"], start_object["pendingCredentialId"], ISSUANCE)
        require(sha(pair_csr_raw) == start_object["csrSha256"] and sha(der_spki(pair_csr.public_key())) == start_object["csrSpkiSha256"], "D4C_PAIR_CRYPTO_BINDING")
        require(sha(pair_leaf_der) == issued_object["newCertificateSha256"] and sha(der_spki(pair_leaf.public_key())) == issued_object["newCertificateSpkiSha256"] == issued_object["csrSpkiSha256"], "D4C_PAIR_CRYPTO_BINDING")
        require(issued_object["oldCertificateSha256"] == start_object["oldCertificateSha256"] and issued_object["oldCertificateSpkiSha256"] == start_object["oldCertificateSpkiSha256"], "D4C_PAIR_CRYPTO_BINDING")

    fixtures = data["cryptoFixtures"]
    exact_keys(fixtures, {"rootCertificatePem", "oldCertificatePem", "csrDer", "newCertificatePem", "signatureDerLengths", "serials", "negativePublic"}, "D4C_CRYPTO_SHAPE")
    root = x509.load_pem_x509_certificate(fixtures["rootCertificatePem"].encode())
    old = x509.load_pem_x509_certificate(fixtures["oldCertificatePem"].encode())
    leaf = x509.load_pem_x509_certificate(fixtures["newCertificatePem"].encode())
    require(root.public_bytes(serialization.Encoding.PEM).decode() == fixtures["rootCertificatePem"], "D4C_CRYPTO_PROFILE")
    require(leaf.public_bytes(serialization.Encoding.PEM).decode() == fixtures["newCertificatePem"], "D4C_CRYPTO_PROFILE")
    csr_raw = base64.urlsafe_b64decode(fixtures["csrDer"] + "=" * ((4 - len(fixtures["csrDer"]) % 4) % 4))
    csr = x509.load_der_x509_csr(csr_raw)
    require(all(value == 72 for value in fixtures["signatureDerLengths"].values()), "D4C_SIGNATURE_LENGTH")
    require(fixtures["serials"] == {"root":MAX_SERIAL-2,"oldLeaf":MAX_SERIAL-1,"newLeaf":MAX_SERIAL}, "D4C_SERIAL_BOUNDARY")
    exact_start = data["capVectors"]["renewalStart"]["exact"]["object"]
    verify_root(root)
    root_der=root.public_bytes(serialization.Encoding.DER)
    serial_ledger={}
    for cert in (root,old,leaf): register_issuer_serial(serial_ledger,root_der,cert.public_bytes(serialization.Encoding.DER))
    verify_csr(csr_raw, exact_start["installationId"], exact_start["pendingCredentialId"])
    verify_leaf(leaf.public_bytes(serialization.Encoding.DER), root, csr, exact_start["installationId"], exact_start["pendingCredentialId"], ISSUANCE)
    verify_leaf_profile(old.public_bytes(serialization.Encoding.DER),root,old.public_key(),exact_start["installationId"],exact_start["oldCredentialId"],ISSUANCE)
    for key in ("exact", "capPlusOne"):
        start_object = data["capVectors"]["renewalStart"][key]["object"]
        verify_raw(old.public_key(), start_object["signature"], start_preimage(start_object))

    rejects: list[str] = []
    negatives = fixtures["negativePublic"]
    exact_keys(negatives, {"alternateChainPem", "badAkiPem", "badEkuPem", "badKuPem", "badRootKuPem", "badSkiPem", "badValidityPem", "oldBadKuPem", "serialCollisionPem"}, "D4C_NEGATIVE_PUBLIC_SHAPE")
    bad_root_ku=x509.load_pem_x509_certificate(negatives["badRootKuPem"].encode())
    expect_reject("root_ku",ProtocolError,"root_ku",lambda:verify_root(bad_root_ku),rejects)
    for label, key in (("alternate_chain", "alternateChainPem"), ("ku", "badKuPem"), ("eku", "badEkuPem"), ("ski", "badSkiPem"), ("aki", "badAkiPem"), ("validity", "badValidityPem")):
        cert = x509.load_pem_x509_certificate(negatives[key].encode())
        expected={"alternate_chain":None,"ku":"leaf_ku","eku":"leaf_eku","ski":"leaf_ski","aki":"leaf_aki","validity":"leaf_duration"}[label]
        expect_reject(label, InvalidSignature if label=="alternate_chain" else ProtocolError, expected, lambda cert=cert: verify_leaf(cert.public_bytes(serialization.Encoding.DER), root, csr, exact_start["installationId"], exact_start["pendingCredentialId"], ISSUANCE), rejects)
    old_bad=x509.load_pem_x509_certificate(negatives["oldBadKuPem"].encode())
    expect_reject("old_ku",ProtocolError,"leaf_ku",lambda:verify_leaf_profile(old_bad.public_bytes(serialization.Encoding.DER),root,old.public_key(),exact_start["installationId"],exact_start["oldCredentialId"],ISSUANCE),rejects)
    collision=x509.load_pem_x509_certificate(negatives["serialCollisionPem"].encode())
    expect_reject("issuer_serial_collision",ProtocolError,"issuer_serial_collision",lambda:register_issuer_serial(serial_ledger,root_der,collision.public_bytes(serialization.Encoding.DER)),rejects)
    expect_reject("serial_zero_builder", CapReject, "D4C_SERIAL_ZERO", lambda: builder_reject(0,"D4C_SERIAL_ZERO"), rejects)
    expect_reject("serial_negative_builder", CapReject, "D4C_SERIAL_NEGATIVE", lambda: builder_reject(-1,"D4C_SERIAL_NEGATIVE"), rejects)
    expect_reject("serial_overbroad_builder", CapReject, "D4C_SERIAL_OVERBROAD", lambda: builder_reject(2**159,"D4C_SERIAL_OVERBROAD"), rejects)
    private_der = ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())
    expect_reject("private_der_as_csr", CapReject, "D4C_CSR_ASN1", lambda: malformed_private_csr_reject(private_der, exact_start["installationId"], exact_start["pendingCredentialId"]), rejects)
    expect_reject("root_curve", ProtocolError, "root_curve", lambda: verify_root(p384_root_like(root)), rejects)
    expect_reject("utctime_calendar", ProtocolError, "utctime_calendar", lambda: parse_utctime(b"300231000000Z"), rejects)
    expect_reject("rfc3339_calendar", ProtocolError, "timestamp_calendar", lambda: parse_time("2030-02-31T00:00:00Z"), rejects)
    require(len(rejects) == 16, "D4C_NEGATIVE_COVERAGE")
    require(caps["csrBase64urlChars"] == len(fixtures["csrDer"]), "D4C_CRYPTO_CAP")
    require(caps["leafPemAsciiBytes"] == len(fixtures["newCertificatePem"].encode()), "D4C_CRYPTO_CAP")
    require(caps["caChainPemAsciiBytes"] == len(fixtures["rootCertificatePem"].encode()), "D4C_CRYPTO_CAP")


def main() -> int:
    try:
        verify()
    except CapReject as exc:
        print(json.dumps({"code": exc.code, "pointer": "", "status": "REJECT"}, sort_keys=True, separators=(",", ":")))
        return 1
    except (InvalidSignature, ProtocolError):
        print(json.dumps({"code": "D4C_CRYPTO_PROFILE", "pointer": "", "status": "REJECT"}, sort_keys=True, separators=(",", ":")))
        return 1
    return 0


if __name__ == "__main__":
    exit_code = main()
    if exit_code:
        raise SystemExit(exit_code)
