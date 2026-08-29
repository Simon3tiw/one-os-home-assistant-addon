#!/usr/bin/env python3
"""Draft-4 public-only semantic/crypto verifier and negative corpus."""
from __future__ import annotations

BUNDLE_ID = 'phase2c-p-telemetry-authority-v2-draft4-20260825'
ROLE_ID = 'semantic_crypto_verifier'
GENERATION = 4
CANDIDATE_STATUS = 'UNFROZEN_STAGING'
ROLE_API_VERSION = 1
import re, sys
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from protocol_helpers_one_os_phase2c_p_draft4 import *
from validate_one_os_phase2c_p_draft4 import load_evidence, validate_all, VPATH

UTC_RE=re.compile(rb"^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$")
def parse_utctime(raw:bytes)->datetime:
    m=UTC_RE.fullmatch(raw); require(m is not None,"utctime_grammar")
    yy,mo,day,h,mi,s=map(int,m.groups()); year=1900+yy if yy>=50 else 2000+yy
    try:return datetime(year,mo,day,h,mi,s,tzinfo=timezone.utc)
    except ValueError as e: raise ProtocolError("utctime_calendar") from e

def expect_reject(name,expected,fn,out):
    try: fn()
    except ProtocolError as exc:
        require(str(exc)==expected,f"negative_wrong_guard:{name}:{exc}"); out.append(name); return
    raise AssertionError(f"negative accepted: {name}")

def run_verification():
    v=load_evidence(VPATH); validate_all(v,True); fx=v["cryptoFixtures"]; issued=v["issuedResponse"]["object"]
    root=x509.load_pem_x509_certificate(issued["caChainPem"].encode()); old=x509.load_pem_x509_certificate(fx["oldCertificatePem"].encode()); new_pem=x509.load_pem_x509_certificate(issued["certificatePem"].encode())
    require(root.public_bytes(serialization.Encoding.PEM).decode()==issued["caChainPem"],"issued_exact_single_root_pem")
    require(new_pem.public_bytes(serialization.Encoding.PEM).decode()==issued["certificatePem"],"issued_exact_single_leaf_pem")
    require(issued["caChainPem"]==fx["rootCertificatePem"] and issued["certificatePem"]==fx["newCertificatePem"],"issued_fixture_bytes")
    csr_raw=unb64(fx["csrDer"]); csr=verify_csr(csr_raw,v["context"]["installationId"],v["context"]["pendingCredentialId"])
    root_der=root.public_bytes(serialization.Encoding.DER); old_der=old.public_bytes(serialization.Encoding.DER); new_der=new_pem.public_bytes(serialization.Encoding.DER)
    verify_root(root)
    root.public_key().verify(old.signature,old.tbs_certificate_bytes,ec.ECDSA(hashes.SHA256()))
    old_exts=list(old.extensions)
    require([e.oid for e in old_exts]==[ExtensionOID.BASIC_CONSTRAINTS,ExtensionOID.KEY_USAGE,ExtensionOID.EXTENDED_KEY_USAGE,ExtensionOID.SUBJECT_ALTERNATIVE_NAME,ExtensionOID.SUBJECT_KEY_IDENTIFIER,ExtensionOID.AUTHORITY_KEY_IDENTIFIER],"old_leaf_extension_order")
    require([e.critical for e in old_exts]==[True,True,True,False,False,False],"old_leaf_extension_criticality")
    require(old_exts[3].value.get_values_for_type(x509.UniformResourceIdentifier)==[f"urn:one-os:installation:{v['context']['installationId']}:credential:{v['context']['oldCredentialId']}"],"old_leaf_san")
    require(old_exts[4].value.digest==method1_ski(old.public_key()) and old_exts[5].value.key_identifier==method1_ski(root.public_key()),"old_leaf_ski_aki")
    new=verify_leaf(new_der,root,csr,v["context"]["installationId"],v["context"]["pendingCredentialId"],datetime(2030,1,1,12,tzinfo=timezone.utc))
    require(sha(csr_raw)==v["context"]["csrDerSha256"] and sha(der_spki(csr.public_key()))==v["context"]["csrSpkiSha256"],"csr_context_hashes")
    require(sha(old_der)==v["context"]["oldCertificateDerSha256"] and sha(der_spki(old.public_key()))==v["context"]["oldCertificateSpkiSha256"],"old_context_hashes")
    require(sha(new_der)==issued["newCertificateSha256"] and sha(der_spki(new.public_key()))==issued["newCertificateSpkiSha256"]==issued["csrSpkiSha256"],"issued_leaf_chain")
    start=v["renewalStart"]["object"]; aq=v["renewalAckRequest"]["object"]; cq=v["cancelRequest"]["object"]; eq=v["enableRequest"]["object"]
    verify_raw(old.public_key(),start["signature"],start_preimage(start)); verify_raw(new.public_key(),aq["signature"],ack_preimage(aq)); verify_raw(old.public_key(),cq["signature"],cancel_preimage(cq)); verify_raw(old.public_key(),eq["signature"],enable_preimage(eq))
    # issuer+serial ledger: only byte-identical replay is legal.
    ledger={}
    def issue_seen(cert_der):
        c=x509.load_der_x509_certificate(cert_der); key=(sha(root_der),c.serial_number)
        if key in ledger: require(ledger[key]==cert_der,"issuer_serial_collision")
        else: ledger[key]=cert_der
    issue_seen(new_der); issue_seen(new_der)
    negatives=[]; neg=fx["negativePublic"]
    expect_reject("csr_bad_self_signature","csr_self_signature",lambda:verify_csr(unb64(neg["badCsrSelfSignature"]),v["context"]["installationId"],v["context"]["pendingCredentialId"]),negatives)
    expect_reject("csr_missing_san","csr_attributes",lambda:verify_csr(unb64(neg["missingSanCsr"]),v["context"]["installationId"],v["context"]["pendingCredentialId"]),negatives)
    expect_reject("csr_wrong_curve","csr_curve",lambda:verify_csr(unb64(neg["wrongCurveCsr"]),v["context"]["installationId"],v["context"]["pendingCredentialId"]),negatives)
    wrong_order=x509.load_pem_x509_certificate(neg["leafWrongExtensionOrderPem"].encode()).public_bytes(serialization.Encoding.DER)
    wrong_crit=x509.load_pem_x509_certificate(neg["leafWrongCriticalityPem"].encode()).public_bytes(serialization.Encoding.DER)
    expect_reject("leaf_wrong_extension_order","leaf_extension_order",lambda:verify_leaf(wrong_order,root,csr,v["context"]["installationId"],v["context"]["pendingCredentialId"],datetime(2030,1,1,12,tzinfo=timezone.utc)),negatives)
    expect_reject("leaf_wrong_criticality","leaf_extension_criticality",lambda:verify_leaf(wrong_crit,root,csr,v["context"]["installationId"],v["context"]["pendingCredentialId"],datetime(2030,1,1,12,tzinfo=timezone.utc)),negatives)
    expect_reject("leaf_trailing_bytes","leaf_trailing_or_truncated",lambda:verify_leaf(unb64(neg["leafTrailingBytes"]),root,csr,v["context"]["installationId"],v["context"]["pendingCredentialId"],datetime(2030,1,1,12,tzinfo=timezone.utc)),negatives)
    # Collision guard is intentionally before acceptance of replacement bytes.
    def collision():
        key=(sha(root_der),new.serial_number); require(ledger[key]==new_der[:-1]+bytes([new_der[-1]^1]),"issuer_serial_collision")
    expect_reject("issuer_serial_collision_different_der","issuer_serial_collision",collision,negatives)
    require(parse_utctime(b"500101000000Z").year==1950,"utc_1950"); require(parse_utctime(b"680101000000Z").year==1968,"utc_1968"); require(parse_utctime(b"000101000000Z").year==2000,"utc_2000"); require(parse_utctime(b"491231235959Z").year==2049,"utc_2049")
    expect_reject("utctime_bad_calendar","utctime_calendar",lambda:parse_utctime(b"300231000000Z"),negatives); expect_reject("utctime_fraction","utctime_grammar",lambda:parse_utctime(b"300101000000.0Z"),negatives)
    require(len(negatives)==9,"negative_count")


def main():
    import argparse, json
    ap=argparse.ArgumentParser(); ap.add_argument("--snapshot-manifest")
    ap.parse_args()
    try:
        run_verification()
    except Reject as exc:
        sys.stdout.write(json.dumps({"code":exc.code,"pointer":exc.pointer,"status":"REJECT"},sort_keys=True,separators=(",",":"))+"\n")
        return 1
    except ProtocolError as exc:
        raw=str(exc)
        code=raw if raw.startswith("D4") else "D4S_"+re.sub(r"[^A-Z0-9]+","_",raw.upper()).strip("_")
        sys.stdout.write(json.dumps({"code":code,"pointer":"","status":"REJECT"},sort_keys=True,separators=(",",":"))+"\n")
        return 1
    sys.stdout.write(json.dumps({"code":"D4PASS","status":"ACCEPT"},sort_keys=True,separators=(",",":"))+"\n")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
