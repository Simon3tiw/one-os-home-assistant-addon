#!/usr/bin/env python3
"""Draft-4 strict wire, semantic DAG and public crypto helpers."""
from __future__ import annotations

BUNDLE_ID = 'phase2c-p-telemetry-authority-v2-draft4-20260825'
ROLE_ID = 'protocol_helpers'
GENERATION = 4
CANDIDATE_STATUS = 'UNFROZEN_STAGING'
ROLE_API_VERSION = 1
import base64, hashlib, json, re, struct
from datetime import datetime, timezone
from typing import Any
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.x509.oid import ExtensionOID, ExtendedKeyUsageOID, NameOID, ObjectIdentifier
from strict_wire_one_os_phase2c_p_draft4 import Reject, canonical_json_bytes, strict_decode_canonical

MAX63=2**63-1
P256_N=0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
UUID4=re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
B64HASH=re.compile(r"^[A-Za-z0-9_-]{43}$")
TS_S=re.compile(r"^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$")
TS_MS=re.compile(r"^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]\.[0-9]{3}Z$")

class ProtocolError(ValueError): pass

def require(ok: bool, reason: str)->None:
    if not ok: raise ProtocolError(reason)

def canonical(o:Any)->bytes:
    return canonical_json_bytes(o)

def b64(b:bytes)->str: return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def unb64(s:str)->bytes: return base64.urlsafe_b64decode(s+"="*((4-len(s)%4)%4))
def sha(b:bytes)->str: return b64(hashlib.sha256(b).digest())
def der_spki(key)->bytes: return key.public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
def uuid_bytes(s:str)->bytes: return bytes.fromhex(s.replace("-",""))
def exact_int(v:Any,lo:int=0,hi:int=MAX63)->bool: return type(v) is int and lo<=v<=hi

CONTROL_OBJECT_BYTE_CAPS={"manifest":60256,"receipt":60628,"start":61703,"issued":63218}

def strict_decode(raw:bytes)->Any:
    try:
        return strict_decode_canonical(raw, max_bytes=16_777_216, expected_root=dict)
    except Reject as exc:
        raise ProtocolError(exc.code) from exc

def parse_time(s:str,millis:bool=False)->datetime:
    require(type(s) is str and (TS_MS if millis else TS_S).fullmatch(s) is not None,"timestamp_lexical")
    try: return datetime.strptime(s,"%Y-%m-%dT%H:%M:%S.%fZ" if millis else "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as e: raise ProtocolError("timestamp_calendar") from e

def calendars(o:Any)->None:
    seconds={"createdAt","acceptedAt","notBefore","expiresAt","ackExpiresAt","issuanceExpiresAt","decidedAt","enabledAt","issuedAt"}
    millis={"observedAt","receivedAtEdge","detectedAt"}
    if type(o) is dict:
        for k,v in o.items():
            if k in seconds: parse_time(v, type(v) is str and "." in v)
            if k in millis: parse_time(v,True)
            calendars(v)
    elif type(o) is list:
        for v in o: calendars(v)

def framed(domain:str, values:list[bytes])->bytes:
    return domain.encode()+b"\0"+b"".join(struct.pack(">HI",i,len(v))+v for i,v in enumerate(values,1))

def start_preimage(o:dict)->bytes:
    return framed("ONE.OS-DEVICE-RENEW-V2",[o["protocol"].encode(),uuid_bytes(o["installationId"]),uuid_bytes(o["oldCredentialId"]),unb64(o["oldCertificateSha256"]),uuid_bytes(o["requestId"]),unb64(o["csrSha256"]),unb64(o["csrSpkiSha256"]),unb64(o["edgeNonce"]),o["epochMinute"].to_bytes(8,"big"),o["installationRevisionBefore"].to_bytes(8,"big"),o["expectedTelemetryAuthorizationRevision"].to_bytes(8,"big"),o["backlogMode"].encode(),unb64(o["backlogManifestSha256"])])

def ack_preimage(o:dict)->bytes:
    keys=["renewalRequestSha256","renewalIssuedResponseSha256","oldCertificateSha256","oldCertificateSpkiSha256","newCertificateSha256","newCertificateSpkiSha256","csrSha256","csrSpkiSha256","backlogManifestSha256"]
    vals=[o["protocol"].encode(),uuid_bytes(o["requestId"]),uuid_bytes(o["installationId"]),uuid_bytes(o["lineageId"]),o["installationRevisionBefore"].to_bytes(8,"big"),uuid_bytes(o["oldCredentialId"]),uuid_bytes(o["newCredentialId"])]
    vals += [unb64(o[k]) for k in keys]
    vals += [o["telemetryAuthorizationRevisionBefore"].to_bytes(8,"big"),o["telemetryAuthorizationRevisionAfter"].to_bytes(8,"big"),o["backlogMode"].encode(),unb64(o["historicalAuthorizationReceiptSha256"])]
    return framed("ONE.OS-DEVICE-RENEW-ACK-V2",vals)

def cancel_preimage(o:dict)->bytes:
    return framed("ONE.OS-DEVICE-RENEW-CANCEL-V2",[o["protocol"].encode(),uuid_bytes(o["cancelRequestId"]),uuid_bytes(o["targetRequestId"]),uuid_bytes(o["installationId"]),uuid_bytes(o["lineageId"]),uuid_bytes(o["currentCredentialId"]),unb64(o["currentCertificateSha256"]),unb64(o["targetRenewalRequestSha256"]),unb64(o["backlogManifestSha256"]),o["expectedTelemetryAuthorizationRevision"].to_bytes(8,"big"),unb64(o["edgeNonce"])])

def enable_preimage(o:dict)->bytes:
    names=("telemetryBatchSchemaSha256","telemetryAckSchemaSha256","telemetryErrorSchemaSha256","renewalControlSchemaSha256")
    vals=[o["protocol"].encode(),uuid_bytes(o["requestId"]),uuid_bytes(o["installationId"]),uuid_bytes(o["currentCredentialId"]),unb64(o["currentCertificateSha256"]),o["protocolId"].encode()]+[unb64(o[k]) for k in names]+[unb64(o["capabilitySha256"]),unb64(o["capabilityServerNonce"]),o["issuedAt"].encode(),o["expiresAt"].encode(),o["expectedTelemetryAuthorizationRevision"].to_bytes(8,"big"),unb64(o["edgeNonce"])]
    return framed("ONE.OS-TELEMETRY-AUTHORITY-ENABLE-V2",vals)

def verify_raw(key, sig:str, preimage:bytes)->None:
    raw=unb64(sig); require(len(raw)==64,"signature_length")
    r,s=int.from_bytes(raw[:32],"big"),int.from_bytes(raw[32:],"big")
    require(1<=r<P256_N and 1<=s<=P256_N//2,"signature_range_or_high_s")
    key.verify(encode_dss_signature(r,s),preimage,ec.ECDSA(hashes.SHA256()))

def _der_total(raw:bytes)->int:
    require(len(raw)>=2 and raw[0]==0x30,"der_sequence")
    n=raw[1]
    if n<128: return 2+n
    count=n&0x7f; require(1<=count<=4 and len(raw)>=2+count,"der_length")
    require(raw[2]!=0,"der_nonminimal_length")
    return 2+count+int.from_bytes(raw[2:2+count],"big")

def method1_ski(key)->bytes:
    point=key.public_bytes(serialization.Encoding.X962,serialization.PublicFormat.UncompressedPoint)
    return hashlib.sha1(point[1:]).digest()

def verify_csr(raw:bytes, installation:str, credential:str)->x509.CertificateSigningRequest:
    require(_der_total(raw)==len(raw),"csr_trailing_or_truncated")
    csr=x509.load_der_x509_csr(raw)
    require(csr.is_signature_valid,"csr_self_signature")
    require(csr.signature_algorithm_oid.dotted_string=="1.2.840.10045.4.3.2","csr_signature_algorithm")
    require(isinstance(csr.public_key(),ec.EllipticCurvePublicKey) and csr.public_key().curve.name=="secp256r1","csr_curve")
    require(csr.subject==x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,credential)]),"csr_subject")
    attrs=list(csr.attributes); require(len(attrs)==1 and attrs[0].oid==ObjectIdentifier("1.2.840.113549.1.9.14"),"csr_attributes")
    exts=list(csr.extensions); require(len(exts)==1 and exts[0].oid==ExtensionOID.SUBJECT_ALTERNATIVE_NAME and not exts[0].critical,"csr_extensions")
    uri=f"urn:one-os:installation:{installation}:credential:{credential}"
    require(exts[0].value.get_values_for_type(x509.UniformResourceIdentifier)==[uri],"csr_san")
    return csr

def verify_root(cert:x509.Certificate)->None:
    require(cert.version==x509.Version.v3 and 1<=cert.serial_number<=2**159-1,"root_version_serial")
    require(cert.subject==cert.issuer==x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,"ONE.OS Draft-4 Test Root")]),"root_name")
    key=cert.public_key()
    require(isinstance(key,ec.EllipticCurvePublicKey) and key.curve.name=="secp256r1","root_curve")
    key.verify(cert.signature,cert.tbs_certificate_bytes,ec.ECDSA(hashes.SHA256()))
    exts=list(cert.extensions); require([e.oid for e in exts]==[ExtensionOID.BASIC_CONSTRAINTS,ExtensionOID.KEY_USAGE,ExtensionOID.SUBJECT_KEY_IDENTIFIER],"root_extension_order")
    require([e.critical for e in exts]==[True,True,False],"root_extension_criticality")
    require(exts[0].value==x509.BasicConstraints(ca=True,path_length=0),"root_bc")
    ku=exts[1].value; require(ku==x509.KeyUsage(False,False,False,False,False,True,True,False,False),"root_ku")
    require(exts[2].value.digest==method1_ski(cert.public_key()),"root_ski")

def verify_leaf_profile(raw:bytes, root:x509.Certificate, expected_public_key, installation:str, credential:str, issuance:datetime, *, spki_code:str="leaf_expected_spki")->x509.Certificate:
    require(_der_total(raw)==len(raw),"leaf_trailing_or_truncated")
    cert=x509.load_der_x509_certificate(raw); verify_root(root)
    require(cert.version==x509.Version.v3 and 1<=cert.serial_number<=2**159-1,"leaf_version_serial")
    require(cert.issuer==root.subject and cert.subject==x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,credential)]),"leaf_names")
    require(cert.signature_algorithm_oid.dotted_string=="1.2.840.10045.4.3.2","leaf_signature_algorithm")
    root.public_key().verify(cert.signature,cert.tbs_certificate_bytes,ec.ECDSA(hashes.SHA256()))
    require(der_spki(cert.public_key())==der_spki(expected_public_key),spki_code)
    order=[ExtensionOID.BASIC_CONSTRAINTS,ExtensionOID.KEY_USAGE,ExtensionOID.EXTENDED_KEY_USAGE,ExtensionOID.SUBJECT_ALTERNATIVE_NAME,ExtensionOID.SUBJECT_KEY_IDENTIFIER,ExtensionOID.AUTHORITY_KEY_IDENTIFIER]
    exts=list(cert.extensions); require([e.oid for e in exts]==order,"leaf_extension_order")
    require([e.critical for e in exts]==[True,True,True,False,False,False],"leaf_extension_criticality")
    require(exts[0].value==x509.BasicConstraints(ca=False,path_length=None),"leaf_bc")
    ku=exts[1].value; require(ku.digital_signature and not any((ku.content_commitment,ku.key_encipherment,ku.data_encipherment,ku.key_agreement,ku.key_cert_sign,ku.crl_sign)),"leaf_ku")
    require(list(exts[2].value)==[ExtendedKeyUsageOID.CLIENT_AUTH],"leaf_eku")
    uri=f"urn:one-os:installation:{installation}:credential:{credential}"; require(exts[3].value.get_values_for_type(x509.UniformResourceIdentifier)==[uri],"leaf_san")
    require(exts[4].value.digest==method1_ski(cert.public_key()),"leaf_ski")
    aki=exts[5].value; require(aki.key_identifier==method1_ski(root.public_key()) and aki.authority_cert_issuer is None and aki.authority_cert_serial_number is None,"leaf_aki")
    require(root.not_valid_before_utc<=cert.not_valid_before_utc<=issuance<cert.not_valid_after_utc<=root.not_valid_after_utc,"leaf_validity")
    require((cert.not_valid_after_utc-cert.not_valid_before_utc).total_seconds()==86400*366,"leaf_duration")
    return cert

def verify_leaf(raw:bytes, root:x509.Certificate, csr:x509.CertificateSigningRequest, installation:str, credential:str, issuance:datetime)->x509.Certificate:
    return verify_leaf_profile(raw,root,csr.public_key(),installation,credential,issuance,spki_code="leaf_csr_spki")

def register_issuer_serial(ledger:dict, issuer_der:bytes, cert_der:bytes)->x509.Certificate:
    cert=x509.load_der_x509_certificate(cert_der)
    key=(sha(issuer_der),cert.serial_number)
    if key in ledger: require(ledger[key]==cert_der,"issuer_serial_collision")
    else: ledger[key]=cert_der
    return cert
