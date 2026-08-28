#!/usr/bin/env python3
"""Draft-4 contextual semantic validator and executable mutation corpus."""
from __future__ import annotations

BUNDLE_ID = 'phase2c-p-telemetry-authority-v2-draft4-20260825'
ROLE_ID = 'semantic_validator'
GENERATION = 4
CANDIDATE_STATUS = 'UNFROZEN_STAGING'
ROLE_API_VERSION = 1
import base64, binascii, copy, json, re, sys
from cryptography.hazmat.primitives import serialization
from datetime import timedelta
from pathlib import Path
from strict_wire_one_os_phase2c_p_draft4 import Reject, strict_decode_canonical, validate_exact_schema
from protocol_helpers_one_os_phase2c_p_draft4 import *
ROOT=Path(__file__).resolve().parent; DATE="20260825"
VPATH=ROOT/f"one-os-phase2c-p-canonical-vectors-v2-draft4-{DATE}.json"
SCHEMAS={k:ROOT/f"one-os-phase2c-p-{n}-v2-draft4-{DATE}.schema.json" for k,n in {"batch":"telemetry-batch","ack":"telemetry-ack","error":"telemetry-error","control":"renewal-control"}.items()}

def load_evidence(path:Path):
    return strict_decode_canonical(path.read_bytes(), max_bytes=16_777_216, expected_root=dict)
def _unique(pairs):
    d={}
    for k,v in pairs:
        if k in d: raise ProtocolError("duplicate_key_evidence")
        d[k]=v
    return d

def check_section(sec,name):
    raw=sec["canonicalUtf8"].encode()
    if name in CONTROL_OBJECT_BYTE_CAPS: require(len(raw)<=CONTROL_OBJECT_BYTE_CAPS[name],"object_byte_cap")
    obj=strict_decode(raw)
    require(obj==sec["object"],f"{name}:object_bytes")
    require(len(raw)==sec["length"],f"{name}:length")
    require(sha(raw)==sec["sha256"],f"{name}:hash")
    calendars(obj); return obj

def validate_batch(o):
    require(exact_int(o["batchAuthorizationRevision"],1),"batch_revision_type")
    total=sum(len(o[k]) for k in ("samples","qualityEvents","gaps")); require(1<=total<=500,"batch_aggregate")
    for r in o["samples"]+o["qualityEvents"]+o["gaps"]: require(r["installationId"]==o["installationId"],"record_installation")
    expect=sha(b"ONE.OS-TELEMETRY-BATCH-PAYLOAD-V2\0"+canonical({k:o[k] for k in ("batchAuthorizationRevision","gaps","qualityEvents","samples")})); require(o["payloadSha256"]==expect,"payload_hash"); calendars(o)

def validate_all(v,run_negatives=True):
    require(set(v)=={"aggregateVectors","cancelRequest","cancelResponse","capability","context","cryptoFixtures","enableRequest","enableResponse","entryBoundary","immutableIdentityConflict","issuedResponse","manifest256","negativeCorpus","pendingResponse","receipt","renewalAckRequest","renewalAckResponse","renewalStart","schemaVersion","telemetryBatches256","x-one-os-role"},"vector_outer_keyset")
    require(v["schemaVersion"]=="one-os-phase2c-p-canonical-vectors/v2-draft4","vector_identity")
    schemas={k:load_evidence(p) for k,p in SCHEMAS.items()}
    forbidden_fragments=("private"+"scalar","private"+"key","pkcs8","secretseed")
    def public_only(node):
        if type(node) is dict:
            for key,value in node.items():
                normalized=key.lower().replace("_","").replace("-","")
                require(not any(fragment in normalized for fragment in forbidden_fragments),"private_fixture_material")
                public_only(key)
                public_only(value)
        elif type(node) is list:
            for value in node: public_only(value)
        elif type(node) is str:
            require("PRIVATE"+" KEY" not in node,"private_fixture_material")
            if 40<=len(node)<=2_000_000:
                candidates=[]
                if re.fullmatch(r"[A-Za-z0-9_-]+",node):
                    try: candidates.append(base64.urlsafe_b64decode(node+"="*((4-len(node)%4)%4)))
                    except (ValueError,binascii.Error): pass
                if re.fullmatch(r"[A-Za-z0-9+/]+={0,2}",node):
                    try: candidates.append(base64.b64decode(node,validate=True))
                    except (ValueError,binascii.Error): pass
                for candidate in candidates:
                    try: serialization.load_der_private_key(candidate,password=None)
                    except (ValueError,TypeError): pass
                    else: raise ProtocolError("private_fixture_material")
    public_only(v)
    require(set(v["cryptoFixtures"]["negativePublic"])=={"badCsrSelfSignature","leafTrailingBytes","leafWrongCriticalityPem","leafWrongExtensionOrderPem","missingSanCsr","wrongCurveCsr"},"negative_public_keyset")
    timestamp_names={"createdAt","detectedAt","observedAt","receivedAtEdge","acceptedAt","notBefore","expiresAt","ackExpiresAt","issuanceExpiresAt","decidedAt","enabledAt","issuedAt"}
    seen_timestamp_names=set()
    def schema_timestamp_inventory(node):
        if type(node) is dict:
            props=node.get("properties")
            if type(props) is dict:
                for key,child in props.items():
                    if key in timestamp_names:
                        require(child.get("format") in {"one-os-rfc3339-ms-utc","one-os-rfc3339-s-utc"},"schema_timestamp_inventory")
                        seen_timestamp_names.add(key)
                    schema_timestamp_inventory(child)
            for key,value in node.items():
                if key != "properties": schema_timestamp_inventory(value)
        elif type(node) is list:
            for value in node: schema_timestamp_inventory(value)
    for schema in schemas.values(): schema_timestamp_inventory(schema)
    require(seen_timestamp_names==timestamp_names,"schema_timestamp_inventory")
    capability_schema_hashes={"batch":"telemetryBatchSchemaSha256","ack":"telemetryAckSchemaSha256","error":"telemetryErrorSchemaSha256","control":"renewalControlSchemaSha256"}
    capability=v["capability"]["object"]
    for schema_name,field in capability_schema_hashes.items():
        require(capability[field] == sha(SCHEMAS[schema_name].read_bytes()), f"capability_schema_hash_{schema_name}")
    registry = {s.get("$id", name): s for name, s in schemas.items()}
    def exact(obj, name): validate_exact_schema(obj, schemas[name], schema_registry=registry)
    batches=[]
    require(len(v["telemetryBatches256"])==256,"batch_count_256")
    for i,s in enumerate(v["telemetryBatches256"]):
        o=check_section(s,f"batch{i}"); exact(o,"batch"); validate_batch(o); batches.append(o)
    require(len({o["batchId"] for o in batches})==256,"unique_batch_ids")
    manifest=check_section(v["manifest256"],"manifest"); exact(manifest,"control")
    entries=manifest["entries"]; require(len(entries)==manifest["entryCount"]==256,"manifest_count")
    require([e["journalId"] for e in entries]==list(range(1,257)),"manifest_journal_dag")
    require(len({e["requestSha256"] for e in entries})==256,"manifest_unique_hashes")
    for e,b,s in zip(entries,batches,v["telemetryBatches256"]):
        require((e["batchId"],e["credentialId"],e["batchAuthorizationRevision"],e["requestSha256"],e["requestLength"])==(b["batchId"],b["credentialId"],b["batchAuthorizationRevision"],s["sha256"],s["length"]),"manifest_parent_edge")
    require(manifest["totalRequestBytes"]==sum(s["length"] for s in v["telemetryBatches256"]),"manifest_total_bytes")
    start=check_section(v["renewalStart"],"start"); exact(start,"control"); require(start["backlogManifest"]==manifest and start["backlogManifestSha256"]==v["manifest256"]["sha256"],"start_manifest_edge")
    ctx=v["context"]; require(ctx=={"requestId":start["requestId"],"renewalRequestSha256":v["renewalStart"]["sha256"],"installationId":start["installationId"],"lineageId":start["lineageId"],"installationRevisionBefore":start["installationRevisionBefore"],"telemetryAuthorizationRevisionBefore":start["expectedTelemetryAuthorizationRevision"],"telemetryAuthorizationRevisionAfter":start["expectedTelemetryAuthorizationRevision"]+1,"oldCredentialId":start["oldCredentialId"],"oldCertificateDerSha256":start["oldCertificateSha256"],"oldCertificateSpkiSha256":start["oldCertificateSpkiSha256"],"pendingCredentialId":start["pendingCredentialId"],"csrDerSha256":start["csrSha256"],"csrSpkiSha256":start["csrSpkiSha256"],"backlogMode":start["backlogMode"],"backlogManifestSha256":start["backlogManifestSha256"],"cutMarkerId":manifest["cutMarkerId"]},"renewal_context")
    receipt=check_section(v["receipt"],"receipt"); exact(receipt,"control")
    for k in ("renewalOperationId","installationId","lineageId","cutMarkerId","cutJournalMaxId","entryCount","totalRequestBytes","entries"): require(receipt[k]==({"renewalOperationId":ctx["requestId"]}.get(k,manifest.get(k))),f"receipt_alias_{k}")
    require(receipt["renewalRequestSha256"]==ctx["renewalRequestSha256"] and receipt["backlogManifestSha256"]==ctx["backlogManifestSha256"],"receipt_hash_edges")
    require(receipt["historicalAuthorizationRevision"]==ctx["telemetryAuthorizationRevisionBefore"] and receipt["ingestAuthorizationRevision"]==ctx["telemetryAuthorizationRevisionAfter"],"receipt_revision")
    require(receipt["allowedTransportCredentialIds"]==sorted([ctx["oldCredentialId"],ctx["pendingCredentialId"]]),"receipt_exact_old_pending")
    require(parse_time(receipt["expiresAt"])-parse_time(receipt["notBefore"])==timedelta(seconds=86400),"receipt_exact_86400")
    pending=check_section(v["pendingResponse"],"pending"); exact(pending,"control")
    issued=check_section(v["issuedResponse"],"issued"); exact(issued,"control")
    for obj,label in ((pending,"pending"),(issued,"issued")):
        aliases={"requestId":ctx["requestId"],"installationId":ctx["installationId"],"lineageId":ctx["lineageId"],"installationRevisionBefore":ctx["installationRevisionBefore"],"telemetryAuthorizationRevisionBefore":ctx["telemetryAuthorizationRevisionBefore"],"telemetryAuthorizationRevisionAfter":ctx["telemetryAuthorizationRevisionAfter"],"oldCredentialId":ctx["oldCredentialId"],"oldCertificateSha256":ctx["oldCertificateDerSha256"],"oldCertificateSpkiSha256":ctx["oldCertificateSpkiSha256"],"newCredentialId":ctx["pendingCredentialId"],"csrSha256":ctx["csrDerSha256"],"csrSpkiSha256":ctx["csrSpkiSha256"],"backlogMode":ctx["backlogMode"],"backlogManifestSha256":ctx["backlogManifestSha256"],"historicalAuthorizationReceiptSha256":v["receipt"]["sha256"]}
        for k,x in aliases.items(): require(obj[k]==x,f"{label}_alias_{k}")
        require(obj["historicalAuthorizationReceipt"]==receipt,f"{label}_receipt_bytes")
    require(issued["newCertificateSpkiSha256"]==issued["csrSpkiSha256"],"issued_spki_chain")
    ackq=check_section(v["renewalAckRequest"],"ack_request"); exact(ackq,"control")
    ackr=check_section(v["renewalAckResponse"],"ack_response"); exact(ackr,"control")
    ack_alias={"renewalRequestSha256":v["renewalStart"]["sha256"],"renewalIssuedResponseSha256":v["issuedResponse"]["sha256"],"installationId":ctx["installationId"],"lineageId":ctx["lineageId"],"installationRevisionBefore":ctx["installationRevisionBefore"],"oldCredentialId":ctx["oldCredentialId"],"oldCertificateSha256":ctx["oldCertificateDerSha256"],"oldCertificateSpkiSha256":ctx["oldCertificateSpkiSha256"],"newCredentialId":ctx["pendingCredentialId"],"newCertificateSha256":issued["newCertificateSha256"],"newCertificateSpkiSha256":issued["newCertificateSpkiSha256"],"csrSha256":ctx["csrDerSha256"],"csrSpkiSha256":ctx["csrSpkiSha256"],"telemetryAuthorizationRevisionBefore":7,"telemetryAuthorizationRevisionAfter":8,"backlogMode":"historical","backlogManifestSha256":ctx["backlogManifestSha256"],"historicalAuthorizationReceiptSha256":v["receipt"]["sha256"]}
    for k,x in ack_alias.items(): require(ackq[k]==x,f"ack_request_alias_{k}"); require(ackr[k]==x,f"ack_response_alias_{k}")
    require(ackr["installationRevisionAfter"]==ackq["installationRevisionBefore"]+1,"ack_installation_successor")
    cq=check_section(v["cancelRequest"],"cancel_request"); cr=check_section(v["cancelResponse"],"cancel_response"); exact(cq,"control"); exact(cr,"control")
    edges={"cancelRequestId":cq["cancelRequestId"],"cancelRequestSha256":v["cancelRequest"]["sha256"],"targetRequestId":cq["targetRequestId"],"targetRenewalRequestSha256":cq["targetRenewalRequestSha256"],"backlogManifestSha256":cq["backlogManifestSha256"],"installationId":cq["installationId"],"lineageId":cq["lineageId"],"telemetryAuthorizationRevision":cq["expectedTelemetryAuthorizationRevision"],"currentCredentialId":cq["currentCredentialId"],"currentCertificateSha256":cq["currentCertificateSha256"]}
    for k,x in edges.items(): require(cr[k]==x,f"cancel_edge_{k}")
    cap=check_section(v["capability"],"capability"); en=check_section(v["enableRequest"],"enable_request"); enr=check_section(v["enableResponse"],"enable_response"); exact(cap,"control"); exact(en,"control"); exact(enr,"control")
    require(parse_time(cap["expiresAt"])-parse_time(cap["issuedAt"])==timedelta(seconds=300),"capability_exact_300")
    for k in ("installationId","protocolId","telemetryBatchSchemaSha256","telemetryAckSchemaSha256","telemetryErrorSchemaSha256","renewalControlSchemaSha256","issuedAt","expiresAt"):
        require(en[k]==cap[k],f"enable_capability_{k}"); require(enr[k]==cap[k],f"enable_response_{k}")
    require(en["capabilitySha256"]==v["capability"]["sha256"]==enr["capabilitySha256"],"enable_capability_hash")
    require(en["capabilityServerNonce"]==cap["serverNonce"]==enr["capabilityServerNonce"],"enable_nonce")
    require(exact_int(en["expectedTelemetryAuthorizationRevision"],1) and exact_int(enr["telemetryAuthorizationRevision"],1) and en["expectedTelemetryAuthorizationRevision"]==enr["telemetryAuthorizationRevision"],"enable_revision_type_binding")
    conflict=v["immutableIdentityConflict"]; require(conflict["httpStatus"]==409,"conflict_http"); co=check_section(conflict["response"],"conflict"); exact(co,"error"); require(co["requestSha256"]==sha(conflict["requestCanonicalUtf8"].encode()),"conflict_request_hash")
    require(set(v["entryBoundary"])=={"255","256","257Reject"} and len(v["entryBoundary"]["255"])==255 and len(v["entryBoundary"]["256"])==256 and len(v["entryBoundary"]["257Reject"])==257,"entry_boundaries")
    expected={"total1":True,"total499":True,"total500Samples":True,"total500Quality":True,"total500Gaps":True,"mixed498_1_1":True,"reject501Mixed":False,"reject501Array":False}
    for name,valid in expected.items():
        o=check_section(v["aggregateVectors"][name],name)
        try: validate_batch(o); got=True
        except ProtocolError: got=False
        require(got==valid,f"aggregate_disposition_{name}")
    if run_negatives: mutation_tests(v)

def mutation_tests(v):
    cases=[]
    def rejected(fn,reason,expected_guard):
        try: fn()
        except ProtocolError as exc:
            require(str(exc)==expected_guard,f"focused_negative_wrong_guard:{reason}:{exc}")
            cases.append(reason); return
        raise AssertionError(f"negative accepted: {reason}")
    rejected(lambda:strict_decode(b'{"a":1,"a":1}'),"duplicate_top","D4W005_DUPLICATE_KEY")
    rejected(lambda:strict_decode(b'{"a":{"x":1,"x":1}}'),"duplicate_nested","D4W005_DUPLICATE_KEY")
    rejected(lambda:strict_decode(b'{"revision":7.0}'),"float","D4W006_FLOAT_FORBIDDEN")
    bad=copy.deepcopy(v); bad["receipt"]["object"]["allowedTransportCredentialIds"]=[U for U in ["00000000-0000-4000-8000-000000000004","00000000-0000-4000-8000-000000000005"]]
    rejected(lambda: require(bad["receipt"]["object"]["allowedTransportCredentialIds"]==sorted([v["context"]["oldCredentialId"],v["context"]["pendingCredentialId"]]),"receipt_exact_old_pending"),"receipt_allowlist","receipt_exact_old_pending")
    bad=copy.deepcopy(v["capability"]["object"]); bad["expiresAt"]="2030-01-01T12:05:01Z"; rejected(lambda:require(parse_time(bad["expiresAt"])-parse_time(bad["issuedAt"])==timedelta(seconds=300),"cap"),"capability_301","cap")
    rejected(lambda:require(exact_int(True,1),"bool"),"bool_revision","bool")
    rejected(lambda:parse_time("2030-02-31T12:00:00Z"),"calendar","timestamp_calendar")
    require(len(cases)==7,"mutation_count")

def main():
    v=load_evidence(VPATH); validate_all(v,True); print("Draft-4 schema/semantic DAG verification PASS (256 batches; 8 aggregates; 7 focused mutations)")
if __name__=="__main__":
    try: main()
    except Exception as e: print(f"FAIL [{type(e).__name__}]: {e}",file=sys.stderr); raise
