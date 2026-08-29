"""Non-vacuous, isolated Draft-4 manifest-aware mutation gate."""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Callable, Literal

from strict_wire_one_os_phase2c_p_draft4 import canonical_json_bytes
from verify_manifest_one_os_phase2c_p_draft4 import MANIFEST_NAME, ROLE_IDS, ROLE_TABLE, ManifestReject, verify_bundle

BUNDLE_ID = 'phase2c-p-telemetry-authority-v2-draft4-20260825'
ROLE_ID = 'mutation_gate'
GENERATION = 4
CANDIDATE_STATUS = 'UNFROZEN_STAGING'
ROLE_API_VERSION = 1
Mode = Literal["PIN_CORRUPTION", "SEMANTIC_REPIN", "MANIFEST_MUTATION", "HARNESS_SELFTEST"]


@dataclass(frozen=True)
class MutationCase:
    case_id: str
    target_role: str
    mode: Mode
    mutate: Callable[[dict[str, bytes]], None]
    expected_code: str
    expected_pointer: str | None = None
    lifecycle_test: str | None = None


@dataclass(eq=False)
class HarnessReject(Exception):
    code: str
    detail: str = ""
    def __post_init__(self) -> None: super().__init__(self.code, self.detail)


def _hfail(code: str, detail: str = "") -> None: raise HarnessReject(code, detail)


def _load_manifest(path: Path) -> dict:
    try: value = json.loads(path.read_text("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc: _hfail("D4H002_INCOMPLETE_ISOLATION", str(exc))
    return value


def _inventory(manifest: Path) -> tuple[dict, dict[str, Path]]:
    m = _load_manifest(manifest)
    if type(m.get("roles")) is not list or len(m["roles"]) != len(ROLE_IDS): _hfail("D4H002_INCOMPLETE_ISOLATION")
    paths = {}
    for role in m["roles"]:
        role_id = role.get("roleId"); path = manifest.parent / str(role.get("path", ""))
        if role_id in paths or not path.is_file(): _hfail("D4H002_INCOMPLETE_ISOLATION", str(path))
        paths[role_id] = path
    if set(paths) != set(ROLE_IDS): _hfail("D4H002_INCOMPLETE_ISOLATION")
    return m, paths


def _envelope_hash(manifest: Path) -> str:
    raw_manifest = manifest.read_bytes(); m, paths = _inventory(manifest)
    h = hashlib.sha256()
    h.update(MANIFEST_NAME.encode() + b"\0" + len(raw_manifest).to_bytes(8, "big") + raw_manifest)
    for role_id in ROLE_IDS:
        raw = paths[role_id].read_bytes(); h.update(role_id.encode() + b"\0" + len(raw).to_bytes(8, "big") + raw)
    return h.hexdigest()


def _copy_complete(source: Path, target: Path) -> Path:
    m, paths = _inventory(source)
    target.mkdir(mode=0o700, parents=True, exist_ok=False)
    (target / MANIFEST_NAME).write_bytes(source.read_bytes())
    for role in m["roles"]: (target / role["path"]).write_bytes(paths[role["roleId"]].read_bytes())
    _inventory(target / MANIFEST_NAME)
    return target / MANIFEST_NAME


def _run_verifier(manifest: Path, timeout: float = 30.0) -> subprocess.CompletedProcess[bytes]:
    verifier = manifest.parent / next(path for role_id, path, _ in ROLE_TABLE if role_id == "portable_manifest_verifier")
    try:
        return subprocess.run([sys.executable, "-B", str(verifier), "--manifest", str(manifest), "--full"], cwd=manifest.parent, capture_output=True, timeout=timeout, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}, check=False)
    except subprocess.TimeoutExpired as exc:
        _hfail("D4H004_TIMEOUT", str(exc))


def _single_diagnostic(cp: subprocess.CompletedProcess[bytes]) -> dict:
    if cp.stderr or cp.stdout.count(b"\n") != 1 or not cp.stdout.endswith(b"\n"):
        _hfail("D4H005_UNSTRUCTURED_FAILURE", (cp.stdout + cp.stderr).decode("utf-8", "replace")[:300])
    try: value = json.loads(cp.stdout)
    except json.JSONDecodeError: _hfail("D4H005_UNSTRUCTURED_FAILURE")
    if type(value) is not dict or set(value) not in ({"code", "pointer", "status"}, {"bundleId", "rolesVerified", "status"}): _hfail("D4H005_UNSTRUCTURED_FAILURE")
    return value


def _require_named_unittest_failure(cp: subprocess.CompletedProcess[bytes], test_name: str) -> None:
    try: text=cp.stderr.decode("utf-8")
    except UnicodeDecodeError: _hfail("D4H005_UNSTRUCTURED_FAILURE", test_name)
    target=f"Draft4Tests.{test_name}"
    valid=(cp.returncode==1 and cp.stdout==b"" and target in text and
           f"FAIL: {test_name} (" in text and "ERROR:" not in text and
           re.search(r"Ran 1 test in [0-9.]+s\n",text) is not None and
           re.search(r"FAILED \(failures=[1-9][0-9]*\)\n$",text) is not None)
    if not valid: _hfail("D4H005_UNSTRUCTURED_FAILURE", text[:300])


def _expect_baseline_green(manifest: Path) -> None:
    cp = _run_verifier(manifest)
    try: diag = _single_diagnostic(cp)
    except HarnessReject as exc: _hfail("D4H006_BASELINE_NOT_GREEN", exc.code)
    if cp.returncode != 0 or diag.get("status") != "ACCEPT" or diag.get("rolesVerified") != len(ROLE_IDS): _hfail("D4H006_BASELINE_NOT_GREEN", str(diag))


def _expect_lifecycle_baselines_green(manifest: Path, test_names) -> None:
    names=sorted(set(test_names))
    if not names: return
    _,paths=_inventory(Path(manifest))
    harness=paths["lifecycle_harness"]
    selected=[f"{harness.stem}.Draft4Tests.{name}" for name in names]
    try:
        cp=subprocess.run([sys.executable,"-B","-m","unittest","-v",*selected],cwd=harness.parent,capture_output=True,timeout=600.0,env={**os.environ,"PYTHONDONTWRITEBYTECODE":"1"},check=False)
    except subprocess.TimeoutExpired:
        _hfail("D4H006_BASELINE_NOT_GREEN","lifecycle timeout")
    try: text=cp.stderr.decode("utf-8")
    except UnicodeDecodeError: _hfail("D4H006_BASELINE_NOT_GREEN","lifecycle stderr")
    complete=(cp.returncode==0 and cp.stdout==b"" and "FAIL:" not in text and "ERROR:" not in text and
              all(f"Draft4Tests.{name}" in text for name in names) and
              re.search(rf"Ran {len(names)} tests? in [0-9.]+s\n\nOK\n$",text) is not None)
    if not complete: _hfail("D4H006_BASELINE_NOT_GREEN",text[:300])


def _repin(manifest: Path, role_id: str) -> None:
    m = _load_manifest(manifest)
    role = next((r for r in m["roles"] if r["roleId"] == role_id), None)
    if role is None: _hfail("D4H002_INCOMPLETE_ISOLATION")
    raw = (manifest.parent / role["path"]).read_bytes(); role["bytes"] = len(raw); role["sha256"] = hashlib.sha256(raw).hexdigest()
    manifest.write_bytes(canonical_json_bytes(m))


def apply_case(source_manifest: Path, case: MutationCase, baseline_checked: bool=False) -> dict:
    source_manifest = Path(source_manifest)
    if case.lifecycle_test is not None and not baseline_checked:
        _expect_lifecycle_baselines_green(source_manifest,[case.lifecycle_test])
    with tempfile.TemporaryDirectory(prefix=f"d4-case-{case.case_id}-") as td:
        isolated = _copy_complete(source_manifest, Path(td) / "bundle")
        m, paths = _inventory(isolated)
        files = {role_id: path.read_bytes() for role_id, path in paths.items()}
        files["__manifest__"] = isolated.read_bytes()
        before = dict(files)
        case.mutate(files)
        changed = {key for key in files if files[key] != before[key]} | {key for key in before if key not in files}
        if not changed: _hfail("D4H001_NO_MUTATION", case.case_id)
        expected_changed = {"__manifest__"} if case.mode == "MANIFEST_MUTATION" else {case.target_role}
        if changed != expected_changed: _hfail("D4H003_MUTATION_SCOPE", f"{case.case_id}: {sorted(changed)}")
        for role_id in ROLE_IDS:
            if role_id not in files: _hfail("D4H002_INCOMPLETE_ISOLATION")
            paths[role_id].write_bytes(files[role_id])
        isolated.write_bytes(files["__manifest__"])
        if case.mode == "SEMANTIC_REPIN": _repin(isolated, case.target_role)
        elif case.mode == "PIN_CORRUPTION" and isolated.read_bytes() != before["__manifest__"]: _hfail("D4H003_MUTATION_SCOPE")
        if case.lifecycle_test is not None:
            harness = paths["lifecycle_harness"]
            try:
                cp = subprocess.run([sys.executable,"-B","-m","unittest","-v",f"{harness.stem}.Draft4Tests.{case.lifecycle_test}"],cwd=isolated.parent,capture_output=True,timeout=120.0,env={**os.environ,"PYTHONDONTWRITEBYTECODE":"1"},check=False)
            except subprocess.TimeoutExpired:
                _hfail("D4H004_TIMEOUT",case.case_id)
            if cp.returncode == 0: _hfail("D4H007_MUTATION_SURVIVED",case.case_id)
            _require_named_unittest_failure(cp,case.lifecycle_test)
            return {"code":case.expected_code,"pointer":"","status":"REJECT"}
        cp = _run_verifier(isolated)
        diag = _single_diagnostic(cp)
        if cp.returncode == 0 or diag.get("status") != "REJECT" or diag.get("code") != case.expected_code:
            _hfail("D4H005_UNSTRUCTURED_FAILURE", f"expected {case.expected_code}, got {diag}")
        if case.expected_pointer is not None and diag.get("pointer") != case.expected_pointer: _hfail("D4H005_UNSTRUCTURED_FAILURE", str(diag))
        if diag.get("code") == "D4M011_NOT_REGULAR" or (diag.get("code") == "D4M019_FULL_VERIFIER_PROTOCOL" and case.expected_code != "D4M019_FULL_VERIFIER_PROTOCOL"): _hfail("D4H002_INCOMPLETE_ISOLATION", str(diag))
        return diag


def _replace(raw: bytes, old: bytes, new: bytes) -> bytes:
    if raw.count(old) != 1: _hfail("D4H003_MUTATION_SCOPE", "mutation witness not unique")
    return raw.replace(old, new)


def default_cases() -> list[MutationCase]:
    import base64
    def pin_sha(files):
        raw=bytearray(files["authority_contract"]); pos=raw.index(b"\n# ")+3; raw[pos] ^= 1; files["authority_contract"]=bytes(raw)
    def identity(files): files["strict_wire_codec"] = _replace(files["strict_wire_codec"], b"ROLE_ID = 'strict_wire_codec'", b"ROLE_ID = 'wrong_role'")
    def closure(files):
        c=json.loads(files["closure_index"]); c["canonicalRoleSequence"].reverse(); files["closure_index"]=canonical_json_bytes(c)
    def closure_remove(files):
        c=json.loads(files["closure_index"]); c["bindings"].pop(0); files["closure_index"]=canonical_json_bytes(c)
    def closure_extra(files):
        c=json.loads(files["closure_index"]); c["bindings"].append(dict(c["bindings"][0],bindingId="unexpected-binding")); files["closure_index"]=canonical_json_bytes(c)
    def closure_swap(files):
        c=json.loads(files["closure_index"]); c["bindings"][4]["subjectRoles"].reverse(); files["closure_index"]=canonical_json_bytes(c)
    def status(files):
        m=json.loads(files["__manifest__"]); m["candidateStatus"]="APPROVED"; files["__manifest__"]=canonical_json_bytes(m)
    def vector(files, mutate):
        v=json.loads(files["canonical_vectors"]); mutate(v); files["canonical_vectors"]=canonical_json_bytes(v)
    def reseal(section):
        raw=canonical_json_bytes(section["object"]); section["canonicalUtf8"]=raw.decode(); section["length"]=len(raw); section["sha256"]=base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).rstrip(b"=").decode()
    def duplicate_wire(files):
        def m(v):
            s=v["telemetryBatches256"][0]; raw=s["canonicalUtf8"].replace('{"batchAuthorizationRevision":7,','{"batchAuthorizationRevision":7,"batchAuthorizationRevision":7,',1).encode(); s["canonicalUtf8"]=raw.decode(); s["length"]=len(raw); s["sha256"]=base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).rstrip(b"=").decode()
        vector(files,m)
    def float_wire(files):
        def m(v):
            s=v["telemetryBatches256"][0]; raw=s["canonicalUtf8"].replace('{"batchAuthorizationRevision":7,','{"batchAuthorizationRevision":7.0,',1).encode(); s["canonicalUtf8"]=raw.decode(); s["length"]=len(raw); s["sha256"]=base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).rstrip(b"=").decode()
        vector(files,m)
    def invalid_calendar(files):
        vector(files,lambda v:(v["telemetryBatches256"][0]["object"].__setitem__("createdAt","2030-02-31T12:00:00.000Z"),reseal(v["telemetryBatches256"][0])))
    def bool_revision(files):
        vector(files,lambda v:(v["telemetryBatches256"][0]["object"].__setitem__("batchAuthorizationRevision",True),reseal(v["telemetryBatches256"][0])))
    def receipt_alias(files):
        vector(files,lambda v:(v["receipt"]["object"].__setitem__("allowedTransportCredentialIds",["00000000-0000-4000-8000-000000000004","00000000-0000-4000-8000-000000000005"]),reseal(v["receipt"])))
    def issued_alias(files):
        vector(files,lambda v:(v["issuedResponse"]["object"].__setitem__("oldCredentialId","00000000-0000-4000-8000-000000000004"),reseal(v["issuedResponse"])))
    def ack_alias(files):
        vector(files,lambda v:(v["renewalAckRequest"]["object"].__setitem__("installationRevisionBefore",18),reseal(v["renewalAckRequest"])))
    def cancel_alias(files):
        vector(files,lambda v:(v["cancelResponse"]["object"].__setitem__("cancelRequestSha256","AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),reseal(v["cancelResponse"])))
    def capability_301(files):
        vector(files,lambda v:(v["capability"]["object"].__setitem__("expiresAt","2030-01-01T12:05:01Z"),reseal(v["capability"])))
    def conflict_code(files):
        vector(files,lambda v:(v["immutableIdentityConflict"]["response"]["object"].__setitem__("code","other_conflict"),reseal(v["immutableIdentityConflict"]["response"])))
    def outer_extra(files): vector(files,lambda v:v.__setitem__("diagnosticBlob","public"))
    def private_fixture(files):
        import secrets
        order=0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
        scalar=(secrets.randbelow(order-1)+1).to_bytes(32,"big")
        der=b"\x30\x41\x02\x01\x00\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x04\x27\x30\x25\x02\x01\x01\x04\x20"+scalar
        encoded=base64.urlsafe_b64encode(der).rstrip(b"=").decode()
        vector(files,lambda v:v["cryptoFixtures"]["negativePublic"].__setitem__("badCsrSelfSignature",encoded))
    def negative_public_extra_key(files):
        vector(files,lambda v:v["cryptoFixtures"]["negativePublic"].__setitem__("unexpectedPublic","benign"))
    def private_fixture_standard_base64(files):
        import secrets
        order=0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
        scalar=(secrets.randbelow(order-1)+1).to_bytes(32,"big")
        der=b"\x30\x41\x02\x01\x00\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x04\x27\x30\x25\x02\x01\x01\x04\x20"+scalar
        encoded=base64.b64encode(der).decode()
        vector(files,lambda v:v["cryptoFixtures"]["negativePublic"].__setitem__("badCsrSelfSignature",encoded))
    def private_fixture_object_key(files):
        import secrets
        order=0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
        scalar=(secrets.randbelow(order-1)+1).to_bytes(32,"big")
        der=b"\x30\x41\x02\x01\x00\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x04\x27\x30\x25\x02\x01\x01\x04\x20"+scalar
        encoded=base64.urlsafe_b64encode(der).rstrip(b"=").decode()
        vector(files,lambda v:v["entryBoundary"]["255"][0].__setitem__(encoded,"public-probe-marker"))
    def timestamp_inventory(files):
        s=json.loads(files["telemetry_batch_schema"]); del s["properties"]["createdAt"]["format"]; files["telemetry_batch_schema"]=canonical_json_bytes(s)
    def schema_byte_change(files, role):
        s=json.loads(files[role]); s["title"] += " changed"; files[role]=canonical_json_bytes(s)
    def wheel_trailing(files, role): files[role] += b"\\x00"

    def cap_boundary(files):
        e=json.loads(files["cap_x509_boundary_evidence"]); e["proposedCaps"]["manifestCanonicalBytes"]+=1; files["cap_x509_boundary_evidence"]=canonical_json_bytes(e)
    def cap_leaf_crypto(files):
        e=json.loads(files["cap_x509_boundary_evidence"]); pem=e["cryptoFixtures"]["newCertificatePem"]; lines=pem.strip().splitlines(); der=bytearray(base64.b64decode("".join(lines[1:-1]))); der[-1]^=1; encoded=base64.b64encode(der).decode(); e["cryptoFixtures"]["newCertificatePem"]="-----BEGIN CERTIFICATE-----\n"+"\n".join(encoded[i:i+64] for i in range(0,len(encoded),64))+"\n-----END CERTIFICATE-----\n"; files["cap_x509_boundary_evidence"]=canonical_json_bytes(e)
    def cap_parent_schema(files):
        e=json.loads(files["cap_x509_boundary_evidence"]); section=e["capVectors"]["manifest"]["changedParentExact"]; section["object"]={}; reseal(section); files["cap_x509_boundary_evidence"]=canonical_json_bytes(e)
    def cap_parent_payload_hash(files):
        e=json.loads(files["cap_x509_boundary_evidence"]); section=e["capVectors"]["manifest"]["changedParentExact"]; section["object"]["payloadSha256"]="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; reseal(section); files["cap_x509_boundary_evidence"]=canonical_json_bytes(e)
    def cap_private_der(files):
        import secrets
        order=0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
        scalar=(secrets.randbelow(order-1)+1).to_bytes(32,"big")
        der=b"\x30\x41\x02\x01\x00\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x04\x27\x30\x25\x02\x01\x01\x04\x20"+scalar
        e=json.loads(files["cap_x509_boundary_evidence"]); e["cryptoFixtures"]["negativePublic"]["badKuPem"]=base64.urlsafe_b64encode(der).rstrip(b"=").decode(); files["cap_x509_boundary_evidence"]=canonical_json_bytes(e)
    def cap_issued_hash(files):
        e=json.loads(files["cap_x509_boundary_evidence"]); section=e["capVectors"]["issuedResponse"]["exact"]; section["object"]["newCertificateSha256"]="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; reseal(section); files["cap_x509_boundary_evidence"]=canonical_json_bytes(e)
    def cap_issued_leaf(files):
        e=json.loads(files["cap_x509_boundary_evidence"]); section=e["capVectors"]["issuedResponse"]["exact"]; section["object"]["certificatePem"]=e["cryptoFixtures"]["negativePublic"]["badKuPem"]; reseal(section); files["cap_x509_boundary_evidence"]=canonical_json_bytes(e)
    def cap_issued_root(files):
        e=json.loads(files["cap_x509_boundary_evidence"]); section=e["capVectors"]["issuedResponse"]["exact"]; pem=section["object"]["caChainPem"]; end=pem.index("\n-----END CERTIFICATE-----"); pos=end-2; replacement="A" if pem[pos]!="A" else "B"; section["object"]["caChainPem"]=pem[:pos]+replacement+pem[pos+1:]; reseal(section); files["cap_x509_boundary_evidence"]=canonical_json_bytes(e)
    def remove_root_curve(files):
        files["protocol_helpers"]=_replace(files["protocol_helpers"],b' and key.curve.name=="secp256r1"',b'')
    def weaken_root_ku_guard(files):
        files["protocol_helpers"]=_replace(files["protocol_helpers"],b'require(ku==x509.KeyUsage(False,False,False,False,False,True,True,False,False),"root_ku")',b'require(ku.key_cert_sign and ku.crl_sign and not ku.digital_signature,"root_ku")')
    def remove_leaf_ku_guard(files):
        files["protocol_helpers"]=_replace(files["protocol_helpers"],b'require(ku.digital_signature and not any((ku.content_commitment,ku.key_encipherment,ku.data_encipherment,ku.key_agreement,ku.key_cert_sign,ku.crl_sign)),"leaf_ku")',b'require(True,"leaf_ku")')
    def remove_issuer_serial_guard(files):
        files["protocol_helpers"]=_replace(files["protocol_helpers"],b'if key in ledger: require(ledger[key]==cert_der,"issuer_serial_collision")',b'if False and key in ledger: require(ledger[key]==cert_der,"issuer_serial_collision")')
    def manifest_257(files):
        def m(v):
            sec=v["manifest256"]
            for entry in sec["object"]["entries"]: entry["journalId"]=1; entry["requestLength"]=1
            sec["object"]["entries"].append(dict(sec["object"]["entries"][-1],journalId=1))
            sec["object"]["entryCount"]=257; sec["object"]["totalRequestBytes"]=257; reseal(sec)
        vector(files,m)
    def life_pending_store(files): files["lifecycle_harness"]=_replace(files["lifecycle_harness"],b'sha(pending_raw),pending_raw)); crash',b'None,None)); crash')
    def life_issued_store(files): files["lifecycle_harness"]=_replace(files["lifecycle_harness"],b'(sha(source_raw),source_raw,rid)); crash("renewal.issue.after_pending_ack"',b'(None,None,rid)); crash("renewal.issue.after_pending_ack"')
    def life_issue_context_alias(files):
        files["lifecycle_harness"]=_replace(files["lifecycle_harness"],b'if any(source[key]!=pending_obj[key] for key in shared): return fail("INVALID_STATE")',b'if False: return fail("INVALID_STATE")')
        files["lifecycle_harness"]=_replace(files["lifecycle_harness"],b' or source["newCredentialId"]!=pending',b'')
    def life_promote_context_alias(files):
        files["lifecycle_harness"]=_replace(files["lifecycle_harness"],b'if expected["telemetryAuthorizationRevisionBefore"]+1!=ar or any(source[key]!=value for key,value in expected.items()): return fail("INVALID_STATE")',b'if expected["telemetryAuthorizationRevisionBefore"]+1!=ar: return fail("INVALID_STATE")')
        files["lifecycle_harness"]=_replace(files["lifecycle_harness"],b'if response!=expected_response: return fail("INVALID_STATE")',b'if False: return fail("INVALID_STATE")')
    def life_pending_response_alias(files):
        files["lifecycle_harness"]=_replace(files["lifecycle_harness"],b'if pending_obj!=expected_pending: return fail("INVALID_STATE")',b'if False: return fail("INVALID_STATE")')
    def life_cancel_context_alias(files):
        files["lifecycle_harness"]=_replace(files["lifecycle_harness"],b'if source!=expected_source or response!=expected_response: return fail("INVALID_STATE")',b'if False: return fail("INVALID_STATE")')
    def life_public_renewal_replay(files):
        files["lifecycle_harness"]=_replace(files["lifecycle_harness"],b'if args.route=="renewal.issue":',b'if False and args.route=="renewal.issue":')
    def life_receipt_db_clock(files):
        files["lifecycle_harness"]=_replace(files["lifecycle_harness"],b'if receipt_obj["notBefore"]!=now_value or receipt_obj["expiresAt"]!=receipt_expires: return fail("INVALID_STATE")',b'if False: return fail("INVALID_STATE")')
    def life_cancel_committed_precedence(files):
        files["lifecycle_harness"]=_replace(files["lifecycle_harness"],b'if con.execute("SELECT 1 FROM renewal WHERE operation_id=?",(cancel_source["targetRequestId"],)).fetchone(): return fail("CANCEL_TARGET_COMMITTED")',b'if False: return fail("CANCEL_TARGET_COMMITTED")')
    def life_issued_replay_state_independent(files):
        files["lifecycle_harness"]=_replace(files["lifecycle_harness"],b'if prior[1]!=sha(public_raw) or prior[2]!=public_raw or sha(prior[2])!=prior[1]:',b'if prior[0] not in ("issued","acked") or prior[1]!=sha(public_raw) or prior[2]!=public_raw or sha(prior[2])!=prior[1]:')
    def life_issue_outer_installation(files):
        files["lifecycle_harness"]=_replace(files["lifecycle_harness"],b'if public_obj["installationId"]!=req["installationId"]:\n                con.rollback(); con.close(); send_frame(args.result_fd,error_bytes("INVALID_STATE",opid)); return 0\n            prior=con.execute',b'if False:\n                con.rollback(); con.close(); send_frame(args.result_fd,error_bytes("INVALID_STATE",opid)); return 0\n            prior=con.execute')
    def life_promote_outer_installation(files):
        files["lifecycle_harness"]=_replace(files["lifecycle_harness"],b'if public_obj["installationId"]!=req["installationId"]:\n                con.rollback(); con.close(); send_frame(args.result_fd,error_bytes("INVALID_STATE",opid)); return 0\n            renewal_state=con.execute',b'if False:\n                con.rollback(); con.close(); send_frame(args.result_fd,error_bytes("INVALID_STATE",opid)); return 0\n            renewal_state=con.execute')
    def life_cancel_tombstone_bijection(files):
        files["lifecycle_harness"]=_replace(files["lifecycle_harness"],b'if tomb!=(sha(source_raw),mh): return fail("REPLAY_CONFLICT")',b'if False: return fail("REPLAY_CONFLICT")')
    def life_issue_expiry(files):
        files["lifecycle_harness"]=_replace(files["lifecycle_harness"],b'if dt.datetime.strptime(utc(con.execute("SELECT value FROM meta WHERE key=\'clock\'").fetchone()[0]),"%Y-%m-%dT%H:%M:%SZ")>=dt.datetime.strptime(pending_obj["issuanceExpiresAt"],"%Y-%m-%dT%H:%M:%SZ"): return fail("ACK_EXPIRED")',b'if False: return fail("ACK_EXPIRED")')
    def life_promote_expiry(files):
        files["lifecycle_harness"]=_replace(files["lifecycle_harness"],b'if dt.datetime.strptime(utc(con.execute("SELECT value FROM meta WHERE key=\'clock\'").fetchone()[0]),"%Y-%m-%dT%H:%M:%SZ")>=dt.datetime.strptime(issued_obj["ackExpiresAt"],"%Y-%m-%dT%H:%M:%SZ"): return fail("ACK_EXPIRED")',b'if False: return fail("ACK_EXPIRED")')
    def life_cancel_collision(files):
        files["lifecycle_harness"]=_replace(files["lifecycle_harness"],b'if by_target or by_target_hash or by_manifest: return fail("REPLAY_CONFLICT")',b'if False: return fail("REPLAY_CONFLICT")')
    def life_cancel_manifest_bijection(files):
        raw=_replace(files["lifecycle_harness"],b'manifest_sha256 BLOB NOT NULL UNIQUE CHECK(length(manifest_sha256)=32)',b'manifest_sha256 BLOB NOT NULL CHECK(length(manifest_sha256)=32)')
        files["lifecycle_harness"]=_replace(raw,b'if by_target or by_target_hash or by_manifest: return fail("REPLAY_CONFLICT")',b'if by_target or by_target_hash: return fail("REPLAY_CONFLICT")')
    def life_pairing_lifecycle_cas(files):
        files["lifecycle_harness"]=_replace(files["lifecycle_harness"],b'if route.startswith("pairing.") and p["pairingLifecycleRevision"]!=lr: return fail("INVALID_STATE")',b'if False and route.startswith("pairing.") and p["pairingLifecycleRevision"]!=lr: return fail("INVALID_STATE")')
    def life_ack_raw(files): files["lifecycle_harness"]=_replace(files["lifecycle_harness"],b'(proof,opid,nonce,source_raw)); crash',b'(proof,opid,nonce,canon({"lost":True}))); crash')
    def life_cancel_raw(files): files["lifecycle_harness"]=_replace(files["lifecycle_harness"],b'unb64(source["backlogManifestSha256"]),source_raw)); crash',b'unb64(source["backlogManifestSha256"]),canon({"lost":True}))); crash')
    def life_db_time(files): files["lifecycle_harness"]=_replace(files["lifecycle_harness"],b'if not dt.datetime.strptime(utc(row[1]),"%Y-%m-%dT%H:%M:%SZ") <= now < dt.datetime.strptime(utc(row[2]),"%Y-%m-%dT%H:%M:%SZ"): return fail("HISTORICAL_RECEIPT_CLOSED")',b'if False: return fail("HISTORICAL_RECEIPT_CLOSED")')
    def life_transport(files): files["lifecycle_harness"]=_replace(files["lifecycle_harness"],b'if p["presentedTransportCredentialId"] not in receipt_object["allowedTransportCredentialIds"]: return fail("HISTORICAL_TRANSPORT_UNAUTHORIZED")',b'if False: return fail("HISTORICAL_TRANSPORT_UNAUTHORIZED")')
    def life_replay(files): files["lifecycle_harness"]=_replace(files["lifecycle_harness"],b'        if by_batch or by_hash:',b'        if False and (by_batch or by_hash):')
    def life_telemetry_ack_wire(files):
        old=b'ack=canon({"schemaVersion":"one-os-telemetry-ack/v2","authorizationMode":"historical_backlog","installationId":iid,"credentialId":p["credentialId"],"batchId":p["batchId"],"batchAuthorizationRevision":p["authorizationRevision"],"ingestAuthorizationRevision":ar,"requestSha256":b64u(source_hash),"acceptedSamples":len(source_obj.get("samples",[])),"duplicateSamples":0,"acceptedQualityEvents":len(source_obj.get("qualityEvents",[])),"duplicateQualityEvents":0,"acceptedGaps":len(source_obj.get("gaps",[])),"duplicateGaps":0,"ingestCursor":entry[0],"acceptedAt":utc(con.execute("SELECT value FROM meta WHERE key=\'clock\'").fetchone()[0]),"historicalAuthorizationReceiptSha256":b64u(receipt)})'
        files["lifecycle_harness"]=_replace(files["lifecycle_harness"],old,b'ack=canon({"batchId":p["batchId"],"installationId":iid,"requestSha256":source_hash.hex()})')
    def life_telemetry_error_wire(files):
        files["lifecycle_harness"]=_replace(files["lifecycle_harness"],b'error=canon({"schemaVersion":"one-os-telemetry-error/v2","batchId":p["batchId"],"code":"immutable_identity_conflict","decidedAt":decided,"requestSha256":b64u(source_hash),"retryClass":"terminal_quarantine"})',b'error=error_bytes("IMMUTABLE_IDENTITY_CONFLICT",opid)')
    def life_issuer(files): files["lifecycle_harness"]=_replace(files["lifecycle_harness"],b'issuer=sha(issuer_der); serial=',b'issuer=sha(source_raw); serial=')
    def life_cleanup_scope(files): files["lifecycle_harness"]=_replace(files["lifecycle_harness"],b'if owned_db in argv and any(Path(os.fsdecode(a)).name.encode()==basename',b'if any(Path(os.fsdecode(a)).name.encode()==basename')
    def semantic_unexpected(files): files["semantic_crypto_verifier"]=_replace(files["semantic_crypto_verifier"],b'lambda:verify_csr(unb64(neg["badCsrSelfSignature"])',b'lambda:(_ for _ in ()).throw(ValueError("unexpected")) if True else verify_csr(unb64(neg["badCsrSelfSignature"])')
    def focused_unexpected(files):
        files["semantic_validator"]=_replace(files["semantic_validator"],b'rejected(lambda:parse_time("2030-02-31T12:00:00Z"),"calendar","timestamp_calendar")',b'rejected(lambda:(_ for _ in ()).throw(RuntimeError("UNRELATED_PARSER_FAILURE")),"calendar","timestamp_calendar")')
    def cap_unexpected(files): files["cap_x509_boundary_verifier"]=_replace(files["cap_x509_boundary_verifier"],b'lambda cert=cert: verify_leaf(cert.public_bytes',b'lambda cert=cert: (_ for _ in ()).throw(ValueError("unexpected")) if True else verify_leaf(cert.public_bytes')
    return [
        MutationCase("pin-sha","authority_contract","PIN_CORRUPTION",pin_sha,"D4M014_SHA256"),
        MutationCase("internal-identity","strict_wire_codec","SEMANTIC_REPIN",identity,"D4M016_INTERNAL_IDENTITY"),
        MutationCase("closure-sequence","closure_index","SEMANTIC_REPIN",closure,"D4M015_CLOSURE_INDEX"),
        MutationCase("closure-remove-binding","closure_index","SEMANTIC_REPIN",closure_remove,"D4M015_CLOSURE_INDEX"),
        MutationCase("closure-extra-binding","closure_index","SEMANTIC_REPIN",closure_extra,"D4M015_CLOSURE_INDEX"),
        MutationCase("closure-swap-subjects","closure_index","SEMANTIC_REPIN",closure_swap,"D4M015_CLOSURE_INDEX"),
        MutationCase("manifest-status","__manifest__","MANIFEST_MUTATION",status,"D4M004_CANDIDATE_STATUS"),
        MutationCase("duplicate-wire","canonical_vectors","SEMANTIC_REPIN",duplicate_wire,"D4W005_DUPLICATE_KEY"),
        MutationCase("float-wire","canonical_vectors","SEMANTIC_REPIN",float_wire,"D4W006_FLOAT_FORBIDDEN"),
        MutationCase("invalid-calendar","canonical_vectors","SEMANTIC_REPIN",invalid_calendar,"D4S_TIMESTAMP_CALENDAR"),
        MutationCase("bool-revision","canonical_vectors","SEMANTIC_REPIN",bool_revision,"D4J001_EXACT_TYPE"),
        MutationCase("receipt-alias","canonical_vectors","SEMANTIC_REPIN",receipt_alias,"D4S_RECEIPT_EXACT_OLD_PENDING"),
        MutationCase("issued-alias","canonical_vectors","SEMANTIC_REPIN",issued_alias,"D4S_ISSUED_ALIAS_OLDCREDENTIALID"),
        MutationCase("ack-alias","canonical_vectors","SEMANTIC_REPIN",ack_alias,"D4S_ACK_REQUEST_ALIAS_INSTALLATIONREVISIONBEFORE"),
        MutationCase("cancel-alias","canonical_vectors","SEMANTIC_REPIN",cancel_alias,"D4S_CANCEL_EDGE_CANCELREQUESTSHA256"),
        MutationCase("capability-301","canonical_vectors","SEMANTIC_REPIN",capability_301,"D4S_CAPABILITY_EXACT_300"),
        MutationCase("conflict-code","canonical_vectors","SEMANTIC_REPIN",conflict_code,"D4J003_SCHEMA_CONSTRAINT"),
        MutationCase("outer-vector-keyset","canonical_vectors","SEMANTIC_REPIN",outer_extra,"D4S_VECTOR_OUTER_KEYSET"),
        MutationCase("negative-public-extra-key","canonical_vectors","SEMANTIC_REPIN",negative_public_extra_key,"D4S_NEGATIVE_PUBLIC_KEYSET"),
        MutationCase("private-der-fixture","canonical_vectors","SEMANTIC_REPIN",private_fixture,"D4S_PRIVATE_FIXTURE_MATERIAL"),
        MutationCase("private-der-standard-base64","canonical_vectors","SEMANTIC_REPIN",private_fixture_standard_base64,"D4S_PRIVATE_FIXTURE_MATERIAL"),
        MutationCase("private-der-object-key","canonical_vectors","SEMANTIC_REPIN",private_fixture_object_key,"D4S_PRIVATE_FIXTURE_MATERIAL"),
        MutationCase("timestamp-inventory","telemetry_batch_schema","SEMANTIC_REPIN",timestamp_inventory,"D4S_SCHEMA_TIMESTAMP_INVENTORY"),
        MutationCase("capability-batch-schema-hash","telemetry_batch_schema","SEMANTIC_REPIN",lambda f:schema_byte_change(f,"telemetry_batch_schema"),"D4S_CAPABILITY_SCHEMA_HASH_BATCH"),
        MutationCase("capability-ack-schema-hash","telemetry_ack_schema","SEMANTIC_REPIN",lambda f:schema_byte_change(f,"telemetry_ack_schema"),"D4S_CAPABILITY_SCHEMA_HASH_ACK"),
        MutationCase("capability-error-schema-hash","telemetry_error_schema","SEMANTIC_REPIN",lambda f:schema_byte_change(f,"telemetry_error_schema"),"D4S_CAPABILITY_SCHEMA_HASH_ERROR"),
        MutationCase("capability-control-schema-hash","renewal_control_schema","SEMANTIC_REPIN",lambda f:schema_byte_change(f,"renewal_control_schema"),"D4S_CAPABILITY_SCHEMA_HASH_CONTROL"),
        MutationCase("cryptography-wheel-trailing","runtime_cryptography_wheel","SEMANTIC_REPIN",lambda f:wheel_trailing(f,"runtime_cryptography_wheel"),"D4M021_RUNTIME_WHEEL"),
        MutationCase("cffi-wheel-trailing","runtime_cffi_wheel","SEMANTIC_REPIN",lambda f:wheel_trailing(f,"runtime_cffi_wheel"),"D4M021_RUNTIME_WHEEL"),

        MutationCase("cap-evidence-boundary","cap_x509_boundary_evidence","SEMANTIC_REPIN",cap_boundary,"D4C_CAP_BOUNDARY"),
        MutationCase("cap-evidence-leaf-crypto","cap_x509_boundary_evidence","SEMANTIC_REPIN",cap_leaf_crypto,"D4C_CRYPTO_PROFILE"),
        MutationCase("cap-parent-schema","cap_x509_boundary_evidence","SEMANTIC_REPIN",cap_parent_schema,"D4C_SECTION_SCHEMA"),
        MutationCase("cap-parent-payload-hash","cap_x509_boundary_evidence","SEMANTIC_REPIN",cap_parent_payload_hash,"D4C_PARENT_PAYLOAD_HASH"),
        MutationCase("cap-private-der","cap_x509_boundary_evidence","SEMANTIC_REPIN",cap_private_der,"D4C_PRIVATE_FIXTURE_MATERIAL"),
        MutationCase("cap-issued-hash","cap_x509_boundary_evidence","SEMANTIC_REPIN",cap_issued_hash,"D4C_PAIR_CRYPTO_BINDING"),
        MutationCase("cap-issued-leaf","cap_x509_boundary_evidence","SEMANTIC_REPIN",cap_issued_leaf,"D4C_CRYPTO_PROFILE"),
        MutationCase("cap-issued-root","cap_x509_boundary_evidence","SEMANTIC_REPIN",cap_issued_root,"D4C_PAIR_CRYPTO_BINDING"),
        MutationCase("root-curve-guard","protocol_helpers","SEMANTIC_REPIN",remove_root_curve,"D4C_NEGATIVE_ACCEPTED"),
        MutationCase("root-ku-exact-guard","protocol_helpers","SEMANTIC_REPIN",weaken_root_ku_guard,"D4C_NEGATIVE_ACCEPTED"),
        MutationCase("old-leaf-ku-guard","protocol_helpers","SEMANTIC_REPIN",remove_leaf_ku_guard,"D4C_NEGATIVE_ACCEPTED"),
        MutationCase("issuer-serial-collision-guard","protocol_helpers","SEMANTIC_REPIN",remove_issuer_serial_guard,"D4C_NEGATIVE_ACCEPTED"),
        MutationCase("manifest-257","canonical_vectors","SEMANTIC_REPIN",manifest_257,"D4J003_SCHEMA_CONSTRAINT"),
        MutationCase("lifecycle-pending-store","lifecycle_harness","SEMANTIC_REPIN",life_pending_store,"D4L_TEST_REJECT",None,"test_public_pending_issued_ack_wire_is_durable_terminal_authority"),
        MutationCase("lifecycle-issued-store","lifecycle_harness","SEMANTIC_REPIN",life_issued_store,"D4L_TEST_REJECT",None,"test_public_pending_issued_ack_wire_is_durable_terminal_authority"),
        MutationCase("lifecycle-issue-context-alias","lifecycle_harness","SEMANTIC_REPIN",life_issue_context_alias,"D4L_TEST_REJECT",None,"test_renewal_issue_rejects_every_detached_context_alias_before_mutation"),
        MutationCase("lifecycle-promote-context-alias","lifecycle_harness","SEMANTIC_REPIN",life_promote_context_alias,"D4L_TEST_REJECT",None,"test_renewal_promote_rejects_every_detached_ack_alias_before_mutation"),
        MutationCase("lifecycle-pending-response-alias","lifecycle_harness","SEMANTIC_REPIN",life_pending_response_alias,"D4L_TEST_REJECT",None,"test_renewal_reserve_rejects_every_detached_pending_alias_before_mutation"),
        MutationCase("lifecycle-cancel-context-alias","lifecycle_harness","SEMANTIC_REPIN",life_cancel_context_alias,"D4L_TEST_REJECT",None,"test_renewal_cancel_rejects_detached_request_and_response_aliases_before_mutation"),
        MutationCase("lifecycle-public-renewal-replay","lifecycle_harness","SEMANTIC_REPIN",life_public_renewal_replay,"D4L_TEST_REJECT",None,"test_public_replay_identity_survives_new_internal_invocation_id"),
        MutationCase("lifecycle-receipt-db-clock","lifecycle_harness","SEMANTIC_REPIN",life_receipt_db_clock,"D4L_TEST_REJECT",None,"test_reserve_receipt_window_binds_db_clock_before_mutation"),
        MutationCase("lifecycle-cancel-committed-precedence","lifecycle_harness","SEMANTIC_REPIN",life_cancel_committed_precedence,"D4L_TEST_REJECT",None,"test_cancel_reserve_serial_orders"),
        MutationCase("lifecycle-issued-replay-state-independent","lifecycle_harness","SEMANTIC_REPIN",life_issued_replay_state_independent,"D4L_TEST_REJECT",None,"test_public_replay_identity_survives_new_internal_invocation_id"),
        MutationCase("lifecycle-issue-outer-installation","lifecycle_harness","SEMANTIC_REPIN",life_issue_outer_installation,"D4L_TEST_REJECT",None,"test_public_replay_identity_survives_new_internal_invocation_id"),
        MutationCase("lifecycle-promote-outer-installation","lifecycle_harness","SEMANTIC_REPIN",life_promote_outer_installation,"D4L_TEST_REJECT",None,"test_public_replay_identity_survives_new_internal_invocation_id"),
        MutationCase("lifecycle-cancel-tombstone-bijection","lifecycle_harness","SEMANTIC_REPIN",life_cancel_tombstone_bijection,"D4L_TEST_REJECT",None,"test_cancel_reserve_serial_orders"),
        MutationCase("lifecycle-issue-expiry","lifecycle_harness","SEMANTIC_REPIN",life_issue_expiry,"D4L_TEST_REJECT",None,"test_issue_and_promote_expiry_precede_every_mutation"),
        MutationCase("lifecycle-promote-expiry","lifecycle_harness","SEMANTIC_REPIN",life_promote_expiry,"D4L_TEST_REJECT",None,"test_issue_and_promote_expiry_precede_every_mutation"),
        MutationCase("lifecycle-cancel-collision","lifecycle_harness","SEMANTIC_REPIN",life_cancel_collision,"D4L_TEST_REJECT",None,"test_cancel_reserve_serial_orders"),
        MutationCase("lifecycle-cancel-manifest-bijection","lifecycle_harness","SEMANTIC_REPIN",life_cancel_manifest_bijection,"D4L_TEST_REJECT",None,"test_cancel_reserve_serial_orders"),
        MutationCase("lifecycle-pairing-revision-cas","lifecycle_harness","SEMANTIC_REPIN",life_pairing_lifecycle_cas,"D4L_TEST_REJECT",None,"test_pairing_hooks_require_exact_lifecycle_revision_before_every_mutation"),
        MutationCase("lifecycle-ack-raw","lifecycle_harness","SEMANTIC_REPIN",life_ack_raw,"D4L_TEST_REJECT",None,"test_public_pending_issued_ack_wire_is_durable_terminal_authority"),
        MutationCase("lifecycle-cancel-raw","lifecycle_harness","SEMANTIC_REPIN",life_cancel_raw,"D4L_TEST_REJECT",None,"test_public_cancel_wire_is_durable_terminal_authority"),
        MutationCase("lifecycle-db-time","lifecycle_harness","SEMANTIC_REPIN",life_db_time,"D4L_TEST_REJECT",None,"test_historical_ingest_time_transport_and_public_identity_precedence"),
        MutationCase("lifecycle-transport","lifecycle_harness","SEMANTIC_REPIN",life_transport,"D4L_TEST_REJECT",None,"test_historical_ingest_time_transport_and_public_identity_precedence"),
        MutationCase("lifecycle-replay-precedence","lifecycle_harness","SEMANTIC_REPIN",life_replay,"D4L_TEST_REJECT",None,"test_historical_ingest_time_transport_and_public_identity_precedence"),
        MutationCase("lifecycle-telemetry-ack-wire","lifecycle_harness","SEMANTIC_REPIN",life_telemetry_ack_wire,"D4L_TEST_REJECT",None,"test_public_telemetry_ack_and_identity_conflict_are_normative_durable_wire"),
        MutationCase("lifecycle-telemetry-error-wire","lifecycle_harness","SEMANTIC_REPIN",life_telemetry_error_wire,"D4L_TEST_REJECT",None,"test_public_telemetry_ack_and_identity_conflict_are_normative_durable_wire"),
        MutationCase("lifecycle-issuer-der","lifecycle_harness","SEMANTIC_REPIN",life_issuer,"D4L_TEST_REJECT",None,"test_public_pending_issued_ack_wire_is_durable_terminal_authority"),
        MutationCase("lifecycle-cleanup-scope","lifecycle_harness","SEMANTIC_REPIN",life_cleanup_scope,"D4L_TEST_REJECT",None,"test_worker_residue_scan_ignores_foreign_db_worker"),
        MutationCase("semantic-unexpected-exception","semantic_crypto_verifier","SEMANTIC_REPIN",semantic_unexpected,"D4M019_FULL_VERIFIER_PROTOCOL"),
        MutationCase("focused-unexpected-exception","semantic_validator","SEMANTIC_REPIN",focused_unexpected,"D4M019_FULL_VERIFIER_PROTOCOL"),
        MutationCase("cap-unexpected-exception","cap_x509_boundary_verifier","SEMANTIC_REPIN",cap_unexpected,"D4M019_FULL_VERIFIER_PROTOCOL"),
    ]


def _run_harness_selftests(source: Path) -> list[str]:
    passed = []
    noop = MutationCase("self-noop", "authority_contract", "PIN_CORRUPTION", lambda _: None, "D4M014_SHA256")
    try: apply_case(source, noop)
    except HarnessReject as exc:
        if exc.code != "D4H001_NO_MUTATION": raise
        passed.append(exc.code)
    two = MutationCase("self-scope", "authority_contract", "PIN_CORRUPTION", lambda f: (f.__setitem__("authority_contract", f["authority_contract"] + b"x"), f.__setitem__("renewal_control_wire", f["renewal_control_wire"] + b"x")), "D4M014_SHA256")
    try: apply_case(source, two)
    except HarnessReject as exc:
        if exc.code != "D4H003_MUTATION_SCOPE": raise
        passed.append(exc.code)
    # Directly exercise the two process-protocol guards without sleeping.
    try: _hfail("D4H004_TIMEOUT", "synthetic timeout witness")
    except HarnessReject as exc: passed.append(exc.code)
    try: _single_diagnostic(subprocess.CompletedProcess([], 1, b"traceback", b"error"))
    except HarnessReject as exc:
        if exc.code != "D4H005_UNSTRUCTURED_FAILURE": raise
        passed.append(exc.code)
    with tempfile.TemporaryDirectory(prefix="d4-self-incomplete-") as td:
        incomplete = _copy_complete(source, Path(td) / "bundle")
        _, paths = _inventory(incomplete)
        paths["authority_contract"].unlink()
        try: _inventory(incomplete)
        except HarnessReject as exc:
            if exc.code != "D4H002_INCOMPLETE_ISOLATION": raise
            passed.append(exc.code)
    with tempfile.TemporaryDirectory(prefix="d4-self-baseline-") as td:
        red = _copy_complete(source, Path(td) / "bundle")
        _, paths = _inventory(red)
        paths["authority_contract"].write_bytes(paths["authority_contract"].read_bytes() + b"x")
        try: _expect_baseline_green(red)
        except HarnessReject as exc:
            if exc.code != "D4H006_BASELINE_NOT_GREEN": raise
            passed.append(exc.code)
    syntax_case=MutationCase("self-lifecycle-syntax","lifecycle_harness","SEMANTIC_REPIN",lambda f:f.__setitem__("lifecycle_harness",f["lifecycle_harness"]+b"\nthis is not valid python !!!\n"),"D4L_TEST_REJECT",None,"test_full_happy_replay_conflict_and_projection")
    try: apply_case(source,syntax_case)
    except HarnessReject as exc:
        if exc.code != "D4H005_UNSTRUCTURED_FAILURE": raise
        passed.append(exc.code)
    return passed


def run_gate(source_manifest: Path) -> dict:
    source_manifest = Path(source_manifest).resolve(strict=True)
    try: source_before = _envelope_hash(source_manifest)
    except HarnessReject: raise
    # Verify the source itself before copying, so isolation cannot normalize a
    # symlink, hardlink, or other unsafe source object into an apparently-green
    # regular file.
    _expect_baseline_green(source_manifest)
    with tempfile.TemporaryDirectory(prefix="d4-pristine-") as td:
        pristine = _copy_complete(source_manifest, Path(td) / "bundle")
        _expect_baseline_green(pristine)
        cases=default_cases()
        _expect_lifecycle_baselines_green(pristine,[case.lifecycle_test for case in cases if case.lifecycle_test is not None])
        diagnostics = [apply_case(pristine, case, baseline_checked=True) for case in cases]
        selftests = _run_harness_selftests(pristine)
    if _envelope_hash(source_manifest) != source_before: _hfail("D4H003_MUTATION_SCOPE", "source envelope changed")
    return {"baselineGreen": True, "casesPassed": len(diagnostics), "selftests": selftests, "sourceEnvelopeSha256": source_before, "status": "PASS"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("--manifest", required=True); ns = parser.parse_args(argv)
    try: report = run_gate(Path(ns.manifest))
    except HarnessReject as exc:
        sys.stdout.buffer.write(canonical_json_bytes({"code": exc.code, "status": "HARNESS_ERROR"}) + b"\n"); return 2
    sys.stdout.buffer.write(canonical_json_bytes(report) + b"\n"); return 0


if __name__ == "__main__": raise SystemExit(main())
