"""Portable Draft-4 closed-role manifest verifier (Python stdlib only)."""
from __future__ import annotations

import argparse
import ast
from dataclasses import dataclass
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Any
import zipfile

BUNDLE_ID = 'phase2c-p-telemetry-authority-v2-draft4-20260825'
ROLE_ID = 'portable_manifest_verifier'
GENERATION = 4
CANDIDATE_STATUS = 'UNFROZEN_STAGING'
ROLE_API_VERSION = 1
MANIFEST_NAME = "one-os-phase2c-p-telemetry-authority-v2-draft4-manifest-20260825.json"
MANIFEST_SCHEMA = "one-os-phase2c-p-bundle-manifest/v4"
ROLE_TABLE = (
    ('authority_contract', 'one-os-phase2c-p-telemetry-authority-contract-v2-draft4-20260825.md', 'text/markdown; charset=utf-8'),
    ('renewal_control_wire', 'one-os-phase2c-p-renewal-control-wire-v2-draft4-20260825.md', 'text/markdown; charset=utf-8'),
    ('telemetry_batch_schema', 'one-os-phase2c-p-telemetry-batch-v2-draft4-20260825.schema.json', 'application/schema+json'),
    ('telemetry_ack_schema', 'one-os-phase2c-p-telemetry-ack-v2-draft4-20260825.schema.json', 'application/schema+json'),
    ('telemetry_error_schema', 'one-os-phase2c-p-telemetry-error-v2-draft4-20260825.schema.json', 'application/schema+json'),
    ('renewal_control_schema', 'one-os-phase2c-p-renewal-control-v2-draft4-20260825.schema.json', 'application/schema+json'),
    ('canonical_vectors', 'one-os-phase2c-p-canonical-vectors-v2-draft4-20260825.json', 'application/json'),
    ('strict_wire_codec', 'strict_wire_one_os_phase2c_p_draft4.py', 'text/x-python; charset=utf-8'),
    ('protocol_helpers', 'protocol_helpers_one_os_phase2c_p_draft4.py', 'text/x-python; charset=utf-8'),
    ('semantic_validator', 'validate_one_os_phase2c_p_draft4.py', 'text/x-python; charset=utf-8'),
    ('semantic_crypto_verifier', 'verify_semantics_one_os_phase2c_p_draft4.py', 'text/x-python; charset=utf-8'),
    ('portable_manifest_verifier', 'verify_manifest_one_os_phase2c_p_draft4.py', 'text/x-python; charset=utf-8'),
    ('closure_index', 'one-os-phase2c-p-telemetry-authority-v2-draft4-closure-index-20260825.json', 'application/json'),
    ('mutation_gate', 'mutation_gate_one_os_phase2c_p_draft4.py', 'text/x-python; charset=utf-8'),
    ('lifecycle_harness', 'lifecycle_harness_one_os_phase2c_p_draft4.py', 'text/x-python; charset=utf-8'),
    ('runtime_cryptography_wheel', 'cryptography-48.0.1-cp311-abi3-manylinux_2_34_x86_64.whl', 'application/vnd.python.wheel'),
    ('runtime_cffi_wheel', 'cffi-2.0.0-cp313-cp313-manylinux2014_x86_64.manylinux_2_17_x86_64.whl', 'application/vnd.python.wheel'),
    ('cap_x509_boundary_evidence', 'one-os-phase2c-p-cap-x509-boundaries-v2-draft4-20260825.json', 'application/json'),
    ('cap_x509_boundary_verifier', 'verify_cap_x509_boundaries_one_os_phase2c_p_draft4.py', 'text/x-python; charset=utf-8'),
)
ROLE_IDS = tuple(row[0] for row in ROLE_TABLE)


@dataclass(eq=False)
class ManifestReject(Exception):
    code: str
    pointer: str = ""
    detail: str = ""
    def __post_init__(self) -> None: super().__init__(self.code, self.pointer, self.detail)
    def diagnostic(self) -> bytes: return _canonical({"code": self.code, "pointer": self.pointer, "status": "REJECT"}) + b"\n"


def _fail(code: str, pointer: str = "", detail: str = "") -> None: raise ManifestReject(code, pointer, detail)


def _string(value: str) -> bytes:
    parts = ['"']; escapes = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}
    for char in value:
        cp = ord(char)
        if 0xD800 <= cp <= 0xDFFF: _fail("D4M001_MANIFEST_RAW_JSON", "", "surrogate")
        if char in escapes: parts.append(escapes[char])
        elif cp < 0x20: parts.append(f"\\u{cp:04x}")
        else: parts.append(char)
    parts.append('"')
    return "".join(parts).encode("utf-8")


def _canonical(v: Any) -> bytes:
    if v is None: return b"null"
    if type(v) is bool: return b"true" if v else b"false"
    if type(v) is int: return str(v).encode()
    if type(v) is str: return _string(v)
    if type(v) is list: return b"[" + b",".join(_canonical(x) for x in v) + b"]"
    if type(v) is dict: return b"{" + b",".join(_string(k) + b":" + _canonical(v[k]) for k in sorted(v)) + b"}"
    _fail("D4M001_MANIFEST_RAW_JSON", "", "non-I-JSON value")


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out = {}
    for key, value in pairs:
        if key in out: _fail("D4M001_MANIFEST_RAW_JSON", "", f"duplicate key {key}")
        out[key] = value
    return out


def _load_canonical(raw: bytes, code: str, max_bytes: int = 16_777_216) -> dict[str, Any]:
    if len(raw) > max_bytes or raw.startswith(b"\xef\xbb\xbf"): _fail(code)
    try:
        text = raw.decode("utf-8", "strict")
        value = json.loads(text, object_pairs_hook=_pairs, parse_float=lambda _: _fail(code), parse_constant=lambda _: _fail(code))
    except ManifestReject: raise
    except (UnicodeDecodeError, json.JSONDecodeError): _fail(code)
    if type(value) is not dict or _canonical(value) != raw: _fail(code)
    return value


def load_manifest(raw: bytes) -> dict[str, Any]: return _load_canonical(raw, "D4M001_MANIFEST_RAW_JSON")


def require_exact_manifest_shape(m: dict[str, Any]) -> None:
    if set(m) != {"authority", "bundleId", "candidateStatus", "reviewVerdicts", "roles", "schemaVersion"}: _fail("D4M002_MANIFEST_SHAPE")
    if m["schemaVersion"] != MANIFEST_SCHEMA: _fail("D4M002_MANIFEST_SHAPE", "/schemaVersion")
    if m["bundleId"] != BUNDLE_ID: _fail("D4M003_BUNDLE_ID", "/bundleId")
    if m["candidateStatus"] != CANDIDATE_STATUS: _fail("D4M004_CANDIDATE_STATUS", "/candidateStatus")
    if m["reviewVerdicts"] != "EXTERNAL": _fail("D4M002_MANIFEST_SHAPE", "/reviewVerdicts")
    expected_authority = {"commitPushDeployAuthorized": False, "directionApproved": True, "implementationAuthorized": False, "protocolApproved": False}
    if m["authority"] != expected_authority: _fail("D4M002_MANIFEST_SHAPE", "/authority")
    if type(m["roles"]) is not list: _fail("D4M002_MANIFEST_SHAPE", "/roles")


def require_exact_role_sequence(m: dict[str, Any]) -> None:
    roles = m["roles"]
    if len(roles) != len(ROLE_TABLE): _fail("D4M005_ROLE_COUNT", "/roles")
    seen_ids: set[str] = set(); seen_paths: set[str] = set(); seen_ordinals: set[int] = set()
    for index, (role, expected) in enumerate(zip(roles, ROLE_TABLE), 1):
        p = f"/roles/{index-1}"
        if type(role) is not dict or set(role) != {"bytes", "mediaType", "ordinal", "path", "roleId", "sha256"}: _fail("D4M002_MANIFEST_SHAPE", p)
        if type(role["ordinal"]) is not int or role["ordinal"] != index: _fail("D4M006_ROLE_ORDER", p + "/ordinal")
        if role["roleId"] != expected[0]: _fail("D4M007_ROLE_ID", p + "/roleId")
        if role["path"] != expected[1]: _fail("D4M008_ROLE_PATH", p + "/path")
        if role["mediaType"] != expected[2] or type(role["bytes"]) is not int or type(role["sha256"]) is not str or re.fullmatch(r"[0-9a-f]{64}", role["sha256"]) is None: _fail("D4M002_MANIFEST_SHAPE", p)
        if role["roleId"] in seen_ids or role["path"] in seen_paths or role["ordinal"] in seen_ordinals: _fail("D4M009_DUPLICATE_ROLE", p)
        seen_ids.add(role["roleId"]); seen_paths.add(role["path"]); seen_ordinals.add(role["ordinal"])


def _safe_path(path: str) -> None:
    if type(path) is not str or not path or PurePosixPath(path).is_absolute() or len(PurePosixPath(path).parts) != 1 or path in (".", ".."):
        _fail("D4M010_PATH_ESCAPE", "", path)


def open_bound_role(root_fd: int, role: dict[str, Any]) -> bytes:
    _safe_path(role["path"])
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try: fd = os.open(role["path"], flags, dir_fd=root_fd)
    except OSError as exc: _fail("D4M011_NOT_REGULAR", f"/{role['roleId']}", str(exc))
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode): _fail("D4M011_NOT_REGULAR", f"/{role['roleId']}")
        if before.st_nlink != 1: _fail("D4M012_LINK_COUNT", f"/{role['roleId']}")
        chunks = []
        while True:
            block = os.read(fd, 131072)
            if not block: break
            chunks.append(block)
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns): _fail("D4M018_SOURCE_CHANGED_DURING_VERIFY", f"/{role['roleId']}")
        return b"".join(chunks)
    finally: os.close(fd)


def verify_role_pin(role: dict[str, Any], raw: bytes) -> None:
    if len(raw) != role["bytes"]: _fail("D4M013_BYTE_COUNT", f"/{role['roleId']}")
    if hashlib.sha256(raw).hexdigest() != role["sha256"]: _fail("D4M014_SHA256", f"/{role['roleId']}")


def _python_identity(raw: bytes) -> dict[str, Any]:
    try: tree = ast.parse(raw.decode("utf-8"))
    except (UnicodeDecodeError, SyntaxError) as exc: _fail("D4M016_INTERNAL_IDENTITY", "", str(exc))
    values = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            if name in {"BUNDLE_ID", "ROLE_ID", "GENERATION", "CANDIDATE_STATUS", "ROLE_API_VERSION"}:
                try: values[name] = ast.literal_eval(node.value)
                except ValueError: pass
    return values


def _verify_runtime_wheel(role: dict[str, Any], raw: bytes) -> None:
    policy={
      "runtime_cryptography_wheel":("cryptography","48.0.1","cryptography-48.0.1.dist-info/METADATA","cp311-abi3-manylinux_2_34_x86_64"),
      "runtime_cffi_wheel":("cffi","2.0.0","cffi-2.0.0.dist-info/METADATA","cp313-cp313-manylinux_2_17_x86_64"),
    }
    name,version,metadata_path,tag=policy[role["roleId"]]
    try:
        if len(raw)<22 or raw[-22:-18]!=b"PK\x05\x06" or raw[-2:]!=b"\x00\x00": _fail("D4M021_RUNTIME_WHEEL")
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            infos=z.infolist(); names=[i.filename for i in infos]
            if len(names)!=len(set(names)) or metadata_path not in names: _fail("D4M021_RUNTIME_WHEEL")
            total=0
            for info in infos:
                p=PurePosixPath(info.filename); mode=(info.external_attr>>16)&0o170000
                if p.is_absolute() or ".." in p.parts or "\\" in info.filename or mode==stat.S_IFLNK: _fail("D4M021_RUNTIME_WHEEL")
                total+=info.file_size
                if total>32_000_000 or (info.compress_size and info.file_size>info.compress_size*200): _fail("D4M021_RUNTIME_WHEEL")
            metadata=z.read(metadata_path).decode("utf-8"); wheel_meta=z.read(metadata_path.replace("METADATA","WHEEL")).decode("utf-8")
    except (KeyError,UnicodeDecodeError,zipfile.BadZipFile,OSError) as exc: _fail("D4M021_RUNTIME_WHEEL","",str(exc))
    if f"Name: {name}\n" not in metadata or f"Version: {version}\n" not in metadata or f"Tag: {tag}\n" not in wheel_meta: _fail("D4M021_RUNTIME_WHEEL")


def verify_internal_identity(role: dict[str, Any], raw: bytes) -> None:
    if role["roleId"] in {"runtime_cryptography_wheel","runtime_cffi_wheel"}:
        _verify_runtime_wheel(role,raw); return
    expected = {"bundleId": BUNDLE_ID, "candidateStatus": CANDIDATE_STATUS, "generation": 4, "roleId": role["roleId"]}
    path = role["path"]
    if path.endswith(".py"):
        actual = _python_identity(raw)
        wanted = {"BUNDLE_ID": BUNDLE_ID, "ROLE_ID": role["roleId"], "GENERATION": 4, "CANDIDATE_STATUS": CANDIDATE_STATUS, "ROLE_API_VERSION": 1}
        if actual != wanted: _fail("D4M016_INTERNAL_IDENTITY", f"/{role['roleId']}")
    elif path.endswith(".md"):
        first = raw.splitlines()[0] if raw.splitlines() else b""
        prefix = b"<!-- one-os-role "; suffix = b" -->"
        if not first.startswith(prefix) or not first.endswith(suffix): _fail("D4M016_INTERNAL_IDENTITY", f"/{role['roleId']}")
        actual = _load_canonical(first[len(prefix):-len(suffix)], "D4M016_INTERNAL_IDENTITY", 4096)
        if actual != expected: _fail("D4M016_INTERNAL_IDENTITY", f"/{role['roleId']}")
    else:
        obj = _load_canonical(raw, "D4M016_INTERNAL_IDENTITY")
        actual = obj.get("roleMetadata") if role["roleId"] == "closure_index" else obj.get("x-one-os-role")
        if actual != expected: _fail("D4M016_INTERNAL_IDENTITY", f"/{role['roleId']}")


def verify_closure_index(raw: bytes, manifest: dict[str, Any]) -> dict[str, Any]:
    c = _load_canonical(raw, "D4M015_CLOSURE_INDEX")
    required = {"bindings", "canonicalRoleSequence", "entrypoints", "identityPolicy", "predecessors", "roleMetadata", "schemaVersion"}
    if set(c) != required or c.get("schemaVersion") != "one-os-phase2c-p-closure-index/v1" or c.get("canonicalRoleSequence") != list(ROLE_IDS): _fail("D4M015_CLOSURE_INDEX")
    if c.get("identityPolicy") != {"currentGenerationToken": "draft4", "forbiddenCurrentTokens": ["draft1", "draft2", "draft3"], "generation": 4, "predecessorHistoryOnlyHere": True}: _fail("D4M015_CLOSURE_INDEX")
    predecessor = [{"bundleId": "phase2c-p-telemetry-authority-v2-draft3-20260825", "disposition": "FAIL_SUPERSEDED", "manifestSha256": "91788f8475ac5ddf07f924f3c9e9ca01db921c30043441c06d50a58d327b0460"}]
    if c.get("predecessors") != predecessor: _fail("D4M015_CLOSURE_INDEX")
    expected_entries = {"baseline": {"args": ["--manifest", "{manifest}", "--full"], "roleId": "portable_manifest_verifier"}, "lifecycle": {"args": ["self-test"], "roleId": "lifecycle_harness"}, "mutationGate": {"args": ["--manifest", "{manifest}"], "roleId": "mutation_gate"}}
    if c.get("entrypoints") != expected_entries: _fail("D4M015_CLOSURE_INDEX")
    if c.get("bindings") != [{'bindingId': 'batch-schema-consumers', 'authorityRole': 'telemetry_batch_schema', 'relation': 'VALIDATED_BY', 'subjectRoles': ['semantic_validator']}, {'bindingId': 'ack-schema-consumers', 'authorityRole': 'telemetry_ack_schema', 'relation': 'VALIDATED_BY', 'subjectRoles': ['semantic_validator']}, {'bindingId': 'error-schema-consumers', 'authorityRole': 'telemetry_error_schema', 'relation': 'VALIDATED_BY', 'subjectRoles': ['semantic_validator']}, {'bindingId': 'renewal-schema-consumers', 'authorityRole': 'renewal_control_schema', 'relation': 'VALIDATED_BY', 'subjectRoles': ['semantic_validator']}, {'bindingId': 'vectors-semantic', 'authorityRole': 'canonical_vectors', 'relation': 'VALIDATED_BY', 'subjectRoles': ['semantic_validator', 'semantic_crypto_verifier', 'lifecycle_harness']}, {'bindingId': 'codec-consumers', 'authorityRole': 'strict_wire_codec', 'relation': 'IMPORTED_BY', 'subjectRoles': ['protocol_helpers', 'semantic_validator', 'mutation_gate']}, {'bindingId': 'helpers-consumers', 'authorityRole': 'protocol_helpers', 'relation': 'IMPORTED_BY', 'subjectRoles': ['semantic_validator', 'semantic_crypto_verifier']}, {'bindingId': 'validator-crypto', 'authorityRole': 'semantic_validator', 'relation': 'CALLED_BY', 'subjectRoles': ['semantic_crypto_verifier']}, {'bindingId': 'crypto-full-verifier', 'authorityRole': 'semantic_crypto_verifier', 'relation': 'INVOKED_BY', 'subjectRoles': ['portable_manifest_verifier']}, {'bindingId': 'manifest-mutation-gate', 'authorityRole': 'portable_manifest_verifier', 'relation': 'INVOKED_BY', 'subjectRoles': ['mutation_gate']}, {'bindingId': 'cryptography-runtime', 'authorityRole': 'runtime_cryptography_wheel', 'relation': 'EXTRACTED_FOR', 'subjectRoles': ['semantic_crypto_verifier', 'portable_manifest_verifier']}, {'bindingId': 'cffi-runtime', 'authorityRole': 'runtime_cffi_wheel', 'relation': 'EXTRACTED_FOR', 'subjectRoles': ['semantic_crypto_verifier', 'portable_manifest_verifier']}, {'bindingId': 'cap-boundary-evidence', 'authorityRole': 'cap_x509_boundary_evidence', 'relation': 'VALIDATED_BY', 'subjectRoles': ['cap_x509_boundary_verifier']}, {'bindingId': 'cap-boundary-full-verifier', 'authorityRole': 'cap_x509_boundary_verifier', 'relation': 'INVOKED_BY', 'subjectRoles': ['portable_manifest_verifier']}, {'bindingId': 'closure-manifest', 'authorityRole': 'closure_index', 'relation': 'VALIDATED_BY', 'subjectRoles': ['portable_manifest_verifier']}, {'bindingId': 'mutation-complete-role-set', 'authorityRole': 'mutation_gate', 'relation': 'MUTATES_IN_ISOLATION', 'subjectRoles': ['authority_contract', 'renewal_control_wire', 'telemetry_batch_schema', 'telemetry_ack_schema', 'telemetry_error_schema', 'renewal_control_schema', 'canonical_vectors', 'strict_wire_codec', 'protocol_helpers', 'semantic_validator', 'semantic_crypto_verifier', 'portable_manifest_verifier', 'closure_index', 'mutation_gate', 'lifecycle_harness', 'runtime_cryptography_wheel', 'runtime_cffi_wheel', 'cap_x509_boundary_evidence', 'cap_x509_boundary_verifier']}, {'bindingId': 'protocol-lifecycle', 'authorityRole': 'authority_contract', 'relation': 'CONSTRAINS', 'subjectRoles': ['renewal_control_wire', 'telemetry_batch_schema', 'telemetry_ack_schema', 'telemetry_error_schema', 'renewal_control_schema', 'lifecycle_harness']}]: _fail("D4M015_CLOSURE_INDEX")
    return c


def verify_generation_closure(role: dict[str, Any], raw: bytes, closure: dict[str, Any] | None = None) -> None:
    lowered = raw.lower()
    if role["roleId"] == "closure_index":
        assert closure is not None
        current = dict(closure); current["predecessors"] = []
        current["identityPolicy"] = dict(current["identityPolicy"])
        current["identityPolicy"]["forbiddenCurrentTokens"] = []
        lowered = _canonical(current).lower()
    elif role["roleId"] == "portable_manifest_verifier":
        # This verifier necessarily carries the forbidden-token policy and the
        # one exact predecessor witness. Remove only those quoted literals;
        # every other occurrence remains subject to the candidate-wide scan.
        allowed_literals = (
            b'b"draft1"', b'b"draft2"', b'b"draft3"',
            b'"draft1"', b'"draft2"', b'"draft3"',
            b'"phase2c-p-telemetry-authority-v2-draft3-20260825"',
        )
        for literal in allowed_literals:
            lowered = lowered.replace(literal, b"")
    if any(token in lowered for token in (b"draft1", b"draft2", b"draft3")): _fail("D4M017_STALE_GENERATION", f"/{role['roleId']}")


def _read_manifest_safely(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try: fd = os.open(path, flags)
    except OSError as exc: _fail("D4M011_NOT_REGULAR", "/manifest", str(exc))
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode): _fail("D4M011_NOT_REGULAR", "/manifest")
        if before.st_nlink != 1: _fail("D4M012_LINK_COUNT", "/manifest")
        raw = os.read(fd, before.st_size + 1)
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            _fail("D4M018_SOURCE_CHANGED_DURING_VERIFY", "/manifest")
        return raw
    finally: os.close(fd)


def _run_full(snapshot: Path) -> None:
    validator=snapshot/next(path for role_id,path,_ in ROLE_TABLE if role_id=="semantic_crypto_verifier")
    cap_verifier=snapshot/next(path for role_id,path,_ in ROLE_TABLE if role_id=="cap_x509_boundary_verifier")
    wheel_paths=[snapshot/next(path for role_id,path,_ in ROLE_TABLE if role_id==rid) for rid in ("runtime_cryptography_wheel","runtime_cffi_wheel")]
    launcher=r"""
import os,pathlib,runpy,sys
runtime=pathlib.Path(sys.argv[1]).resolve(); validator=pathlib.Path(sys.argv[2]).resolve(); manifest=pathlib.Path(sys.argv[3]).resolve(); cap_verifier=pathlib.Path(sys.argv[4]).resolve()
if sys.version_info[:2]!=(3,13) or os.uname().machine!="x86_64": raise SystemExit(91)
sys.path[:0]=[str(runtime),str(validator.parent)]
import cryptography,_cffi_backend
if cryptography.__version__!="48.0.1": raise SystemExit(92)
for module in (cryptography,_cffi_backend):
    if not pathlib.Path(module.__file__).resolve().is_relative_to(runtime): raise SystemExit(93)
sys.argv=[str(cap_verifier)]
runpy.run_path(str(cap_verifier),run_name="__main__")
sys.argv=[str(validator),"--snapshot-manifest",str(manifest)]
runpy.run_path(str(validator),run_name="__main__")
"""
    try:
        with tempfile.TemporaryDirectory(prefix="one-os-d4-runtime-") as td:
            runtime=Path(td)
            for wheel in wheel_paths:
                with zipfile.ZipFile(wheel) as z: z.extractall(runtime)
            cp=subprocess.run([sys.executable,"-I","-S","-B","-c",launcher,str(runtime),str(validator),str(snapshot/MANIFEST_NAME),str(cap_verifier)],cwd=snapshot,capture_output=True,timeout=30,env={"PYTHONDONTWRITEBYTECODE":"1","LC_ALL":"C.UTF-8"},check=False)
    except (subprocess.TimeoutExpired,zipfile.BadZipFile,OSError) as exc: _fail("D4M019_FULL_VERIFIER_PROTOCOL","",str(exc))
    expected=_canonical({"code":"D4PASS","status":"ACCEPT"})+b"\n"
    if cp.returncode==0 and cp.stdout==expected and cp.stderr==b"": return
    if cp.returncode in {91,92,93}: _fail("D4M020_RUNTIME_INCOMPATIBLE","",str(cp.returncode))
    if cp.returncode==1 and cp.stderr==b"" and cp.stdout.endswith(b"\n") and cp.stdout.count(b"\n")==1:
        try: diag=_load_canonical(cp.stdout[:-1],"D4M019_FULL_VERIFIER_PROTOCOL",4096)
        except ManifestReject: _fail("D4M019_FULL_VERIFIER_PROTOCOL")
        if set(diag)=={"code","pointer","status"} and diag["status"]=="REJECT" and re.fullmatch(r"D4[A-Z0-9_]+",diag["code"]): _fail(diag["code"],diag["pointer"])
    _fail("D4M019_FULL_VERIFIER_PROTOCOL","",(cp.stdout+cp.stderr).decode("utf-8","replace")[:300])


def verify_bundle(manifest_path: Path, full: bool = False) -> dict[str, Any]:
    manifest_path = Path(manifest_path)
    raw_manifest = _read_manifest_safely(manifest_path)
    m = load_manifest(raw_manifest); require_exact_manifest_shape(m); require_exact_role_sequence(m)
    root_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    try: root_fd = os.open(manifest_path.parent, root_flags)
    except OSError as exc: _fail("D4M010_PATH_ESCAPE", "", str(exc))
    role_bytes: dict[str, bytes] = {}
    try:
        for role in m["roles"]:
            raw = open_bound_role(root_fd, role); verify_role_pin(role, raw); role_bytes[role["roleId"]] = raw
    finally: os.close(root_fd)
    closure = verify_closure_index(role_bytes["closure_index"], m)
    for role in m["roles"]:
        raw = role_bytes[role["roleId"]]; verify_internal_identity(role, raw); verify_generation_closure(role, raw, closure if role["roleId"] == "closure_index" else None)
    if full:
        with tempfile.TemporaryDirectory(prefix="d4-verified-snapshot-") as td:
            snap = Path(td)
            (snap / MANIFEST_NAME).write_bytes(raw_manifest)
            for role in m["roles"]: (snap / role["path"]).write_bytes(role_bytes[role["roleId"]])
            _run_full(snap)
    return {"bundleId": BUNDLE_ID, "rolesVerified": len(role_bytes), "status": "ACCEPT"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("--manifest", required=True); parser.add_argument("--full", action="store_true"); ns = parser.parse_args(argv)
    try: report = verify_bundle(Path(ns.manifest), ns.full)
    except ManifestReject as exc: sys.stdout.buffer.write(exc.diagnostic()); return 1
    sys.stdout.buffer.write(_canonical(report) + b"\n"); return 0


if __name__ == "__main__": raise SystemExit(main())
