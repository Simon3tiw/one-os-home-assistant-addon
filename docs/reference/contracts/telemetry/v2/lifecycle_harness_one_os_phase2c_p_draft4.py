#!/usr/bin/env python3
"""Draft-4 hermetic durable exact-wire SQLite lifecycle executor.

Gate-0 reference evidence only: SQLite/WAL process-crash atomicity, exact stored
wire replay and total writer ordering.  This is not a product route, migration,
PostgreSQL/HA proof, pairing authority implementation, or X.509 verifier.

The ``pairing.repair`` and ``pairing.replacement`` worker cases represent calls
made *inside an already validated pairing transaction*.  They are telemetry
hooks, not public/admin wire and cannot be enabled by a digest or flag.

Only Python stdlib and SQLite are used.  Run the hermetic suite with:
    python -B draft4_executor.py self-test
"""
from __future__ import annotations

BUNDLE_ID = 'phase2c-p-telemetry-authority-v2-draft4-20260825'
ROLE_ID = 'lifecycle_harness'
GENERATION = 4
CANDIDATE_STATUS = 'UNFROZEN_STAGING'
ROLE_API_VERSION = 1

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
import select
import shutil
import sqlite3
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Callable

MAX_I64 = 2**63 - 1
FRAME_CAP = 2 * 1024 * 1024
ROUTE_CAP = 1024 * 1024
EXIT_FRAMING = 64
EXIT_INTERNAL = 70
EXIT_STORE = 75
EXIT_CRASH = 86
SCHEMA = "one-os-draft4-executor/v1"
ERROR_SCHEMA = "one-os-renewal-error/v2"
SUCCESS_SCHEMA = "one-os-draft4-success/v1"

ERRORS: dict[str, tuple[int, str]] = {
    "REPLAY_CONFLICT": (409, "terminal_repair"),
    "CANCELLED_NO_RESERVATION": (409, "terminal_repair"),
    "CANCEL_TARGET_COMMITTED": (409, "terminal_repair"),
    "SUPERSEDED_BY_REVOKE": (409, "terminal_repair"),
    "SUPERSEDED_BY_REPAIR": (409, "terminal_repair"),
    "SUPERSEDED_BY_REPLACEMENT": (409, "terminal_repair"),
    "HISTORICAL_RECEIPT_CLOSED": (409, "terminal_quarantine"),
    "ACK_CONFLICT": (409, "terminal_repair"),
    "ACK_EXPIRED": (422, "terminal_repair"),
    "CAPABILITY_DISABLED": (409, "terminal_repair"),
    "INVALID_STATE": (409, "terminal_repair"),
    "REVISION_SATURATED": (409, "terminal_repair"),
    "CAPABILITY_NOT_CURRENT": (409, "terminal_repair"),
    "HISTORICAL_ENTRY_MISMATCH": (409, "terminal_quarantine"),
    "HISTORICAL_TRANSPORT_UNAUTHORIZED": (409, "terminal_quarantine"),
    "IMMUTABLE_IDENTITY_CONFLICT": (409, "terminal_quarantine"),
}

# Every name below is an actual os._exit boundary in mutate()/durable_worker().
# The closure tests execute the Cartesian route x generic-boundary matrix plus
# every applicable route-specific boundary, rather than sampling one crashpoint.
GENERIC_PRECOMMIT = (
    "after_begin_immediate", "after_operation_identity_store",
    "after_context_validation", "after_terminal_response_store",
)
ROUTE_PRECOMMIT = {
    "capability.enable": ("capability.enable.after_consumption", "capability.enable.after_cas"),
    "renewal.cancel": ("renewal.cancel.after_tombstone",),
    "renewal.reserve": (
        "renewal.reserve.after_manifest", "renewal.reserve.after_receipt",
        "renewal.reserve.after_entries", "renewal.reserve.after_old_retire",
        "renewal.reserve.after_pending_insert",
        "renewal.reserve.after_installation_cas",
    ),
    "renewal.issue": (
        "renewal.issue.after_issuing_claim",
        "renewal.issue.after_certificate_store",
        "renewal.issue.after_pending_ack",
    ),
    "renewal.promote": (
        "renewal.promote.after_proof", "renewal.promote.after_old_supersede",
        "renewal.promote.after_new_active", "renewal.promote.after_pointer",
    ),
    "telemetry.ingest": (
        "telemetry.ingest.after_ack_store",
        "telemetry.ingest.after_entry_commit",
    ),
    "receipt.expire": (
        "receipt.expire.after_quarantine", "receipt.expire.after_terminal",
    ),
    "lifecycle.revoke": (
        "lifecycle.revoke.after_credential_close",
        "lifecycle.revoke.after_receipt_invalidate",
        "lifecycle.revoke.after_renewal_tombstone",
        "lifecycle.revoke.after_pointer_clear",
    ),
    "pairing.repair": (
        "pairing.repair.after_credential_close",
        "pairing.repair.after_receipt_invalidate",
        "pairing.repair.after_renewal_tombstone",
        "pairing.repair.after_pointer_clear", "pairing.repair.after_event",
    ),
    "pairing.replacement": (
        "pairing.replacement.after_credential_close",
        "pairing.replacement.after_receipt_invalidate",
        "pairing.replacement.after_renewal_tombstone",
        "pairing.replacement.after_pointer_clear",
        "pairing.replacement.after_event",
    ),
}

ROUTES = {
    "capability.enable", "renewal.reserve", "renewal.cancel", "renewal.issue",
    "renewal.promote", "telemetry.ingest", "receipt.expire", "lifecycle.revoke",
    "pairing.repair", "pairing.replacement",
}

DDL = r"""
CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT;
CREATE TABLE installation(
 installation_id TEXT PRIMARY KEY,
 lifecycle_revision INTEGER NOT NULL CHECK(lifecycle_revision BETWEEN 0 AND 9223372036854775807),
 telemetry_authorization_revision INTEGER NOT NULL CHECK(telemetry_authorization_revision BETWEEN 1 AND 9223372036854775807),
 telemetry_lineage_id TEXT,
 current_credential_id TEXT,
 lifecycle_state TEXT NOT NULL CHECK(lifecycle_state IN ('ACTIVE','RENEWING','REPAIRING','REPLACED','REVOKED','TERMINAL')),
 v2_enabled INTEGER NOT NULL CHECK(v2_enabled IN (0,1)),
 v2_authority_used INTEGER NOT NULL CHECK(v2_authority_used IN (0,1)),
 replacement_installation_id TEXT,
 CHECK((lifecycle_state IN ('REVOKED','REPLACED','TERMINAL') AND current_credential_id IS NULL) OR lifecycle_state NOT IN ('REVOKED','REPLACED','TERMINAL'))
) STRICT;
CREATE TABLE credential(
 credential_id TEXT PRIMARY KEY,
 installation_id TEXT NOT NULL REFERENCES installation(installation_id),
 lineage_id TEXT NOT NULL,
 purpose TEXT NOT NULL CHECK(purpose IN ('pairing','telemetry','renewal_pending','repair_pending')),
 status TEXT NOT NULL CHECK(status IN ('active','retiring','reserved','issuing','pending_ack','superseded','revoked','abandoned')),
 authorized_from_revision INTEGER CHECK(authorized_from_revision BETWEEN 1 AND 9223372036854775807),
 authorized_until_revision INTEGER CHECK(authorized_until_revision BETWEEN 2 AND 9223372036854775807),
 operation_id TEXT,
 spki_sha256 BLOB CHECK(spki_sha256 IS NULL OR length(spki_sha256)=32),
 leaf_sha256 BLOB CHECK(leaf_sha256 IS NULL OR length(leaf_sha256)=32),
 raw_leaf_der BLOB,
 CHECK(authorized_until_revision IS NULL OR authorized_from_revision < authorized_until_revision)
) STRICT;
CREATE UNIQUE INDEX one_current_active_credential ON credential(installation_id)
 WHERE status='active' AND purpose IN ('telemetry','renewal_pending','repair_pending');
CREATE TABLE operation(
 operation_id TEXT PRIMARY KEY,
 installation_id TEXT NOT NULL REFERENCES installation(installation_id),
 route TEXT NOT NULL,
 request_sha256 BLOB NOT NULL UNIQUE CHECK(length(request_sha256)=32),
 raw_request BLOB NOT NULL,
 request_length INTEGER NOT NULL CHECK(request_length=length(raw_request) AND request_length>0),
 status TEXT NOT NULL CHECK(status IN ('processing','terminal_success','terminal_error')),
 http_status INTEGER,
 response_sha256 BLOB CHECK(response_sha256 IS NULL OR length(response_sha256)=32),
 raw_response BLOB,
 response_length INTEGER CHECK(response_length IS NULL OR response_length=length(raw_response)),
 retry_class TEXT,
 before_authority_revision INTEGER,
 after_authority_revision INTEGER,
 before_lifecycle_revision INTEGER,
 after_lifecycle_revision INTEGER,
 committed_at TEXT
) STRICT;
CREATE TABLE proof_consumption(
 proof_sha256 BLOB PRIMARY KEY CHECK(length(proof_sha256)=32),
 operation_id TEXT NOT NULL UNIQUE,
 challenge_nonce BLOB NOT NULL UNIQUE CHECK(length(challenge_nonce)=32),
 raw_proof BLOB NOT NULL
) STRICT;
CREATE TABLE capability_consumption(
 operation_id TEXT PRIMARY KEY,
 installation_id TEXT NOT NULL,
 capability_sha256 BLOB NOT NULL UNIQUE CHECK(length(capability_sha256)=32),
 capability_server_nonce BLOB NOT NULL UNIQUE CHECK(length(capability_server_nonce)=32),
 edge_nonce BLOB NOT NULL UNIQUE CHECK(length(edge_nonce)=32),
 protocol_id TEXT NOT NULL,
 telemetry_batch_schema_sha256 BLOB NOT NULL CHECK(length(telemetry_batch_schema_sha256)=32),
 telemetry_ack_schema_sha256 BLOB NOT NULL CHECK(length(telemetry_ack_schema_sha256)=32),
 telemetry_error_schema_sha256 BLOB NOT NULL CHECK(length(telemetry_error_schema_sha256)=32),
 renewal_control_schema_sha256 BLOB NOT NULL CHECK(length(renewal_control_schema_sha256)=32),
 current_credential_id TEXT NOT NULL,
 current_certificate_sha256 BLOB NOT NULL CHECK(length(current_certificate_sha256)=32),
 expected_authorization_revision INTEGER NOT NULL,
 issued_at TEXT NOT NULL,
 expires_at TEXT NOT NULL,
 raw_enable_request BLOB NOT NULL
) STRICT;
CREATE TABLE renewal(
 operation_id TEXT PRIMARY KEY,
 old_credential_id TEXT NOT NULL,
 pending_credential_id TEXT NOT NULL UNIQUE,
 state TEXT NOT NULL CHECK(state IN ('reserved','issuing','issued','acked','repair_required','tombstoned')),
 backlog_mode TEXT NOT NULL CHECK(backlog_mode IN ('none','historical')),
 manifest_sha256 BLOB NOT NULL CHECK(length(manifest_sha256)=32),
 raw_manifest BLOB NOT NULL,
 pending_response_sha256 BLOB CHECK(pending_response_sha256 IS NULL OR length(pending_response_sha256)=32),
 raw_pending_response BLOB,
 issued_response_sha256 BLOB,
 raw_issued_response BLOB,
 tombstone_winner_operation_id TEXT
) STRICT;
CREATE TABLE cancel_tombstone(
 cancel_operation_id TEXT PRIMARY KEY,
 target_operation_id TEXT NOT NULL UNIQUE,
 target_request_sha256 BLOB NOT NULL UNIQUE CHECK(length(target_request_sha256)=32),
 manifest_sha256 BLOB NOT NULL UNIQUE CHECK(length(manifest_sha256)=32),
 raw_tombstone BLOB NOT NULL
) STRICT;
CREATE TABLE historical_receipt(
 receipt_sha256 BLOB PRIMARY KEY CHECK(length(receipt_sha256)=32),
 renewal_operation_id TEXT NOT NULL UNIQUE,
 installation_id TEXT NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('OPEN','DRAINED','EXPIRED_TERMINAL','INVALIDATED')),
 terminal_reason TEXT,
 not_before TEXT NOT NULL,
 expires_at TEXT NOT NULL,
 raw_receipt BLOB NOT NULL,
 CHECK((status='INVALIDATED' AND terminal_reason IS NOT NULL) OR (status!='INVALIDATED' AND terminal_reason IS NULL))
) STRICT;
CREATE UNIQUE INDEX one_open_receipt ON historical_receipt(installation_id) WHERE status='OPEN';
CREATE TABLE receipt_entry(
 receipt_sha256 BLOB NOT NULL,
 journal_id INTEGER NOT NULL CHECK(journal_id BETWEEN 1 AND 9223372036854775807),
 batch_id TEXT NOT NULL,
 request_sha256 BLOB NOT NULL CHECK(length(request_sha256)=32),
 request_length INTEGER NOT NULL CHECK(request_length>0),
 credential_id TEXT NOT NULL,
 batch_authorization_revision INTEGER NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('UNCOMMITTED','COMMITTED','TERMINAL_QUARANTINE')),
 ingest_operation_id TEXT,
 raw_ack BLOB,
 ack_sha256 BLOB,
 PRIMARY KEY(receipt_sha256,journal_id), UNIQUE(receipt_sha256,batch_id), UNIQUE(receipt_sha256,request_sha256)
) STRICT;
CREATE TABLE ingest_batch(
 installation_id TEXT NOT NULL, batch_id TEXT NOT NULL,
 operation_id TEXT NOT NULL UNIQUE, request_sha256 BLOB NOT NULL,
 raw_request BLOB NOT NULL, body_credential_id TEXT NOT NULL, presented_transport_credential_id TEXT NOT NULL,
 batch_authorization_revision INTEGER NOT NULL, ingest_authorization_revision INTEGER NOT NULL,
 authorization_mode TEXT NOT NULL CHECK(authorization_mode IN ('current','historical_backlog')),
 receipt_sha256 BLOB, raw_ack BLOB NOT NULL, ack_sha256 BLOB NOT NULL,
 PRIMARY KEY(installation_id,batch_id), UNIQUE(installation_id,request_sha256)
) STRICT;
CREATE TABLE immutable_identity_conflict(
 conflict_operation_id TEXT PRIMARY KEY, installation_id TEXT NOT NULL, batch_id TEXT NOT NULL,
 conflict_key BLOB NOT NULL UNIQUE CHECK(length(conflict_key)=32),
 existing_request_sha256 BLOB NOT NULL CHECK(length(existing_request_sha256)=32),
 attempted_request_sha256 BLOB NOT NULL CHECK(length(attempted_request_sha256)=32),
 attempted_raw_request BLOB NOT NULL, decided_at TEXT NOT NULL,
 raw_error BLOB NOT NULL, error_sha256 BLOB NOT NULL CHECK(length(error_sha256)=32),
 UNIQUE(installation_id,batch_id,attempted_request_sha256)
) STRICT;
CREATE TABLE issued_certificate(
 issuer_der_sha256 BLOB NOT NULL, serial_der BLOB NOT NULL,
 serial_positive INTEGER NOT NULL CHECK(serial_positive=1), credential_id TEXT NOT NULL UNIQUE,
 issuance_operation_id TEXT NOT NULL, raw_leaf_der BLOB NOT NULL,
 leaf_sha256 BLOB NOT NULL UNIQUE, PRIMARY KEY(issuer_der_sha256,serial_der)
) STRICT;
CREATE TABLE pairing_lifecycle_event(
 pairing_operation_id TEXT PRIMARY KEY, installation_id TEXT NOT NULL,
 event_kind TEXT NOT NULL CHECK(event_kind IN ('repair','replacement')),
 replacement_installation_id TEXT, raw_pairing_request BLOB NOT NULL,
 pairing_request_sha256 BLOB NOT NULL UNIQUE, telemetry_hook_applied INTEGER NOT NULL CHECK(telemetry_hook_applied IN (0,1)),
 CHECK((event_kind='repair' AND replacement_installation_id IS NULL) OR (event_kind='replacement' AND replacement_installation_id IS NOT NULL))
) STRICT;
"""


def sha(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def canon(obj: Any) -> bytes:
    return json.dumps(obj, ensure_ascii=False, allow_nan=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate JSON key")
        out[key] = value
    return out


def _no_float(_: str) -> Any:
    raise ValueError("floating-point JSON forbidden")


def strict_json(raw: bytes, cap: int = FRAME_CAP) -> dict[str, Any]:
    if not raw or len(raw) > cap or raw.startswith(b"\xef\xbb\xbf"):
        raise ValueError("invalid byte envelope")
    try:
        text = raw.decode("utf-8", "strict")
        obj = json.loads(text, object_pairs_hook=_pairs, parse_float=_no_float,
                         parse_constant=_no_float)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid JSON") from exc
    def walk(v: Any, depth: int = 0) -> None:
        if depth > 32:
            raise ValueError("JSON nesting too deep")
        if v is None or isinstance(v, str):
            if isinstance(v, str) and any(0xD800 <= ord(c) <= 0xDFFF for c in v):
                raise ValueError("surrogate forbidden")
            return
        if type(v) is bool:
            return
        if type(v) is int:
            if not -MAX_I64 <= v <= MAX_I64:
                raise ValueError("integer out of range")
            return
        if isinstance(v, list):
            for x in v: walk(x, depth + 1)
            return
        if isinstance(v, dict):
            for k, x in v.items():
                if not isinstance(k, str): raise ValueError("non-string key")
                walk(x, depth + 1)
            return
        raise ValueError("unsupported JSON scalar")
    walk(obj)
    if type(obj) is not dict or canon(obj) != raw:
        raise ValueError("noncanonical JSON")
    return obj


def exact_keys(obj: dict[str, Any], keys: set[str]) -> None:
    if set(obj) != keys:
        raise ValueError(f"keyset mismatch: {set(obj) ^ keys}")


def text(v: Any, name: str) -> str:
    if type(v) is not str or not v or len(v) > 256:
        raise ValueError(f"invalid {name}")
    return v


def integer(v: Any, name: str, lo: int = 0) -> int:
    if type(v) is not int or not lo <= v <= MAX_I64:
        raise ValueError(f"invalid {name}")
    return v


def utc(v: Any, millis: bool = False) -> str:
    text(v, "timestamp")
    fmt = "%Y-%m-%dT%H:%M:%S.%fZ" if millis else "%Y-%m-%dT%H:%M:%SZ"
    try:
        parsed = dt.datetime.strptime(v, fmt)
    except ValueError as exc:
        raise ValueError("invalid Gregorian UTC timestamp") from exc
    if millis and len(v.rsplit(".", 1)[1].split("Z")[0]) != 3:
        raise ValueError("milliseconds required")
    return v


def hex32(v: Any, name: str) -> bytes:
    if type(v) is not str or len(v) != 64:
        raise ValueError(f"invalid {name}")
    try: b = bytes.fromhex(v)
    except ValueError as exc: raise ValueError(f"invalid {name}") from exc
    if len(b) != 32 or v != v.lower(): raise ValueError(f"invalid {name}")
    return b


def validate_request(route: str, raw: bytes) -> dict[str, Any]:
    if route not in ROUTES or len(raw) > ROUTE_CAP:
        raise ValueError("unknown route or cap exceeded")
    obj = strict_json(raw)
    exact_keys(obj, {"installationId", "operationId", "payload", "schemaVersion"})
    if obj["schemaVersion"] != SCHEMA: raise ValueError("schema")
    text(obj["installationId"], "installationId"); text(obj["operationId"], "operationId")
    if type(obj["payload"]) is not dict: raise ValueError("payload")
    p = obj["payload"]
    specs: dict[str, set[str]] = {
      "capability.enable": {"sourceRequestCanonicalUtf8"},
      "renewal.reserve": {"sourceRequestCanonicalUtf8","expectedReceiptCanonicalUtf8","expectedPendingResponseCanonicalUtf8"},
      "renewal.cancel": {"sourceRequestCanonicalUtf8","expectedResponseCanonicalUtf8"},
      "renewal.issue": {"sourceResponseCanonicalUtf8"},
      "renewal.promote": {"sourceRequestCanonicalUtf8","expectedResponseCanonicalUtf8"},
      "telemetry.ingest": {"batchId","credentialId","presentedTransportCredentialId","authorizationRevision","receiptSha256","sourceRequestCanonicalUtf8"},
      "receipt.expire": {"receiptSha256"}, "lifecycle.revoke": {"reason"},
      "pairing.repair": {"pairingLifecycleRevision"},
      "pairing.replacement": {"pairingLifecycleRevision","replacementInstallationId","replacementCredentialId","replacementLineageId"},
    }
    exact_keys(p, specs[route])
    for k, v in p.items():
        if k.endswith("Revision"): integer(v, k, 0)
        if k.endswith("Sha256"): hex32(v, k)
    if route == "capability.enable":
        source_raw=p["sourceRequestCanonicalUtf8"].encode("utf-8")
        source=strict_json(source_raw,ROUTE_CAP)
        exact_keys(source,{"capabilityServerNonce","capabilitySha256","currentCertificateSha256","currentCredentialId","edgeNonce","expectedTelemetryAuthorizationRevision","expiresAt","installationId","issuedAt","protocol","protocolId","renewalControlSchemaSha256","requestId","signature","telemetryAckSchemaSha256","telemetryBatchSchemaSha256","telemetryErrorSchemaSha256"})
        if source["installationId"]!=obj["installationId"] or source["requestId"]!=obj["operationId"] or source["protocol"]!="2.0": raise ValueError("capability source aliases")
        for key in ("capabilityServerNonce","capabilitySha256","currentCertificateSha256","edgeNonce","renewalControlSchemaSha256","telemetryAckSchemaSha256","telemetryBatchSchemaSha256","telemetryErrorSchemaSha256"):
            if len(unb64(source[key]))!=32: raise ValueError("capability hash width")
        integer(source["expectedTelemetryAuthorizationRevision"],"expectedTelemetryAuthorizationRevision",1)
        issued = dt.datetime.strptime(utc(source["issuedAt"]), "%Y-%m-%dT%H:%M:%SZ")
        expires = dt.datetime.strptime(utc(source["expiresAt"]), "%Y-%m-%dT%H:%M:%SZ")
        if expires - issued != dt.timedelta(seconds=300): raise ValueError("capability lifetime")
    elif route == "renewal.reserve":
        source_raw=p["sourceRequestCanonicalUtf8"].encode("utf-8")
        receipt_raw=p["expectedReceiptCanonicalUtf8"].encode("utf-8")
        source=strict_json(source_raw,ROUTE_CAP); receipt=strict_json(receipt_raw,ROUTE_CAP)
        pending_raw=p["expectedPendingResponseCanonicalUtf8"].encode("utf-8"); pending=strict_json(pending_raw,ROUTE_CAP)
        exact_keys(source,{"backlogManifest","backlogManifestSha256","backlogMode","csrDer","csrSha256","csrSpkiSha256","edgeNonce","epochMinute","expectedTelemetryAuthorizationRevision","installationId","installationRevisionBefore","lineageId","oldCertificateSha256","oldCertificateSpkiSha256","oldCredentialId","pendingCredentialId","protocol","requestId","signature"})
        integer(source["epochMinute"],"epochMinute",0)
        if source["installationId"]!=obj["installationId"] or source["requestId"]!=obj["operationId"] or source["protocol"]!="2.0" or source["backlogMode"]!="historical": raise ValueError("renewal source aliases")
        manifest=source["backlogManifest"]
        entries=manifest.get("entries") if type(manifest) is dict else None
        if type(entries) is not list or not 1 <= len(entries) <= 256 or sha(canon(manifest))!=unb64(source["backlogManifestSha256"]): raise ValueError("manifest binding")
        for i, e in enumerate(entries, 1):
            if type(e) is not dict: raise ValueError("entry")
            exact_keys(e, {"batchAuthorizationRevision","batchId","credentialId","journalId","requestLength","requestSha256"})
            text(e["batchId"], "batchId"); text(e["credentialId"], "credentialId")
            integer(e["journalId"], "journalId", 1); integer(e["requestLength"], "requestLength", 1)
            if len(unb64(e["requestSha256"]))!=32: raise ValueError("requestSha256")
            integer(e["batchAuthorizationRevision"],"batchAuthorizationRevision",1)
            if e["journalId"] != i: raise ValueError("journal order")
        exact_keys(receipt,{"allowedTransportCredentialIds","backlogManifestSha256","cutJournalMaxId","cutMarkerId","entries","entryCount","expiresAt","historicalAuthorizationRevision","ingestAuthorizationRevision","installationId","lineageId","notBefore","receiptNonce","renewalOperationId","renewalRequestSha256","schemaVersion","totalRequestBytes"})
        exact_keys(pending,{"backlogManifestSha256","backlogMode","csrSha256","csrSpkiSha256","historicalAuthorizationReceipt","historicalAuthorizationReceiptSha256","installationId","installationRevisionBefore","issuanceExpiresAt","lineageId","newCredentialId","oldCertificateSha256","oldCertificateSpkiSha256","oldCredentialId","protocol","requestId","status","telemetryAuthorizationRevisionAfter","telemetryAuthorizationRevisionBefore"})
        if receipt["entries"]!=entries or receipt["renewalOperationId"]!=source["requestId"] or receipt["renewalRequestSha256"]!=b64u(sha(source_raw)): raise ValueError("receipt source binding")
        if receipt["backlogManifestSha256"]!=source["backlogManifestSha256"] or receipt["installationId"]!=source["installationId"] or receipt["lineageId"]!=source["lineageId"]: raise ValueError("receipt identity binding")
        if receipt["historicalAuthorizationRevision"]!=source["expectedTelemetryAuthorizationRevision"] or receipt["ingestAuthorizationRevision"]!=source["expectedTelemetryAuthorizationRevision"]+1: raise ValueError("receipt revision binding")
        if receipt["allowedTransportCredentialIds"]!=sorted([source["oldCredentialId"],source["pendingCredentialId"]]): raise ValueError("receipt credential binding")
        if receipt["entryCount"]!=len(entries) or receipt["totalRequestBytes"]!=manifest["totalRequestBytes"] or receipt["cutMarkerId"]!=manifest["cutMarkerId"] or receipt["cutJournalMaxId"]!=manifest["cutJournalMaxId"]: raise ValueError("receipt manifest aliases")
        not_before=dt.datetime.strptime(utc(receipt["notBefore"]),"%Y-%m-%dT%H:%M:%SZ"); expires=dt.datetime.strptime(utc(receipt["expiresAt"]),"%Y-%m-%dT%H:%M:%SZ")
        if expires-not_before!=dt.timedelta(seconds=86400): raise ValueError("receipt lifetime")
        if pending.get("requestId")!=source["requestId"] or pending.get("installationId")!=source["installationId"] or pending.get("historicalAuthorizationReceipt")!=receipt: raise ValueError("pending response binding")
    elif route == "renewal.issue":
        source=strict_json(p["sourceResponseCanonicalUtf8"].encode("utf-8"),ROUTE_CAP)
        exact_keys(source,{"ackExpiresAt","backlogManifestSha256","backlogMode","caChainPem","certificatePem","csrSha256","csrSpkiSha256","historicalAuthorizationReceipt","historicalAuthorizationReceiptSha256","installationId","installationRevisionBefore","lineageId","newCertificateSha256","newCertificateSpkiSha256","newCredentialId","oldCertificateSha256","oldCertificateSpkiSha256","oldCredentialId","protocol","requestId","status","telemetryAuthorizationRevisionAfter","telemetryAuthorizationRevisionBefore"})
        text(source["requestId"],"requestId")
        for key in ("certificatePem","caChainPem"):
            if type(source.get(key)) is not str or not 1 <= len(source[key].encode("ascii")) <= ROUTE_CAP: raise ValueError("invalid "+key)
        leaf=_pem_der(source["certificatePem"]); serial=_certificate_serial_der(leaf)
        if not serial or len(serial)>20 or serial[0]&0x80 or int.from_bytes(serial,"big")<1: raise ValueError("positive serial")
        if not leaf: raise ValueError("leaf")
    elif route == "renewal.promote":
        source=strict_json(p["sourceRequestCanonicalUtf8"].encode("utf-8"),ROUTE_CAP); response=strict_json(p["expectedResponseCanonicalUtf8"].encode("utf-8"),ROUTE_CAP)
        exact_keys(source,{"backlogManifestSha256","backlogMode","csrSha256","csrSpkiSha256","historicalAuthorizationReceiptSha256","installationId","installationRevisionBefore","lineageId","newCertificateSha256","newCertificateSpkiSha256","newCredentialId","oldCertificateSha256","oldCertificateSpkiSha256","oldCredentialId","protocol","renewalIssuedResponseSha256","renewalRequestSha256","requestId","signature","telemetryAuthorizationRevisionAfter","telemetryAuthorizationRevisionBefore"})
        exact_keys(response,{"backlogManifestSha256","backlogMode","csrSha256","csrSpkiSha256","historicalAuthorizationReceiptSha256","installationId","installationRevisionAfter","installationRevisionBefore","lineageId","newCertificateSha256","newCertificateSpkiSha256","newCredentialId","oldCertificateSha256","oldCertificateSpkiSha256","oldCredentialId","protocol","renewalIssuedResponseSha256","renewalRequestSha256","requestId","status","telemetryAuthorizationRevisionAfter","telemetryAuthorizationRevisionBefore"})
        if source.get("requestId")!=response.get("requestId") or source.get("installationId")!=response.get("installationId"): raise ValueError("ack response binding")
    elif route == "renewal.cancel":
        source=strict_json(p["sourceRequestCanonicalUtf8"].encode("utf-8"),ROUTE_CAP); response=strict_json(p["expectedResponseCanonicalUtf8"].encode("utf-8"),ROUTE_CAP)
        exact_keys(source,{"backlogManifestSha256","cancelRequestId","currentCertificateSha256","currentCredentialId","edgeNonce","expectedTelemetryAuthorizationRevision","installationId","lineageId","protocol","signature","targetRenewalRequestSha256","targetRequestId"})
        exact_keys(response,{"backlogManifestSha256","cancelRequestId","cancelRequestSha256","currentCertificateSha256","currentCredentialId","decidedAt","installationId","lineageId","protocol","status","targetRenewalRequestSha256","targetRequestId","telemetryAuthorizationRevision"})
        if source.get("cancelRequestId")!=obj["operationId"] or source.get("installationId")!=obj["installationId"] or response.get("cancelRequestId")!=source["cancelRequestId"] or response.get("targetRequestId")!=source["targetRequestId"] or response.get("cancelRequestSha256")!=b64u(sha(p["sourceRequestCanonicalUtf8"].encode("utf-8"))): raise ValueError("cancel wire binding")
    elif route == "telemetry.ingest":
        text(p["batchId"], "batchId"); text(p["credentialId"], "credentialId"); text(p["presentedTransportCredentialId"],"presentedTransportCredentialId")
        if type(p["sourceRequestCanonicalUtf8"]) is not str or not 1 <= len(p["sourceRequestCanonicalUtf8"].encode("utf-8")) <= ROUTE_CAP:
            raise ValueError("invalid sourceRequestCanonicalUtf8")
        source=strict_json(p["sourceRequestCanonicalUtf8"].encode("utf-8"), ROUTE_CAP)
        if source.get("batchId") != p["batchId"] or source.get("credentialId") != p["credentialId"] or source.get("batchAuthorizationRevision") != p["authorizationRevision"]:
            raise ValueError("trusted source aliases")
    elif route in ("pairing.repair", "pairing.replacement"):
        if route.endswith("replacement"):
            for k in ("replacementInstallationId","replacementCredentialId","replacementLineageId"): text(p[k], k)
    return obj


def error_bytes(code: str, opid: str) -> bytes:
    status, retry = ERRORS[code]
    return canon({"code":code,"requestId":opid,"retryClass":retry,"schemaVersion":ERROR_SCHEMA})


def success_bytes(route: str, opid: str, installation: str, result: dict[str, Any]) -> bytes:
    return canon({"installationId":installation,"operationId":opid,"result":result,
                  "route":route,"schemaVersion":SUCCESS_SCHEMA})


def send_frame(fd: int, payload: bytes) -> None:
    os.write(fd, struct.pack(">Q", len(payload)) + payload)


def read_exact(fd: int, n: int) -> bytes:
    chunks=[]
    while n:
        b=os.read(fd,n)
        if not b: raise EOFError("short frame")
        chunks.append(b); n-=len(b)
    return b"".join(chunks)


def read_frame(fd: int) -> bytes:
    size=struct.unpack(">Q",read_exact(fd,8))[0]
    if size < 1 or size > FRAME_CAP: raise ValueError("frame cap")
    data=read_exact(fd,size)
    if os.read(fd,1): raise ValueError("trailing frame bytes")
    return data


def secure_db(path: Path) -> sqlite3.Connection:
    con=sqlite3.connect(path, timeout=15, isolation_level=None)
    con.execute("PRAGMA foreign_keys=ON")
    mode=con.execute("PRAGMA journal_mode=WAL").fetchone()[0]
    con.execute("PRAGMA synchronous=FULL"); con.execute("PRAGMA busy_timeout=15000"); con.execute("PRAGMA trusted_schema=OFF")
    if mode.lower()!="wal" or con.execute("PRAGMA synchronous").fetchone()[0]!=2 or con.execute("PRAGMA foreign_keys").fetchone()[0]!=1:
        raise RuntimeError("SQLite durability pragma mismatch")
    return con


def init_db(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700); os.chmod(path.parent,0o700)
    con=secure_db(path)
    con.executescript(DDL)
    con.execute("INSERT INTO meta VALUES('clock','2030-01-01T12:00:00Z')")
    con.execute("INSERT INTO installation VALUES('I',1,1,'L0','C0','ACTIVE',0,0,NULL)")
    con.execute("INSERT INTO credential VALUES('C0','I','L0','telemetry','active',1,NULL,NULL,?,?,?)",(sha(b'spki0'),sha(b'leaf0'),b'leaf0'))
    con.commit(); con.execute("PRAGMA wal_checkpoint(TRUNCATE)"); con.close(); os.chmod(path,0o600)


def crash(name: str, active: str | None) -> None:
    if active == name: os._exit(EXIT_CRASH)


def terminalize(con: sqlite3.Connection, opid: str, raw_response: bytes, status: int, retry: str,
                success: bool, before: tuple[int,int], after: tuple[int,int], now: str) -> None:
    con.execute("UPDATE operation SET status=?,http_status=?,response_sha256=?,raw_response=?,response_length=?,retry_class=?,before_authority_revision=?,after_authority_revision=?,before_lifecycle_revision=?,after_lifecycle_revision=?,committed_at=? WHERE operation_id=?",
      ("terminal_success" if success else "terminal_error",status,sha(raw_response),raw_response,len(raw_response),retry,before[0],after[0],before[1],after[1],now,opid))


def mutate(con: sqlite3.Connection, route: str, req: dict[str,Any], raw: bytes, crashpoint: str | None) -> tuple[bytes,int,str,bool]:
    iid=req["installationId"]; opid=req["operationId"]; p=req["payload"]
    inst=con.execute("SELECT telemetry_authorization_revision,lifecycle_revision,current_credential_id,lifecycle_state,v2_enabled,telemetry_lineage_id FROM installation WHERE installation_id=?",(iid,)).fetchone()
    if not inst: return error_bytes("INVALID_STATE",opid),409,"terminal_repair",False
    ar,lr,current,state,enabled,lineage=inst
    def fail(code: str):
        status,retry=ERRORS[code]; return error_bytes(code,opid),status,retry,False
    terminal_reason={"REVOKED":"SUPERSEDED_BY_REVOKE","REPAIRING":"SUPERSEDED_BY_REPAIR","REPLACED":"SUPERSEDED_BY_REPLACEMENT"}
    if route=="renewal.cancel":
        cancel_source=strict_json(p["sourceRequestCanonicalUtf8"].encode("utf-8"),ROUTE_CAP)
        if con.execute("SELECT 1 FROM renewal WHERE operation_id=?",(cancel_source["targetRequestId"],)).fetchone(): return fail("CANCEL_TARGET_COMMITTED")
    if route not in ("capability.enable","lifecycle.revoke","pairing.repair","pairing.replacement") and state in terminal_reason:
        if route in ("telemetry.ingest","receipt.expire"): return fail("HISTORICAL_RECEIPT_CLOSED")
        return fail(terminal_reason[state])
    if route != "capability.enable" and not enabled and route not in ("pairing.repair","pairing.replacement","lifecycle.revoke"):
        return fail("CAPABILITY_DISABLED")
    result: dict[str,Any]
    if route=="capability.enable":
        source_raw=p["sourceRequestCanonicalUtf8"].encode("utf-8"); source=strict_json(source_raw,ROUTE_CAP)
        expected_revision=source["expectedTelemetryAuthorizationRevision"]
        if expected_revision!=ar or enabled or source["currentCredentialId"]!=current: return fail("INVALID_STATE")
        current_leaf=con.execute("SELECT leaf_sha256 FROM credential WHERE credential_id=? AND installation_id=? AND status='active'",(current,iid)).fetchone()
        if not current_leaf or current_leaf[0]!=unb64(source["currentCertificateSha256"]): return fail("INVALID_STATE")
        now_value=con.execute("SELECT value FROM meta WHERE key='clock'").fetchone()[0]
        now_dt=dt.datetime.strptime(utc(now_value), "%Y-%m-%dT%H:%M:%SZ")
        issued_dt=dt.datetime.strptime(utc(source["issuedAt"]), "%Y-%m-%dT%H:%M:%SZ")
        expires_dt=dt.datetime.strptime(utc(source["expiresAt"]), "%Y-%m-%dT%H:%M:%SZ")
        if not issued_dt <= now_dt < expires_dt: return fail("CAPABILITY_NOT_CURRENT")
        con.execute("INSERT INTO capability_consumption VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",(
          opid,iid,unb64(source["capabilitySha256"]),unb64(source["capabilityServerNonce"]),unb64(source["edgeNonce"]),source["protocolId"],
          unb64(source["telemetryBatchSchemaSha256"]),unb64(source["telemetryAckSchemaSha256"]),unb64(source["telemetryErrorSchemaSha256"]),unb64(source["renewalControlSchemaSha256"]),
          current,unb64(source["currentCertificateSha256"]),expected_revision,source["issuedAt"],source["expiresAt"],source_raw))
        crash("capability.enable.after_consumption",crashpoint)
        con.execute("UPDATE installation SET v2_enabled=1 WHERE installation_id=?",(iid,)); crash("capability.enable.after_cas",crashpoint)
        result={"enabled":True,"telemetryAuthorizationRevision":ar,"issuedAt":source["issuedAt"],"expiresAt":source["expiresAt"]}
    elif route=="renewal.cancel":
        source_raw=p["sourceRequestCanonicalUtf8"].encode("utf-8"); source=strict_json(source_raw,ROUTE_CAP); response_raw=p["expectedResponseCanonicalUtf8"].encode("utf-8"); response=strict_json(response_raw,ROUTE_CAP); target=source["targetRequestId"]
        if con.execute("SELECT 1 FROM renewal WHERE operation_id=?",(target,)).fetchone(): return fail("CANCEL_TARGET_COMMITTED")
        now_value=utc(con.execute("SELECT value FROM meta WHERE key='clock'").fetchone()[0])
        current_row=con.execute("SELECT leaf_sha256,status FROM credential WHERE credential_id=? AND installation_id=?",(current,iid)).fetchone()
        if not current_row or current_row[1]!="active": return fail("INVALID_STATE")
        expected_source={"protocol":"2.0","cancelRequestId":opid,"targetRequestId":target,"installationId":iid,"lineageId":lineage,"currentCredentialId":current,"currentCertificateSha256":b64u(current_row[0]),"targetRenewalRequestSha256":source["targetRenewalRequestSha256"],"backlogManifestSha256":source["backlogManifestSha256"],"expectedTelemetryAuthorizationRevision":ar,"edgeNonce":source["edgeNonce"],"signature":source["signature"]}
        expected_response={"protocol":"2.0","status":"cancelled_no_reservation","cancelRequestId":opid,"targetRequestId":target,"installationId":iid,"lineageId":lineage,"currentCredentialId":current,"currentCertificateSha256":b64u(current_row[0]),"targetRenewalRequestSha256":source["targetRenewalRequestSha256"],"backlogManifestSha256":source["backlogManifestSha256"],"telemetryAuthorizationRevision":ar,"cancelRequestSha256":b64u(sha(source_raw)),"decidedAt":now_value}
        if source!=expected_source or response!=expected_response: return fail("INVALID_STATE")
        by_target=con.execute("SELECT target_operation_id,target_request_sha256,manifest_sha256 FROM cancel_tombstone WHERE target_operation_id=?",(target,)).fetchone()
        by_target_hash=con.execute("SELECT target_operation_id,target_request_sha256,manifest_sha256 FROM cancel_tombstone WHERE target_request_sha256=?",(unb64(source["targetRenewalRequestSha256"]),)).fetchone()
        by_manifest=con.execute("SELECT target_operation_id,target_request_sha256,manifest_sha256 FROM cancel_tombstone WHERE manifest_sha256=?",(unb64(source["backlogManifestSha256"]),)).fetchone()
        if by_target or by_target_hash or by_manifest: return fail("REPLAY_CONFLICT")
        con.execute("INSERT INTO cancel_tombstone VALUES(?,?,?,?,?)",(opid,target,unb64(source["targetRenewalRequestSha256"]),unb64(source["backlogManifestSha256"]),source_raw)); crash("renewal.cancel.after_tombstone",crashpoint)
        return response_raw,200,"none",True
    elif route=="renewal.reserve":
        source_raw=p["sourceRequestCanonicalUtf8"].encode("utf-8"); source=strict_json(source_raw,ROUTE_CAP)
        receipt_raw=p["expectedReceiptCanonicalUtf8"].encode("utf-8"); receipt_obj=strict_json(receipt_raw,ROUTE_CAP)
        pending_raw=p["expectedPendingResponseCanonicalUtf8"].encode("utf-8")
        expected_revision=source["expectedTelemetryAuthorizationRevision"]
        if ar==MAX_I64: return fail("REVISION_SATURATED")
        if expected_revision!=ar or source["installationRevisionBefore"]!=lr or source["lineageId"]!=lineage or source["oldCredentialId"]!=current or state!="ACTIVE": return fail("INVALID_STATE")
        old_row=con.execute("SELECT spki_sha256,leaf_sha256 FROM credential WHERE credential_id=? AND installation_id=? AND status='active'",(current,iid)).fetchone()
        if not old_row or old_row!=(unb64(source["oldCertificateSpkiSha256"]),unb64(source["oldCertificateSha256"])): return fail("INVALID_STATE")
        pending_obj=strict_json(pending_raw,ROUTE_CAP); now_value=utc(con.execute("SELECT value FROM meta WHERE key='clock'").fetchone()[0]); now_dt=dt.datetime.strptime(now_value,"%Y-%m-%dT%H:%M:%SZ")
        issuance_start=dt.datetime.fromtimestamp(source["epochMinute"]*60,dt.timezone.utc).replace(tzinfo=None)
        issuance_expires=(issuance_start+dt.timedelta(seconds=300)).strftime("%Y-%m-%dT%H:%M:%SZ")
        receipt_expires=(now_dt+dt.timedelta(seconds=86400)).strftime("%Y-%m-%dT%H:%M:%SZ")
        if receipt_obj["notBefore"]!=now_value or receipt_obj["expiresAt"]!=receipt_expires: return fail("INVALID_STATE")
        expected_pending={"protocol":"2.0","status":"pending","requestId":opid,"installationId":iid,"installationRevisionBefore":lr,"lineageId":lineage,"oldCredentialId":current,"oldCertificateSha256":source["oldCertificateSha256"],"oldCertificateSpkiSha256":source["oldCertificateSpkiSha256"],"newCredentialId":source["pendingCredentialId"],"csrSha256":source["csrSha256"],"csrSpkiSha256":source["csrSpkiSha256"],"telemetryAuthorizationRevisionBefore":ar,"telemetryAuthorizationRevisionAfter":ar+1,"backlogMode":"historical","backlogManifestSha256":source["backlogManifestSha256"],"historicalAuthorizationReceipt":receipt_obj,"historicalAuthorizationReceiptSha256":b64u(sha(receipt_raw)),"issuanceExpiresAt":issuance_expires}
        if pending_obj!=expected_pending: return fail("INVALID_STATE")
        pending=source["pendingCredentialId"]; manifest=canon(source["backlogManifest"]); mh=sha(manifest)
        if mh!=unb64(source["backlogManifestSha256"]): return fail("INVALID_STATE")
        tomb=con.execute("SELECT target_request_sha256,manifest_sha256 FROM cancel_tombstone WHERE target_operation_id=?",(opid,)).fetchone()
        if tomb:
            if tomb!=(sha(source_raw),mh): return fail("REPLAY_CONFLICT")
            return fail("CANCELLED_NO_RESERVATION")
        old=current
        con.execute("INSERT INTO renewal VALUES(?,?,?,?,?,?,?,?,?,NULL,NULL,NULL)",(opid,old,pending,"reserved","historical",mh,manifest,sha(pending_raw),pending_raw)); crash("renewal.reserve.after_manifest",crashpoint)
        rh=sha(receipt_raw)
        con.execute("INSERT INTO historical_receipt VALUES(?,?,?,'OPEN',NULL,?,?,?)",(rh,opid,iid,receipt_obj["notBefore"],receipt_obj["expiresAt"],receipt_raw)); crash("renewal.reserve.after_receipt",crashpoint)
        for e in source["backlogManifest"]["entries"]:
            con.execute("INSERT INTO receipt_entry VALUES(?,?,?,?,?,?,?,'UNCOMMITTED',NULL,NULL,NULL)",(rh,e["journalId"],e["batchId"],unb64(e["requestSha256"]),e["requestLength"],e["credentialId"],e["batchAuthorizationRevision"]))
        crash("renewal.reserve.after_entries",crashpoint)
        con.execute("UPDATE credential SET status='retiring',authorized_until_revision=?,operation_id=? WHERE credential_id=?",(ar+1,opid,old)); crash("renewal.reserve.after_old_retire",crashpoint)
        con.execute("INSERT INTO credential VALUES(?,?,?,'renewal_pending','reserved',?,NULL,?,NULL,NULL,NULL)",(pending,iid,lineage,ar+1,opid)); crash("renewal.reserve.after_pending_insert",crashpoint)
        con.execute("UPDATE installation SET telemetry_authorization_revision=?,lifecycle_state='RENEWING',v2_authority_used=1 WHERE installation_id=?",(ar+1,iid)); crash("renewal.reserve.after_installation_cas",crashpoint)
        return pending_raw,200,"none",True
    elif route=="renewal.issue":
        source_raw=p["sourceResponseCanonicalUtf8"].encode("utf-8"); source=strict_json(source_raw,ROUTE_CAP); rid=source["requestId"]
        r=con.execute("SELECT old_credential_id,pending_credential_id,state,raw_pending_response FROM renewal WHERE operation_id=?",(rid,)).fetchone()
        if not r or r[2] not in ('reserved','issuing') or state!='RENEWING': return fail("INVALID_STATE")
        old,pending,_,pending_raw=r; pending_obj=strict_json(pending_raw,ROUTE_CAP)
        if dt.datetime.strptime(utc(con.execute("SELECT value FROM meta WHERE key='clock'").fetchone()[0]),"%Y-%m-%dT%H:%M:%SZ")>=dt.datetime.strptime(pending_obj["issuanceExpiresAt"],"%Y-%m-%dT%H:%M:%SZ"): return fail("ACK_EXPIRED")
        shared=("requestId","installationId","installationRevisionBefore","lineageId","oldCredentialId","newCredentialId","oldCertificateSha256","oldCertificateSpkiSha256","csrSha256","csrSpkiSha256","backlogManifestSha256","backlogMode","historicalAuthorizationReceipt","historicalAuthorizationReceiptSha256","telemetryAuthorizationRevisionBefore","telemetryAuthorizationRevisionAfter")
        if any(source[key]!=pending_obj[key] for key in shared): return fail("INVALID_STATE")
        if source["protocol"]!="2.0" or source["status"]!="issued" or source["oldCredentialId"]!=old or source["newCredentialId"]!=pending or source["installationId"]!=iid or source["lineageId"]!=lineage: return fail("INVALID_STATE")
        pending_row=con.execute("SELECT installation_id,lineage_id,status,authorized_from_revision FROM credential WHERE credential_id=?",(pending,)).fetchone()
        if not pending_row or pending_row!=(iid,lineage,'reserved',ar): return fail("INVALID_STATE")
        leaf=_pem_der(source["certificatePem"]); issuer_der=_pem_der(source["caChainPem"]); leafhash=sha(leaf)
        if b64u(leafhash)!=source["newCertificateSha256"] or source["newCertificateSpkiSha256"]!=source["csrSpkiSha256"]: return fail("INVALID_STATE")
        con.execute("UPDATE renewal SET state='issuing' WHERE operation_id=?",(rid,)); con.execute("UPDATE credential SET status='issuing' WHERE credential_id=?",(pending,)); crash("renewal.issue.after_issuing_claim",crashpoint)
        issuer=sha(issuer_der); serial=_certificate_serial_der(leaf)
        con.execute("INSERT INTO issued_certificate VALUES(?,?,1,?,?,?,?)",(issuer,serial,pending,opid,leaf,leafhash)); crash("renewal.issue.after_certificate_store",crashpoint)
        con.execute("UPDATE credential SET status='pending_ack',spki_sha256=?,leaf_sha256=?,raw_leaf_der=? WHERE credential_id=?",(unb64(source["newCertificateSpkiSha256"]),leafhash,leaf,pending)); con.execute("UPDATE renewal SET state='issued',issued_response_sha256=?,raw_issued_response=? WHERE operation_id=?",(sha(source_raw),source_raw,rid)); crash("renewal.issue.after_pending_ack",crashpoint)
        return source_raw,200,"none",True
    elif route=="renewal.promote":
        source_raw=p["sourceRequestCanonicalUtf8"].encode("utf-8"); source=strict_json(source_raw,ROUTE_CAP); response_raw=p["expectedResponseCanonicalUtf8"].encode("utf-8"); response=strict_json(response_raw,ROUTE_CAP); rid=source["requestId"]
        r=con.execute("SELECT old_credential_id,pending_credential_id,state,backlog_mode,manifest_sha256,pending_response_sha256,raw_pending_response,issued_response_sha256,raw_issued_response FROM renewal WHERE operation_id=?",(rid,)).fetchone()
        if not r or r[2]!="issued" or state!="RENEWING": return fail("INVALID_STATE")
        # Overflow is decided before proof consumption or credential mutation.
        if lr==MAX_I64: return fail("REVISION_SATURATED")
        old,new,_,backlog_mode,manifest_hash,pending_hash,pending_raw,issued_hash,issued_raw=r
        if not pending_raw or sha(pending_raw)!=pending_hash or not issued_raw or sha(issued_raw)!=issued_hash: raise RuntimeError("corrupt stored renewal response")
        pending_obj=strict_json(pending_raw,ROUTE_CAP); issued_obj=strict_json(issued_raw,ROUTE_CAP)
        if dt.datetime.strptime(utc(con.execute("SELECT value FROM meta WHERE key='clock'").fetchone()[0]),"%Y-%m-%dT%H:%M:%SZ")>=dt.datetime.strptime(issued_obj["ackExpiresAt"],"%Y-%m-%dT%H:%M:%SZ"): return fail("ACK_EXPIRED")
        shared=("requestId","installationId","installationRevisionBefore","lineageId","oldCredentialId","newCredentialId","oldCertificateSha256","oldCertificateSpkiSha256","csrSha256","csrSpkiSha256","backlogManifestSha256","backlogMode","historicalAuthorizationReceipt","historicalAuthorizationReceiptSha256","telemetryAuthorizationRevisionBefore","telemetryAuthorizationRevisionAfter")
        if any(issued_obj[key]!=pending_obj[key] for key in shared): raise RuntimeError("corrupt stored issued aliases")
        reserve_op=con.execute("SELECT raw_request FROM operation WHERE operation_id=? AND route='renewal.reserve' AND status='terminal_success'",(rid,)).fetchone()
        receipt_row=con.execute("SELECT receipt_sha256,raw_receipt FROM historical_receipt WHERE renewal_operation_id=? AND installation_id=?",(rid,iid)).fetchone()
        old_row=con.execute("SELECT spki_sha256,leaf_sha256,status FROM credential WHERE credential_id=? AND installation_id=?",(old,iid)).fetchone()
        new_row=con.execute("SELECT spki_sha256,leaf_sha256,status FROM credential WHERE credential_id=? AND installation_id=?",(new,iid)).fetchone()
        if not reserve_op or not receipt_row or sha(receipt_row[1])!=receipt_row[0] or not old_row or not new_row: raise RuntimeError("corrupt stored promote context")
        reserve_outer=strict_json(reserve_op[0],ROUTE_CAP); reserve_source=reserve_outer["payload"]["sourceRequestCanonicalUtf8"].encode("utf-8")
        if (old_row[2],new_row[2])!=("retiring","pending_ack") or issued_obj["newCertificateSha256"]!=b64u(new_row[1]) or issued_obj["newCertificateSpkiSha256"]!=b64u(new_row[0]): raise RuntimeError("corrupt stored credential context")
        expected={
          "protocol":"2.0","requestId":rid,"renewalRequestSha256":b64u(sha(reserve_source)),"renewalIssuedResponseSha256":b64u(issued_hash),
          "installationId":iid,"lineageId":lineage,"installationRevisionBefore":lr,"oldCredentialId":old,
          "oldCertificateSha256":b64u(old_row[1]),"oldCertificateSpkiSha256":b64u(old_row[0]),"newCredentialId":new,
          "newCertificateSha256":b64u(new_row[1]),"newCertificateSpkiSha256":b64u(new_row[0]),
          "csrSha256":pending_obj["csrSha256"],"csrSpkiSha256":pending_obj["csrSpkiSha256"],
          "telemetryAuthorizationRevisionBefore":pending_obj["telemetryAuthorizationRevisionBefore"],"telemetryAuthorizationRevisionAfter":ar,
          "backlogMode":backlog_mode,"backlogManifestSha256":b64u(manifest_hash),"historicalAuthorizationReceiptSha256":b64u(receipt_row[0]),
        }
        if expected["telemetryAuthorizationRevisionBefore"]+1!=ar or any(source[key]!=value for key,value in expected.items()): return fail("INVALID_STATE")
        expected_response={**expected,"status":"acked","installationRevisionAfter":lr+1}
        if response!=expected_response: return fail("INVALID_STATE")
        proof=sha(source_raw); nonce=sha(unb64(source["signature"]))
        con.execute("INSERT INTO proof_consumption VALUES(?,?,?,?)",(proof,opid,nonce,source_raw)); crash("renewal.promote.after_proof",crashpoint)
        con.execute("UPDATE credential SET status='superseded',operation_id=NULL WHERE credential_id=?",(old,)); crash("renewal.promote.after_old_supersede",crashpoint)
        con.execute("UPDATE credential SET status='active',operation_id=NULL WHERE credential_id=?",(new,)); crash("renewal.promote.after_new_active",crashpoint)
        con.execute("UPDATE installation SET current_credential_id=?,lifecycle_state='ACTIVE',lifecycle_revision=lifecycle_revision+1 WHERE installation_id=?",(new,iid)); con.execute("UPDATE renewal SET state='acked' WHERE operation_id=?",(rid,)); crash("renewal.promote.after_pointer",crashpoint)
        return response_raw,200,"none",True
    elif route=="telemetry.ingest":
        receipt=hex32(p["receiptSha256"],"receipt"); source=p["sourceRequestCanonicalUtf8"].encode("utf-8"); source_obj=strict_json(source,ROUTE_CAP); source_hash=sha(source)
        if canon(source_obj)!=source: return fail("HISTORICAL_ENTRY_MISMATCH")
        by_batch=con.execute("SELECT batch_id,request_sha256,raw_request,raw_ack FROM ingest_batch WHERE installation_id=? AND batch_id=?",(iid,p["batchId"])).fetchone()
        by_hash=con.execute("SELECT batch_id,request_sha256,raw_request,raw_ack FROM ingest_batch WHERE installation_id=? AND request_sha256=?",(iid,source_hash)).fetchone()
        if by_batch or by_hash:
            if by_batch and by_hash and by_batch[0]==by_hash[0] and by_batch[1]==source_hash and by_batch[2]==source: return by_batch[3],200,"none",True
            conflict_key=sha(b"ONE.OS-TELEMETRY-CONFLICT-V2\0"+iid.encode()+p["batchId"].encode()+source_hash)
            prior=con.execute("SELECT raw_error,error_sha256 FROM immutable_identity_conflict WHERE conflict_key=?",(conflict_key,)).fetchone()
            if prior:
                if sha(prior[0])!=prior[1]: raise RuntimeError("corrupt stored telemetry conflict")
                return prior[0],409,"terminal_quarantine",False
            decided=utc(con.execute("SELECT value FROM meta WHERE key='clock'").fetchone()[0])
            error=canon({"schemaVersion":"one-os-telemetry-error/v2","batchId":p["batchId"],"code":"immutable_identity_conflict","decidedAt":decided,"requestSha256":b64u(source_hash),"retryClass":"terminal_quarantine"})
            existing_hash=by_batch[1] if by_batch else by_hash[1]
            con.execute("INSERT INTO immutable_identity_conflict VALUES(?,?,?,?,?,?,?,?,?,?)",(opid,iid,p["batchId"],conflict_key,existing_hash,source_hash,source,decided,error,sha(error)))
            return error,409,"terminal_quarantine",False
        row=con.execute("SELECT status,not_before,expires_at,raw_receipt FROM historical_receipt WHERE receipt_sha256=? AND installation_id=?",(receipt,iid)).fetchone()
        if not row or row[0]!="OPEN": return fail("HISTORICAL_RECEIPT_CLOSED")
        now=dt.datetime.strptime(utc(con.execute("SELECT value FROM meta WHERE key='clock'").fetchone()[0]),"%Y-%m-%dT%H:%M:%SZ")
        if not dt.datetime.strptime(utc(row[1]),"%Y-%m-%dT%H:%M:%SZ") <= now < dt.datetime.strptime(utc(row[2]),"%Y-%m-%dT%H:%M:%SZ"): return fail("HISTORICAL_RECEIPT_CLOSED")
        receipt_object=strict_json(row[3],ROUTE_CAP)
        if p["presentedTransportCredentialId"] not in receipt_object["allowedTransportCredentialIds"]: return fail("HISTORICAL_TRANSPORT_UNAUTHORIZED")
        entry=con.execute("SELECT journal_id,status,request_sha256,request_length,credential_id,batch_authorization_revision FROM receipt_entry WHERE receipt_sha256=? AND batch_id=?",(receipt,p["batchId"])).fetchone()
        if not entry or entry[1]!="UNCOMMITTED": return fail("HISTORICAL_RECEIPT_CLOSED")
        if (entry[2],entry[3],entry[4],entry[5]) != (source_hash,len(source),p["credentialId"],p["authorizationRevision"]): return fail("HISTORICAL_ENTRY_MISMATCH")
        ack=canon({"schemaVersion":"one-os-telemetry-ack/v2","authorizationMode":"historical_backlog","installationId":iid,"credentialId":p["credentialId"],"batchId":p["batchId"],"batchAuthorizationRevision":p["authorizationRevision"],"ingestAuthorizationRevision":ar,"requestSha256":b64u(source_hash),"acceptedSamples":len(source_obj.get("samples",[])),"duplicateSamples":0,"acceptedQualityEvents":len(source_obj.get("qualityEvents",[])),"duplicateQualityEvents":0,"acceptedGaps":len(source_obj.get("gaps",[])),"duplicateGaps":0,"ingestCursor":entry[0],"acceptedAt":utc(con.execute("SELECT value FROM meta WHERE key='clock'").fetchone()[0]),"historicalAuthorizationReceiptSha256":b64u(receipt)}); ah=sha(ack)
        con.execute("INSERT INTO ingest_batch VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",(iid,p["batchId"],opid,source_hash,source,p["credentialId"],p["presentedTransportCredentialId"],p["authorizationRevision"],ar,"historical_backlog",receipt,ack,ah)); crash("telemetry.ingest.after_ack_store",crashpoint)
        con.execute("UPDATE receipt_entry SET status='COMMITTED',ingest_operation_id=?,raw_ack=?,ack_sha256=? WHERE receipt_sha256=? AND journal_id=?",(opid,ack,ah,receipt,entry[0])); crash("telemetry.ingest.after_entry_commit",crashpoint)
        if not con.execute("SELECT 1 FROM receipt_entry WHERE receipt_sha256=? AND status='UNCOMMITTED'",(receipt,)).fetchone(): con.execute("UPDATE historical_receipt SET status='DRAINED' WHERE receipt_sha256=?",(receipt,))
        return ack,200,"none",True
    elif route=="receipt.expire":
        receipt=hex32(p["receiptSha256"],"receipt"); row=con.execute("SELECT status FROM historical_receipt WHERE receipt_sha256=?",(receipt,)).fetchone()
        if not row or row[0]!="OPEN": return fail("HISTORICAL_RECEIPT_CLOSED")
        con.execute("UPDATE receipt_entry SET status='TERMINAL_QUARANTINE' WHERE receipt_sha256=? AND status='UNCOMMITTED'",(receipt,)); crash("receipt.expire.after_quarantine",crashpoint)
        remaining=con.execute("SELECT changes()").fetchone()[0]
        con.execute("UPDATE historical_receipt SET status=? WHERE receipt_sha256=?",("EXPIRED_TERMINAL" if remaining else "DRAINED",receipt)); crash("receipt.expire.after_terminal",crashpoint)
        result={"receiptSha256":receipt.hex(),"status":"EXPIRED_TERMINAL" if remaining else "DRAINED"}
    elif route in ("lifecycle.revoke","pairing.repair","pairing.replacement"):
        # Pairing hooks run inside an already validated pairing transaction and
        # must bind exactly to its durable installation lifecycle revision.
        # Reject before saturation handling and before every authority mutation.
        if route.startswith("pairing.") and p["pairingLifecycleRevision"]!=lr: return fail("INVALID_STATE")
        # All three transitions require the next authority revision; refusing at
        # max is normative and must precede credential/receipt/tombstone writes.
        if ar==MAX_I64: return fail("REVISION_SATURATED")
        kind="revoked" if route=="lifecycle.revoke" else ("repair" if route.endswith("repair") else "replacement")
        winner=opid
        con.execute("UPDATE credential SET status='revoked',authorized_until_revision=COALESCE(authorized_until_revision,?),operation_id=NULL WHERE installation_id=? AND status IN ('active','retiring','reserved','issuing','pending_ack')",(ar+1,iid)); crash(f"{route}.after_credential_close",crashpoint)
        con.execute("UPDATE historical_receipt SET status='INVALIDATED',terminal_reason=? WHERE installation_id=? AND status='OPEN'",(kind,iid)); crash(f"{route}.after_receipt_invalidate",crashpoint)
        con.execute("UPDATE receipt_entry SET status='TERMINAL_QUARANTINE' WHERE receipt_sha256 IN (SELECT receipt_sha256 FROM historical_receipt WHERE installation_id=?) AND status='UNCOMMITTED'",(iid,))
        con.execute("UPDATE renewal SET state='tombstoned',tombstone_winner_operation_id=? WHERE operation_id IN (SELECT operation_id FROM operation WHERE installation_id=?) AND state IN ('reserved','issuing','issued')",(winner,iid)); crash(f"{route}.after_renewal_tombstone",crashpoint)
        newstate={"revoked":"REVOKED","repair":"REPAIRING","replacement":"REPLACED"}[kind]
        replacement=p.get("replacementInstallationId")
        con.execute("UPDATE installation SET telemetry_authorization_revision=?,current_credential_id=NULL,lifecycle_state=?,v2_authority_used=1,replacement_installation_id=? WHERE installation_id=?",(ar+1,newstate,replacement,iid)); crash(f"{route}.after_pointer_clear",crashpoint)
        if route.startswith("pairing."):
            con.execute("INSERT INTO pairing_lifecycle_event VALUES(?,?,?,?,?,?,1)",(opid,iid,kind,replacement,raw,sha(raw))); crash(f"{route}.after_event",crashpoint)
        if route=="pairing.replacement":
            con.execute("INSERT INTO installation VALUES(?,1,1,?,?, 'ACTIVE',0,0,NULL)",(replacement,p["replacementLineageId"],p["replacementCredentialId"]))
            con.execute("INSERT INTO credential VALUES(?,?,?,'telemetry','active',1,NULL,NULL,?,?,?)",(p["replacementCredentialId"],replacement,p["replacementLineageId"],sha(b'replacement-spki'),sha(b'replacement-leaf'),b'replacement-leaf'))
        result={"kind":kind,"telemetryHookApplied":True}
    else: raise AssertionError(route)
    return success_bytes(route,opid,iid,result),200,"none",True


def durable_worker(args: argparse.Namespace) -> int:
    try: raw=read_frame(args.request_fd); req=validate_request(args.route,raw)
    except Exception as exc:
        print(f"framing/codec: {exc}",file=sys.stderr); return EXIT_FRAMING
    opid=req["operationId"]; iid=req["installationId"]; h=sha(raw)
    try:
        con=secure_db(Path(args.db))
        if args.begin_attempt_fd is not None:
            sent=False
            def trace(sql: str) -> None:
                nonlocal sent
                if not sent and sql.strip().upper()=="BEGIN IMMEDIATE": os.write(args.begin_attempt_fd,b"B"); sent=True
            con.set_trace_callback(trace)
        con.execute("BEGIN IMMEDIATE")
        if args.lock_owned_fd is not None: os.write(args.lock_owned_fd,b"L")
        if args.lock_release_fd is not None: read_exact(args.lock_release_fd,1)
        crash("after_begin_immediate",args.crashpoint)
        # Public renewal replay identity precedes wrapper invocation identity and
        # current lifecycle/expiry checks. Internal delivery IDs are not authority.
        if args.route=="renewal.issue":
            public_raw=req["payload"]["sourceResponseCanonicalUtf8"].encode("utf-8"); public_obj=strict_json(public_raw,ROUTE_CAP); rid=public_obj["requestId"]
            if public_obj["installationId"]!=req["installationId"]:
                con.rollback(); con.close(); send_frame(args.result_fd,error_bytes("INVALID_STATE",opid)); return 0
            prior=con.execute("SELECT state,issued_response_sha256,raw_issued_response FROM renewal WHERE operation_id=?",(rid,)).fetchone()
            if prior and prior[1] is not None:
                if prior[1]!=sha(public_raw) or prior[2]!=public_raw or sha(prior[2])!=prior[1]:
                    con.rollback(); con.close(); send_frame(args.result_fd,error_bytes("REPLAY_CONFLICT",opid)); return 0
                response=prior[2]; con.commit(); con.close(); send_frame(args.result_fd,response); return 0
        elif args.route=="renewal.promote":
            public_raw=req["payload"]["sourceRequestCanonicalUtf8"].encode("utf-8"); public_obj=strict_json(public_raw,ROUTE_CAP); rid=public_obj["requestId"]; proof_hash=sha(public_raw)
            if public_obj["installationId"]!=req["installationId"]:
                con.rollback(); con.close(); send_frame(args.result_fd,error_bytes("INVALID_STATE",opid)); return 0
            renewal_state=con.execute("SELECT state FROM renewal WHERE operation_id=?",(rid,)).fetchone()
            prior=con.execute("SELECT p.raw_proof,o.status,o.response_sha256,o.raw_response FROM proof_consumption p JOIN operation o ON o.operation_id=p.operation_id WHERE p.proof_sha256=?",(proof_hash,)).fetchone()
            if prior:
                if not renewal_state or renewal_state[0]!="acked" or prior[0]!=public_raw or prior[1]!="terminal_success" or prior[2]!=sha(prior[3]):
                    raise RuntimeError("corrupt stored public ACK replay")
                response=prior[3]; con.commit(); con.close(); send_frame(args.result_fd,response); return 0
            if renewal_state and renewal_state[0]=="acked":
                con.rollback(); con.close(); send_frame(args.result_fd,error_bytes("REPLAY_CONFLICT",opid)); return 0
        by_id=con.execute("SELECT operation_id,request_sha256,raw_request,status,response_sha256,raw_response FROM operation WHERE operation_id=?",(opid,)).fetchone()
        by_hash=con.execute("SELECT operation_id,request_sha256,raw_request,status,response_sha256,raw_response FROM operation WHERE request_sha256=?",(h,)).fetchone()
        if by_id or by_hash:
            if by_id and by_hash and by_id[0]==by_hash[0] and by_id[1]==h and by_id[2]==raw:
                if by_id[3] not in ("terminal_success","terminal_error") or by_id[4]!=sha(by_id[5]): raise RuntimeError("corrupt stored operation")
                response=by_id[5]; con.commit(); con.close(); send_frame(args.result_fd,response); return 0
            if by_id and by_hash and by_id[0]!=by_hash[0]: raise RuntimeError("split identity rows")
            con.rollback(); con.close(); send_frame(args.result_fd,error_bytes("REPLAY_CONFLICT",opid)); return 0
        now=con.execute("SELECT value FROM meta WHERE key='clock'").fetchone()[0]
        before=con.execute("SELECT telemetry_authorization_revision,lifecycle_revision FROM installation WHERE installation_id=?",(iid,)).fetchone()
        if before is None: raise RuntimeError("unknown installation")
        con.execute("INSERT INTO operation(operation_id,installation_id,route,request_sha256,raw_request,request_length,status) VALUES(?,?,?,?,?,?,'processing')",(opid,iid,args.route,h,raw,len(raw)))
        crash("after_operation_identity_store",args.crashpoint)
        response,status,retry,success=mutate(con,args.route,req,raw,args.crashpoint)
        strict_json(response); crash("after_context_validation",args.crashpoint)
        after=con.execute("SELECT telemetry_authorization_revision,lifecycle_revision FROM installation WHERE installation_id=?",(iid,)).fetchone()
        terminalize(con,opid,response,status,retry,success,before,after,now)
        crash("after_terminal_response_store",args.crashpoint)
        con.commit(); crash("after_commit_before_delivery",args.crashpoint)
        con.close(); send_frame(args.result_fd,response); return 0
    except sqlite3.OperationalError as exc:
        print(f"store unavailable: {exc}",file=sys.stderr); return EXIT_STORE
    except Exception as exc:
        print(f"internal: {type(exc).__name__}: {exc}",file=sys.stderr); return EXIT_INTERNAL


def projection_worker(dbpath: Path, result_fd: int) -> int:
    con=secure_db(dbpath)
    orders={
      "installation":"installation_id", "credential":"credential_id", "operation":"operation_id",
      "capability_consumption":"operation_id", "proof_consumption":"proof_sha256", "renewal":"operation_id", "cancel_tombstone":"cancel_operation_id",
      "historical_receipt":"receipt_sha256", "receipt_entry":"receipt_sha256,journal_id",
      "ingest_batch":"installation_id,batch_id", "issued_certificate":"issuer_der_sha256,serial_der",
      "immutable_identity_conflict":"conflict_operation_id",
      "pairing_lifecycle_event":"pairing_operation_id",
    }
    out={}
    for table, order in orders.items():
        cur=con.execute(f"SELECT * FROM {table} ORDER BY {order}")
        cols=[d[0] for d in cur.description]; rows=[]
        for row in cur.fetchall(): rows.append({k:({"$hex":v.hex()} if isinstance(v,bytes) else v) for k,v in zip(cols,row)})
        out[table]=rows
    con.close(); send_frame(result_fd,canon(out)); return 0


def request(route: str, opid: str, payload: dict[str,Any], iid: str="I") -> bytes:
    if route=="capability.enable" and "sourceRequestCanonicalUtf8" not in payload:
        payload=synthetic_enable_payload(opid,payload,iid)
    elif route=="renewal.reserve" and "sourceRequestCanonicalUtf8" not in payload:
        payload=synthetic_reserve_payload(opid,payload,iid)
    elif route=="renewal.issue" and "sourceResponseCanonicalUtf8" not in payload:
        payload=synthetic_issue_payload(payload,iid)
    elif route=="renewal.promote" and "sourceRequestCanonicalUtf8" not in payload:
        payload=synthetic_promote_payload(payload,iid)
    elif route=="renewal.cancel" and "sourceRequestCanonicalUtf8" not in payload:
        payload=synthetic_cancel_payload(opid,payload,iid)
    return canon({"installationId":iid,"operationId":opid,"payload":payload,"schemaVersion":SCHEMA})


def telemetry_source(batch="B1", credential="C0", revision=1) -> bytes:
    return canon({"batchAuthorizationRevision":revision,"batchId":batch,"credentialId":credential})


def telemetry_payload(receipt: str, batch="B1", credential="C0", revision=1) -> dict[str,Any]:
    source=telemetry_source(batch,credential,revision)
    return {"batchId":batch,"credentialId":credential,"presentedTransportCredentialId":credential,"authorizationRevision":revision,
            "receiptSha256":receipt,"sourceRequestCanonicalUtf8":source.decode()}


def receipt_sha256_from_pending(raw: bytes) -> str:
    return unb64(strict_json(raw)["historicalAuthorizationReceiptSha256"]).hex()


def base_entry(batch="B1") -> dict[str,Any]:
    source=telemetry_source(batch)
    return {"batchId":batch,"credentialId":"C0","journalId":1,"observedAt":"2030-01-01T12:00:00.000Z","requestLength":len(source),"requestSha256":sha(source).hex()}


def payloads() -> dict[str,dict[str,Any]]:
    e=base_entry()
    return {
      "enable":{"expectedAuthorizationRevision":1,"issuedAt":"2030-01-01T12:00:00Z","expiresAt":"2030-01-01T12:05:00Z","nonce":"N1"},
      "reserve":{"expectedAuthorizationRevision":1,"pendingCredentialId":"C1","manifest":{"entries":[e]},"entries":[e]},
      "issue":{"renewalOperationId":"R1","issuerDerSha256":sha(b'issuer').hex(),"serialHex":"0101","leafDerHex":b'leaf-one'.hex()},
      "promote":{"renewalOperationId":"R1","proofSha256":sha(b'proof').hex(),"challengeNonce":sha(b'nonce').hex()},
    }


VECTOR_FILE = Path(__file__).with_name(
    "one-os-phase2c-p-canonical-vectors-v2-draft4-20260825.json"
)


def unb64(value: str) -> bytes:
    if type(value) is not str:
        raise ValueError("base64url string required")
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def b64u(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def vector_raw(section: dict[str, Any]) -> bytes:
    """Return only a self-consistent, already-validated public vector envelope."""
    exact_keys(section, {"canonicalUtf8", "length", "object", "sha256"})
    raw = section["canonicalUtf8"].encode("utf-8")
    if canon(section["object"]) != raw or len(raw) != section["length"]:
        raise ValueError("vector canonical bytes/length mismatch")
    if sha(raw) != unb64(section["sha256"]):
        raise ValueError("vector digest mismatch")
    return raw


def load_validated_vectors() -> dict[str, Any]:
    vectors = strict_json(VECTOR_FILE.read_bytes(), 8 * 1024 * 1024)
    checked = 0
    def walk(value: Any) -> None:
        nonlocal checked
        if isinstance(value, dict):
            if set(("canonicalUtf8", "length", "object", "sha256")) <= set(value):
                vector_raw(value); checked += 1
            for child in value.values(): walk(child)
        elif isinstance(value, list):
            for child in value: walk(child)
    walk(vectors)
    if checked < 270:
        raise ValueError("incomplete Draft-4 public vector inventory")
    return vectors


def synthetic_enable_payload(opid: str, config: dict[str,Any], iid: str) -> dict[str,Any]:
    template=load_validated_vectors()["enableRequest"]["object"]
    source=strict_json(canon(template))
    source.update({
      "installationId":iid,"requestId":opid,"currentCredentialId":"C0",
      "currentCertificateSha256":b64u(sha(b"leaf0")),
      "expectedTelemetryAuthorizationRevision":config["expectedAuthorizationRevision"],
      "issuedAt":config["issuedAt"],"expiresAt":config["expiresAt"],
      "capabilityServerNonce":b64u(sha(("cap-server:"+opid).encode())),
      "edgeNonce":b64u(sha(("edge:"+opid).encode())),
    })
    return {"sourceRequestCanonicalUtf8":canon(source).decode("utf-8")}


def synthetic_reserve_payload(opid: str, config: dict[str,Any], iid: str) -> dict[str,Any]:
    vectors=load_validated_vectors()
    revision=config["expectedAuthorizationRevision"]
    entries=[]
    for old in config["entries"]:
        entries.append({
          "batchAuthorizationRevision":revision,"batchId":old["batchId"],
          "credentialId":old["credentialId"],"journalId":old["journalId"],
          "requestLength":old["requestLength"],
          "requestSha256":b64u(bytes.fromhex(old["requestSha256"])),
        })
    manifest={
      "batchAuthorizationRevision":revision,"createdAt":"2030-01-01T12:00:00.000Z",
      "cutJournalMaxId":entries[-1]["journalId"],"cutMarkerId":"CUT:"+opid,
      "entries":entries,"entryCount":len(entries),"firstJournalId":entries[0]["journalId"],
      "installationId":iid,"lastJournalId":entries[-1]["journalId"],"lineageId":"L0",
      "renewalOperationId":opid,"schemaVersion":"2.0",
      "totalRequestBytes":sum(e["requestLength"] for e in entries),
    }
    source=strict_json(canon(vectors["renewalStart"]["object"]))
    source.update({
      "backlogManifest":manifest,"backlogManifestSha256":b64u(sha(canon(manifest))),
      "edgeNonce":b64u(sha(("renewal-edge:"+opid).encode())),
      "expectedTelemetryAuthorizationRevision":revision,"installationId":iid,
      "installationRevisionBefore":1,"lineageId":"L0","oldCredentialId":"C0",
      "oldCertificateSha256":b64u(sha(b"leaf0")),"oldCertificateSpkiSha256":b64u(sha(b"spki0")),
      "pendingCredentialId":config["pendingCredentialId"],"requestId":opid,
    })
    source_raw=canon(source)
    receipt=strict_json(canon(vectors["receipt"]["object"]))
    receipt.update({
      "allowedTransportCredentialIds":sorted(["C0",config["pendingCredentialId"]]),
      "backlogManifestSha256":source["backlogManifestSha256"],
      "cutJournalMaxId":manifest["cutJournalMaxId"],"cutMarkerId":manifest["cutMarkerId"],
      "entries":entries,"entryCount":len(entries),
      "historicalAuthorizationRevision":revision,"ingestAuthorizationRevision":revision+1,
      "installationId":iid,"lineageId":"L0","notBefore":"2030-01-01T12:00:00Z",
      "expiresAt":"2030-01-02T12:00:00Z","receiptNonce":b64u(sha(("receipt:"+opid).encode())),
      "renewalOperationId":opid,"renewalRequestSha256":b64u(sha(source_raw)),
      "totalRequestBytes":manifest["totalRequestBytes"],
    })
    pending=strict_json(canon(vectors["pendingResponse"]["object"]))
    for key in ("installationRevisionBefore","oldCertificateSha256","oldCertificateSpkiSha256","csrSha256","csrSpkiSha256","backlogMode","backlogManifestSha256"):
        pending[key]=source[key]
    pending.update({"requestId":opid,"installationId":iid,"lineageId":"L0",
      "oldCredentialId":"C0","newCredentialId":config["pendingCredentialId"],
      "historicalAuthorizationReceipt":receipt,
      "historicalAuthorizationReceiptSha256":b64u(sha(canon(receipt))),
      "telemetryAuthorizationRevisionBefore":revision,
      "telemetryAuthorizationRevisionAfter":revision+1})
    return {"sourceRequestCanonicalUtf8":source_raw.decode("utf-8"),
            "expectedReceiptCanonicalUtf8":canon(receipt).decode("utf-8"),
            "expectedPendingResponseCanonicalUtf8":canon(pending).decode("utf-8")}


def synthetic_issue_payload(config: dict[str,Any], iid: str) -> dict[str,Any]:
    obj=strict_json(canon(load_validated_vectors()["issuedResponse"]["object"]))
    reserve=synthetic_reserve_payload(config["renewalOperationId"],payloads()["reserve"],iid)
    pending=strict_json(reserve["expectedPendingResponseCanonicalUtf8"].encode())
    for key in ("requestId","installationId","installationRevisionBefore","lineageId","oldCredentialId","newCredentialId","oldCertificateSha256","oldCertificateSpkiSha256","csrSha256","csrSpkiSha256","backlogManifestSha256","backlogMode","historicalAuthorizationReceipt","historicalAuthorizationReceiptSha256","telemetryAuthorizationRevisionBefore","telemetryAuthorizationRevisionAfter"):
        obj[key]=pending[key]
    return {"sourceResponseCanonicalUtf8":canon(obj).decode("utf-8")}


def synthetic_promote_payload(config: dict[str,Any], iid: str) -> dict[str,Any]:
    vectors=load_validated_vectors(); req=strict_json(canon(vectors["renewalAckRequest"]["object"])); res=strict_json(canon(vectors["renewalAckResponse"]["object"]))
    issued_raw=synthetic_issue_payload(payloads()["issue"],iid)["sourceResponseCanonicalUtf8"].encode(); issued=strict_json(issued_raw); receipt=issued["historicalAuthorizationReceipt"]
    reserve_source=strict_json(synthetic_reserve_payload(issued["requestId"],payloads()["reserve"],iid)["sourceRequestCanonicalUtf8"].encode())
    aliases={key:issued[key] for key in ("protocol","requestId","installationId","lineageId","oldCredentialId","oldCertificateSha256","oldCertificateSpkiSha256","newCredentialId","newCertificateSha256","newCertificateSpkiSha256","csrSha256","csrSpkiSha256","telemetryAuthorizationRevisionBefore","telemetryAuthorizationRevisionAfter","backlogMode","backlogManifestSha256","historicalAuthorizationReceiptSha256")}
    aliases.update({"installationRevisionBefore":reserve_source["installationRevisionBefore"],"renewalRequestSha256":receipt["renewalRequestSha256"],"renewalIssuedResponseSha256":b64u(sha(issued_raw))})
    req.update(aliases); req["signature"]=b64u(bytes.fromhex(config["proofSha256"]))
    res.update(aliases); res.update({"status":"acked","installationRevisionAfter":aliases["installationRevisionBefore"]+1})
    return {"sourceRequestCanonicalUtf8":canon(req).decode("utf-8"),
            "expectedResponseCanonicalUtf8":canon(res).decode("utf-8")}


def synthetic_cancel_payload(opid: str, config: dict[str,Any], iid: str) -> dict[str,Any]:
    vectors=load_validated_vectors(); req=strict_json(canon(vectors["cancelRequest"]["object"])); res=strict_json(canon(vectors["cancelResponse"]["object"]))
    req.update({"cancelRequestId":opid,"installationId":iid,"lineageId":"L0","currentCredentialId":"C0","currentCertificateSha256":b64u(sha(b"leaf0")),"expectedTelemetryAuthorizationRevision":1,"targetRequestId":config["targetOperationId"],
      "targetRenewalRequestSha256":b64u(bytes.fromhex(config["targetRequestSha256"])),
      "backlogManifestSha256":b64u(bytes.fromhex(config["manifestSha256"]))})
    raw=canon(req)
    res.update({"cancelRequestId":opid,"installationId":iid,"lineageId":"L0","currentCredentialId":"C0","currentCertificateSha256":b64u(sha(b"leaf0")),"telemetryAuthorizationRevision":1,"targetRequestId":config["targetOperationId"],
      "targetRenewalRequestSha256":req["targetRenewalRequestSha256"],"backlogManifestSha256":req["backlogManifestSha256"],
      "cancelRequestSha256":b64u(sha(raw)),"decidedAt":"2030-01-01T12:00:00Z"})
    return {"sourceRequestCanonicalUtf8":raw.decode(),"expectedResponseCanonicalUtf8":canon(res).decode()}


def _pem_der(pem: str) -> bytes:
    lines = [line for line in pem.splitlines() if not line.startswith("-----")]
    return base64.b64decode("".join(lines), validate=True)


def _der_tlv(data: bytes, offset: int) -> tuple[int, bytes, int]:
    tag=data[offset]; n=data[offset+1]; pos=offset+2
    if n & 0x80:
        width=n & 0x7f
        if not 1 <= width <= 4: raise ValueError("DER length")
        n=int.from_bytes(data[pos:pos+width],"big"); pos+=width
    end=pos+n
    if end>len(data): raise ValueError("truncated DER")
    return tag,data[pos:end],end


def _certificate_serial_der(cert_der: bytes) -> bytes:
    tag,cert,_=_der_tlv(cert_der,0)
    if tag != 0x30: raise ValueError("certificate sequence")
    tag,tbs,_=_der_tlv(cert,0)
    if tag != 0x30: raise ValueError("tbs sequence")
    pos=0; tag,_,end=_der_tlv(tbs,pos)
    if tag == 0xa0: pos=end
    tag,serial,_=_der_tlv(tbs,pos)
    if tag != 0x02 or not serial or serial[0]&0x80: raise ValueError("certificate serial")
    return serial


def trusted_command_from_vector(name: str, vectors: dict[str, Any]) -> tuple[str, bytes]:
    """Project verified public wire into the trusted transaction command seam.

    Crypto verification remains an upstream P-verifier responsibility; this
    mapper never treats a caller-supplied digest as authority. Every source
    envelope is rebound to canonical bytes before aliases are projected.
    """
    section = vectors[name] if name != "telemetryBatch0" else vectors["telemetryBatches256"][0]
    vector_raw(section); obj=section["object"]
    if name == "enableRequest":
        route="capability.enable"; opid=obj["requestId"]
        payload={"sourceRequestCanonicalUtf8":section["canonicalUtf8"]}
    elif name == "renewalStart":
        route="renewal.reserve"; opid=obj["requestId"]
        payload={"sourceRequestCanonicalUtf8":section["canonicalUtf8"],
                 "expectedReceiptCanonicalUtf8":vectors["receipt"]["canonicalUtf8"],
                 "expectedPendingResponseCanonicalUtf8":vectors["pendingResponse"]["canonicalUtf8"]}
    elif name == "issuedResponse":
        route="renewal.issue"; opid="trusted-issue:"+obj["requestId"]
        payload={"sourceResponseCanonicalUtf8":section["canonicalUtf8"]}
    elif name == "renewalAckRequest":
        route="renewal.promote"; opid="trusted-ack:"+obj["requestId"]
        payload={"sourceRequestCanonicalUtf8":section["canonicalUtf8"],
                 "expectedResponseCanonicalUtf8":vectors["renewalAckResponse"]["canonicalUtf8"]}
    elif name == "cancelRequest":
        route="renewal.cancel"; opid=obj["cancelRequestId"]
        payload={"sourceRequestCanonicalUtf8":section["canonicalUtf8"],
                 "expectedResponseCanonicalUtf8":vectors["cancelResponse"]["canonicalUtf8"]}
    elif name == "telemetryBatch0":
        route="telemetry.ingest"; opid="trusted-ingest:"+obj["batchId"]
        payload={"batchId":obj["batchId"],"credentialId":obj["credentialId"],
                 "presentedTransportCredentialId":obj["credentialId"],
                 "authorizationRevision":obj["batchAuthorizationRevision"],
                 "receiptSha256":unb64(vectors["receipt"]["sha256"]).hex(),
                 "sourceRequestCanonicalUtf8":section["canonicalUtf8"]}
    else:
        raise ValueError("no trusted transaction mapping")
    raw=request(route,opid,payload,obj["installationId"])
    validate_request(route,raw)
    return route,raw


def _spawn_call(db: Path, route: str, raw: bytes, crashpoint: str|None=None,
                owned_w: int|None=None, release_r: int|None=None, attempt_w: int|None=None):
    req_r,req_w=os.pipe(); res_r,res_w=os.pipe(); passfds=[req_r,res_w]
    cmd=[sys.executable,"-B",str(Path(__file__).resolve()),"durable-worker","--db",str(db),"--route",route,"--request-fd",str(req_r),"--result-fd",str(res_w)]
    for flag,fd in (("--lock-owned-fd",owned_w),("--lock-release-fd",release_r),("--begin-attempt-fd",attempt_w)):
        if fd is not None: cmd += [flag,str(fd)]; passfds.append(fd)
    if crashpoint: cmd += ["--crashpoint",crashpoint]
    p=subprocess.Popen(cmd,pass_fds=tuple(passfds),stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    os.close(req_r); os.close(res_w); os.write(req_w,struct.pack(">Q",len(raw))+raw); os.close(req_w)
    return p,res_r


def call(db: Path, route: str, raw: bytes, crashpoint: str|None=None) -> tuple[int,bytes,bytes,bytes]:
    p,r=_spawn_call(db,route,raw,crashpoint)
    try: framed=b"" if crashpoint else read_frame(r)
    except EOFError: framed=b""
    finally: os.close(r)
    out,err=p.communicate(timeout=20)
    return p.returncode,framed,out,err


def project(db: Path) -> bytes:
    r,w=os.pipe(); p=subprocess.Popen([sys.executable,"-B",str(Path(__file__).resolve()),"projection-worker","--db",str(db),"--result-fd",str(w)],pass_fds=(w,),stdout=subprocess.PIPE,stderr=subprocess.PIPE); os.close(w)
    data=read_frame(r); os.close(r); out,err=p.communicate(timeout=20)
    if p.returncode or out: raise AssertionError((p.returncode,out,err))
    return data


def assert_no_owned_workers(db: Path) -> None:
    owned_db=os.fsencode(str(db)); basename=Path(__file__).name.encode()
    for proc in Path("/proc").iterdir():
        if not proc.name.isdigit(): continue
        try: argv=(proc/"cmdline").read_bytes().split(b"\0")
        except (FileNotFoundError, PermissionError, ProcessLookupError): continue
        if owned_db in argv and any(Path(os.fsdecode(a)).name.encode()==basename for a in argv if a) and any(a in (b"durable-worker",b"projection-worker") for a in argv):
            raise AssertionError(f"owned worker residue pid={proc.name}")


class Draft4Tests(unittest.TestCase):
    def setUp(self):
        self.td=Path(tempfile.mkdtemp(prefix="draft4-executor-")); os.chmod(self.td,0o700); self.db=self.td/"state.sqlite3"; init_db(self.db)
    def tearDown(self):
        shutil.rmtree(self.td)
        assert_no_owned_workers(self.db)
    def _reset(self):
        shutil.rmtree(self.td)
        self.td=Path(tempfile.mkdtemp(prefix="draft4-executor-")); os.chmod(self.td,0o700)
        self.db=self.td/"state.sqlite3"; init_db(self.db)
    def c(self,route,raw,code=0):
        rc,data,out,err=call(self.db,route,raw); self.assertEqual(rc,code,err); self.assertEqual(out,b""); return data
    def enable(self): return self.c("capability.enable",request("capability.enable","E1",payloads()["enable"]))
    def reserve(self): return self.c("renewal.reserve",request("renewal.reserve","R1",payloads()["reserve"]))
    def setup_reserved(self): self.enable(); return self.reserve()

    def test_strict_codec_and_modes(self):
        self.assertEqual(stat.S_IMODE(self.td.stat().st_mode),0o700); self.assertEqual(stat.S_IMODE(self.db.stat().st_mode),0o600)
        good=request("capability.enable","E1",payloads()["enable"]); strict_json(good)
        for bad in (b'{"a":1,"a":2}',b'{"a":1.0}',b' {"a":1}',b'\xef\xbb\xbf{}',b'{"a":01}'):
            with self.assertRaises(ValueError): strict_json(bad)
        con=secure_db(self.db); self.assertEqual(con.execute("PRAGMA journal_mode").fetchone()[0],"wal"); self.assertEqual(con.execute("PRAGMA synchronous").fetchone()[0],2); con.close()

    def test_full_happy_replay_conflict_and_projection(self):
        enabled=self.enable(); self.assertEqual(enabled,self.enable())
        reserve=self.reserve(); self.assertEqual(reserve,self.reserve())
        issued=self.c("renewal.issue",request("renewal.issue","IS1",payloads()["issue"])); self.assertEqual(issued,self.c("renewal.issue",request("renewal.issue","IS1",payloads()["issue"])))
        promoted=self.c("renewal.promote",request("renewal.promote","P1",payloads()["promote"])); self.assertEqual(promoted,self.c("renewal.promote",request("renewal.promote","P1",payloads()["promote"])))
        changed=payloads()["promote"].copy(); changed["proofSha256"]=sha(b'other').hex()
        conflict=self.c("renewal.promote",request("renewal.promote","P1",changed)); self.assertEqual(conflict,error_bytes("REPLAY_CONFLICT","P1"))
        snap=strict_json(project(self.db)); self.assertEqual(len(snap["operation"]),4); self.assertEqual(snap["installation"][0]["current_credential_id"],"C1")

    def test_cancel_reserve_serial_orders(self):
        self.enable(); target=request("renewal.reserve","R1",payloads()["reserve"]); target_source=strict_json(strict_json(target)["payload"]["sourceRequestCanonicalUtf8"].encode()); target_public=canon(target_source); target_manifest=unb64(target_source["backlogManifestSha256"]).hex()
        cancel=request("renewal.cancel","CANCEL",{"targetOperationId":"R1","targetRequestSha256":sha(target_public).hex(),"manifestSha256":target_manifest})
        self.c("renewal.cancel",cancel)
        manifest_collision=request("renewal.cancel","CANCEL-MANIFEST-COLLISION",{"targetOperationId":"R2","targetRequestSha256":sha(b"other-public-start").hex(),"manifestSha256":target_manifest})
        self.assertEqual(self.c("renewal.cancel",manifest_collision),error_bytes("REPLAY_CONFLICT","CANCEL-MANIFEST-COLLISION"))
        cancel2=request("renewal.cancel","CANCEL-2",{"targetOperationId":"R1","targetRequestSha256":sha(target_public).hex(),"manifestSha256":target_manifest})
        self.assertEqual(self.c("renewal.cancel",cancel2),error_bytes("REPLAY_CONFLICT","CANCEL-2"))
        self.assertEqual(self.c("renewal.reserve",target),error_bytes("CANCELLED_NO_RESERVATION","R1"))
        # A partial target-ID collision is not cancellation authority.
        shutil.rmtree(self.td); self.td=Path(tempfile.mkdtemp(prefix="draft4-executor-")); os.chmod(self.td,0o700); self.db=self.td/"state.sqlite3"; init_db(self.db); self.enable()
        detached=request("renewal.cancel","DETACHED",{"targetOperationId":"R1","targetRequestSha256":sha(b"other-start").hex(),"manifestSha256":sha(b"other-manifest").hex()}); self.c("renewal.cancel",detached)
        self.assertEqual(self.c("renewal.reserve",target),error_bytes("REPLAY_CONFLICT","R1"))
        # Opposite serial order in a fresh DB.
        shutil.rmtree(self.td); self.td=Path(tempfile.mkdtemp(prefix="draft4-executor-")); os.chmod(self.td,0o700); self.db=self.td/"state.sqlite3"; init_db(self.db); self.enable(); self.reserve()
        self.assertEqual(self.c("renewal.cancel",cancel),error_bytes("CANCEL_TARGET_COMMITTED","CANCEL"))
        self.c("lifecycle.revoke",request("lifecycle.revoke","REVOKE-AFTER-RESERVE",{"reason":"test"}))
        cancel_after_revoke=strict_json(cancel); cancel_after_revoke["operationId"]="CANCEL-AFTER-REVOKE"; source=strict_json(cancel_after_revoke["payload"]["sourceRequestCanonicalUtf8"].encode()); response=strict_json(cancel_after_revoke["payload"]["expectedResponseCanonicalUtf8"].encode()); source["cancelRequestId"]="CANCEL-AFTER-REVOKE"; source_raw=canon(source); response["cancelRequestId"]="CANCEL-AFTER-REVOKE"; response["cancelRequestSha256"]=b64u(sha(source_raw)); cancel_after_revoke["payload"]["sourceRequestCanonicalUtf8"]=source_raw.decode(); cancel_after_revoke["payload"]["expectedResponseCanonicalUtf8"]=canon(response).decode()
        self.assertEqual(self.c("renewal.cancel",canon(cancel_after_revoke)),error_bytes("CANCEL_TARGET_COMMITTED","CANCEL-AFTER-REVOKE"))

    def test_ingest_expiry_revoke_and_pairing_hooks(self):
        self.setup_reserved(); receipt=receipt_sha256_from_pending(self.reserve())
        ingest=request("telemetry.ingest","IN1",telemetry_payload(receipt))
        ack=self.c("telemetry.ingest",ingest); self.assertEqual(ack,self.c("telemetry.ingest",ingest))
        self.assertEqual(strict_json(self.c("receipt.expire",request("receipt.expire","X1",{"receiptSha256":receipt})))["code"],"HISTORICAL_RECEIPT_CLOSED")
        self.c("lifecycle.revoke",request("lifecycle.revoke","V1",{"reason":"compromise"})); self.assertEqual(ack,self.c("telemetry.ingest",ingest))
        # Hooks execute atomically inside the pairing-owned worker transaction.
        for route in ("pairing.repair","pairing.replacement"):
            td=Path(tempfile.mkdtemp(prefix="draft4-hook-")); db=td/"s.sqlite3"; init_db(db)
            payload={"pairingLifecycleRevision":1}
            if route.endswith("replacement"): payload.update({"replacementInstallationId":"J","replacementCredentialId":"JC","replacementLineageId":"JL"})
            raw=request(route,"PAIR",payload); baseline=project(db)
            rc,data,out,err=call(db,route,raw,f"{route}.after_event"); self.assertEqual((rc,data,out),(EXIT_CRASH,b"",b""),err); self.assertEqual(project(db),baseline)
            rc,data,out,err=call(db,route,raw); self.assertEqual((rc,out),(0,b""),err); self.assertTrue(strict_json(data)["result"]["telemetryHookApplied"])
            snap=strict_json(project(db)); self.assertEqual(len(snap["pairing_lifecycle_event"]),1)
            if route.endswith("replacement"): self.assertEqual(len(snap["installation"]),2)
            shutil.rmtree(td)

    def test_public_telemetry_ack_and_identity_conflict_are_normative_durable_wire(self):
        vectors=load_validated_vectors(); enable=vectors["enableRequest"]["object"]; start=vectors["renewalStart"]["object"]
        con=secure_db(self.db)
        con.execute("UPDATE meta SET value=? WHERE key='clock'",(vectors["receipt"]["object"]["notBefore"],))
        con.execute("INSERT INTO installation VALUES(?,?,?,?,?,'ACTIVE',0,0,NULL)",(start["installationId"],start["installationRevisionBefore"],start["expectedTelemetryAuthorizationRevision"],start["lineageId"],start["oldCredentialId"]))
        con.execute("INSERT INTO credential VALUES(?,?,?,'telemetry','active',1,NULL,NULL,?,?,?)",(start["oldCredentialId"],start["installationId"],start["lineageId"],unb64(start["oldCertificateSpkiSha256"]),unb64(enable["currentCertificateSha256"]),b'vector-leaf'))
        con.commit(); con.close()
        for name in ("enableRequest","renewalStart"):
            route,raw=trusted_command_from_vector(name,vectors); self.c(route,raw)
        route,winner=trusted_command_from_vector("telemetryBatch0",vectors); winner_payload=strict_json(winner)["payload"]; submitted=strict_json(winner_payload["sourceRequestCanonicalUtf8"].encode())
        ack=self.c(route,winner)
        expected_ack=canon({"schemaVersion":"one-os-telemetry-ack/v2","authorizationMode":"historical_backlog","installationId":submitted["installationId"],"credentialId":submitted["credentialId"],"batchId":submitted["batchId"],"batchAuthorizationRevision":submitted["batchAuthorizationRevision"],"ingestAuthorizationRevision":start["expectedTelemetryAuthorizationRevision"]+1,"requestSha256":b64u(sha(canon(submitted))),"acceptedSamples":len(submitted["samples"]),"duplicateSamples":0,"acceptedQualityEvents":len(submitted["qualityEvents"]),"duplicateQualityEvents":0,"acceptedGaps":len(submitted["gaps"]),"duplicateGaps":0,"ingestCursor":vectors["receipt"]["object"]["entries"][0]["journalId"],"acceptedAt":vectors["receipt"]["object"]["notBefore"],"historicalAuthorizationReceiptSha256":b64u(sha(canon(vectors["receipt"]["object"])))})
        self.assertEqual(ack,expected_ack); ack_obj=strict_json(ack)
        from strict_wire_one_os_phase2c_p_draft4 import validate_exact_schema
        ack_schema=strict_json(Path(__file__).with_name("one-os-phase2c-p-telemetry-ack-v2-draft4-20260825.schema.json").read_bytes())
        error_schema=strict_json(Path(__file__).with_name("one-os-phase2c-p-telemetry-error-v2-draft4-20260825.schema.json").read_bytes())
        registry={ack_schema["$id"]:ack_schema,error_schema["$id"]:error_schema}
        validate_exact_schema(ack_obj,ack_schema,schema_registry=registry)
        self.assertEqual(set(ack_obj),{"schemaVersion","authorizationMode","installationId","credentialId","batchId","batchAuthorizationRevision","ingestAuthorizationRevision","requestSha256","acceptedSamples","duplicateSamples","acceptedQualityEvents","duplicateQualityEvents","acceptedGaps","duplicateGaps","ingestCursor","acceptedAt","historicalAuthorizationReceiptSha256"})
        self.assertEqual((ack_obj["schemaVersion"],ack_obj["authorizationMode"]),("one-os-telemetry-ack/v2","historical_backlog"))
        self.assertEqual(ack_obj["requestSha256"],b64u(sha(canon(submitted))))
        self.assertEqual(ack,self.c(route,winner))
        loser_obj=strict_json(canon(submitted)); loser_obj["payloadSha256"]="A"*43
        winner_payload=strict_json(winner)["payload"]; loser_payload=dict(winner_payload); loser_payload["sourceRequestCanonicalUtf8"]=canon(loser_obj).decode()
        loser=request("telemetry.ingest","trusted-conflict:"+submitted["batchId"],loser_payload,start["installationId"])
        error=self.c("telemetry.ingest",loser)
        expected_error=canon({"schemaVersion":"one-os-telemetry-error/v2","batchId":submitted["batchId"],"code":"immutable_identity_conflict","decidedAt":vectors["receipt"]["object"]["notBefore"],"requestSha256":b64u(sha(canon(loser_obj))),"retryClass":"terminal_quarantine"})
        self.assertEqual(error,expected_error); error_obj=strict_json(error)
        validate_exact_schema(error_obj,error_schema,schema_registry=registry)
        self.assertEqual(set(error_obj),{"schemaVersion","batchId","code","decidedAt","requestSha256","retryClass"})
        self.assertEqual(error_obj,{"schemaVersion":"one-os-telemetry-error/v2","batchId":submitted["batchId"],"code":"immutable_identity_conflict","decidedAt":error_obj["decidedAt"],"requestSha256":b64u(sha(canon(loser_obj))),"retryClass":"terminal_quarantine"})
        self.assertEqual(error,self.c("telemetry.ingest",loser))
        replay_other_op=request("telemetry.ingest","trusted-conflict-replay:"+submitted["batchId"],loser_payload,start["installationId"])
        self.assertEqual(error,self.c("telemetry.ingest",replay_other_op))
        snap=strict_json(project(self.db)); conflict=snap["immutable_identity_conflict"][0]
        self.assertEqual(conflict["raw_error"]["$hex"],error.hex()); self.assertEqual(conflict["error_sha256"]["$hex"],sha(error).hex()); self.assertEqual(conflict["decided_at"],error_obj["decidedAt"])
        operation=next(row for row in snap["operation"] if row["operation_id"]=="trusted-conflict:"+submitted["batchId"])
        self.assertEqual((operation["status"],operation["http_status"],operation["retry_class"]),("terminal_error",409,"terminal_quarantine"))
        self.assertEqual(operation["raw_response"]["$hex"],error.hex())
        # Reverse bijection: one stored request hash may not authorize another batch alias.
        con=secure_db(self.db); con.execute("UPDATE ingest_batch SET batch_id='ffffffff-ffff-4fff-bfff-ffffffffffff' WHERE installation_id=?",(start["installationId"],)); con.commit(); con.close()
        reverse=request("telemetry.ingest","trusted-reverse-conflict:"+submitted["batchId"],winner_payload,start["installationId"])
        reverse_error=self.c("telemetry.ingest",reverse); reverse_obj=strict_json(reverse_error)
        validate_exact_schema(reverse_obj,error_schema,schema_registry=registry)
        self.assertEqual((reverse_obj["batchId"],reverse_obj["requestSha256"],reverse_obj["code"],reverse_obj["retryClass"]),(submitted["batchId"],b64u(sha(canon(submitted))),"immutable_identity_conflict","terminal_quarantine"))

    def test_identity_uniqueness_and_corruption_fences(self):
        raw=request("capability.enable","E1",payloads()["enable"]); response=self.c("capability.enable",raw)
        con=secure_db(self.db)
        with self.assertRaises(sqlite3.IntegrityError):
            con.execute("INSERT INTO operation(operation_id,installation_id,route,request_sha256,raw_request,request_length,status) VALUES('OTHER','I','capability.enable',?,?,?,'processing')",(sha(raw),raw,len(raw)))
        con.rollback()
        con.execute("UPDATE operation SET response_sha256=? WHERE operation_id='E1'",(sha(b'corrupt'),)); con.commit(); con.close()
        rc,data,out,err=call(self.db,"capability.enable",raw)
        self.assertEqual((rc,data,out),(EXIT_INTERNAL,b"",b"")); self.assertIn(b"corrupt stored operation",err)
        self.assertNotEqual(sha(response),sha(b'corrupt'))

    def test_worker_residue_scan_ignores_foreign_db_worker(self):
        with tempfile.TemporaryDirectory(prefix="draft4-foreign-") as td:
            other=Path(td)/"foreign.sqlite3"; init_db(other)
            owned_r,owned_w=os.pipe(); release_r,release_w=os.pipe()
            p,result_r=_spawn_call(other,"capability.enable",request("capability.enable","FOREIGN",payloads()["enable"]),owned_w=owned_w,release_r=release_r)
            os.close(owned_w); os.close(release_r)
            try:
                self.assertEqual(os.read(owned_r,1),b"L"); assert_no_owned_workers(self.db)
            finally:
                os.write(release_w,b"1"); os.close(release_w); os.close(owned_r)
                try: read_frame(result_r)
                except EOFError: pass
                os.close(result_r); p.communicate(timeout=20)

    def test_true_precommit_crash_and_postcommit_loss(self):
        self.enable(); baseline=project(self.db); raw=request("renewal.reserve","R1",payloads()["reserve"])
        rc,data,out,err=call(self.db,"renewal.reserve",raw,"renewal.reserve.after_entries"); self.assertEqual(rc,EXIT_CRASH,(data,out,err)); self.assertEqual(project(self.db),baseline)
        rc,data,out,err=call(self.db,"renewal.reserve",raw,"after_commit_before_delivery"); self.assertEqual(rc,EXIT_CRASH,(data,out,err)); self.assertEqual(data,b"")
        replay=self.c("renewal.reserve",raw); snap=strict_json(project(self.db)); row=next(x for x in snap["operation"] if x["operation_id"]=="R1")
        self.assertEqual(sha(replay).hex(),row["response_sha256"]["$hex"]); self.assertEqual(replay.hex(),row["raw_response"]["$hex"])

    def _race(self,first_route,first_raw,second_route,second_raw):
        own_r,own_w=os.pipe(); rel_r,rel_w=os.pipe(); att_r,att_w=os.pipe()
        a=ar=b=br=None
        try:
            a,ar=_spawn_call(self.db,first_route,first_raw,owned_w=own_w,release_r=rel_r); os.close(own_w); own_w=None; os.close(rel_r); rel_r=None
            self.assertEqual(read_exact(own_r,1),b"L"); os.close(own_r); own_r=None
            b,br=_spawn_call(self.db,second_route,second_raw,attempt_w=att_w); os.close(att_w); att_w=None
            self.assertEqual(read_exact(att_r,1),b"B"); os.close(att_r); att_r=None
            self.assertIsNone(b.poll()); ready,_,_=select.select([br],[],[],0); self.assertEqual(ready,[])
            os.write(rel_w,b"R"); os.close(rel_w); rel_w=None
            ad=read_frame(ar); os.close(ar); ar=None; ao,ae=a.communicate(timeout=20)
            bd=read_frame(br); os.close(br); br=None; bo,be=b.communicate(timeout=20)
            self.assertEqual((a.returncode,b.returncode,ao,bo),(0,0,b"",b""),(ae,be)); return ad,bd
        finally:
            for fd in (own_r,own_w,rel_r,rel_w,att_r,att_w,ar,br):
                if fd is not None:
                    try: os.close(fd)
                    except OSError: pass
            for p in (a,b):
                if p and p.poll() is None: p.terminate(); p.wait(timeout=5)

    def test_deterministic_begin_immediate_race_both_orders(self):
        self.enable(); reserve_raw=request("renewal.reserve","R1",payloads()["reserve"]); reserve_source=strict_json(strict_json(reserve_raw)["payload"]["sourceRequestCanonicalUtf8"].encode()); cancel_raw=request("renewal.cancel","C1",{"targetOperationId":"R1","targetRequestSha256":sha(canon(reserve_source)).hex(),"manifestSha256":unb64(reserve_source["backlogManifestSha256"]).hex()})
        first,second=self._race("renewal.cancel",cancel_raw,"renewal.reserve",reserve_raw); self._assert_success(first,"renewal.cancel"); self.assertEqual(second,error_bytes("CANCELLED_NO_RESERVATION","R1"))
        shutil.rmtree(self.td); self.td=Path(tempfile.mkdtemp(prefix="draft4-executor-")); os.chmod(self.td,0o700); self.db=self.td/"state.sqlite3"; init_db(self.db); self.enable()
        first,second=self._race("renewal.reserve",reserve_raw,"renewal.cancel",cancel_raw); self._assert_success(first,"renewal.reserve"); self.assertEqual(second,error_bytes("CANCEL_TARGET_COMMITTED","C1"))

    def _prepare_route(self, route: str) -> bytes:
        """Create prerequisites through real worker calls, never direct pending seeding."""
        if route == "capability.enable":
            return request(route,"E2",payloads()["enable"])
        self.enable()
        if route == "renewal.reserve":
            return request(route,"R2",payloads()["reserve"])
        if route == "renewal.cancel":
            target=request("renewal.reserve","TARGET",payloads()["reserve"])
            return request(route,"C2",{"targetOperationId":"TARGET",
                "targetRequestSha256":sha(target).hex(),
                "manifestSha256":sha(canon(payloads()["reserve"]["manifest"])).hex()})
        if route in ("renewal.issue","renewal.promote","telemetry.ingest","receipt.expire",
                     "lifecycle.revoke","pairing.repair","pairing.replacement"):
            reserve_raw=request("renewal.reserve","R1",payloads()["reserve"])
            reserve_response=self.c("renewal.reserve",reserve_raw)
            receipt=receipt_sha256_from_pending(reserve_response)
        if route == "renewal.issue":
            return request(route,"IS2",payloads()["issue"])
        if route == "renewal.promote":
            self.c("renewal.issue",request("renewal.issue","IS1",payloads()["issue"]))
            return request(route,"P2",payloads()["promote"])
        if route == "telemetry.ingest":
            return request(route,"IN2",telemetry_payload(receipt))
        if route == "receipt.expire":
            return request(route,"X2",{"receiptSha256":receipt})
        if route == "lifecycle.revoke":
            return request(route,"V2",{"reason":"compromise"})
        payload={"pairingLifecycleRevision":1}
        if route == "pairing.replacement":
            payload.update({"replacementInstallationId":"J","replacementCredentialId":"JC",
                            "replacementLineageId":"JL"})
        return request(route,"PAIR2",payload)

    def test_capability_db_clock_window_and_replay_order(self):
        cases=(
            ("before-issued","2030-01-01T12:01:00Z","2030-01-01T12:06:00Z"),
            ("at-expiry","2030-01-01T11:55:00Z","2030-01-01T12:00:00Z"),
            ("expired","2030-01-01T11:50:00Z","2030-01-01T11:55:00Z"),
        )
        for label,issued,expires in cases:
            with self.subTest(label=label):
                self._reset(); p=payloads()["enable"].copy(); p.update({"issuedAt":issued,"expiresAt":expires})
                raw=request("capability.enable","WINDOW",p)
                self.assertEqual(self.c("capability.enable",raw),error_bytes("CAPABILITY_NOT_CURRENT","WINDOW"))
                # Terminal replay precedes a later clock/state evaluation.
                con=secure_db(self.db); con.execute("UPDATE meta SET value='2030-01-01T12:03:00Z' WHERE key='clock'"); con.commit(); con.close()
                self.assertEqual(self.c("capability.enable",raw),error_bytes("CAPABILITY_NOT_CURRENT","WINDOW"))
        self._reset(); raw=request("capability.enable","LOWER",payloads()["enable"]); accepted=self.c("capability.enable",raw)
        con=secure_db(self.db); con.execute("UPDATE meta SET value='2030-01-01T13:00:00Z' WHERE key='clock'"); con.commit(); con.close()
        self.assertEqual(self.c("capability.enable",raw),accepted)

    def test_historical_ingest_binds_every_receipt_entry_alias(self):
        def prepared():
            self._reset(); self.setup_reserved(); return receipt_sha256_from_pending(self.reserve())
        receipt=prepared(); self._assert_success(self.c("telemetry.ingest",request("telemetry.ingest","GOOD",telemetry_payload(receipt))),"telemetry.ingest")
        for label,mutate_payload,mutate_db in (
            ("request-hash",lambda p:p.__setitem__("sourceRequestCanonicalUtf8",canon({**strict_json(p["sourceRequestCanonicalUtf8"].encode()),"extra":"x"}).decode()),None),
            ("credential",lambda p:(p.__setitem__("credentialId","OTHER"),p.__setitem__("sourceRequestCanonicalUtf8",telemetry_source("B1","OTHER",1).decode())),None),
            ("authorization-revision",lambda p:(p.__setitem__("authorizationRevision",2),p.__setitem__("sourceRequestCanonicalUtf8",telemetry_source("B1","C0",2).decode())),None),
            ("stored-length",lambda p:None,lambda con:con.execute("UPDATE receipt_entry SET request_length=request_length+1")),
        ):
            with self.subTest(alias=label):
                receipt=prepared(); p=telemetry_payload(receipt); mutate_payload(p)
                if mutate_db:
                    con=secure_db(self.db); mutate_db(con); con.commit(); con.close()
                opid="BAD-"+label; raw=request("telemetry.ingest",opid,p)
                expected=error_bytes("HISTORICAL_ENTRY_MISMATCH",opid)
                self.assertEqual(self.c("telemetry.ingest",raw),expected)
                self.assertEqual(self.c("telemetry.ingest",raw),expected)
                snap=strict_json(project(self.db)); self.assertEqual(snap["ingest_batch"],[])
                self.assertEqual(snap["receipt_entry"][0]["status"],"UNCOMMITTED")

    def test_validated_wire_vector_to_trusted_command_mapping(self):
        vectors=load_validated_vectors()
        expected={"enableRequest":"capability.enable","renewalStart":"renewal.reserve",
                  "issuedResponse":"renewal.issue","renewalAckRequest":"renewal.promote",
                  "cancelRequest":"renewal.cancel","telemetryBatch0":"telemetry.ingest"}
        for name, wanted in expected.items():
            with self.subTest(vector=name):
                route,raw=trusted_command_from_vector(name,vectors)
                self.assertEqual(route,wanted); self.assertEqual(validate_request(route,raw),strict_json(raw))
        # The transaction seam preserves exact canonical public source bytes.
        _,enable=trusted_command_from_vector("enableRequest",vectors)
        enable_payload=strict_json(enable)["payload"]
        self.assertEqual(enable_payload["sourceRequestCanonicalUtf8"],vectors["enableRequest"]["canonicalUtf8"])
        self.assertEqual(strict_json(enable_payload["sourceRequestCanonicalUtf8"].encode()),vectors["enableRequest"]["object"])

        _,reserve=trusted_command_from_vector("renewalStart",vectors)
        reserve_payload=strict_json(reserve)["payload"]
        self.assertEqual(reserve_payload["sourceRequestCanonicalUtf8"],vectors["renewalStart"]["canonicalUtf8"])
        self.assertEqual(reserve_payload["expectedReceiptCanonicalUtf8"],vectors["receipt"]["canonicalUtf8"])
        source=strict_json(reserve_payload["sourceRequestCanonicalUtf8"].encode())
        receipt=strict_json(reserve_payload["expectedReceiptCanonicalUtf8"].encode())
        self.assertEqual(len(source["backlogManifest"]["entries"]),256)
        self.assertEqual(receipt["entries"],source["backlogManifest"]["entries"])
        self.assertEqual(sha(canon(source["backlogManifest"])),unb64(source["backlogManifestSha256"]))
        self.assertEqual(sha(reserve_payload["sourceRequestCanonicalUtf8"].encode()),unb64(receipt["renewalRequestSha256"]))

    def test_capability_enable_consumes_complete_public_tuple(self):
        vectors=load_validated_vectors(); obj=vectors["enableRequest"]["object"]
        con=secure_db(self.db)
        con.execute("INSERT INTO installation VALUES(?,?,?,?,?,'ACTIVE',0,0,NULL)",(obj["installationId"],1,obj["expectedTelemetryAuthorizationRevision"],"vector-lineage",obj["currentCredentialId"]))
        con.execute("INSERT INTO credential VALUES(?,?,?,'telemetry','active',1,NULL,NULL,?,?,?)",(obj["currentCredentialId"],obj["installationId"],"vector-lineage",sha(b'vector-spki'),unb64(obj["currentCertificateSha256"]),b'vector-leaf'))
        con.commit(); con.close()
        route,raw=trusted_command_from_vector("enableRequest",vectors)
        response=self.c(route,raw); self.assertTrue(strict_json(response)["result"]["enabled"])
        snap=strict_json(project(self.db)); self.assertEqual(len(snap["capability_consumption"]),1)
        row=snap["capability_consumption"][0]
        self.assertEqual(row["raw_enable_request"]["$hex"],vectors["enableRequest"]["canonicalUtf8"].encode().hex())
        self.assertEqual(row["capability_sha256"]["$hex"],unb64(obj["capabilitySha256"]).hex())
        self.assertEqual(row["capability_server_nonce"]["$hex"],unb64(obj["capabilityServerNonce"]).hex())
        self.assertEqual(row["edge_nonce"]["$hex"],unb64(obj["edgeNonce"]).hex())
        self.assertEqual(row["protocol_id"],obj["protocolId"])
        self.assertEqual(row["expected_authorization_revision"],obj["expectedTelemetryAuthorizationRevision"])

    def test_renewal_reserve_persists_complete_manifest_receipt_closure(self):
        vectors=load_validated_vectors(); enable_obj=vectors["enableRequest"]["object"]; start=vectors["renewalStart"]["object"]
        con=secure_db(self.db)
        con.execute("UPDATE meta SET value=? WHERE key='clock'",(vectors["receipt"]["object"]["notBefore"],))
        con.execute("INSERT INTO installation VALUES(?,?,?,?,?,'ACTIVE',0,0,NULL)",(start["installationId"],start["installationRevisionBefore"],start["expectedTelemetryAuthorizationRevision"],start["lineageId"],start["oldCredentialId"]))
        con.execute("INSERT INTO credential VALUES(?,?,?,'telemetry','active',1,NULL,NULL,?,?,?)",(start["oldCredentialId"],start["installationId"],start["lineageId"],unb64(start["oldCertificateSpkiSha256"]),unb64(enable_obj["currentCertificateSha256"]),b'vector-leaf'))
        con.commit(); con.close()
        enable_route,enable_raw=trusted_command_from_vector("enableRequest",vectors); self.c(enable_route,enable_raw)
        route,raw=trusted_command_from_vector("renewalStart",vectors); response=self.c(route,raw)
        pending_response=strict_json(response); snap=strict_json(project(self.db))
        renewal=next(x for x in snap["renewal"] if x["operation_id"]==start["requestId"])
        receipt=snap["historical_receipt"][0]
        self.assertEqual(renewal["raw_manifest"]["$hex"],canon(start["backlogManifest"]).hex())
        self.assertEqual(renewal["manifest_sha256"]["$hex"],unb64(start["backlogManifestSha256"]).hex())
        self.assertEqual(receipt["raw_receipt"]["$hex"],vectors["receipt"]["canonicalUtf8"].encode().hex())
        self.assertEqual(receipt["receipt_sha256"]["$hex"],unb64(vectors["receipt"]["sha256"]).hex())
        self.assertEqual(unb64(pending_response["historicalAuthorizationReceiptSha256"]).hex(),unb64(vectors["receipt"]["sha256"]).hex())
        self.assertEqual(len(snap["receipt_entry"]),256)
        first=snap["receipt_entry"][0]; source_entry=start["backlogManifest"]["entries"][0]
        self.assertEqual(first["request_sha256"]["$hex"],unb64(source_entry["requestSha256"]).hex())
        self.assertEqual(first["batch_authorization_revision"],source_entry["batchAuthorizationRevision"])

    def test_renewal_reserve_rejects_every_detached_pending_alias_before_mutation(self):
        vectors=load_validated_vectors(); e=vectors["enableRequest"]["object"]; start=vectors["renewalStart"]["object"]
        aliases=("protocol","status","installationRevisionBefore","lineageId","oldCredentialId","newCredentialId","oldCertificateSha256","oldCertificateSpkiSha256","csrSha256","csrSpkiSha256","backlogManifestSha256","backlogMode","historicalAuthorizationReceiptSha256","telemetryAuthorizationRevisionBefore","telemetryAuthorizationRevisionAfter","issuanceExpiresAt")
        for alias in aliases:
            with self.subTest(alias=alias):
                self._reset(); con=secure_db(self.db)
                con.execute("DELETE FROM credential"); con.execute("DELETE FROM installation"); con.execute("UPDATE meta SET value=? WHERE key='clock'",(vectors["receipt"]["object"]["notBefore"],))
                con.execute("INSERT INTO installation VALUES(?,?,?,?,?,'ACTIVE',0,0,NULL)",(e["installationId"],start["installationRevisionBefore"],e["expectedTelemetryAuthorizationRevision"],start["lineageId"],e["currentCredentialId"]))
                con.execute("INSERT INTO credential VALUES(?,?,?,'telemetry','active',1,NULL,NULL,?,?,?)",(e["currentCredentialId"],e["installationId"],start["lineageId"],unb64(start["oldCertificateSpkiSha256"]),unb64(e["currentCertificateSha256"]),b"leaf"))
                con.commit(); con.close()
                route,enable=trusted_command_from_vector("enableRequest",vectors); self.c(route,enable)
                route,reserve=trusted_command_from_vector("renewalStart",vectors); outer=strict_json(reserve); pending=strict_json(outer["payload"]["expectedPendingResponseCanonicalUtf8"].encode())
                value=pending[alias]
                if type(value) is int: pending[alias]=value+1
                else: pending[alias]="detached-"+alias
                outer["payload"]["expectedPendingResponseCanonicalUtf8"]=canon(pending).decode(); raw=canon(outer)
                baseline=strict_json(project(self.db)); self.assertEqual(self.c(route,raw),error_bytes("INVALID_STATE",outer["operationId"]))
                after=strict_json(project(self.db))
                for table in ("renewal","historical_receipt","receipt_entry","credential","installation"):
                    self.assertEqual(after[table],baseline[table],f"{alias}:{table}")

    def test_renewal_cancel_rejects_detached_request_and_response_aliases_before_mutation(self):
        cases=[("request:"+x,x,None) for x in ("protocol","lineageId","currentCredentialId","currentCertificateSha256","expectedTelemetryAuthorizationRevision")]
        cases += [("response:"+x,None,x) for x in ("protocol","status","installationId","lineageId","currentCredentialId","currentCertificateSha256","telemetryAuthorizationRevision","decidedAt","targetRenewalRequestSha256","backlogManifestSha256")]
        for label,source_alias,response_alias in cases:
            with self.subTest(alias=label):
                self._reset(); self.c("capability.enable",request("capability.enable","E1",payloads()["enable"]))
                cfg={"targetOperationId":"R-never","targetRequestSha256":sha(b"target").hex(),"manifestSha256":sha(b"manifest").hex()}; p=synthetic_cancel_payload("K1",cfg,"I")
                source=strict_json(p["sourceRequestCanonicalUtf8"].encode()); response=strict_json(p["expectedResponseCanonicalUtf8"].encode())
                alias=source_alias or response_alias; obj=source if source_alias else response; value=obj[alias]
                if type(value) is int: obj[alias]=value+1
                else: obj[alias]="detached-"+alias
                if source_alias:
                    p["sourceRequestCanonicalUtf8"]=canon(source).decode(); response["cancelRequestSha256"]=b64u(sha(canon(source)))
                p["expectedResponseCanonicalUtf8"]=canon(response).decode(); raw=request("renewal.cancel","K1",p)
                baseline=strict_json(project(self.db)); self.assertEqual(self.c("renewal.cancel",raw),error_bytes("INVALID_STATE","K1"))
                after=strict_json(project(self.db))
                for table in ("cancel_tombstone","renewal","credential","installation"):
                    self.assertEqual(after[table],baseline[table],f"{label}:{table}")

    def test_renewal_issue_rejects_every_detached_context_alias_before_mutation(self):
        vectors=load_validated_vectors(); e=vectors["enableRequest"]["object"]; start=vectors["renewalStart"]["object"]
        aliases=("requestId","installationId","installationRevisionBefore","lineageId","oldCredentialId","newCredentialId","oldCertificateSha256","oldCertificateSpkiSha256","csrSha256","csrSpkiSha256","backlogManifestSha256","backlogMode","historicalAuthorizationReceipt","historicalAuthorizationReceiptSha256","telemetryAuthorizationRevisionBefore","telemetryAuthorizationRevisionAfter")
        for alias in aliases:
            with self.subTest(alias=alias):
                self._reset(); con=secure_db(self.db)
                con.execute("DELETE FROM credential"); con.execute("DELETE FROM installation"); con.execute("UPDATE meta SET value=? WHERE key='clock'",(vectors["receipt"]["object"]["notBefore"],))
                con.execute("INSERT INTO installation VALUES(?,?,?,?,?,'ACTIVE',0,0,NULL)",(e["installationId"],start["installationRevisionBefore"],e["expectedTelemetryAuthorizationRevision"],start["lineageId"],e["currentCredentialId"]))
                con.execute("INSERT INTO credential VALUES(?,?,?,'telemetry','active',1,NULL,NULL,?,?,?)",(e["currentCredentialId"],e["installationId"],start["lineageId"],unb64(start["oldCertificateSpkiSha256"]),unb64(e["currentCertificateSha256"]),b"leaf"))
                con.commit(); con.close()
                for name in ("enableRequest","renewalStart"):
                    route,raw=trusted_command_from_vector(name,vectors); self.c(route,raw)
                baseline=strict_json(project(self.db)); issued=strict_json(canon(vectors["issuedResponse"]["object"]))
                value=issued[alias]
                if type(value) is int: issued[alias]=value+1
                elif type(value) is dict: issued[alias]={}
                else: issued[alias]="detached-"+alias
                original_rid=vectors["issuedResponse"]["object"]["requestId"]; opid="trusted-issue:"+original_rid
                raw=request("renewal.issue",opid,{"sourceResponseCanonicalUtf8":canon(issued).decode()},e["installationId"])
                validate_request("renewal.issue",raw)
                self.assertEqual(self.c("renewal.issue",raw),error_bytes("INVALID_STATE",opid))
                after=strict_json(project(self.db))
                for table in ("renewal","credential","issued_certificate"):
                    self.assertEqual(after[table],baseline[table],f"{alias}:{table}")
                self.assertFalse(any(row["raw_issued_response"] is not None for row in after["renewal"]))

    def test_public_pending_issued_ack_wire_is_durable_terminal_authority(self):
        vectors=load_validated_vectors(); e=vectors["enableRequest"]["object"]
        con=secure_db(self.db)
        con.execute("UPDATE meta SET value=? WHERE key='clock'",(vectors["receipt"]["object"]["notBefore"],))
        start=vectors["renewalStart"]["object"]
        con.execute("INSERT INTO installation VALUES(?,?,?,?,?,'ACTIVE',0,0,NULL)",(e["installationId"],start["installationRevisionBefore"],e["expectedTelemetryAuthorizationRevision"],start["lineageId"],e["currentCredentialId"]))
        con.execute("INSERT INTO credential VALUES(?,?,?,'telemetry','active',1,NULL,NULL,?,?,?)",(e["currentCredentialId"],e["installationId"],vectors["renewalStart"]["object"]["lineageId"],unb64(vectors["renewalStart"]["object"]["oldCertificateSpkiSha256"]),unb64(e["currentCertificateSha256"]),b"leaf"))
        con.commit(); con.close()
        for name in ("enableRequest","renewalStart","issuedResponse","renewalAckRequest"):
            route,raw=trusted_command_from_vector(name,vectors)
            response=self.c(route,raw)
            expected={"renewalStart":"pendingResponse","issuedResponse":"issuedResponse","renewalAckRequest":"renewalAckResponse"}.get(name)
            if expected: self.assertEqual(response,vector_raw(vectors[expected]))
        snap=strict_json(project(self.db)); renewal=next(x for x in snap["renewal"] if x["operation_id"]==vectors["renewalStart"]["object"]["requestId"])
        self.assertEqual(renewal["pending_response_sha256"]["$hex"],sha(vector_raw(vectors["pendingResponse"])).hex())
        self.assertEqual(renewal["raw_pending_response"]["$hex"],vector_raw(vectors["pendingResponse"]).hex())
        self.assertEqual(renewal["raw_issued_response"]["$hex"],vector_raw(vectors["issuedResponse"]).hex())
        self.assertEqual(renewal["issued_response_sha256"]["$hex"],sha(vector_raw(vectors["issuedResponse"])).hex())
        self.assertEqual(snap["issued_certificate"][0]["issuer_der_sha256"]["$hex"],sha(_pem_der(vectors["issuedResponse"]["object"]["caChainPem"])).hex())
        self.assertEqual(snap["proof_consumption"][0]["raw_proof"]["$hex"],vector_raw(vectors["renewalAckRequest"]).hex())

    def test_renewal_promote_rejects_every_detached_ack_alias_before_mutation(self):
        request_aliases=("protocol","requestId","renewalRequestSha256","renewalIssuedResponseSha256","installationId","lineageId","installationRevisionBefore","oldCredentialId","oldCertificateSha256","oldCertificateSpkiSha256","newCredentialId","newCertificateSha256","newCertificateSpkiSha256","csrSha256","csrSpkiSha256","telemetryAuthorizationRevisionBefore","telemetryAuthorizationRevisionAfter","backlogMode","backlogManifestSha256","historicalAuthorizationReceiptSha256")
        response_aliases=("protocol","status","requestId","renewalRequestSha256","renewalIssuedResponseSha256","installationId","lineageId","installationRevisionBefore","installationRevisionAfter","oldCredentialId","oldCertificateSha256","oldCertificateSpkiSha256","newCredentialId","newCertificateSha256","newCertificateSpkiSha256","csrSha256","csrSpkiSha256","telemetryAuthorizationRevisionBefore","telemetryAuthorizationRevisionAfter","backlogMode","backlogManifestSha256","historicalAuthorizationReceiptSha256")
        authority=("installation","credential","renewal","historical_receipt","receipt_entry","issued_certificate","proof_consumption")
        def detached(key,value):
            if type(value) is int: return value+7
            if key=="protocol": return "2.1"
            if key=="status": return "detached"
            if key=="backlogMode": return "none"
            if key.endswith("Sha256"): return b64u(sha(("detached:"+key).encode()))
            return "detached-"+key
        for carrier,aliases in (("sourceRequestCanonicalUtf8",request_aliases),("expectedResponseCanonicalUtf8",response_aliases)):
            for alias in aliases:
                with self.subTest(carrier=carrier,alias=alias):
                    self._reset(); self.setup_reserved(); self.c("renewal.issue",request("renewal.issue","IS1",payloads()["issue"]))
                    payload=synthetic_promote_payload(payloads()["promote"],"I")
                    obj=strict_json(payload[carrier].encode()); obj[alias]=detached(alias,obj[alias]); payload[carrier]=canon(obj).decode()
                    if alias in ("requestId","installationId"):
                        peer="expectedResponseCanonicalUtf8" if carrier=="sourceRequestCanonicalUtf8" else "sourceRequestCanonicalUtf8"
                        peer_obj=strict_json(payload[peer].encode()); peer_obj[alias]=obj[alias]; payload[peer]=canon(peer_obj).decode()
                    opid="PROMOTE-DETACHED-"+carrier[0]+"-"+alias
                    raw=request("renewal.promote",opid,payload); validate_request("renewal.promote",raw)
                    before=strict_json(project(self.db)); expected=error_bytes("INVALID_STATE",opid)
                    self.assertEqual(self.c("renewal.promote",raw),expected)
                    self.assertEqual(self.c("renewal.promote",raw),expected)
                    after=strict_json(project(self.db))
                    for table in authority: self.assertEqual(after[table],before[table],f"{carrier}:{alias}:{table}")

    def test_reserve_receipt_window_binds_db_clock_before_mutation(self):
        self.enable(); p=synthetic_reserve_payload("R1",payloads()["reserve"],"I"); receipt=strict_json(p["expectedReceiptCanonicalUtf8"].encode()); pending=strict_json(p["expectedPendingResponseCanonicalUtf8"].encode())
        receipt["notBefore"]="2031-01-01T00:00:00Z"; receipt["expiresAt"]="2031-01-02T00:00:00Z"; pending["historicalAuthorizationReceipt"]=receipt; pending["historicalAuthorizationReceiptSha256"]=b64u(sha(canon(receipt)))
        p["expectedReceiptCanonicalUtf8"]=canon(receipt).decode(); p["expectedPendingResponseCanonicalUtf8"]=canon(pending).decode(); raw=request("renewal.reserve","R1",p)
        baseline=strict_json(project(self.db)); self.assertEqual(self.c("renewal.reserve",raw),error_bytes("INVALID_STATE","R1")); after=strict_json(project(self.db))
        for table in ("renewal","historical_receipt","receipt_entry","credential","installation"): self.assertEqual(after[table],baseline[table],table)

    def test_issue_and_promote_expiry_precede_every_mutation(self):
        self.setup_reserved(); con=secure_db(self.db); con.execute("UPDATE meta SET value='2031-01-01T00:00:00Z' WHERE key='clock'"); con.commit(); con.close(); baseline=strict_json(project(self.db))
        self.assertEqual(self.c("renewal.issue",request("renewal.issue","EXPIRED-ISSUE",payloads()["issue"])),error_bytes("ACK_EXPIRED","EXPIRED-ISSUE")); after=strict_json(project(self.db))
        for table in ("renewal","credential","installation","issued_certificate","proof_consumption"): self.assertEqual(after[table],baseline[table],table)
        self._reset(); self.setup_reserved(); self.c("renewal.issue",request("renewal.issue","IS1",payloads()["issue"])); con=secure_db(self.db); con.execute("UPDATE meta SET value='2031-01-01T00:00:00Z' WHERE key='clock'"); con.commit(); con.close(); baseline=strict_json(project(self.db))
        self.assertEqual(self.c("renewal.promote",request("renewal.promote","EXPIRED-ACK",payloads()["promote"])),error_bytes("ACK_EXPIRED","EXPIRED-ACK")); after=strict_json(project(self.db))
        for table in ("renewal","credential","installation","issued_certificate","proof_consumption"): self.assertEqual(after[table],baseline[table],table)

    def test_public_replay_identity_survives_new_internal_invocation_id(self):
        self.setup_reserved()
        issued_payload=synthetic_issue_payload(payloads()["issue"],"I")
        first_issue=request("renewal.issue","ISSUE-INTERNAL-1",issued_payload); issued_response=self.c("renewal.issue",first_issue)
        second_issue=request("renewal.issue","ISSUE-INTERNAL-2",issued_payload)
        self.assertEqual(self.c("renewal.issue",second_issue),issued_response)
        self.c("lifecycle.revoke",request("lifecycle.revoke","REVOKE-AFTER-ISSUE",{"reason":"test"}))
        third_issue=request("renewal.issue","ISSUE-INTERNAL-3",issued_payload)
        self.assertEqual(self.c("renewal.issue",third_issue),issued_response)
        foreign=strict_json(third_issue); foreign["operationId"]="ISSUE-INTERNAL-FOREIGN"; foreign["installationId"]="FOREIGN-INSTALLATION"
        self.assertEqual(self.c("renewal.issue",canon(foreign)),error_bytes("INVALID_STATE","ISSUE-INTERNAL-FOREIGN"))
        self._reset(); self.setup_reserved(); self.c("renewal.issue",first_issue)
        promote_payload=synthetic_promote_payload(payloads()["promote"],"I")
        first_ack=request("renewal.promote","ACK-INTERNAL-1",promote_payload); ack_response=self.c("renewal.promote",first_ack)
        second_ack=request("renewal.promote","ACK-INTERNAL-2",promote_payload)
        self.assertEqual(self.c("renewal.promote",second_ack),ack_response)
        foreign_ack=strict_json(second_ack); foreign_ack["operationId"]="ACK-INTERNAL-FOREIGN"; foreign_ack["installationId"]="FOREIGN-INSTALLATION"
        self.assertEqual(self.c("renewal.promote",canon(foreign_ack)),error_bytes("INVALID_STATE","ACK-INTERNAL-FOREIGN"))
        snap=strict_json(project(self.db)); renewal=next(x for x in snap["renewal"] if x["operation_id"]=="R1")
        self.assertEqual(next(x for x in snap["renewal"] if x["operation_id"]=="R1")["state"],"acked")

    def test_public_cancel_wire_is_durable_terminal_authority(self):
        vectors=load_validated_vectors(); e=vectors["enableRequest"]["object"]; start=vectors["renewalStart"]["object"]
        con=secure_db(self.db); con.execute("UPDATE meta SET value=? WHERE key='clock'",(vectors["cancelResponse"]["object"]["decidedAt"],)); con.execute("INSERT INTO installation VALUES(?,?,?,?,?,'ACTIVE',0,0,NULL)",(e["installationId"],start["installationRevisionBefore"],e["expectedTelemetryAuthorizationRevision"],start["lineageId"],e["currentCredentialId"])); con.execute("INSERT INTO credential VALUES(?,?,?,'telemetry','active',1,NULL,NULL,?,?,?)",(e["currentCredentialId"],e["installationId"],start["lineageId"],unb64(start["oldCertificateSpkiSha256"]),unb64(e["currentCertificateSha256"]),b"leaf")); con.commit(); con.close()
        route,raw=trusted_command_from_vector("enableRequest",vectors); self.c(route,raw)
        route,raw=trusted_command_from_vector("cancelRequest",vectors); response=self.c(route,raw)
        self.assertEqual(response,vector_raw(vectors["cancelResponse"])); self.assertEqual(self.c(route,raw),response)
        self.assertEqual(strict_json(project(self.db))["cancel_tombstone"][0]["raw_tombstone"]["$hex"],vector_raw(vectors["cancelRequest"]).hex())

    def test_historical_ingest_time_transport_and_public_identity_precedence(self):
        pending=strict_json(self.setup_reserved()); receipt=unb64(pending["historicalAuthorizationReceiptSha256"]).hex()
        raw=request("telemetry.ingest","LATE",telemetry_payload(receipt))
        con=secure_db(self.db); con.execute("UPDATE meta SET value='2030-01-02T12:00:00Z' WHERE key='clock'"); con.commit(); con.close()
        self.assertEqual(self.c("telemetry.ingest",raw),error_bytes("HISTORICAL_RECEIPT_CLOSED","LATE"))
        self._reset(); pending=strict_json(self.setup_reserved()); receipt=unb64(pending["historicalAuthorizationReceiptSha256"]).hex()
        denied=telemetry_payload(receipt); denied["presentedTransportCredentialId"]="UNAUTHORIZED"
        self.assertEqual(self.c("telemetry.ingest",request("telemetry.ingest","DENIED",denied)),error_bytes("HISTORICAL_TRANSPORT_UNAUTHORIZED","DENIED"))
        first=request("telemetry.ingest","FIRST",telemetry_payload(receipt)); ack=self.c("telemetry.ingest",first)
        replay_obj=strict_json(first); replay_obj["operationId"]="REPLAY"
        self.assertEqual(self.c("telemetry.ingest",canon(replay_obj)),ack)
        conflict_obj=strict_json(first); conflict_obj["operationId"]="CONFLICT"; source=strict_json(conflict_obj["payload"]["sourceRequestCanonicalUtf8"].encode()); source["credentialId"]="C1"; conflict_obj["payload"]["credentialId"]="C1"; conflict_obj["payload"]["sourceRequestCanonicalUtf8"]=canon(source).decode()
        conflict_raw=canon(conflict_obj); conflict_response=self.c("telemetry.ingest",conflict_raw)
        self.assertEqual(strict_json(conflict_response),{"schemaVersion":"one-os-telemetry-error/v2","batchId":"B1","code":"immutable_identity_conflict","decidedAt":"2030-01-01T12:00:00Z","requestSha256":b64u(sha(canon(source))),"retryClass":"terminal_quarantine"})
        self.assertEqual(len(strict_json(project(self.db))["immutable_identity_conflict"]),1)

    def test_all_implemented_precommit_failpoints_per_route(self):
        self.assertEqual(set(ROUTE_PRECOMMIT),ROUTES)
        for route in sorted(ROUTES):
            self._reset(); raw=self._prepare_route(route); baseline=project(self.db)
            for point in GENERIC_PRECOMMIT + ROUTE_PRECOMMIT[route]:
                with self.subTest(route=route, crashpoint=point):
                    rc,data,out,err=call(self.db,route,raw,point)
                    self.assertEqual((rc,data,out),(EXIT_CRASH,b"",b""),err)
                    self.assertEqual(project(self.db),baseline)

    def test_postcommit_response_loss_exact_stored_replay_per_route(self):
        for route in sorted(ROUTES):
            with self.subTest(route=route):
                self._reset(); raw=self._prepare_route(route)
                rc,data,out,err=call(self.db,route,raw,"after_commit_before_delivery")
                self.assertEqual((rc,data,out),(EXIT_CRASH,b"",b""),err)
                replay=self.c(route,raw); snap=strict_json(project(self.db))
                opid=strict_json(raw)["operationId"]
                row=next(x for x in snap["operation"] if x["operation_id"]==opid)
                self.assertEqual(replay.hex(),row["raw_response"]["$hex"])
                self.assertEqual(sha(replay).hex(),row["response_sha256"]["$hex"])

    def test_revision_saturation_precedes_every_mutation(self):
        for route in ("renewal.reserve","lifecycle.revoke","pairing.repair","pairing.replacement"):
            with self.subTest(route=route):
                self._reset(); self.enable()
                con=secure_db(self.db); con.execute("UPDATE installation SET telemetry_authorization_revision=?",(MAX_I64,)); con.commit(); con.close()
                if route=="renewal.reserve":
                    raw=request(route,"SAT",payloads()["reserve"])
                elif route=="lifecycle.revoke": raw=request(route,"SAT",{"reason":"compromise"})
                else:
                    p={"pairingLifecycleRevision":1}
                    if route.endswith("replacement"): p.update({"replacementInstallationId":"J","replacementCredentialId":"JC","replacementLineageId":"JL"})
                    raw=request(route,"SAT",p)
                response=self.c(route,raw); self.assertEqual(response,error_bytes("REVISION_SATURATED","SAT"))
                snap=strict_json(project(self.db)); self.assertEqual(snap["installation"][0]["telemetry_authorization_revision"],MAX_I64)
                self.assertEqual(snap["pairing_lifecycle_event"],[])
        self._reset(); self.setup_reserved(); self.c("renewal.issue",request("renewal.issue","IS1",payloads()["issue"]))
        con=secure_db(self.db); con.execute("UPDATE installation SET lifecycle_revision=?",(MAX_I64,)); con.commit(); con.close()
        response=self.c("renewal.promote",request("renewal.promote","SATP",payloads()["promote"]))
        self.assertEqual(response,error_bytes("REVISION_SATURATED","SATP"))
        snap=strict_json(project(self.db)); self.assertEqual(snap["proof_consumption"],[])
        self.assertEqual(snap["installation"][0]["current_credential_id"],"C0")

    def _assert_success(self, raw: bytes, route: str) -> None:
        obj=strict_json(raw)
        if "route" in obj:
            self.assertEqual(obj["route"],route); return
        if route=="renewal.reserve": self.assertEqual(obj["status"],"pending")
        elif route=="renewal.issue": self.assertEqual(obj["status"],"issued")
        elif route=="renewal.promote": self.assertEqual(obj["status"],"acked")
        elif route=="renewal.cancel": self.assertEqual(obj["status"],"cancelled_no_reservation")
        elif route=="telemetry.ingest":
            self.assertEqual(set(obj),{"schemaVersion","authorizationMode","installationId","credentialId","batchId","batchAuthorizationRevision","ingestAuthorizationRevision","requestSha256","acceptedSamples","duplicateSamples","acceptedQualityEvents","duplicateQualityEvents","acceptedGaps","duplicateGaps","ingestCursor","acceptedAt","historicalAuthorizationReceiptSha256"})
            self.assertEqual((obj["schemaVersion"],obj["authorizationMode"]),("one-os-telemetry-ack/v2","historical_backlog"))
        else: self.fail(f"unexpected public success for {route}: {obj}")

    def test_revoke_races_reserve_issue_promote_both_commit_orders(self):
        for operation in ("renewal.reserve","renewal.issue","renewal.promote"):
            for terminal_first in (True,False):
                with self.subTest(operation=operation,terminal_first=terminal_first):
                    self._reset(); op_raw=self._prepare_route(operation)
                    revoke=request("lifecycle.revoke","RV",{"reason":"compromise"})
                    if terminal_first:
                        a,b=self._race("lifecycle.revoke",revoke,operation,op_raw)
                        self._assert_success(a,"lifecycle.revoke")
                        self.assertEqual(b,error_bytes("SUPERSEDED_BY_REVOKE",strict_json(op_raw)["operationId"]))
                    else:
                        a,b=self._race(operation,op_raw,"lifecycle.revoke",revoke)
                        self._assert_success(a,operation); self._assert_success(b,"lifecycle.revoke")
                    snap=strict_json(project(self.db)); self.assertEqual(snap["installation"][0]["lifecycle_state"],"REVOKED")

    def test_ingest_races_expiry_and_revoke_both_commit_orders(self):
        for terminal in ("receipt.expire","lifecycle.revoke"):
            for terminal_first in (True,False):
                with self.subTest(terminal=terminal,terminal_first=terminal_first):
                    self._reset(); ingest=self._prepare_route("telemetry.ingest")
                    receipt=strict_json(ingest)["payload"]["receiptSha256"]
                    other=(request("receipt.expire","TERM",{"receiptSha256":receipt}) if terminal=="receipt.expire"
                           else request("lifecycle.revoke","TERM",{"reason":"compromise"}))
                    if terminal_first:
                        a,b=self._race(terminal,other,"telemetry.ingest",ingest)
                        self._assert_success(a,terminal)
                        self.assertEqual(b,error_bytes("HISTORICAL_RECEIPT_CLOSED","IN2"))
                    else:
                        a,b=self._race("telemetry.ingest",ingest,terminal,other)
                        self._assert_success(a,"telemetry.ingest")
                        if terminal=="receipt.expire": self.assertEqual(b,error_bytes("HISTORICAL_RECEIPT_CLOSED","TERM"))
                        else: self._assert_success(b,terminal)

    def test_pairing_hooks_require_exact_lifecycle_revision_before_every_mutation(self):
        authority_tables=("installation","credential","historical_receipt","receipt_entry","renewal","issued_certificate","pairing_lifecycle_event")
        for route in ("pairing.repair","pairing.replacement"):
            with self.subTest(route=route):
                self._reset(); self._prepare_route("renewal.promote")
                before=strict_json(project(self.db)); before={k:before[k] for k in authority_tables}
                p={"pairingLifecycleRevision":MAX_I64}
                if route.endswith("replacement"): p.update({"replacementInstallationId":"J","replacementCredentialId":"JC","replacementLineageId":"JL"})
                raw=request(route,"PAIR-CAS",p); expected=error_bytes("INVALID_STATE","PAIR-CAS")
                self.assertEqual(self.c(route,raw),expected)
                self.assertEqual(self.c(route,raw),expected)
                after=strict_json(project(self.db)); after={k:after[k] for k in authority_tables}
                self.assertEqual(after,before)

    def test_repair_replacement_hooks_vs_promote_both_commit_orders(self):
        for hook,code in (("pairing.repair","SUPERSEDED_BY_REPAIR"),
                          ("pairing.replacement","SUPERSEDED_BY_REPLACEMENT")):
            for hook_first in (True,False):
                with self.subTest(hook=hook,hook_first=hook_first):
                    self._reset(); promote=self._prepare_route("renewal.promote")
                    p={"pairingLifecycleRevision":1}
                    if hook.endswith("replacement"): p.update({"replacementInstallationId":"J","replacementCredentialId":"JC","replacementLineageId":"JL"})
                    hook_raw=request(hook,"HOOK",p)
                    if hook_first:
                        a,b=self._race(hook,hook_raw,"renewal.promote",promote)
                        self._assert_success(a,hook); self.assertEqual(b,error_bytes(code,"P2"))
                    else:
                        a,b=self._race("renewal.promote",promote,hook,hook_raw)
                        self._assert_success(a,"renewal.promote")
                        self.assertEqual(b,error_bytes("INVALID_STATE","HOOK"))
                    snap=strict_json(project(self.db)); self.assertEqual(len(snap["pairing_lifecycle_event"]),1 if hook_first else 0)


def main() -> int:
    ap=argparse.ArgumentParser(); sub=ap.add_subparsers(dest="cmd",required=True)
    w=sub.add_parser("durable-worker"); w.add_argument("--db",required=True); w.add_argument("--route",required=True); w.add_argument("--request-fd",type=int,required=True); w.add_argument("--result-fd",type=int,required=True); w.add_argument("--lock-owned-fd",type=int); w.add_argument("--lock-release-fd",type=int); w.add_argument("--begin-attempt-fd",type=int); w.add_argument("--crashpoint")
    p=sub.add_parser("projection-worker"); p.add_argument("--db",required=True); p.add_argument("--result-fd",type=int,required=True)
    sub.add_parser("self-test")
    args=ap.parse_args()
    if args.cmd=="durable-worker": return durable_worker(args)
    if args.cmd=="projection-worker": return projection_worker(Path(args.db),args.result_fd)
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(Draft4Tests); result=unittest.TextTestRunner(verbosity=2).run(suite); return 0 if result.wasSuccessful() else 1

if __name__=="__main__": raise SystemExit(main())
