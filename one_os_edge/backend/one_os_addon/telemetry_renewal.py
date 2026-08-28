from __future__ import annotations

import base64
import hashlib
import hmac
import json
import struct
from datetime import UTC, datetime
from typing import Any, Protocol
from uuid import UUID, uuid4

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
)
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, NameOID
from sqlalchemy import select, text

from .models import (
    EdgeIdentity,
    TelemetryAuthorityActivation,
    TelemetryAuthorityCut,
    TelemetryBatch,
    TelemetryJournalState,
    TelemetryRenewalOperation,
)
from .pairing_storage import IdentityStore
from .telemetry_contract_v2 import (
    canonical_json,
    parse_backlog_manifest,
    parse_historical_receipt,
)

_MAX_INT64 = 9_223_372_036_854_775_807
_START_FIELDS = {
    "protocol",
    "requestId",
    "installationId",
    "lineageId",
    "oldCredentialId",
    "oldCertificateSha256",
    "oldCertificateSpkiSha256",
    "pendingCredentialId",
    "csrDer",
    "csrSha256",
    "csrSpkiSha256",
    "edgeNonce",
    "epochMinute",
    "installationRevisionBefore",
    "expectedTelemetryAuthorizationRevision",
    "backlogMode",
    "backlogManifest",
    "backlogManifestSha256",
    "signature",
}
_PENDING_FIELDS = {
    "protocol",
    "requestId",
    "installationId",
    "lineageId",
    "installationRevisionBefore",
    "telemetryAuthorizationRevisionBefore",
    "telemetryAuthorizationRevisionAfter",
    "backlogMode",
    "backlogManifestSha256",
    "oldCredentialId",
    "oldCertificateSha256",
    "oldCertificateSpkiSha256",
    "newCredentialId",
    "csrSha256",
    "csrSpkiSha256",
    "historicalAuthorizationReceipt",
    "historicalAuthorizationReceiptSha256",
    "issuanceExpiresAt",
    "status",
}
_HISTORICAL_RECEIPT_FIELDS = {
    "historicalAuthorizationReceipt",
    "historicalAuthorizationReceiptSha256",
}
_PENDING_NONE_FIELDS = _PENDING_FIELDS - _HISTORICAL_RECEIPT_FIELDS
_ISSUED_FIELDS = (_PENDING_FIELDS - {"issuanceExpiresAt"}) | {
    "ackExpiresAt",
    "certificatePem",
    "caChainPem",
    "newCertificateSha256",
    "newCertificateSpkiSha256",
}
_ISSUED_NONE_FIELDS = _ISSUED_FIELDS - _HISTORICAL_RECEIPT_FIELDS
_ACK_FIELDS = {
    "protocol",
    "requestId",
    "installationId",
    "lineageId",
    "installationRevisionBefore",
    "telemetryAuthorizationRevisionBefore",
    "telemetryAuthorizationRevisionAfter",
    "backlogMode",
    "backlogManifestSha256",
    "oldCredentialId",
    "oldCertificateSha256",
    "oldCertificateSpkiSha256",
    "newCredentialId",
    "csrSha256",
    "csrSpkiSha256",
    "renewalRequestSha256",
    "renewalIssuedResponseSha256",
    "newCertificateSha256",
    "newCertificateSpkiSha256",
    "historicalAuthorizationReceiptSha256",
    "signature",
}
_ACK_RESPONSE_FIELDS = (_ACK_FIELDS - {"signature"}) | {"installationRevisionAfter", "status"}
_ACK_NONE_FIELDS = _ACK_FIELDS - {"historicalAuthorizationReceiptSha256"}
_ACK_NONE_RESPONSE_FIELDS = (_ACK_NONE_FIELDS - {"signature"}) | {
    "installationRevisionAfter",
    "status",
}
_P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_CANCEL_FIELDS = {
    "protocol",
    "cancelRequestId",
    "targetRequestId",
    "installationId",
    "lineageId",
    "currentCredentialId",
    "currentCertificateSha256",
    "targetRenewalRequestSha256",
    "backlogManifestSha256",
    "expectedTelemetryAuthorizationRevision",
    "edgeNonce",
    "signature",
}
_CANCEL_RESPONSE_FIELDS = {
    "protocol",
    "cancelRequestId",
    "cancelRequestSha256",
    "targetRequestId",
    "targetRenewalRequestSha256",
    "backlogManifestSha256",
    "installationId",
    "lineageId",
    "telemetryAuthorizationRevision",
    "currentCredentialId",
    "currentCertificateSha256",
    "status",
    "decidedAt",
}


class TelemetryRenewalError(RuntimeError):
    pass


class TelemetryRenewalClient(Protocol):
    def start_renewal_v2(
        self, request_bytes: bytes, certificate_pem: str, private_key_pem: str
    ) -> bytes: ...

    def renewal_status_v2(
        self, request_id: str, certificate_pem: str, private_key_pem: str
    ) -> bytes: ...

    def ack_renewal_v2(
        self,
        request_id: str,
        request_bytes: bytes,
        certificate_pem: str,
        private_key_pem: str,
    ) -> bytes: ...

    def cancel_renewal_v2(
        self,
        request_id: str,
        request_bytes: bytes,
        certificate_pem: str,
        private_key_pem: str,
    ) -> bytes: ...

    def cancel_status_v2(
        self, cancel_request_id: str, certificate_pem: str, private_key_pem: str
    ) -> bytes: ...


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _unb64(value: Any, length: int = 32) -> bytes:
    if not isinstance(value, str):
        raise TelemetryRenewalError("invalid_base64url")
    try:
        raw = base64.b64decode(
            value + "=" * ((4 - len(value) % 4) % 4), altchars=b"-_", validate=True
        )
    except ValueError:
        raise TelemetryRenewalError("invalid_base64url") from None
    if len(raw) != length or not hmac.compare_digest(_b64(raw), value):
        raise TelemetryRenewalError("invalid_base64url")
    return raw


def _framed(domain: str, values: list[bytes]) -> bytes:
    return (
        domain.encode("ascii")
        + b"\0"
        + b"".join(
            struct.pack(">HI", index, len(value)) + value for index, value in enumerate(values, 1)
        )
    )


def build_start_preimage(value: dict[str, Any]) -> bytes:
    return _framed(
        "ONE.OS-DEVICE-RENEW-V2",
        [
            value["protocol"].encode(),
            UUID(value["installationId"]).bytes,
            UUID(value["oldCredentialId"]).bytes,
            _unb64(value["oldCertificateSha256"]),
            UUID(value["requestId"]).bytes,
            _unb64(value["csrSha256"]),
            _unb64(value["csrSpkiSha256"]),
            _unb64(value["edgeNonce"]),
            value["epochMinute"].to_bytes(8, "big"),
            value["installationRevisionBefore"].to_bytes(8, "big"),
            value["expectedTelemetryAuthorizationRevision"].to_bytes(8, "big"),
            value["backlogMode"].encode(),
            _unb64(value["backlogManifestSha256"]),
        ],
    )


def build_cancel_preimage(value: dict[str, Any]) -> bytes:
    return _framed(
        "ONE.OS-DEVICE-RENEW-CANCEL-V2",
        [
            value["protocol"].encode(),
            UUID(value["cancelRequestId"]).bytes,
            UUID(value["targetRequestId"]).bytes,
            UUID(value["installationId"]).bytes,
            UUID(value["lineageId"]).bytes,
            UUID(value["currentCredentialId"]).bytes,
            _unb64(value["currentCertificateSha256"]),
            _unb64(value["targetRenewalRequestSha256"]),
            _unb64(value["backlogManifestSha256"]),
            value["expectedTelemetryAuthorizationRevision"].to_bytes(8, "big"),
            _unb64(value["edgeNonce"]),
        ],
    )


def build_ack_preimage(value: dict[str, Any]) -> bytes:
    digest_names = (
        "renewalRequestSha256",
        "renewalIssuedResponseSha256",
        "oldCertificateSha256",
        "oldCertificateSpkiSha256",
        "newCertificateSha256",
        "newCertificateSpkiSha256",
        "csrSha256",
        "csrSpkiSha256",
        "backlogManifestSha256",
    )
    values = [
        value["protocol"].encode(),
        UUID(value["requestId"]).bytes,
        UUID(value["installationId"]).bytes,
        UUID(value["lineageId"]).bytes,
        value["installationRevisionBefore"].to_bytes(8, "big"),
        UUID(value["oldCredentialId"]).bytes,
        UUID(value["newCredentialId"]).bytes,
        *(_unb64(value[name]) for name in digest_names),
        value["telemetryAuthorizationRevisionBefore"].to_bytes(8, "big"),
        value["telemetryAuthorizationRevisionAfter"].to_bytes(8, "big"),
        value["backlogMode"].encode(),
    ]
    if value["backlogMode"] == "historical":
        values.append(_unb64(value["historicalAuthorizationReceiptSha256"]))
    elif value["backlogMode"] != "none" or "historicalAuthorizationReceiptSha256" in value:
        raise TelemetryRenewalError("ack_request_conflict")
    return _framed("ONE.OS-DEVICE-RENEW-ACK-V2", values)


def _document(raw: bytes, fields: set[str], maximum: int) -> dict[str, Any]:
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= maximum:
        raise TelemetryRenewalError("invalid_wire")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise TelemetryRenewalError("duplicate_json_member")
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique)
    except (UnicodeError, ValueError, json.JSONDecodeError):
        raise TelemetryRenewalError("invalid_wire") from None
    if type(value) is not dict or set(value) != fields or canonical_json(value) != raw:
        raise TelemetryRenewalError("invalid_wire")
    return value


def _timestamp_seconds(value: Any) -> datetime:
    if not isinstance(value, str) or len(value) != 20 or not value.endswith("Z"):
        raise TelemetryRenewalError("invalid_timestamp")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError:
        raise TelemetryRenewalError("invalid_timestamp") from None


def _begin(session) -> str:
    dialect = session.get_bind().dialect.name
    if dialect == "sqlite":
        session.execute(text("BEGIN IMMEDIATE"))
    return dialect


def _locked(statement, dialect: str):
    return statement.with_for_update() if dialect == "postgresql" else statement


class TelemetryRenewalManager:
    """Durable, explicit-trigger Draft-4 start/pending/cancel operation foundation."""

    def __init__(
        self,
        session_factory,
        store: IdentityStore,
        client: TelemetryRenewalClient,
        identity_provider,
        signer,
        *,
        uuid_factory=lambda: str(uuid4()),
        nonce_factory=lambda: __import__("secrets").token_bytes(32),
        clock=lambda: datetime.now(UTC),
        reactivate=None,
    ) -> None:
        self._session_factory = session_factory
        self._store = store
        self._client = client
        self._identity_provider = identity_provider
        self._signer = signer
        self._uuid_factory = uuid_factory
        self._nonce_factory = nonce_factory
        self._clock = clock
        self._reactivate = reactivate

    def status(self) -> dict[str, Any] | None:
        with self._session_factory() as session:
            row = session.get(TelemetryRenewalOperation, 1)
            if row is None:
                return None
            row.validate_exact_artifacts()
            return {
                "status": row.status,
                "requestId": row.request_id,
                "pendingCredentialId": row.pending_credential_id,
                "cancelRequestId": row.cancel_request_id,
            }

    def _material(self, identity: EdgeIdentity | None = None) -> dict[str, Any]:
        try:
            material = self._identity_provider()
        except Exception:
            raise TelemetryRenewalError("identity_not_eligible") from None
        expected = {
            "status": "paired",
            "installationId": identity.installation_id
            if identity
            else material.get("installationId"),
            "credentialId": identity.credential_id if identity else material.get("credentialId"),
            "certificateSha256": (
                identity.certificate_sha256 if identity else material.get("certificateSha256")
            ),
        }
        if (
            any(material.get(key) != value for key, value in expected.items())
            or not isinstance(material.get("certificatePem"), str)
            or not isinstance(material.get("privateKeyPem"), str)
        ):
            raise TelemetryRenewalError("identity_not_eligible")
        return material

    def _create_start(self) -> None:
        request_id = self._uuid_factory()
        pending_credential_id = self._uuid_factory()
        cut_marker_id = self._uuid_factory()
        for value in (request_id, pending_credential_id, cut_marker_id):
            if UUID(value).version != 4 or str(UUID(value)) != value:
                raise TelemetryRenewalError("invalid_uuid_factory")
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, pending_credential_id)])
        uri = f"urn:one-os:installation:{{installation}}:credential:{pending_credential_id}"

        with self._session_factory() as session:
            dialect = _begin(session)
            identity = session.scalar(
                _locked(select(EdgeIdentity).where(EdgeIdentity.id == 1), dialect)
            )
            journal = session.scalar(
                _locked(select(TelemetryJournalState).where(TelemetryJournalState.id == 1), dialect)
            )
            existing = session.scalar(
                _locked(
                    select(TelemetryRenewalOperation).where(TelemetryRenewalOperation.id == 1),
                    dialect,
                )
            )
            if existing is not None:
                session.rollback()
                return
            material = self._material(identity)
            if (
                identity is None
                or journal is None
                or identity.status != "paired"
                or type(identity.installation_revision) is not int
                or not 0 <= identity.installation_revision < _MAX_INT64
                or type(identity.telemetry_authorization_revision) is not int
                or not 1 <= identity.telemetry_authorization_revision < _MAX_INT64
            ):
                raise TelemetryRenewalError("identity_not_eligible")
            key = ec.generate_private_key(ec.SECP256R1())
            csr = (
                x509.CertificateSigningRequestBuilder()
                .subject_name(subject)
                .add_extension(
                    x509.SubjectAlternativeName(
                        [
                            x509.UniformResourceIdentifier(
                                uri.format(installation=identity.installation_id)
                            )
                        ]
                    ),
                    critical=False,
                )
                .sign(key, hashes.SHA256())
                .public_bytes(serialization.Encoding.DER)
            )
            spki = key.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            batches = session.scalars(
                _locked(
                    select(TelemetryBatch)
                    .where(
                        TelemetryBatch.journal_id <= journal.last_journal_id,
                        TelemetryBatch.status != "acked",
                    )
                    .order_by(TelemetryBatch.journal_id),
                    dialect,
                )
            ).all()
            if len(batches) > 256:
                raise TelemetryRenewalError("historical_journal_not_eligible")
            entries = [
                {
                    "batchAuthorizationRevision": batch.batch_authorization_revision,
                    "batchId": batch.batch_id,
                    "credentialId": batch.credential_id,
                    "journalId": batch.journal_id,
                    "requestLength": len(batch.request_bytes),
                    "requestSha256": batch.request_sha256,
                }
                for batch in batches
            ]
            now = self._clock().astimezone(UTC)
            created_at = now.strftime("%Y-%m-%dT%H:%M:%SZ")
            backlog_mode = "historical" if entries else "none"
            cut_journal_max_id = entries[-1]["journalId"] if entries else 0
            manifest = {
                "batchAuthorizationRevision": (
                    identity.telemetry_authorization_revision if entries else 0
                ),
                "createdAt": created_at,
                "cutJournalMaxId": cut_journal_max_id,
                "cutMarkerId": cut_marker_id,
                "entries": entries,
                "entryCount": len(entries),
                "firstJournalId": entries[0]["journalId"] if entries else 0,
                "installationId": identity.installation_id,
                "lastJournalId": entries[-1]["journalId"] if entries else 0,
                "lineageId": identity.lineage_id,
                "renewalOperationId": request_id,
                "schemaVersion": "one-os-telemetry-backlog-manifest/v2",
                "totalRequestBytes": sum(entry["requestLength"] for entry in entries),
            }
            manifest, manifest_bytes = parse_backlog_manifest(manifest)
            manifest_hash = hashlib.sha256(manifest_bytes).digest()
            certificate = x509.load_pem_x509_certificate(material["certificatePem"].encode())
            old_spki = certificate.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            if material.get("activeSpkiSha256") not in {
                None,
                _b64(hashlib.sha256(old_spki).digest()),
            }:
                raise TelemetryRenewalError("identity_not_eligible")
            unsigned = {
                "backlogManifest": manifest,
                "backlogManifestSha256": _b64(manifest_hash),
                "backlogMode": backlog_mode,
                "csrDer": _b64(csr),
                "csrSha256": _b64(hashlib.sha256(csr).digest()),
                "csrSpkiSha256": _b64(hashlib.sha256(spki).digest()),
                "edgeNonce": _b64(self._nonce_factory()),
                "epochMinute": int(now.timestamp()) // 60,
                "expectedTelemetryAuthorizationRevision": identity.telemetry_authorization_revision,
                "installationId": identity.installation_id,
                "installationRevisionBefore": identity.installation_revision,
                "lineageId": identity.lineage_id,
                "oldCertificateSha256": identity.certificate_sha256,
                "oldCertificateSpkiSha256": _b64(hashlib.sha256(old_spki).digest()),
                "oldCredentialId": identity.credential_id,
                "pendingCredentialId": pending_credential_id,
                "protocol": "2.0",
                "requestId": request_id,
            }
            signature = self._signer(build_start_preimage(unsigned))
            if not isinstance(signature, bytes) or len(signature) != 64:
                raise TelemetryRenewalError("invalid_signature")
            request = unsigned | {"signature": _b64(signature)}
            if set(request) != _START_FIELDS:
                raise TelemetryRenewalError("invalid_start_shape")
            request_bytes = canonical_json(request)
            if len(request_bytes) > 61_703:
                raise TelemetryRenewalError("start_too_large")
            cut = TelemetryAuthorityCut(
                cut_marker_id=cut_marker_id,
                renewal_request_id=request_id,
                installation_id=identity.installation_id,
                lineage_id=identity.lineage_id,
                historical_authorization_revision=identity.telemetry_authorization_revision,
                ingest_authorization_revision=identity.telemetry_authorization_revision + 1,
                cut_journal_max_id=cut_journal_max_id,
                backlog_mode=backlog_mode,
                manifest_bytes=manifest_bytes,
                manifest_sha256=manifest_hash,
                milestone="cut_open",
                cut_opened_at=now,
            )
            self._store.write_renewal_candidate(key)
            try:
                session.add(cut)
                session.add(
                    TelemetryRenewalOperation(
                        id=1,
                        status="start_requested",
                        request_id=request_id,
                        pending_credential_id=pending_credential_id,
                        installation_revision_before=identity.installation_revision,
                        telemetry_authorization_revision_before=identity.telemetry_authorization_revision,
                        telemetry_authorization_revision_after=identity.telemetry_authorization_revision
                        + 1,
                        cut_marker_id=cut_marker_id,
                        cut_journal_max_id=cut_journal_max_id,
                        pending_spki_der=spki,
                        pending_spki_sha256=hashlib.sha256(spki).digest(),
                        csr_der=csr,
                        csr_sha256=hashlib.sha256(csr).digest(),
                        manifest_bytes=manifest_bytes,
                        manifest_sha256=manifest_hash,
                        start_request_bytes=request_bytes,
                        start_request_sha256=hashlib.sha256(request_bytes).digest(),
                        created_at=now,
                        updated_at=now,
                    )
                )
                session.commit()
            except BaseException:
                self._store.delete_renewal()
                raise

    def _validate_pending(
        self, raw: bytes, row: TelemetryRenewalOperation
    ) -> tuple[dict[str, Any], bytes | None]:
        request = _document(row.start_request_bytes, _START_FIELDS, 61_703)
        backlog_mode = "none" if row.cut_journal_max_id == 0 else "historical"
        pending_fields = _PENDING_NONE_FIELDS if backlog_mode == "none" else _PENDING_FIELDS
        response = _document(raw, pending_fields, 63_218)
        aliases = {
            "protocol": "2.0",
            "requestId": row.request_id,
            "installationId": request["installationId"],
            "lineageId": request["lineageId"],
            "installationRevisionBefore": row.installation_revision_before,
            "telemetryAuthorizationRevisionBefore": row.telemetry_authorization_revision_before,
            "telemetryAuthorizationRevisionAfter": row.telemetry_authorization_revision_after,
            "backlogMode": backlog_mode,
            "backlogManifestSha256": request["backlogManifestSha256"],
            "oldCredentialId": request["oldCredentialId"],
            "oldCertificateSha256": request["oldCertificateSha256"],
            "oldCertificateSpkiSha256": request["oldCertificateSpkiSha256"],
            "newCredentialId": row.pending_credential_id,
            "csrSha256": request["csrSha256"],
            "csrSpkiSha256": request["csrSpkiSha256"],
            "status": "pending",
        }
        if any(response.get(key) != value for key, value in aliases.items()):
            raise TelemetryRenewalError("pending_response_conflict")
        _timestamp_seconds(response["issuanceExpiresAt"])
        if backlog_mode == "none":
            return response, None
        try:
            receipt, receipt_bytes = parse_historical_receipt(
                response["historicalAuthorizationReceipt"]
            )
        except ValueError:
            raise TelemetryRenewalError("pending_response_conflict") from None
        receipt_hash = hashlib.sha256(receipt_bytes).digest()
        relations = {
            "renewalOperationId": row.request_id,
            "renewalRequestSha256": _b64(row.start_request_sha256),
            "backlogManifestSha256": _b64(row.manifest_sha256),
            "cutMarkerId": row.cut_marker_id,
            "cutJournalMaxId": row.cut_journal_max_id,
            "installationId": request["installationId"],
            "lineageId": request["lineageId"],
            "historicalAuthorizationRevision": row.telemetry_authorization_revision_before,
            "ingestAuthorizationRevision": row.telemetry_authorization_revision_after,
            "entries": request["backlogManifest"]["entries"],
        }
        if (
            any(receipt.get(key) != value for key, value in relations.items())
            or receipt["allowedTransportCredentialIds"]
            != sorted([request["oldCredentialId"], row.pending_credential_id])
            or not hmac.compare_digest(
                response["historicalAuthorizationReceiptSha256"], _b64(receipt_hash)
            )
        ):
            raise TelemetryRenewalError("pending_response_conflict")
        return response, receipt_bytes

    def start(self) -> bytes:
        with self._session_factory() as session:
            exists = session.get(TelemetryRenewalOperation, 1) is not None
        if not exists:
            self._create_start()
        with self._session_factory() as session:
            row = session.get(TelemetryRenewalOperation, 1)
            if row is None:
                raise TelemetryRenewalError("start_persistence_conflict")
            row.validate_exact_artifacts()
            if row.status == "pending":
                assert row.pending_response_bytes is not None
                self._validate_pending(row.pending_response_bytes, row)
                return row.pending_response_bytes
            if row.status != "start_requested":
                raise TelemetryRenewalError("renewal_operation_conflict")
            request_id = row.request_id
            request_bytes = row.start_request_bytes
        material = self._material()
        response_bytes = self._client.start_renewal_v2(
            request_bytes, material["certificatePem"], material["privateKeyPem"]
        )
        with self._session_factory() as session:
            dialect = _begin(session)
            row = session.scalar(
                _locked(
                    select(TelemetryRenewalOperation).where(TelemetryRenewalOperation.id == 1),
                    dialect,
                )
            )
            if row is None or row.request_id != request_id or row.status != "start_requested":
                raise TelemetryRenewalError("renewal_operation_conflict")
            _response, receipt_bytes = self._validate_pending(response_bytes, row)
            cut = session.get(TelemetryAuthorityCut, row.cut_marker_id)
            if cut is None or cut.milestone != "cut_open":
                raise TelemetryRenewalError("renewal_cut_conflict")
            cut.receipt_bytes = receipt_bytes
            cut.receipt_sha256 = (
                hashlib.sha256(receipt_bytes).digest() if receipt_bytes is not None else None
            )
            cut.receipt_stored_at = self._clock().astimezone(UTC)
            cut.milestone = "receipt_stored"
            row.pending_response_bytes = response_bytes
            row.pending_response_sha256 = hashlib.sha256(response_bytes).digest()
            row.receipt_bytes = receipt_bytes
            row.receipt_sha256 = (
                hashlib.sha256(receipt_bytes).digest() if receipt_bytes is not None else None
            )
            row.status = "pending"
            row.updated_at = self._clock().astimezone(UTC)
            session.commit()
        return response_bytes

    @staticmethod
    def _method1_ski(key) -> bytes:
        point = key.public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
        return hashlib.sha1(point[1:]).digest()  # noqa: S324 - X.509 SKI method 1

    def _validate_issued(
        self, raw: bytes, row: TelemetryRenewalOperation
    ) -> tuple[dict[str, Any], x509.Certificate, str]:
        issued_fields = _ISSUED_NONE_FIELDS if row.cut_journal_max_id == 0 else _ISSUED_FIELDS
        pending_fields = _PENDING_NONE_FIELDS if row.cut_journal_max_id == 0 else _PENDING_FIELDS
        response = _document(raw, issued_fields, 63_218)
        pending = _document(row.pending_response_bytes or b"", pending_fields, 63_218)
        shared = pending_fields - {"issuanceExpiresAt", "status"}
        if response["status"] != "issued" or any(
            response.get(name) != pending.get(name) for name in shared
        ):
            raise TelemetryRenewalError("issued_response_conflict")
        if row.cut_journal_max_id != 0 and response["historicalAuthorizationReceiptSha256"] != _b64(
            row.receipt_sha256 or b""
        ):
            raise TelemetryRenewalError("issued_response_conflict")
        _timestamp_seconds(response["ackExpiresAt"])
        try:
            certificate_pem = response["certificatePem"].encode("ascii")
            chain_pem = response["caChainPem"].encode("ascii")
            leaves = x509.load_pem_x509_certificates(certificate_pem)
            roots = x509.load_pem_x509_certificates(chain_pem)
            if len(leaves) != 1 or len(roots) != 1:
                raise ValueError("certificate_count")
            leaf, root = leaves[0], roots[0]
            if (
                leaf.public_bytes(serialization.Encoding.PEM) != certificate_pem
                or root.public_bytes(serialization.Encoding.PEM) != chain_pem
            ):
                raise ValueError("noncanonical_pem")
            root_key = root.public_key()
            if (
                root.version != x509.Version.v3
                or not 1 <= root.serial_number <= 2**159 - 1
                or root.subject != root.issuer
                or root.subject
                != x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ONE.OS Draft-4 Test Root")])
                or not isinstance(root_key, ec.EllipticCurvePublicKey)
                or not isinstance(root_key.curve, ec.SECP256R1)
            ):
                raise ValueError("root_profile")
            root_key.verify(root.signature, root.tbs_certificate_bytes, ec.ECDSA(hashes.SHA256()))
            root_ext = list(root.extensions)
            if (
                [item.oid for item in root_ext]
                != [
                    ExtensionOID.BASIC_CONSTRAINTS,
                    ExtensionOID.KEY_USAGE,
                    ExtensionOID.SUBJECT_KEY_IDENTIFIER,
                ]
                or [item.critical for item in root_ext] != [True, True, False]
                or root_ext[0].value != x509.BasicConstraints(ca=True, path_length=0)
                or root_ext[1].value
                != x509.KeyUsage(False, False, False, False, False, True, True, False, False)
                or root_ext[2].value.digest != self._method1_ski(root_key)
            ):
                raise ValueError("root_extensions")
            leaf_key = leaf.public_key()
            expected_key = serialization.load_der_public_key(row.pending_spki_der)
            if (
                leaf.version != x509.Version.v3
                or not 1 <= leaf.serial_number <= 2**159 - 1
                or leaf.issuer != root.subject
                or leaf.subject
                != x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, row.pending_credential_id)])
                or not isinstance(leaf_key, ec.EllipticCurvePublicKey)
                or not isinstance(leaf_key.curve, ec.SECP256R1)
                or leaf_key.public_bytes(
                    serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
                )
                != row.pending_spki_der
                or expected_key.public_bytes(
                    serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
                )
                != row.pending_spki_der
            ):
                raise ValueError("leaf_profile")
            root_key.verify(leaf.signature, leaf.tbs_certificate_bytes, ec.ECDSA(hashes.SHA256()))
            extensions = list(leaf.extensions)
            expected_oids = [
                ExtensionOID.BASIC_CONSTRAINTS,
                ExtensionOID.KEY_USAGE,
                ExtensionOID.EXTENDED_KEY_USAGE,
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
                ExtensionOID.SUBJECT_KEY_IDENTIFIER,
                ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
            ]
            usage = extensions[1].value if len(extensions) == 6 else None
            authority = extensions[5].value if len(extensions) == 6 else None
            expected_uri = (
                f"urn:one-os:installation:{response['installationId']}:credential:"
                f"{row.pending_credential_id}"
            )
            if (
                [item.oid for item in extensions] != expected_oids
                or [item.critical for item in extensions] != [True, True, True, False, False, False]
                or extensions[0].value != x509.BasicConstraints(ca=False, path_length=None)
                or not usage.digital_signature
                or any(
                    (
                        usage.content_commitment,
                        usage.key_encipherment,
                        usage.data_encipherment,
                        usage.key_agreement,
                        usage.key_cert_sign,
                        usage.crl_sign,
                    )
                )
                or list(extensions[2].value) != [ExtendedKeyUsageOID.CLIENT_AUTH]
                or extensions[3].value.get_values_for_type(x509.UniformResourceIdentifier)
                != [expected_uri]
                or extensions[4].value.digest != self._method1_ski(leaf_key)
                or authority.key_identifier != self._method1_ski(root_key)
                or authority.authority_cert_issuer is not None
                or authority.authority_cert_serial_number is not None
                or (leaf.not_valid_after_utc - leaf.not_valid_before_utc).total_seconds()
                != 366 * 86400
                or not root.not_valid_before_utc
                <= leaf.not_valid_before_utc
                <= self._clock().astimezone(UTC)
                < leaf.not_valid_after_utc
                <= root.not_valid_after_utc
            ):
                raise ValueError("leaf_extensions")
            leaf_der = leaf.public_bytes(serialization.Encoding.DER)
            spki = leaf_key.public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            if response["newCertificateSha256"] != _b64(
                hashlib.sha256(leaf_der).digest()
            ) or response["newCertificateSpkiSha256"] != _b64(hashlib.sha256(spki).digest()):
                raise ValueError("certificate_hash")
        except Exception:
            raise TelemetryRenewalError("issued_response_conflict") from None
        return response, leaf, response["caChainPem"]

    def poll(self) -> bytes:
        with self._session_factory() as session:
            row = session.get(TelemetryRenewalOperation, 1)
            if row is None:
                raise TelemetryRenewalError("renewal_operation_missing")
            row.validate_exact_artifacts()
            if row.status in {"issued", "ack_requested", "acked", "terminal"}:
                assert row.issued_response_bytes is not None
                self._validate_issued(row.issued_response_bytes, row)
                return row.issued_response_bytes
            if row.status != "pending":
                raise TelemetryRenewalError("renewal_operation_conflict")
            request_id = row.request_id
        material = self._material()
        raw = self._client.renewal_status_v2(
            request_id, material["certificatePem"], material["privateKeyPem"]
        )
        with self._session_factory() as session:
            dialect = _begin(session)
            row = session.scalar(
                _locked(
                    select(TelemetryRenewalOperation).where(TelemetryRenewalOperation.id == 1),
                    dialect,
                )
            )
            if row is None or row.status != "pending" or row.request_id != request_id:
                raise TelemetryRenewalError("renewal_operation_conflict")
            pending_fields = (
                _PENDING_NONE_FIELDS if row.cut_journal_max_id == 0 else _PENDING_FIELDS
            )
            if set(json.loads(raw)) == pending_fields:
                self._validate_pending(raw, row)
                if raw != row.pending_response_bytes:
                    raise TelemetryRenewalError("pending_response_conflict")
                session.rollback()
                return raw
            response, _leaf, chain = self._validate_issued(raw, row)
            self._store.write_renewal_credential(response["certificatePem"], chain)
            row.issued_response_bytes = raw
            row.issued_response_sha256 = hashlib.sha256(raw).digest()
            row.status = "issued"
            row.updated_at = self._clock().astimezone(UTC)
            session.commit()
        return raw

    def _ensure_drained(self, session, row: TelemetryRenewalOperation) -> None:
        if row.cut_journal_max_id == 0:
            if row.receipt_bytes is not None or row.receipt_sha256 is not None:
                raise TelemetryRenewalError("zero_backlog_receipt_conflict")
            return
        receipt, exact = parse_historical_receipt(row.receipt_bytes or b"")
        if exact != row.receipt_bytes:
            raise TelemetryRenewalError("historical_backlog_conflict")
        entries = receipt["entries"]
        batch_ids = [entry["batchId"] for entry in entries]
        batches = session.scalars(
            select(TelemetryBatch).where(TelemetryBatch.batch_id.in_(batch_ids))
        ).all()
        batch_by_id = {batch.batch_id: batch for batch in batches}
        if len(batches) != len(entries) or any(
            (batch := batch_by_id.get(entry["batchId"])) is None
            or batch.status != "acked"
            or entry["journalId"] != batch.journal_id
            or batch.journal_id > row.cut_journal_max_id
            or entry["credentialId"] != batch.credential_id
            or entry["batchAuthorizationRevision"] != batch.batch_authorization_revision
            or entry["requestSha256"] != batch.request_sha256
            or entry["requestLength"] != len(batch.request_bytes)
            for entry in entries
        ):
            raise TelemetryRenewalError("historical_backlog_not_drained")

    @staticmethod
    def _sign_pending(key: ec.EllipticCurvePrivateKey, preimage: bytes) -> bytes:
        r, s = decode_dss_signature(key.sign(preimage, ec.ECDSA(hashes.SHA256())))
        if s > _P256_N // 2:
            s = _P256_N - s
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    def _create_ack(self) -> None:
        with self._session_factory() as session:
            dialect = _begin(session)
            row = session.scalar(
                _locked(
                    select(TelemetryRenewalOperation).where(TelemetryRenewalOperation.id == 1),
                    dialect,
                )
            )
            if row is None or row.status != "issued":
                raise TelemetryRenewalError("renewal_operation_conflict")
            self._ensure_drained(session, row)
            issued, _leaf, _chain = self._validate_issued(row.issued_response_bytes or b"", row)
            pending_fields = (
                _PENDING_NONE_FIELDS if row.cut_journal_max_id == 0 else _PENDING_FIELDS
            )
            pending = _document(row.pending_response_bytes or b"", pending_fields, 63_218)
            unsigned = {
                "protocol": "2.0",
                "requestId": row.request_id,
                "installationId": issued["installationId"],
                "lineageId": issued["lineageId"],
                "installationRevisionBefore": row.installation_revision_before,
                "telemetryAuthorizationRevisionBefore": row.telemetry_authorization_revision_before,
                "telemetryAuthorizationRevisionAfter": row.telemetry_authorization_revision_after,
                "backlogMode": issued["backlogMode"],
                "backlogManifestSha256": issued["backlogManifestSha256"],
                "oldCredentialId": issued["oldCredentialId"],
                "oldCertificateSha256": issued["oldCertificateSha256"],
                "oldCertificateSpkiSha256": issued["oldCertificateSpkiSha256"],
                "newCredentialId": row.pending_credential_id,
                "csrSha256": issued["csrSha256"],
                "csrSpkiSha256": issued["csrSpkiSha256"],
                "renewalRequestSha256": _b64(row.start_request_sha256),
                "renewalIssuedResponseSha256": _b64(row.issued_response_sha256 or b""),
                "newCertificateSha256": issued["newCertificateSha256"],
                "newCertificateSpkiSha256": issued["newCertificateSpkiSha256"],
            }
            if row.cut_journal_max_id != 0:
                unsigned["historicalAuthorizationReceiptSha256"] = pending[
                    "historicalAuthorizationReceiptSha256"
                ]
            key = self._store.load_renewal_candidate()
            signature = self._sign_pending(key, build_ack_preimage(unsigned))
            request_bytes = canonical_json(unsigned | {"signature": _b64(signature)})
            expected_fields = _ACK_NONE_FIELDS if row.cut_journal_max_id == 0 else _ACK_FIELDS
            if set(unsigned | {"signature": ""}) != expected_fields:
                raise TelemetryRenewalError("ack_request_conflict")
            row.ack_request_bytes = request_bytes
            row.ack_request_sha256 = hashlib.sha256(request_bytes).digest()
            row.status = "ack_requested"
            row.updated_at = self._clock().astimezone(UTC)
            session.commit()

    def _validate_ack_response(self, raw: bytes, row: TelemetryRenewalOperation) -> None:
        response_fields = (
            _ACK_NONE_RESPONSE_FIELDS if row.cut_journal_max_id == 0 else _ACK_RESPONSE_FIELDS
        )
        request_fields = _ACK_NONE_FIELDS if row.cut_journal_max_id == 0 else _ACK_FIELDS
        response = _document(raw, response_fields, 16_384)
        request = _document(row.ack_request_bytes or b"", request_fields, 16_384)
        expected = {key: value for key, value in request.items() if key != "signature"}
        expected["installationRevisionAfter"] = row.installation_revision_before + 1
        expected["status"] = "acked"
        if response != expected:
            raise TelemetryRenewalError("ack_response_conflict")

    def _active_identity_matches(
        self, row: TelemetryRenewalOperation, issued: dict[str, Any]
    ) -> bool:
        try:
            certificate, _chain = self._store.read_identity_credential()
            active_leaf = x509.load_pem_x509_certificate(certificate.encode("ascii"))
            active_key = self._store.load_identity().public_key()
            return (
                _b64(hashlib.sha256(active_leaf.public_bytes(serialization.Encoding.DER)).digest())
                == issued["newCertificateSha256"]
                and active_key.public_bytes(
                    serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
                )
                == row.pending_spki_der
            )
        except Exception:
            return False

    def _finish_local(self) -> None:
        with self._session_factory() as session:
            dialect = _begin(session)
            identity = session.scalar(
                _locked(select(EdgeIdentity).where(EdgeIdentity.id == 1), dialect)
            )
            row = session.scalar(
                _locked(
                    select(TelemetryRenewalOperation).where(TelemetryRenewalOperation.id == 1),
                    dialect,
                )
            )
            if row is None or row.status not in {"acked", "terminal"} or identity is None:
                raise TelemetryRenewalError("renewal_operation_conflict")
            if row.status == "terminal":
                session.rollback()
                return
            issued, leaf, _chain = self._validate_issued(row.issued_response_bytes or b"", row)
            if not self._active_identity_matches(row, issued):
                self._store.promote_renewal()
            if identity.credential_id == issued["oldCredentialId"]:
                now = self._clock().astimezone(UTC)
                identity.credential_id = row.pending_credential_id
                identity.certificate_sha256 = issued["newCertificateSha256"]
                identity.active_spki_sha256 = issued["newCertificateSpkiSha256"]
                identity.certificate_not_after = leaf.not_valid_after_utc
                identity.installation_revision = row.installation_revision_before + 1
                identity.telemetry_authorization_revision = (
                    row.telemetry_authorization_revision_after
                )
                identity.revision += 1
                identity.updated_at = now
            elif (
                identity.credential_id != row.pending_credential_id
                or identity.certificate_sha256 != issued["newCertificateSha256"]
                or identity.active_spki_sha256 != issued["newCertificateSpkiSha256"]
                or identity.installation_revision != row.installation_revision_before + 1
                or identity.telemetry_authorization_revision
                != row.telemetry_authorization_revision_after
            ):
                raise TelemetryRenewalError("identity_promotion_conflict")
            now = self._clock().astimezone(UTC)
            cut = session.get(TelemetryAuthorityCut, row.cut_marker_id)
            if cut is None or cut.milestone not in {
                "receipt_stored",
                "identity_promoted",
                "backlog_drained",
            }:
                raise TelemetryRenewalError("renewal_cut_conflict")
            cut.identity_promoted_at = cut.identity_promoted_at or now
            cut.milestone = "identity_promoted"
            row.updated_at = now
            session.commit()

        with self._session_factory() as session:
            activation_exists = session.get(TelemetryAuthorityActivation, 1) is not None
        if activation_exists and self._reactivate is None:
            raise TelemetryRenewalError("activation_reenable_required")
        if self._reactivate is not None:
            try:
                enable_response = self._reactivate()
            except Exception:
                raise TelemetryRenewalError("activation_reenable_failed") from None
            if not isinstance(enable_response, bytes) or not enable_response:
                raise TelemetryRenewalError("activation_reenable_failed")

        with self._session_factory() as session:
            dialect = _begin(session)
            identity = session.scalar(
                _locked(select(EdgeIdentity).where(EdgeIdentity.id == 1), dialect)
            )
            row = session.scalar(
                _locked(
                    select(TelemetryRenewalOperation).where(TelemetryRenewalOperation.id == 1),
                    dialect,
                )
            )
            if row is None or row.status not in {"acked", "terminal"} or identity is None:
                raise TelemetryRenewalError("renewal_operation_conflict")
            if row.status == "terminal":
                session.rollback()
                return
            if (
                identity.credential_id != row.pending_credential_id
                or identity.installation_revision != row.installation_revision_before + 1
                or identity.telemetry_authorization_revision
                != row.telemetry_authorization_revision_after
            ):
                raise TelemetryRenewalError("identity_promotion_conflict")
            now = self._clock().astimezone(UTC)
            cut = session.get(TelemetryAuthorityCut, row.cut_marker_id)
            if cut is None or cut.milestone not in {"identity_promoted", "backlog_drained"}:
                raise TelemetryRenewalError("renewal_cut_conflict")
            if cut.backlog_mode == "historical":
                cut.backlog_drained_at = cut.backlog_drained_at or now
            cut.terminal_at = cut.terminal_at or now
            cut.milestone = "terminal"
            row.status = "terminal"
            row.updated_at = now
            session.commit()
        self._store.delete_renewal()

    def terminalize(self, reason: str) -> None:
        if reason not in {"repair", "replacement", "revoke"}:
            raise TelemetryRenewalError("renewal_quarantine_reason_invalid")
        now = self._clock().astimezone(UTC)
        with self._session_factory() as session:
            dialect = _begin(session)
            row = session.scalar(
                _locked(
                    select(TelemetryRenewalOperation).where(TelemetryRenewalOperation.id == 1),
                    dialect,
                )
            )
            if row is None:
                session.rollback()
            else:
                if row.status == "acked":
                    issued, _leaf, _chain = self._validate_issued(
                        row.issued_response_bytes or b"", row
                    )
                    if self._active_identity_matches(row, issued):
                        session.rollback()
                        return
                cut = session.scalar(
                    _locked(
                        select(TelemetryAuthorityCut).where(
                            TelemetryAuthorityCut.cut_marker_id == row.cut_marker_id
                        ),
                        dialect,
                    )
                )
                if cut is not None and cut.milestone != "terminal":
                    batches = session.scalars(
                        _locked(
                            select(TelemetryBatch).where(
                                TelemetryBatch.journal_id <= cut.cut_journal_max_id,
                                TelemetryBatch.batch_authorization_revision
                                == cut.historical_authorization_revision,
                                TelemetryBatch.status.in_(("pending", "leased")),
                            ),
                            dialect,
                        )
                    ).all()
                    for batch in batches:
                        batch.status = "quarantined"
                        batch.lease_owner = None
                        batch.lease_until = None
                        batch.terminal_reason = "authority_terminalized"
                        batch.quarantined_at = now
                    cut.terminal_at = now
                    cut.milestone = "terminal"
                if row.status not in {"terminal", "cancelled", "quarantined"}:
                    row.status = "quarantined"
                    row.updated_at = now
                session.commit()
        self._store.delete_renewal()

    def quarantine(self, reason: str) -> None:
        self.terminalize(reason)

    def finalize(self) -> bytes:
        with self._session_factory() as session:
            row = session.get(TelemetryRenewalOperation, 1)
            if row is None:
                raise TelemetryRenewalError("renewal_operation_missing")
            status = row.status
            terminal_response = row.ack_response_bytes
        if status == "issued":
            self._create_ack()
            status = "ack_requested"
        if status == "ack_requested":
            with self._session_factory() as session:
                row = session.get(TelemetryRenewalOperation, 1)
                assert row is not None and row.ack_request_bytes is not None
                request_id, request_bytes = row.request_id, row.ack_request_bytes
            certificate, chain = self._store.read_renewal_credential()
            raw = self._client.ack_renewal_v2(
                request_id,
                request_bytes,
                certificate + chain,
                self._store.renewal_private_pem(),
            )
            with self._session_factory() as session:
                dialect = _begin(session)
                row = session.scalar(
                    _locked(
                        select(TelemetryRenewalOperation).where(TelemetryRenewalOperation.id == 1),
                        dialect,
                    )
                )
                if row is None or row.status != "ack_requested":
                    raise TelemetryRenewalError("renewal_operation_conflict")
                self._validate_ack_response(raw, row)
                row.ack_response_bytes = raw
                row.ack_response_sha256 = hashlib.sha256(raw).digest()
                row.status = "acked"
                row.updated_at = self._clock().astimezone(UTC)
                session.commit()
            terminal_response = raw
        self._finish_local()
        if terminal_response is None:
            with self._session_factory() as session:
                row = session.get(TelemetryRenewalOperation, 1)
                terminal_response = None if row is None else row.ack_response_bytes
        if terminal_response is None:
            raise TelemetryRenewalError("renewal_operation_conflict")
        return terminal_response

    def _validate_cancel(self, raw: bytes, row: TelemetryRenewalOperation) -> None:
        response = _document(raw, _CANCEL_RESPONSE_FIELDS, 16_384)
        request = _document(row.cancel_request_bytes or b"", _CANCEL_FIELDS, 16_384)
        aliases = {
            "protocol": "2.0",
            "cancelRequestId": row.cancel_request_id,
            "cancelRequestSha256": _b64(row.cancel_request_sha256 or b""),
            "targetRequestId": row.request_id,
            "targetRenewalRequestSha256": _b64(row.start_request_sha256),
            "backlogManifestSha256": _b64(row.manifest_sha256),
            "installationId": request["installationId"],
            "lineageId": request["lineageId"],
            "telemetryAuthorizationRevision": row.telemetry_authorization_revision_before,
            "currentCredentialId": request["currentCredentialId"],
            "currentCertificateSha256": request["currentCertificateSha256"],
            "status": "cancelled_no_reservation",
        }
        if any(response.get(key) != value for key, value in aliases.items()):
            raise TelemetryRenewalError("cancel_response_conflict")
        _timestamp_seconds(response["decidedAt"])

    def cancel(self) -> bytes:
        created = False
        with self._session_factory() as session:
            dialect = _begin(session)
            row = session.scalar(
                _locked(
                    select(TelemetryRenewalOperation).where(TelemetryRenewalOperation.id == 1),
                    dialect,
                )
            )
            if row is None:
                raise TelemetryRenewalError("renewal_operation_missing")
            row.validate_exact_artifacts()
            if row.status == "cancelled":
                assert row.cancel_response_bytes is not None
                self._validate_cancel(row.cancel_response_bytes, row)
                return row.cancel_response_bytes
            if row.status == "start_requested":
                start = _document(row.start_request_bytes, _START_FIELDS, 61_703)
                cancel_id = self._uuid_factory()
                unsigned = {
                    "backlogManifestSha256": _b64(row.manifest_sha256),
                    "cancelRequestId": cancel_id,
                    "currentCertificateSha256": start["oldCertificateSha256"],
                    "currentCredentialId": start["oldCredentialId"],
                    "edgeNonce": _b64(self._nonce_factory()),
                    "expectedTelemetryAuthorizationRevision": (
                        row.telemetry_authorization_revision_before
                    ),
                    "installationId": start["installationId"],
                    "lineageId": start["lineageId"],
                    "protocol": "2.0",
                    "targetRenewalRequestSha256": _b64(row.start_request_sha256),
                    "targetRequestId": row.request_id,
                }
                signature = self._signer(build_cancel_preimage(unsigned))
                if not isinstance(signature, bytes) or len(signature) != 64:
                    raise TelemetryRenewalError("invalid_signature")
                request_bytes = canonical_json(unsigned | {"signature": _b64(signature)})
                row.cancel_request_id = cancel_id
                row.cancel_request_bytes = request_bytes
                row.cancel_request_sha256 = hashlib.sha256(request_bytes).digest()
                row.status = "cancel_requested"
                row.updated_at = self._clock().astimezone(UTC)
                session.commit()
                created = True
            elif row.status != "cancel_requested":
                raise TelemetryRenewalError("renewal_operation_conflict")
            request_id = row.request_id
            cancel_id = row.cancel_request_id
            request_bytes = row.cancel_request_bytes
        assert cancel_id is not None and request_bytes is not None
        material = self._material()
        if created:
            response_bytes = self._client.cancel_renewal_v2(
                request_id, request_bytes, material["certificatePem"], material["privateKeyPem"]
            )
        else:
            response_bytes = self._client.cancel_status_v2(
                cancel_id, material["certificatePem"], material["privateKeyPem"]
            )
        with self._session_factory() as session:
            dialect = _begin(session)
            row = session.scalar(
                _locked(
                    select(TelemetryRenewalOperation).where(TelemetryRenewalOperation.id == 1),
                    dialect,
                )
            )
            if (
                row is None
                or row.status != "cancel_requested"
                or row.cancel_request_id != cancel_id
            ):
                raise TelemetryRenewalError("renewal_operation_conflict")
            self._validate_cancel(response_bytes, row)
            cut = session.get(TelemetryAuthorityCut, row.cut_marker_id)
            if cut is not None:
                session.delete(cut)
            row.cancel_response_bytes = response_bytes
            row.cancel_response_sha256 = hashlib.sha256(response_bytes).digest()
            row.status = "cancelled"
            row.updated_at = self._clock().astimezone(UTC)
            session.commit()
        return response_bytes
