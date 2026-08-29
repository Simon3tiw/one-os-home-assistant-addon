from __future__ import annotations

import base64
import hashlib
import hmac
import json
import struct
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol
from uuid import UUID, uuid4

from sqlalchemy import select, text

from .models import EdgeIdentity, TelemetryAuthorityActivation
from .telemetry_contract_v2 import canonical_json

PROTOCOL_ID = "one-os-telemetry-authority/v2"
PINNED_SCHEMA_HASHES = {
    "telemetryBatchSchemaSha256": "uw1ey0FOeI_wmNUrIsz5f81JbsuSKcQRyUQLJd_iMGk",
    "telemetryAckSchemaSha256": "Jc0L6vacmW2fv84cN2d5uFlPXvXK0CSrXPZRe4WZNrM",
    "telemetryErrorSchemaSha256": "Vqfv87Vr1YhMs-erfcKy3GZPrV6UCm2qmrjrMEgdeUo",
    "renewalControlSchemaSha256": "u1slFBNNgZ1TT_eHRNdxltIRBRcJ_suIXjgOYrYuigs",
}
_CAPABILITY_FIELDS = {
    "schemaVersion",
    "installationId",
    "protocolId",
    *PINNED_SCHEMA_HASHES,
    "renewalV2Available",
    "ingestV2Available",
    "serverNonce",
    "issuedAt",
    "expiresAt",
}
_ENABLE_RESPONSE_FIELDS = {
    "protocol",
    "requestId",
    "installationId",
    "status",
    "protocolId",
    *PINNED_SCHEMA_HASHES,
    "capabilitySha256",
    "capabilityServerNonce",
    "issuedAt",
    "expiresAt",
    "telemetryAuthorizationRevision",
    "enabledAt",
}
_ENABLE_REQUEST_FIELDS = {
    "protocol",
    "requestId",
    "installationId",
    "currentCredentialId",
    "currentCertificateSha256",
    "protocolId",
    *PINNED_SCHEMA_HASHES,
    "capabilitySha256",
    "capabilityServerNonce",
    "issuedAt",
    "expiresAt",
    "expectedTelemetryAuthorizationRevision",
    "edgeNonce",
    "signature",
}


class TelemetryAuthorityError(RuntimeError):
    pass


class TelemetryAuthorityClient(Protocol):
    def get_capability(self, certificate_pem: str, private_key_pem: str) -> bytes: ...
    def enable(self, request_bytes: bytes, certificate_pem: str, private_key_pem: str) -> bytes: ...


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _unb64(value: Any) -> bytes:
    if not isinstance(value, str) or len(value) != 43:
        raise TelemetryAuthorityError("invalid_digest")
    try:
        raw = base64.b64decode(value + "=", altchars=b"-_", validate=True)
    except ValueError:
        raise TelemetryAuthorityError("invalid_digest") from None
    if len(raw) != 32 or not hmac.compare_digest(_b64(raw), value):
        raise TelemetryAuthorityError("invalid_digest")
    return raw


def _timestamp(value: Any) -> datetime:
    if not isinstance(value, str) or len(value) != 20 or not value.endswith("Z"):
        raise TelemetryAuthorityError("invalid_timestamp")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError:
        raise TelemetryAuthorityError("invalid_timestamp") from None
    return parsed


def _uuid(value: Any) -> str:
    try:
        parsed = UUID(value)
    except (TypeError, ValueError, AttributeError):
        raise TelemetryAuthorityError("invalid_uuid") from None
    if parsed.version != 4 or str(parsed) != value:
        raise TelemetryAuthorityError("invalid_uuid")
    return value


def _document(raw: bytes, fields: set[str]) -> dict[str, Any]:
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= 16_384:
        raise TelemetryAuthorityError("invalid_wire")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise TelemetryAuthorityError("duplicate_json_member")
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique)
    except (UnicodeError, ValueError, json.JSONDecodeError):
        raise TelemetryAuthorityError("invalid_wire") from None
    if not isinstance(value, dict) or set(value) != fields or canonical_json(value) != raw:
        raise TelemetryAuthorityError("invalid_wire")
    return value


def _capability(raw: bytes, installation_id: str) -> tuple[dict[str, Any], datetime, datetime]:
    value = _document(raw, _CAPABILITY_FIELDS)
    if (
        value["schemaVersion"] != "one-os-telemetry-authority-capability/v2"
        or value["installationId"] != installation_id
        or value["protocolId"] != PROTOCOL_ID
        or value["renewalV2Available"] is not True
        or value["ingestV2Available"] is not True
        or any(value[key] != expected for key, expected in PINNED_SCHEMA_HASHES.items())
    ):
        raise TelemetryAuthorityError("capability_conflict")
    _uuid(value["installationId"])
    _unb64(value["serverNonce"])
    issued, expires = _timestamp(value["issuedAt"]), _timestamp(value["expiresAt"])
    if expires - issued != timedelta(seconds=300):
        raise TelemetryAuthorityError("capability_conflict")
    return value, issued, expires


def _stored_capability(
    raw: bytes, stored_sha256: bytes, installation_id: str
) -> tuple[dict[str, Any], datetime, datetime]:
    if not isinstance(stored_sha256, bytes) or not hmac.compare_digest(
        hashlib.sha256(raw).digest(), stored_sha256
    ):
        raise TelemetryAuthorityError("capability_hash_conflict")
    return _capability(raw, installation_id)


def _framed(domain: str, values: list[bytes]) -> bytes:
    return (
        domain.encode("ascii")
        + b"\0"
        + b"".join(
            struct.pack(">HI", index, len(value)) + value for index, value in enumerate(values, 1)
        )
    )


def build_enable_preimage(value: dict[str, Any]) -> bytes:
    names = tuple(PINNED_SCHEMA_HASHES)
    values = [
        value["protocol"].encode(),
        UUID(value["requestId"]).bytes,
        UUID(value["installationId"]).bytes,
        UUID(value["currentCredentialId"]).bytes,
        _unb64(value["currentCertificateSha256"]),
        value["protocolId"].encode(),
        *(_unb64(value[key]) for key in names),
        _unb64(value["capabilitySha256"]),
        _unb64(value["capabilityServerNonce"]),
        value["issuedAt"].encode(),
        value["expiresAt"].encode(),
        value["expectedTelemetryAuthorizationRevision"].to_bytes(8, "big"),
        _unb64(value["edgeNonce"]),
    ]
    return _framed("ONE.OS-TELEMETRY-AUTHORITY-ENABLE-V2", values)


def _activation_lock_statements(dialect: str):
    statements = (
        select(EdgeIdentity).where(EdgeIdentity.id == 1),
        select(TelemetryAuthorityActivation).where(TelemetryAuthorityActivation.id == 1),
    )
    if dialect == "postgresql":
        return tuple(statement.with_for_update() for statement in statements)
    return statements


def _begin_write(session) -> str:
    dialect = session.get_bind().dialect.name
    if dialect == "sqlite":
        session.execute(text("BEGIN IMMEDIATE"))
    return dialect


class TelemetryAuthorityManager:
    def __init__(
        self,
        session_factory,
        client: TelemetryAuthorityClient,
        identity_provider,
        signer,
        *,
        uuid_factory=lambda: str(uuid4()),
        nonce_factory=lambda: __import__("secrets").token_bytes(32),
        clock=lambda: datetime.now(UTC),
    ) -> None:
        self._session_factory = session_factory
        self._client = client
        self._identity_provider = identity_provider
        self._signer = signer
        self._uuid_factory = uuid_factory
        self._nonce_factory = nonce_factory
        self._clock = clock

    @staticmethod
    def _aware(value: datetime) -> datetime:
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)

    def _current(self, session, dialect: str | None = None) -> tuple[EdgeIdentity, dict[str, Any]]:
        identity = (
            session.scalar(_activation_lock_statements(dialect)[0])
            if dialect is not None
            else session.get(EdgeIdentity, 1)
        )
        try:
            material = self._identity_provider()
        except Exception:
            raise TelemetryAuthorityError("identity_not_eligible") from None
        if (
            identity is None
            or identity.status != "paired"
            or not identity.credential_id
            or not identity.certificate_sha256
            or type(identity.telemetry_authorization_revision) is not int
            or material.get("status") != "paired"
            or material.get("installationId") != identity.installation_id
            or material.get("credentialId") != identity.credential_id
            or material.get("certificateSha256") != identity.certificate_sha256
            or not isinstance(material.get("certificatePem"), str)
            or not isinstance(material.get("privateKeyPem"), str)
        ):
            raise TelemetryAuthorityError("identity_not_eligible")
        return identity, material

    def enabled_revision(self) -> int | None:
        with self._session_factory() as session:
            identity = session.get(EdgeIdentity, 1)
            row = session.get(TelemetryAuthorityActivation, 1)
            if row is None:
                return None
            if (
                identity is None
                or row.status != "enabled"
                or row.enable_request_bytes is None
                or row.enable_response_bytes is None
                or row.request_sha256 is None
                or row.response_sha256 is None
                or row.installation_id != identity.installation_id
                or row.credential_id != identity.credential_id
                or row.certificate_sha256 != identity.certificate_sha256
                or row.telemetry_authorization_revision != identity.telemetry_authorization_revision
            ):
                raise TelemetryAuthorityError("durable_activation_conflict")
            try:
                capability, _, _ = _stored_capability(
                    row.capability_bytes, row.capability_sha256, identity.installation_id
                )
                if not hmac.compare_digest(
                    hashlib.sha256(row.enable_request_bytes).digest(), row.request_sha256
                ) or not hmac.compare_digest(
                    hashlib.sha256(row.enable_response_bytes).digest(), row.response_sha256
                ):
                    raise TelemetryAuthorityError("durable_activation_conflict")
                request = _document(row.enable_request_bytes, _ENABLE_REQUEST_FIELDS)
                response = self._validate_response(
                    row.enable_response_bytes, capability, request, identity
                )
                if self._aware(row.enabled_at) != _timestamp(response["enabledAt"]):
                    raise TelemetryAuthorityError("durable_activation_conflict")
            except (TelemetryAuthorityError, ValueError, TypeError) as error:
                raise TelemetryAuthorityError("durable_activation_conflict") from error
            return row.telemetry_authorization_revision

    def _validate_response(
        self, raw: bytes, cap: dict[str, Any], request: dict[str, Any], identity: EdgeIdentity
    ) -> dict[str, Any]:
        response = _document(raw, _ENABLE_RESPONSE_FIELDS)
        aliases = ("installationId", "protocolId", *PINNED_SCHEMA_HASHES, "issuedAt", "expiresAt")
        if (
            response["protocol"] != "2.0"
            or response["status"] != "enabled"
            or response["requestId"] != request["requestId"]
            or any(response[key] != cap[key] for key in aliases)
            or response["capabilitySha256"] != request["capabilitySha256"]
            or response["capabilityServerNonce"] != cap["serverNonce"]
            or type(response["telemetryAuthorizationRevision"]) is not int
            or response["telemetryAuthorizationRevision"]
            != identity.telemetry_authorization_revision
        ):
            raise TelemetryAuthorityError("enable_response_conflict")
        _timestamp(response["enabledAt"])
        return response

    def activate(self) -> bytes:
        now = self._aware(self._clock())
        request_bytes: bytes
        request: dict[str, Any]
        capability: dict[str, Any]
        with self._session_factory() as session:
            dialect = _begin_write(session)
            identity, material = self._current(session, dialect)
            row = session.scalar(_activation_lock_statements(dialect)[1])
            current_tuple = (
                identity.installation_id,
                identity.credential_id,
                identity.certificate_sha256,
                identity.telemetry_authorization_revision,
            )
            if row is not None and row.status == "enabled":
                stored_tuple = (
                    row.installation_id,
                    row.credential_id,
                    row.certificate_sha256,
                    row.telemetry_authorization_revision,
                )
                if stored_tuple == current_tuple:
                    if (
                        row.enable_request_bytes is None
                        or row.request_sha256 is None
                        or row.enable_response_bytes is None
                        or row.response_sha256 is None
                        or not hmac.compare_digest(
                            hashlib.sha256(row.enable_request_bytes).digest(), row.request_sha256
                        )
                        or not hmac.compare_digest(
                            hashlib.sha256(row.enable_response_bytes).digest(), row.response_sha256
                        )
                    ):
                        raise TelemetryAuthorityError("durable_activation_conflict")
                    capability, _, _ = _stored_capability(
                        row.capability_bytes, row.capability_sha256, identity.installation_id
                    )
                    request = _document(row.enable_request_bytes, _ENABLE_REQUEST_FIELDS)
                    self._validate_response(
                        row.enable_response_bytes, capability, request, identity
                    )
                    return bytes(row.enable_response_bytes)

                capability_bytes = self._client.get_capability(
                    material["certificatePem"], material["privateKeyPem"]
                )
                capability, issued, expires = _capability(
                    capability_bytes, identity.installation_id
                )
                if not issued <= now < expires:
                    raise TelemetryAuthorityError("capability_not_current")
                row.installation_id = identity.installation_id
                row.credential_id = identity.credential_id
                row.certificate_sha256 = identity.certificate_sha256
                row.telemetry_authorization_revision = identity.telemetry_authorization_revision
                row.capability_bytes = capability_bytes
                row.capability_sha256 = hashlib.sha256(capability_bytes).digest()
                row.server_nonce = _unb64(capability["serverNonce"])
                row.issued_at = issued
                row.expires_at = expires
                row.enable_request_bytes = None
                row.request_sha256 = None
                row.enable_response_bytes = None
                row.response_sha256 = None
                row.status = "capability_stored"
                row.enabled_at = None
                row.updated_at = now
                session.commit()
            elif row is None:
                capability_bytes = self._client.get_capability(
                    material["certificatePem"], material["privateKeyPem"]
                )
                capability, issued, expires = _capability(
                    capability_bytes, identity.installation_id
                )
                if not issued <= now < expires:
                    raise TelemetryAuthorityError("capability_not_current")
                row = TelemetryAuthorityActivation(
                    id=1,
                    installation_id=identity.installation_id,
                    credential_id=identity.credential_id,
                    certificate_sha256=identity.certificate_sha256,
                    telemetry_authorization_revision=identity.telemetry_authorization_revision,
                    capability_bytes=capability_bytes,
                    capability_sha256=hashlib.sha256(capability_bytes).digest(),
                    server_nonce=_unb64(capability["serverNonce"]),
                    issued_at=issued,
                    expires_at=expires,
                    enable_request_bytes=None,
                    request_sha256=None,
                    enable_response_bytes=None,
                    response_sha256=None,
                    status="capability_stored",
                    enabled_at=None,
                    updated_at=now,
                )
                session.add(row)
                session.commit()

            if row.status == "enable_requested":
                if (
                    (
                        row.installation_id,
                        row.credential_id,
                        row.certificate_sha256,
                        row.telemetry_authorization_revision,
                    )
                    != current_tuple
                    or row.enable_request_bytes is None
                    or row.request_sha256 is None
                ):
                    raise TelemetryAuthorityError("durable_activation_conflict")
                capability, _, _ = _stored_capability(
                    row.capability_bytes, row.capability_sha256, identity.installation_id
                )
                request_bytes = bytes(row.enable_request_bytes)
                if not hmac.compare_digest(
                    hashlib.sha256(request_bytes).digest(), row.request_sha256
                ):
                    raise TelemetryAuthorityError("durable_activation_conflict")
                request = _document(request_bytes, _ENABLE_REQUEST_FIELDS)
            elif row.status == "capability_stored":
                if (
                    row.installation_id,
                    row.credential_id,
                    row.certificate_sha256,
                    row.telemetry_authorization_revision,
                ) != current_tuple:
                    raise TelemetryAuthorityError("durable_activation_conflict")
                capability, issued, expires = _stored_capability(
                    row.capability_bytes, row.capability_sha256, identity.installation_id
                )
                if not issued <= now < expires:
                    raise TelemetryAuthorityError("capability_not_current")
                edge_nonce = self._nonce_factory()
                if not isinstance(edge_nonce, bytes) or len(edge_nonce) != 32:
                    raise TelemetryAuthorityError("invalid_edge_nonce")
                request = {
                    "protocol": "2.0",
                    "requestId": _uuid(self._uuid_factory()),
                    "installationId": identity.installation_id,
                    "currentCredentialId": identity.credential_id,
                    "currentCertificateSha256": identity.certificate_sha256,
                    "protocolId": PROTOCOL_ID,
                    **PINNED_SCHEMA_HASHES,
                    "capabilitySha256": _b64(row.capability_sha256),
                    "capabilityServerNonce": capability["serverNonce"],
                    "issuedAt": capability["issuedAt"],
                    "expiresAt": capability["expiresAt"],
                    "expectedTelemetryAuthorizationRevision": (
                        identity.telemetry_authorization_revision
                    ),
                    "edgeNonce": _b64(edge_nonce),
                }
                signature = self._signer(build_enable_preimage(request))
                if not isinstance(signature, bytes) or len(signature) != 64:
                    raise TelemetryAuthorityError("invalid_signature")
                request["signature"] = _b64(signature)
                request_bytes = canonical_json(request)
                with self._session_factory() as request_session:
                    request_dialect = _begin_write(request_session)
                    self._current(request_session, request_dialect)
                    durable = request_session.scalar(
                        _activation_lock_statements(request_dialect)[1]
                    )
                    if (
                        durable is None
                        or durable.status != "capability_stored"
                        or durable.capability_bytes != row.capability_bytes
                        or (
                            durable.installation_id,
                            durable.credential_id,
                            durable.certificate_sha256,
                            durable.telemetry_authorization_revision,
                        )
                        != current_tuple
                    ):
                        raise TelemetryAuthorityError("durable_activation_conflict")
                    durable.enable_request_bytes = request_bytes
                    durable.request_sha256 = hashlib.sha256(request_bytes).digest()
                    durable.status = "enable_requested"
                    durable.updated_at = now
                    request_session.commit()
            else:
                raise TelemetryAuthorityError("durable_activation_conflict")

        response_bytes = self._client.enable(
            request_bytes, material["certificatePem"], material["privateKeyPem"]
        )
        with self._session_factory() as session:
            dialect = _begin_write(session)
            identity, _ = self._current(session, dialect)
            row = session.scalar(_activation_lock_statements(dialect)[1])
            if (
                row is None
                or row.status != "enable_requested"
                or row.enable_request_bytes != request_bytes
            ):
                raise TelemetryAuthorityError("durable_activation_conflict")
            capability, _, _ = _stored_capability(
                row.capability_bytes, row.capability_sha256, identity.installation_id
            )
            response = self._validate_response(response_bytes, capability, request, identity)
            row.enable_response_bytes = response_bytes
            row.response_sha256 = hashlib.sha256(response_bytes).digest()
            row.status = "enabled"
            row.enabled_at = _timestamp(response["enabledAt"])
            row.updated_at = self._aware(self._clock())
            session.commit()
        return response_bytes
