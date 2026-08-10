from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from threading import RLock
from typing import Any

from sqlalchemy import delete, select

from .models import Audit, EdgeIdentity, EdgePairing, now, uid

_AUDIT_ACTIONS = {
    "pairing.cancel",
    "pairing.initial.start",
    "pairing.reconcile",
    "pairing.refresh",
    "pairing.renewal",
    "pairing.repair.start",
    "pairing.reset",
    "pairing.rotate",
    "pairing.transition",
}
_ACTOR = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}", re.ASCII)

_DATETIME_FIELDS = {
    "registrationExpiresAt": "registration_expires_at",
    "codeExpiresAt": "code_expires_at",
    "claimExpiresAt": "claim_expires_at",
    "issuanceExpiresAt": "issuance_expires_at",
    "ackExpiresAt": "ack_expires_at",
}
_PAIRING_FIELDS = {
    "centralSessionRevision": "central_session_revision",
    "mode": "mode",
    "status": "status",
    "registrationRequestId": "registration_request_id",
    "sessionId": "session_id",
    "tokenGeneration": "token_generation",
    "candidateSpkiSha256": "candidate_spki_sha256",
    "csrSha256": "csr_sha256",
    "tenantId": "tenant_id",
    "siteId": "site_id",
    "claimRevision": "claim_revision",
    "installationRevision": "installation_revision",
    "credentialId": "credential_id",
    "certificateSha256": "certificate_sha256",
    "lastError": "last_error",
}


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _parse_datetime(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    else:
        raise ValueError("invalid persisted pairing deadline")
    if parsed.tzinfo is None:
        raise ValueError("naive persisted pairing deadline")
    return parsed.astimezone(UTC)


class PairingRepository:
    """Transactional singleton repository for public Edge pairing state."""

    def __init__(self, session_factory) -> None:
        self._session_factory = session_factory
        self._lock = RLock()
        self.audit_capable = True

    @staticmethod
    def _state(identity: EdgeIdentity, pairing: EdgePairing | None) -> dict[str, Any]:
        state: dict[str, Any] = {
            "installationId": identity.installation_id,
            "status": identity.status,
            "revision": identity.revision,
        }
        if identity.active_spki_sha256 is not None:
            state["activeSpkiSha256"] = identity.active_spki_sha256
        if identity.credential_id is not None:
            state["credentialId"] = identity.credential_id
        if identity.certificate_sha256 is not None:
            state["certificateSha256"] = identity.certificate_sha256
        if identity.certificate_not_after is not None:
            state["certificateNotAfter"] = _aware(identity.certificate_not_after).isoformat()
        if identity.installation_revision is not None:
            state["installationRevision"] = identity.installation_revision
        if identity.renewal_status is not None:
            state["renewalStatus"] = identity.renewal_status
        if identity.renewal_request_id is not None:
            state["renewalRequestId"] = identity.renewal_request_id
        if identity.renewal_issuance_expires_at is not None:
            state["renewalIssuanceExpiresAt"] = _aware(
                identity.renewal_issuance_expires_at
            ).isoformat()
        if identity.renewal_ack_expires_at is not None:
            state["renewalAckExpiresAt"] = _aware(identity.renewal_ack_expires_at).isoformat()
        if pairing is None:
            return state
        state["revision"] = pairing.revision
        for public, column in _PAIRING_FIELDS.items():
            value = getattr(pairing, column)
            if value is not None:
                state[public] = value
        for public, column in _DATETIME_FIELDS.items():
            value = _aware(getattr(pairing, column))
            if value is not None:
                state[public] = value.isoformat()
        return state

    def load(self) -> dict[str, Any]:
        with self._lock, self._session_factory() as session:
            identity = session.get(EdgeIdentity, 1)
            if identity is None:
                raise RuntimeError("edge identity is not initialized")
            pairing = session.get(EdgePairing, 1)
            return self._state(identity, pairing)

    def save(
        self,
        state: dict[str, Any],
        *,
        actor_id: str = "system:edge-worker",
        action: str = "pairing.transition",
    ) -> dict[str, Any]:
        """Replace public state in one transaction, incrementing its revision."""
        if (
            action not in _AUDIT_ACTIONS
            or not isinstance(actor_id, str)
            or not _ACTOR.fullmatch(actor_id)
        ):
            raise ValueError("invalid pairing audit metadata")
        with self._lock, self._session_factory() as session:
            identity = session.scalar(
                select(EdgeIdentity).where(EdgeIdentity.id == 1).with_for_update()
            )
            if identity is None:
                raise RuntimeError("edge identity is not initialized")
            installation_id = state.get("installationId")
            if installation_id != identity.installation_id:
                raise ValueError("public pairing installation binding mismatch")
            pairing = session.scalar(
                select(EdgePairing).where(EdgePairing.id == 1).with_for_update()
            )
            previous = self._state(identity, pairing)
            desired = {key: value for key, value in state.items() if key != "revision"}
            current = {key: value for key, value in previous.items() if key != "revision"}
            if desired == current:
                return previous
            next_revision = (pairing.revision if pairing else identity.revision) + 1
            registration_id = state.get("registrationRequestId")
            if registration_id is None:
                if pairing is not None:
                    session.delete(pairing)
            else:
                if pairing is None:
                    pairing = EdgePairing(
                        id=1,
                        revision=next_revision,
                        mode=state["mode"],
                        status=state["status"],
                        registration_request_id=registration_id,
                        token_generation=state.get("tokenGeneration", 0),
                        candidate_spki_sha256=state["candidateSpkiSha256"],
                        csr_sha256=state["csrSha256"],
                        updated_at=now(),
                    )
                    session.add(pairing)
                pairing.revision = next_revision
                for public, column in _PAIRING_FIELDS.items():
                    setattr(pairing, column, state.get(public))
                for public, column in _DATETIME_FIELDS.items():
                    setattr(pairing, column, _parse_datetime(state.get(public)))
                pairing.updated_at = now()
            identity.status = state["status"]
            identity.revision = next_revision
            identity.credential_id = state.get("credentialId")
            identity.certificate_sha256 = state.get("certificateSha256")
            identity.active_spki_sha256 = state.get("activeSpkiSha256")
            identity.certificate_not_after = _parse_datetime(state.get("certificateNotAfter"))
            identity.installation_revision = state.get("installationRevision")
            identity.renewal_status = state.get("renewalStatus")
            identity.renewal_request_id = state.get("renewalRequestId")
            identity.renewal_issuance_expires_at = _parse_datetime(
                state.get("renewalIssuanceExpiresAt")
            )
            identity.renewal_ack_expires_at = _parse_datetime(state.get("renewalAckExpiresAt"))
            identity.updated_at = now()
            changed = sorted(
                key
                for key in set(current) | set(desired)
                if key != "installationId" and current.get(key) != desired.get(key)
            )
            detail: dict[str, Any] = {"changed": changed}
            if previous.get("status") != state.get("status"):
                detail.update(fromStatus=previous.get("status"), toStatus=state.get("status"))
            if previous.get("mode") != state.get("mode"):
                detail.update(fromMode=previous.get("mode"), toMode=state.get("mode"))
            session.add(
                Audit(
                    id=uid("audit"),
                    actor_id=actor_id,
                    action=action,
                    object_id=identity.installation_id,
                    revision=next_revision,
                    fields_json=json.dumps(detail, sort_keys=True, separators=(",", ":")),
                )
            )
            session.commit()
        return self.load()

    def clear_pairing(self, status: str) -> dict[str, Any]:
        with self._lock, self._session_factory() as session:
            identity = session.scalar(
                select(EdgeIdentity).where(EdgeIdentity.id == 1).with_for_update()
            )
            if identity is None:
                raise RuntimeError("edge identity is not initialized")
            session.execute(delete(EdgePairing).where(EdgePairing.id == 1))
            identity.status = status
            identity.revision += 1
            identity.updated_at = now()
            session.commit()
        return self.load()
