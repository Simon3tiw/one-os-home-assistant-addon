from __future__ import annotations

import base64
import hashlib
import re
import secrets
import struct
from datetime import UTC, datetime, timedelta
from functools import wraps
from threading import RLock
from typing import Any, Protocol
from uuid import UUID, uuid4

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID

from .central_pairing_client import CentralDeviceRevokedError
from .pairing_crypto import (
    build_certificate_ack_preimage,
    build_claim_pop_preimage,
    build_first_pop_preimage,
    generate_pairing_code,
    normalize_pairing_code,
    sign_low_s,
)
from .pairing_storage import IdentityStore, UnsafeIdentityStorage


class PairingError(RuntimeError):
    pass


class CentralPairingClient(Protocol):
    def register(self, body: dict[str, Any]) -> dict[str, Any]: ...

    def proof(
        self, session_id: str, bootstrap_token: str, body: dict[str, Any]
    ) -> dict[str, Any]: ...

    def result(self, session_id: str, bootstrap_token: str) -> dict[str, Any]: ...

    def cancel(
        self, session_id: str, bootstrap_token: str, expected_session_revision: int
    ) -> dict[str, Any]: ...

    def claim_proof(
        self, session_id: str, bootstrap_token: str, body: dict[str, Any]
    ) -> dict[str, Any]: ...

    def ack(
        self,
        body: dict[str, Any],
        certificate_pem: str,
        private_key_pem: str,
        bootstrap_token: str,
    ) -> dict[str, Any]: ...

    def device_status(self, certificate_pem: str, private_key_pem: str) -> dict[str, Any]: ...

    def start_renewal(
        self, body: dict[str, Any], certificate_pem: str, private_key_pem: str
    ) -> dict[str, Any]: ...

    def renewal_result(
        self, request_id: str, certificate_pem: str, private_key_pem: str
    ) -> dict[str, Any]: ...

    def ack_renewal(
        self,
        request_id: str,
        body: dict[str, Any],
        certificate_pem: str,
        private_key_pem: str,
    ) -> dict[str, Any]: ...


def _serialized(method):
    @wraps(method)
    def locked(self, *args, **kwargs):
        with self._operation_lock:
            actor_id = kwargs.pop("actor_id", None)
            root_operation = self._audit_depth == 0
            if root_operation:
                self._audit_actor = actor_id or "system:edge-worker"
                if method.__name__ == "start":
                    mode = args[0] if args else kwargs.get("mode")
                    self._audit_action = f"pairing.{mode}.start"
                else:
                    self._audit_action = {
                        "cancel": "pairing.cancel",
                        "maintain_device": "pairing.renewal",
                        "refresh": "pairing.refresh",
                        "reset": "pairing.reset",
                        "rotate_key": "pairing.rotate",
                    }.get(method.__name__, "pairing.transition")
            self._audit_depth += 1
            try:
                return method(self, *args, **kwargs)
            finally:
                self._audit_depth -= 1
                if root_operation:
                    self._audit_actor = "system:edge-worker"
                    self._audit_action = "pairing.transition"

    return locked


def _b64u(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _renewal_fields(domain: str, fields: list[tuple[int, bytes]]) -> bytes:
    return (
        domain.encode("ascii")
        + b"\0"
        + b"".join(struct.pack(">HI", tag, len(value)) + value for tag, value in fields)
    )


def build_renewal_proof_preimage(
    *,
    protocol: str,
    request_id: str,
    installation_id: str,
    current_credential_id: str,
    current_certificate_sha256: bytes,
    csr_sha256: bytes,
    edge_nonce: bytes,
    epoch_minute: int,
    installation_revision: int,
) -> bytes:
    if (
        protocol != "1.0"
        or any(len(value) != 32 for value in (current_certificate_sha256, csr_sha256, edge_nonce))
        or any(
            not 0 <= value <= 0xFFFFFFFFFFFFFFFF for value in (epoch_minute, installation_revision)
        )
    ):
        raise ValueError("invalid renewal proof input")
    return _renewal_fields(
        "ONE.OS-DEVICE-RENEW-V1",
        [
            (1, b"1.0"),
            (2, UUID(installation_id).bytes),
            (3, UUID(current_credential_id).bytes),
            (4, current_certificate_sha256),
            (5, UUID(request_id).bytes),
            (6, csr_sha256),
            (7, edge_nonce),
            (8, epoch_minute.to_bytes(8, "big")),
            (9, installation_revision.to_bytes(8, "big")),
        ],
    )


def build_renewal_ack_preimage(
    *,
    protocol: str,
    installation_id: str,
    old_credential_id: str,
    old_certificate_sha256: bytes,
    new_credential_id: str,
    new_certificate_sha256: bytes,
    request_id: str,
    ack_expires_epoch_seconds: int,
    installation_revision: int,
) -> bytes:
    if (
        protocol != "1.0"
        or any(len(value) != 32 for value in (old_certificate_sha256, new_certificate_sha256))
        or any(
            not 0 <= value <= 0xFFFFFFFFFFFFFFFF
            for value in (ack_expires_epoch_seconds, installation_revision)
        )
    ):
        raise ValueError("invalid renewal ACK input")
    return _renewal_fields(
        "ONE.OS-DEVICE-RENEW-ACK-V1",
        [
            (1, b"1.0"),
            (2, UUID(installation_id).bytes),
            (3, UUID(old_credential_id).bytes),
            (4, old_certificate_sha256),
            (5, UUID(new_credential_id).bytes),
            (6, new_certificate_sha256),
            (7, UUID(request_id).bytes),
            (8, ack_expires_epoch_seconds.to_bytes(8, "big")),
            (9, installation_revision.to_bytes(8, "big")),
        ],
    )


def _decode_b64u(value: str, expected: int) -> bytes:
    if not isinstance(value, str) or "=" in value:
        raise PairingError("invalid_base64url")
    try:
        result = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except ValueError as error:
        raise PairingError("invalid_base64url") from error
    if len(result) != expected:
        raise PairingError("invalid_base64url_length")
    return result


_RFC3339 = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})",
    re.ASCII,
)


def _parse_time(value: str) -> datetime:
    if not isinstance(value, str) or not _RFC3339.fullmatch(value):
        raise PairingError("invalid_timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise PairingError("invalid_timestamp") from error
    if parsed.tzinfo is None:
        raise PairingError("invalid_timestamp")
    return parsed.astimezone(UTC)


def _deadline(value: Any) -> tuple[datetime, int]:
    """Return a deadline and the exact whole UTC epoch second signed on the wire."""
    if type(value) is int:
        try:
            return datetime.fromtimestamp(value, UTC), value
        except (OverflowError, OSError, ValueError) as error:
            raise PairingError("invalid_timestamp") from error
    parsed = _parse_time(value)
    epoch = int(parsed.timestamp())
    if datetime.fromtimestamp(epoch, UTC) != parsed:
        raise PairingError("invalid_timestamp")
    return parsed, epoch


def _pem_certificates(value: str) -> list[x509.Certificate]:
    if not isinstance(value, str) or len(value) > 32768:
        raise PairingError("invalid_certificate_chain")
    marker = "-----END CERTIFICATE-----"
    parts = value.split(marker)
    if not parts or parts[-1] not in {"", "\n"}:
        raise PairingError("invalid_certificate_chain")
    certificates = []
    try:
        for part in parts[:-1]:
            certificates.append(
                x509.load_pem_x509_certificate((part + marker + "\n").encode("ascii"))
            )
    except (ValueError, UnicodeEncodeError) as error:
        raise PairingError("invalid_certificate_chain") from error
    if not certificates:
        raise PairingError("invalid_certificate_chain")
    return certificates


def _verify_certificate_signature(certificate: x509.Certificate, issuer: x509.Certificate) -> None:
    key = issuer.public_key()
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise PairingError("invalid_issuer_key")
    if certificate.issuer != issuer.subject:
        raise PairingError("invalid_certificate_issuer")
    try:
        key.verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            ec.ECDSA(certificate.signature_hash_algorithm),
        )
    except Exception as error:
        raise PairingError("invalid_certificate_signature") from error


def validate_issued_credential(
    private_key: ec.EllipticCurvePrivateKey,
    certificate_pem: str,
    chain_pem: str,
    certificate_sha256: str,
    installation_id: str,
    tenant_id: str,
    site_id: str,
    at: datetime,
) -> x509.Certificate:
    if at.tzinfo is None:
        raise PairingError("untrusted_clock")
    try:
        UUID(installation_id)
        leaf = x509.load_pem_x509_certificate(certificate_pem.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as error:
        raise PairingError("invalid_issued_certificate") from error
    chain = _pem_certificates(chain_pem)
    expected_digest = _decode_b64u(certificate_sha256, 32)
    if not secrets.compare_digest(
        hashlib.sha256(leaf.public_bytes(serialization.Encoding.DER)).digest(), expected_digest
    ):
        raise PairingError("certificate_fingerprint_mismatch")
    expected_spki = private_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    actual_key = leaf.public_key()
    if not isinstance(actual_key, ec.EllipticCurvePublicKey) or not isinstance(
        actual_key.curve, ec.SECP256R1
    ):
        raise PairingError("invalid_leaf_key")
    actual_spki = actual_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    if not secrets.compare_digest(expected_spki, actual_spki):
        raise PairingError("certificate_key_mismatch")

    try:
        basic = leaf.extensions.get_extension_for_class(x509.BasicConstraints).value
        usage = leaf.extensions.get_extension_for_class(x509.KeyUsage).value
        extended = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound as error:
        raise PairingError("missing_leaf_extension") from error
    if (
        basic.ca
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
    ):
        raise PairingError("invalid_leaf_key_usage")
    if list(extended) != [ExtendedKeyUsageOID.CLIENT_AUTH]:
        raise PairingError("invalid_leaf_extended_key_usage")
    expected_uri = (
        f"spiffe://one-os/tenants/{tenant_id}/sites/{site_id}/installations/{installation_id}"
    )
    if san.get_values_for_type(x509.UniformResourceIdentifier) != [expected_uri] or len(san) != 1:
        raise PairingError("invalid_leaf_san")

    moment = at.astimezone(UTC)
    not_before = leaf.not_valid_before_utc
    not_after = leaf.not_valid_after_utc
    if (
        not_before > moment
        or not_after <= moment
        or not_after - not_before > timedelta(days=30, minutes=5)
    ):
        raise PairingError("invalid_leaf_validity")
    issuer = chain[0]
    if not_after > issuer.not_valid_after_utc:
        raise PairingError("leaf_outlives_issuer")
    _verify_certificate_signature(leaf, issuer)
    for index, certificate in enumerate(chain):
        try:
            constraints = certificate.extensions.get_extension_for_class(
                x509.BasicConstraints
            ).value
            key_usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
        except x509.ExtensionNotFound as error:
            raise PairingError("missing_ca_extension") from error
        if not constraints.ca or not key_usage.key_cert_sign or not key_usage.crl_sign:
            raise PairingError("invalid_ca_constraints")
        if certificate.not_valid_before_utc > moment or certificate.not_valid_after_utc <= moment:
            raise PairingError("invalid_ca_validity")
        parent = chain[index + 1] if index + 1 < len(chain) else certificate
        _verify_certificate_signature(certificate, parent)
    return leaf


class PairingBackend:
    """Crash-recoverable Edge half of the V1 pairing state machine."""

    def __init__(
        self,
        store: IdentityStore,
        central: CentralPairingClient,
        public_state: dict[str, Any] | None = None,
        clock=lambda: datetime.now(UTC),
        repository=None,
    ):
        self.store = store
        self.central = central
        self.repository = repository
        self.state = public_state if public_state is not None else {}
        self.clock = clock
        self._operation_lock = RLock()
        self._audit_actor = "system:edge-worker"
        self._audit_action = "pairing.reconcile"
        self._audit_depth = 0
        if self.repository is not None:
            self.state.clear()
            self.state.update(self.repository.load())
            self._reconcile_local_secrets()

    def _persist(self, candidate: dict[str, Any]) -> None:
        if self.repository is None:
            persisted = candidate
        else:
            try:
                if getattr(self.repository, "audit_capable", False):
                    persisted = self.repository.save(
                        candidate, actor_id=self._audit_actor, action=self._audit_action
                    )
                else:
                    persisted = self.repository.save(candidate)
            except Exception:
                authoritative = self.repository.load()
                self.state.clear()
                self.state.update(authoritative)
                if self._audit_action.endswith(".start") and authoritative.get("status") not in {
                    "registering",
                    "registered",
                    "pop_verified",
                    "claimed",
                    "claim_proved",
                    "issued",
                }:
                    self.store.delete_transient()
                    self.store.delete_candidate()
                    self.store.delete_renewal()
                raise
        self.state.clear()
        self.state.update(persisted)

    def _replace_state(self, values: dict[str, Any]) -> None:
        self._persist(dict(values))

    def _update_state(self, **values: Any) -> None:
        self._persist(self.state | values)

    def _expected_transient_binding(self) -> dict[str, Any]:
        expected = {
            key: self.state[key]
            for key in ("installationId", "registrationRequestId", "sessionId")
            if self.state.get(key) is not None
        }
        if self.state.get("candidateSpkiSha256") is not None:
            expected["spkiSha256"] = self.state["candidateSpkiSha256"]
        return expected

    def _read_transient(self) -> dict[str, Any] | None:
        return self.store.read_transient(expected=self._expected_transient_binding())

    def _reconcile_local_secrets(self) -> None:
        status = self.state.get("status")
        if status == "identity_missing_after_restore":
            return
        if status == "compromised":
            try:
                self.store.load_identity()
                self.store.read_identity_credential()
            except (UnsafeIdentityStorage, OSError, UnicodeError):
                self._update_state(status="identity_missing_after_restore", lastError=None)
                return
            self.store.delete_transient()
            self.store.delete_candidate()
            return
        if status in {"unpaired", "cancelled", "expired", "revoked"}:
            transient = self.store.read_transient()
            if (
                status == "unpaired"
                and transient
                and transient.get("installationId") == self.state.get("installationId")
                and transient.get("sessionId")
                and transient.get("bootstrapToken")
            ):
                self._restore_registered_intent(transient)
            else:
                self.store.delete_transient()
                self.store.delete_candidate()
            return
        try:
            transient = self._read_transient()
            if status in {"registering", "registered"} and transient and transient.get("sessionId"):
                self._restore_registered_intent(transient)
                status = self.state.get("status")
            if status == "paired":
                self.store.load_identity()
                self.store.read_identity_credential()
                self.store.delete_transient()
                self.store.delete_candidate()
            else:
                if transient is None:
                    raise UnsafeIdentityStorage("missing or mismatched transient secret")
                try:
                    self.store.load_candidate()
                    if status == "issued":
                        self.store.read_candidate_credential()
                except UnsafeIdentityStorage:
                    if status != "issued":
                        raise
                    if self.store.promotion_in_progress():
                        self.store.promote_candidate()
                    self.store.load_identity()
                    self.store.read_identity_credential()
        except (UnsafeIdentityStorage, OSError, UnicodeError):
            self._update_state(status="identity_missing_after_restore", lastError=None)

    def _restore_registered_intent(self, record: dict[str, Any]) -> None:
        required = {
            "mode",
            "registrationRequestId",
            "sessionId",
            "tokenGeneration",
            "spkiSha256",
            "csrSha256",
            "registrationExpiresAt",
            "centralSessionRevision",
        }
        if not required.issubset(record):
            self.store.delete_transient()
            self.store.delete_candidate()
            return
        self.store.load_candidate()
        restored = {
            "installationId": record["installationId"],
            "mode": record["mode"],
            "status": "pop_verified" if record.get("codeExpiresAt") else "registered",
            "registrationRequestId": record["registrationRequestId"],
            "sessionId": record["sessionId"],
            "tokenGeneration": record["tokenGeneration"],
            "candidateSpkiSha256": record["spkiSha256"],
            "csrSha256": record["csrSha256"],
            "registrationExpiresAt": record["registrationExpiresAt"],
            "centralSessionRevision": record["centralSessionRevision"],
        }
        if record.get("codeExpiresAt"):
            restored["codeExpiresAt"] = record["codeExpiresAt"]
        self._replace_state(restored)

    def status(self) -> dict[str, Any]:
        return {key: value for key, value in self.state.items() if key not in {"code", "secrets"}}

    def _current_material(self) -> tuple[str, str]:
        certificate, chain = self.store.read_identity_credential()
        return certificate + chain, self.store.identity_private_pem()

    def _assert_device_status(self, response: dict[str, Any]) -> None:
        expected = {
            "installationId": self.state.get("installationId"),
            "status": "paired",
            "credentialId": self.state.get("credentialId"),
            "certificateSha256": self.state.get("certificateSha256"),
            "installationRevision": self.state.get("installationRevision"),
        }
        if any(response.get(key) != value for key, value in expected.items()):
            self._update_state(status="compromised", lastError=None)
            raise PairingError("device_generation_drift")

    def _renewal_due(self) -> bool:
        remaining = _parse_time(self.state.get("certificateNotAfter")) - self.clock().astimezone(
            UTC
        )
        if remaining <= timedelta(hours=48):
            self._update_state(status="compromised", lastError=None)
            raise PairingError("renewal_safety_window_missed")
        return remaining <= timedelta(days=6)

    def _send_renewal_start(self, record: dict[str, Any]) -> None:
        certificate, private_key = self._current_material()
        try:
            response = self.central.start_renewal(record["startRequest"], certificate, private_key)
        except Exception as error:
            raise PairingError("central_renewal_unreachable") from error
        request = record["startRequest"]
        if (
            response.get("requestId") != request["requestId"]
            or response.get("installationId") != request["installationId"]
            or response.get("installationRevision") != request["installationRevision"]
            or response.get("status") not in {"pending", "issuing"}
        ):
            raise PairingError("invalid_renewal_response")
        record.update(status="pending", issuanceExpiresAt=response.get("issuanceExpiresAt"))
        self.store.write_renewal(record)
        self._update_state(
            renewalStatus="pending",
            renewalRequestId=request["requestId"],
            renewalIssuanceExpiresAt=response.get("issuanceExpiresAt"),
        )

    def _start_renewal(self) -> None:
        key = self.store.create_renewal_candidate()
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([]))
            .sign(key, hashes.SHA256())
            .public_bytes(serialization.Encoding.DER)
        )
        request_id, nonce = str(uuid4()), secrets.token_bytes(32)
        csr_hash = hashlib.sha256(csr).digest()
        epoch_minute = int(self.clock().astimezone(UTC).timestamp()) // 60
        revision = self.state.get("installationRevision")
        if type(revision) is not int:
            raise PairingError("device_generation_drift")
        body = {
            "protocol": "1.0",
            "requestId": request_id,
            "installationId": self.state["installationId"],
            "currentCredentialId": self.state["credentialId"],
            "currentCertificateSha256": self.state["certificateSha256"],
            "csrDer": _b64u(csr),
            "csrSha256": _b64u(csr_hash),
            "edgeNonce": _b64u(nonce),
            "epochMinute": epoch_minute,
            "installationRevision": revision,
        }
        body["signature"] = _b64u(
            sign_low_s(
                self.store.load_identity(),
                build_renewal_proof_preimage(
                    protocol="1.0",
                    request_id=request_id,
                    installation_id=body["installationId"],
                    current_credential_id=body["currentCredentialId"],
                    current_certificate_sha256=_decode_b64u(body["currentCertificateSha256"], 32),
                    csr_sha256=csr_hash,
                    edge_nonce=nonce,
                    epoch_minute=epoch_minute,
                    installation_revision=revision,
                ),
            )
        )
        record = {"status": "starting", "startRequest": body}
        self.store.write_renewal(record)
        self._update_state(renewalStatus="starting", renewalRequestId=request_id)
        self._send_renewal_start(record)

    def _poll_renewal(self, record: dict[str, Any]) -> None:
        if (
            record.get("issuanceExpiresAt")
            and _parse_time(record["issuanceExpiresAt"]) <= self.clock()
        ):
            self.store.delete_renewal()
            self._update_state(renewalStatus=None, renewalRequestId=None)
            return
        certificate, private_key = self._current_material()
        request = record["startRequest"]
        try:
            response = self.central.renewal_result(request["requestId"], certificate, private_key)
        except Exception as error:
            raise PairingError("central_renewal_unreachable") from error
        if response.get("status") in {"pending", "issuing"}:
            return
        if response.get("status") == "expired":
            self.store.delete_renewal()
            self._update_state(renewalStatus=None, renewalRequestId=None)
            return
        expected = {
            "requestId": request["requestId"],
            "installationId": request["installationId"],
            "installationRevision": request["installationRevision"],
            "oldCredentialId": request["currentCredentialId"],
            "oldCertificateSha256": request["currentCertificateSha256"],
        }
        if response.get("status") != "issued" or any(
            response.get(k) != v for k, v in expected.items()
        ):
            raise PairingError("invalid_renewal_result")
        expiry, expiry_epoch = _deadline(response.get("ackExpiresAt"))
        if expiry <= self.clock().astimezone(UTC):
            raise PairingError("renewal_ack_expired")
        key = self.store.load_renewal_candidate()
        leaf = validate_issued_credential(
            key,
            response["certificatePem"],
            response["caChainPem"],
            response["newCertificateSha256"],
            request["installationId"],
            self.state["tenantId"],
            self.state["siteId"],
            self.clock(),
        )
        self.store.write_renewal_credential(response["certificatePem"], response["caChainPem"])
        ack = {
            "protocol": "1.0",
            "installationId": request["installationId"],
            "oldCredentialId": request["currentCredentialId"],
            "oldCertificateSha256": request["currentCertificateSha256"],
            "newCredentialId": response["newCredentialId"],
            "newCertificateSha256": response["newCertificateSha256"],
            "requestId": request["requestId"],
            "ackExpiresEpochSeconds": expiry_epoch,
            "installationRevision": request["installationRevision"],
        }
        ack["signature"] = _b64u(
            sign_low_s(
                key,
                build_renewal_ack_preimage(
                    protocol="1.0",
                    installation_id=ack["installationId"],
                    old_credential_id=ack["oldCredentialId"],
                    old_certificate_sha256=_decode_b64u(ack["oldCertificateSha256"], 32),
                    new_credential_id=ack["newCredentialId"],
                    new_certificate_sha256=_decode_b64u(ack["newCertificateSha256"], 32),
                    request_id=ack["requestId"],
                    ack_expires_epoch_seconds=expiry_epoch,
                    installation_revision=ack["installationRevision"],
                ),
            )
        )
        record.update(
            status="ack_ready",
            issuedResult=response,
            ackRequest=ack,
            certificateNotAfter=leaf.not_valid_after_utc.isoformat(),
        )
        self.store.write_renewal(record)
        self._update_state(renewalStatus="ack_ready", renewalAckExpiresAt=expiry.isoformat())

    def _ack_renewal(self, record: dict[str, Any]) -> None:
        if _deadline(record["issuedResult"]["ackExpiresAt"])[0] <= self.clock().astimezone(UTC):
            self.store.delete_renewal()
            self._update_state(renewalStatus=None, renewalRequestId=None)
            return
        certificate, chain = self.store.read_renewal_credential()
        try:
            response = self.central.ack_renewal(
                record["ackRequest"]["requestId"],
                record["ackRequest"],
                certificate + chain,
                self.store.renewal_private_pem(),
            )
        except CentralDeviceRevokedError as error:
            self._mark_device_revoked()
            raise PairingError("device_revoked") from error
        except Exception as error:
            raise PairingError("central_renewal_ack_unreachable") from error
        ack = record["ackRequest"]
        expected = {
            "requestId": ack["requestId"],
            "installationId": ack["installationId"],
            "status": "acked",
            "installationRevision": ack["installationRevision"] + 1,
            "oldCredentialId": ack["oldCredentialId"],
            "oldCertificateSha256": ack["oldCertificateSha256"],
            "newCredentialId": ack["newCredentialId"],
            "newCertificateSha256": ack["newCertificateSha256"],
        }
        if any(response.get(key) != value for key, value in expected.items()):
            raise PairingError("invalid_renewal_ack_response")
        record.update(status="acked", ackResponse=response)
        self.store.write_renewal(record)
        self._update_state(renewalStatus="acked")
        self._finish_acked_renewal(record)

    def _finish_acked_renewal(self, record: dict[str, Any]) -> None:
        ack = record["ackRequest"]
        try:
            self.store.read_renewal_credential()
        except UnsafeIdentityStorage as error:
            certificate, _chain = self.store.read_identity_credential()
            leaf = x509.load_pem_x509_certificate(certificate.encode("ascii"))
            digest = _b64u(hashlib.sha256(leaf.public_bytes(serialization.Encoding.DER)).digest())
            if not secrets.compare_digest(digest, ack["newCertificateSha256"]):
                self._update_state(status="compromised", lastError=None)
                raise PairingError("renewal_promotion_incomplete") from error
        else:
            self.store.promote_renewal()
        response = record["ackResponse"]
        self._update_state(
            status="paired",
            credentialId=ack["newCredentialId"],
            certificateSha256=ack["newCertificateSha256"],
            certificateNotAfter=record["certificateNotAfter"],
            installationRevision=response["installationRevision"],
            renewalStatus=None,
            renewalRequestId=None,
            renewalAckExpiresAt=None,
        )
        self.store.delete_renewal()

    def _mark_device_revoked(self) -> None:
        self._update_state(
            status="revoked",
            renewalStatus=None,
            renewalRequestId=None,
            renewalIssuanceExpiresAt=None,
            renewalAckExpiresAt=None,
        )
        self.store.delete_renewal()

    @_serialized
    def maintain_device(self) -> dict[str, Any]:
        if self.state.get("status") != "paired":
            raise PairingError("device_not_paired")
        record = self.store.read_renewal()
        if record and record.get("status") == "ack_ready":
            self._ack_renewal(record)
            return self.status()
        if record and record.get("status") == "acked":
            self._finish_acked_renewal(record)
            return self.status()
        certificate, private_key = self._current_material()
        try:
            response = self.central.device_status(certificate, private_key)
        except CentralDeviceRevokedError as error:
            self._mark_device_revoked()
            raise PairingError("device_revoked") from error
        except Exception as error:
            raise PairingError("central_device_status_unreachable") from error
        self._assert_device_status(response)
        if record is None:
            if self._renewal_due():
                self._start_renewal()
        elif record.get("status") == "starting":
            self._send_renewal_start(record)
        elif record.get("status") == "pending":
            self._poll_renewal(record)
        else:
            self._update_state(status="compromised", lastError=None)
            raise PairingError("corrupt_renewal_state")
        return self.status()

    def code(self) -> dict[str, Any]:
        if self.state.get("status") != "pop_verified":
            raise PairingError("code_unavailable")
        transient = self._read_transient()
        if not transient or "displayedCode" not in transient:
            raise PairingError("code_unavailable")
        return {"code": transient["displayedCode"], "expiresAt": self.state["codeExpiresAt"]}

    @_serialized
    def start(self, mode: str, installation_id: str) -> dict[str, Any]:
        if mode not in {"initial", "repair"}:
            raise PairingError("invalid_pairing_mode")
        try:
            parsed = UUID(installation_id)
        except ValueError as error:
            raise PairingError("invalid_installation_id") from error
        if parsed.version != 4 or str(parsed) != installation_id:
            raise PairingError("invalid_installation_id")
        if mode == "initial" and (
            self.state.get("status", "unpaired") != "unpaired"
            or set(self.state) - {"installationId", "status", "revision"}
            or self.store.has_pairing_material()
        ):
            raise PairingError("initial_pairing_not_allowed")
        if self.store.read_transient() is not None:
            raise PairingError("pairing_already_active")
        if mode == "repair":
            self.store.delete_renewal()
        key = self.store.create_candidate()
        spki = key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([]))
            .sign(key, hashes.SHA256())
            .public_bytes(serialization.Encoding.DER)
        )
        shown_code = generate_pairing_code()
        normalized_code = normalize_pairing_code(shown_code)
        record = {
            "protocol": "1.0",
            "registrationRequestId": str(uuid4()),
            "recoverySecret": _b64u(secrets.token_bytes(32)),
            "mode": mode,
            "installationId": installation_id,
            "normalizedCode": normalized_code,
            "displayedCode": shown_code,
            "edgeNonce": _b64u(secrets.token_bytes(32)),
            "spkiDer": _b64u(spki),
            "spkiSha256": _b64u(hashlib.sha256(spki).digest()),
            "csrDer": _b64u(csr),
            "csrSha256": _b64u(hashlib.sha256(csr).digest()),
            "tokenGeneration": 0,
        }
        self.store.write_transient(record)
        next_state = {
            "installationId": installation_id,
            "mode": mode,
            "status": "registering",
            "registrationRequestId": record["registrationRequestId"],
            "candidateSpkiSha256": record["spkiSha256"],
            "csrSha256": record["csrSha256"],
            "tokenGeneration": 0,
        }
        if mode == "repair":
            for key in (
                "tenantId",
                "siteId",
                "credentialId",
                "certificateSha256",
                "certificateNotAfter",
                "activeSpkiSha256",
                "installationRevision",
            ):
                if key in self.state:
                    next_state[key] = self.state[key]
        self._replace_state(next_state)
        self._register()
        return self.status()

    def _registration_body(self, record: dict[str, Any]) -> dict[str, Any]:
        return {
            key: record[key]
            for key in (
                "protocol",
                "registrationRequestId",
                "recoverySecret",
                "mode",
                "installationId",
                "normalizedCode",
                "edgeNonce",
                "spkiDer",
                "csrDer",
            )
        }

    def _register(self) -> None:
        record = self._read_transient()
        if not record:
            raise PairingError("transient_secret_missing")
        try:
            response = self.central.register(self._registration_body(record))
        except Exception as error:
            raise PairingError("central_registration_unreachable") from error
        if not self.apply_registration_response(response):
            return
        record = self._read_transient()
        if not record:
            raise PairingError("transient_secret_missing")
        self._prepare_first_proof(record)
        self._send_first_proof(record)

    def _prepare_first_proof(self, record: dict[str, Any]) -> None:
        if record.get("proofRequest"):
            return
        registration_expiry, registration_epoch = _deadline(record["registrationExpiresAt"])
        if registration_expiry <= self.clock().astimezone(UTC):
            raise PairingError("expired_registration_response")
        values = {
            "protocol": "1.0",
            "sessionId": record["sessionId"],
            "installationId": record["installationId"],
            "spkiSha256": record["spkiSha256"],
            "csrSha256": record["csrSha256"],
            "edgeNonce": record["edgeNonce"],
            "serverNonce": record["serverNonce"],
            "registrationExpiresEpochSeconds": registration_epoch,
            "codeSha256": _b64u(hashlib.sha256(record["normalizedCode"].encode("ascii")).digest()),
        }
        signature = sign_low_s(self.store.load_candidate(), build_first_pop_preimage(values))
        record["proofRequest"] = {
            "normalizedCode": record["normalizedCode"],
            "signature": _b64u(signature),
        }
        self.store.write_transient(record)

    def _send_first_proof(self, record: dict[str, Any]) -> None:
        proof_request = record.get("proofRequest")
        if not isinstance(proof_request, dict):
            raise PairingError("proof_intent_missing")
        try:
            proof = self.central.proof(
                record["sessionId"],
                record["bootstrapToken"],
                proof_request,
            )
        except Exception as error:
            raise PairingError("central_proof_unreachable") from error
        session_revision = proof.get("sessionRevision")
        if (
            proof.get("status") != "pop_verified"
            or proof.get("sessionId") != record["sessionId"]
            or type(session_revision) is not int
            or session_revision <= record["centralSessionRevision"]
        ):
            raise PairingError("invalid_proof_response")
        expires = _parse_time(proof.get("codeExpiresAt"))
        if expires <= self.clock().astimezone(UTC):
            raise PairingError("expired_code_response")
        record.update(
            centralSessionRevision=session_revision,
            codeExpiresAt=expires.isoformat(),
        )
        self.store.write_transient(record)
        self._update_state(
            status="pop_verified",
            codeExpiresAt=expires.isoformat(),
            centralSessionRevision=session_revision,
        )

    def apply_registration_response(self, response: dict[str, Any]) -> bool:
        record = self._read_transient()
        if not record:
            raise PairingError("transient_secret_missing")
        generation = response.get("tokenGeneration")
        if type(generation) is not int or generation <= record["tokenGeneration"]:
            return False
        try:
            UUID(response["sessionId"])
            _decode_b64u(response["serverNonce"], 32)
            _decode_b64u(response["bootstrapToken"], 32)
            expiry, _expiry_epoch = _deadline(response["registrationExpiresAt"])
            session_revision = response["sessionRevision"]
            if type(session_revision) is not int or session_revision < 0:
                raise PairingError("invalid_registration_response")
            if expiry <= self.clock().astimezone(UTC):
                raise PairingError("invalid_registration_response")
        except (KeyError, TypeError, ValueError) as error:
            raise PairingError("invalid_registration_response") from error
        record.update(
            sessionId=response["sessionId"],
            serverNonce=response["serverNonce"],
            bootstrapToken=response["bootstrapToken"],
            tokenGeneration=generation,
            registrationExpiresAt=expiry.isoformat(),
            centralSessionRevision=session_revision,
        )
        self.store.write_transient(record)
        self._update_state(
            sessionId=response["sessionId"],
            tokenGeneration=generation,
            status="registered",
            registrationExpiresAt=expiry.isoformat(),
            centralSessionRevision=session_revision,
        )
        return True

    @_serialized
    def refresh(self) -> dict[str, Any]:
        if self.state.get("status") == "identity_missing_after_restore":
            raise PairingError("identity_missing_after_restore")
        record = self._read_transient()
        if not record:
            raise PairingError("transient_secret_missing")
        if self.state.get("status") in {None, "registering"}:
            self._register()
            return self.status()
        if self.state.get("status") == "registered":
            self._prepare_first_proof(record)
            self._send_first_proof(record)
            return self.status()
        if self.state.get("status") == "issued" and record.get("ackRequest"):
            self._send_ack(record)
            return self.status()
        try:
            result = self.central.result(record["sessionId"], record["bootstrapToken"])
        except Exception as error:
            raise PairingError("central_result_unreachable") from error
        status = result.get("status")
        if status == "claimed":
            self._claim_proof(record, result)
        elif status == "issued":
            self._accept_issued(record, result)
        elif status == "pop_verified":
            session_revision = result.get("sessionRevision")
            if (
                type(session_revision) is not int
                or session_revision < record["centralSessionRevision"]
            ):
                raise PairingError("invalid_result_response")
            self._update_state(status=status, centralSessionRevision=session_revision)
        elif status in {"claim_proved", "issuing"}:
            issuance_expiry = _parse_time(result.get("issuanceExpiresAt"))
            session_revision = result.get("sessionRevision")
            if (
                result.get("sessionId") != record["sessionId"]
                or result.get("installationId") != record["installationId"]
                or result.get("claimRevision") != record.get("claimRevision")
                or result.get("installationRevision") != record.get("installationRevision")
                or issuance_expiry <= self.clock().astimezone(UTC)
                or type(session_revision) is not int
                or session_revision < record["centralSessionRevision"]
            ):
                raise PairingError("invalid_issuance_result")
            record.update(
                centralSessionRevision=session_revision,
                issuanceExpiresAt=issuance_expiry.isoformat(),
            )
            self.store.write_transient(record)
            self._update_state(
                status=status,
                issuanceExpiresAt=issuance_expiry.isoformat(),
                centralSessionRevision=session_revision,
            )
        elif status in {"cancelled", "expired"}:
            self.reset(local_only=True, terminal=status)
        else:
            raise PairingError("invalid_result_response")
        return self.status()

    def _claim_proof(self, record: dict[str, Any], result: dict[str, Any]) -> None:
        claim_expiry, claim_epoch = _deadline(result["claimExpiresAt"])
        if claim_expiry <= self.clock().astimezone(UTC):
            raise PairingError("claim_expired")
        session_revision = result.get("sessionRevision")
        if (
            type(session_revision) is not int
            or session_revision <= record["centralSessionRevision"]
        ):
            raise PairingError("invalid_claim_result")
        values = {
            "protocol": "1.0",
            "sessionId": record["sessionId"],
            "installationId": record["installationId"],
            "spkiSha256": record["spkiSha256"],
            "tenantId": result["tenantId"],
            "siteId": result["siteId"],
            "claimNonce": result["claimNonce"],
            "claimExpiresEpochSeconds": claim_epoch,
            "claimRevision": result["claimRevision"],
            "csrSha256": record["csrSha256"],
            "installationRevision": result["installationRevision"],
        }
        signature = sign_low_s(self.store.load_candidate(), build_claim_pop_preimage(values))
        for secret_key in ("normalizedCode", "displayedCode"):
            record.pop(secret_key, None)
        record.update(
            tenantId=result["tenantId"],
            siteId=result["siteId"],
            claimRevision=result["claimRevision"],
            installationRevision=result["installationRevision"],
            claimExpiresAt=claim_expiry.isoformat(),
            centralSessionRevision=session_revision,
        )
        self.store.write_transient(record)
        self._update_state(
            status="claimed",
            tenantId=result["tenantId"],
            siteId=result["siteId"],
            claimRevision=result["claimRevision"],
            installationRevision=result["installationRevision"],
            claimExpiresAt=claim_expiry.isoformat(),
            centralSessionRevision=session_revision,
        )
        try:
            response = self.central.claim_proof(
                record["sessionId"],
                record["bootstrapToken"],
                {"claimRevision": result["claimRevision"], "signature": _b64u(signature)},
            )
        except Exception as error:
            raise PairingError("central_claim_proof_unreachable") from error
        issuance_expiry = _parse_time(response.get("issuanceExpiresAt"))
        next_session_revision = response.get("sessionRevision")
        if (
            response.get("status") != "claim_proved"
            or response.get("sessionId") != record["sessionId"]
            or response.get("claimRevision") != result["claimRevision"]
            or response.get("installationRevision") != result["installationRevision"]
            or issuance_expiry <= self.clock().astimezone(UTC)
            or type(next_session_revision) is not int
            or next_session_revision <= session_revision
        ):
            raise PairingError("invalid_claim_proof_response")
        record.update(
            centralSessionRevision=next_session_revision,
            issuanceExpiresAt=issuance_expiry.isoformat(),
        )
        self.store.write_transient(record)
        self._update_state(
            status="claim_proved",
            tenantId=result["tenantId"],
            siteId=result["siteId"],
            claimRevision=result["claimRevision"],
            installationRevision=result["installationRevision"],
            issuanceExpiresAt=issuance_expiry.isoformat(),
            centralSessionRevision=next_session_revision,
        )

    def _accept_issued(self, record: dict[str, Any], result: dict[str, Any]) -> None:
        expected = {
            "sessionId": record["sessionId"],
            "installationId": record["installationId"],
            "claimRevision": record["claimRevision"],
            "installationRevision": record["installationRevision"],
        }
        if any(result.get(key) != value for key, value in expected.items()):
            raise PairingError("issued_result_binding_mismatch")
        next_session_revision = result.get("sessionRevision")
        current_session_revision = record.get("centralSessionRevision")
        if (
            type(next_session_revision) is not int
            or type(current_session_revision) is not int
            or next_session_revision <= current_session_revision
        ):
            raise PairingError("invalid_issued_session_revision")
        expires = _parse_time(result["ackExpiresAt"])
        if expires <= self.clock().astimezone(UTC):
            raise PairingError("ack_expired")
        key = self.store.load_candidate()
        leaf = validate_issued_credential(
            key,
            result["certificatePem"],
            result["caChainPem"],
            result["certificateSha256"],
            record["installationId"],
            record["tenantId"],
            record["siteId"],
            self.clock(),
        )
        self.store.write_candidate_credential(result["certificatePem"], result["caChainPem"])
        ack_values = {
            "protocol": "1.0",
            "sessionId": record["sessionId"],
            "installationId": record["installationId"],
            "credentialId": result["credentialId"],
            "certificateSha256": result["certificateSha256"],
            "claimRevision": record["claimRevision"],
            "installationRevision": record["installationRevision"],
        }
        ack = dict(ack_values)
        ack["signature"] = _b64u(sign_low_s(key, build_certificate_ack_preimage(ack_values)))
        record.update(
            credentialId=result["credentialId"],
            certificateSha256=result["certificateSha256"],
            ackExpiresAt=expires.isoformat(),
            ackRequest=ack,
            centralSessionRevision=next_session_revision,
        )
        self.store.write_transient(record)
        self._update_state(
            status="issued",
            credentialId=result["credentialId"],
            certificateSha256=result["certificateSha256"],
            ackExpiresAt=expires.isoformat(),
            certificateNotAfter=leaf.not_valid_after_utc.isoformat(),
            centralSessionRevision=next_session_revision,
        )
        self._send_ack(record)

    def _send_ack(self, record: dict[str, Any]) -> None:
        if _parse_time(record["ackExpiresAt"]) <= self.clock().astimezone(UTC):
            raise PairingError("ack_expired")
        if record.get("ackResponse") is not None:
            self._finish_acked_pairing(record)
            return
        try:
            certificate, chain = self.store.read_candidate_credential()
            private_key_pem = self.store.candidate_private_pem()
        except UnsafeIdentityStorage:
            certificate, chain = self.store.read_identity_credential()
            private_key_pem = self.store.identity_private_pem()
        try:
            response = self.central.ack(
                record["ackRequest"],
                certificate + chain,
                private_key_pem,
                record["bootstrapToken"],
            )
        except Exception as error:
            raise PairingError("central_ack_unreachable") from error
        ack = record["ackRequest"]
        expected = {
            "sessionId": ack["sessionId"],
            "installationId": ack["installationId"],
            "status": "acked",
            "installationRevision": ack["installationRevision"],
            "credentialId": ack["credentialId"],
            "certificateSha256": ack["certificateSha256"],
        }
        if any(response.get(key) != value for key, value in expected.items()):
            raise PairingError("invalid_ack_response")
        record["ackResponse"] = response
        self.store.write_transient(record)
        self._finish_acked_pairing(record)

    def _finish_acked_pairing(self, record: dict[str, Any]) -> None:
        try:
            self.store.read_candidate_credential()
            self.store.candidate_private_pem()
        except UnsafeIdentityStorage as error:
            if self.store.promotion_in_progress():
                self.store.promote_candidate()
            try:
                certificate, _chain = self.store.read_identity_credential()
                leaf = x509.load_pem_x509_certificate(certificate.encode("ascii"))
                digest = _b64u(
                    hashlib.sha256(leaf.public_bytes(serialization.Encoding.DER)).digest()
                )
            except (UnsafeIdentityStorage, ValueError) as identity_error:
                raise PairingError("candidate_promotion_incomplete") from identity_error
            if not secrets.compare_digest(digest, record["certificateSha256"]):
                raise PairingError("candidate_promotion_incomplete") from error
        else:
            self.store.promote_candidate()
        response = record["ackResponse"]
        self._update_state(
            status="paired",
            credentialId=record["credentialId"],
            activeSpkiSha256=record["spkiSha256"],
            certificateSha256=record["certificateSha256"],
            installationRevision=response["installationRevision"],
        )
        self.store.delete_transient()

    @_serialized
    def cancel(self) -> dict[str, Any]:
        if self.state.get("status") not in {"registered", "pop_verified", "claimed"}:
            raise PairingError("pairing_not_cancellable")
        record = self._read_transient()
        if not record:
            raise PairingError("transient_secret_missing")
        expected_revision = self.state.get("centralSessionRevision")
        if type(expected_revision) is not int:
            raise PairingError("session_revision_missing")
        try:
            response = self.central.cancel(
                record["sessionId"], record["bootstrapToken"], expected_revision
            )
        except Exception as error:
            raise PairingError("central_cancel_unreachable") from error
        if response != {"sessionId": record["sessionId"], "status": "cancelled"}:
            raise PairingError("invalid_cancel_response")
        self.reset(local_only=True, terminal="cancelled")
        return self.status()

    @_serialized
    def rotate_key(self) -> dict[str, Any]:
        if self.state.get("status") not in {
            "paired",
            "revoked",
            "compromised",
            "expired",
            "cancelled",
            "identity_missing_after_restore",
        }:
            raise PairingError("repair_not_allowed")
        return self.start("repair", self.state["installationId"])

    @_serialized
    def reset(self, local_only: bool = False, terminal: str = "cancelled") -> None:
        if not local_only:
            status = self.state.get("status")
            identity_bearing = status in {
                "paired",
                "revoked",
                "compromised",
                "identity_missing_after_restore",
            } or any(
                self.state.get(field) is not None
                for field in ("credentialId", "certificateSha256", "activeSpkiSha256")
            )
            if identity_bearing:
                raise PairingError("identity_repair_required")
            if status not in {"unpaired", "expired", "cancelled"}:
                raise PairingError("central_cancel_required")
            self.store.delete_transient()
            self.store.delete_candidate()
            self._replace_state(
                {"installationId": self.state["installationId"], "status": "unpaired"}
            )
            return
        self.store.delete_transient()
        self.store.delete_candidate()
        terminal_state = {
            "installationId": self.state["installationId"],
            "status": terminal,
        }
        if self.state.get("mode") == "repair":
            for key in (
                "credentialId",
                "certificateSha256",
                "certificateNotAfter",
                "activeSpkiSha256",
                "installationRevision",
            ):
                if key in self.state:
                    terminal_state[key] = self.state[key]
        self._replace_state(terminal_state)

    def assert_restore_safe(self) -> None:
        self._reconcile_local_secrets()
        if self.state.get("status") == "identity_missing_after_restore":
            raise PairingError("identity_missing_after_restore")
