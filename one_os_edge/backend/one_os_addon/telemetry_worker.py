from __future__ import annotations

import asyncio
import secrets
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from .telemetry_delivery import TelemetryDeliveryError, TelemetryDeliveryJournal
from .telemetry_transport import TelemetryTransportError


class UploadTransport(Protocol):
    def upload(
        self,
        request_bytes: bytes,
        certificate_pem: str,
        private_key_pem: str,
        *,
        protocol: str = "1.0",
        authorization_mode: str = "current",
        historical_receipt_sha256: str | None = None,
    ) -> bytes: ...


class TelemetryDeliveryWorker:
    """Single restart-safe telemetry uploader over the durable delivery journal."""

    def __init__(
        self,
        journal: TelemetryDeliveryJournal,
        identity_provider: Callable[[], dict[str, Any]],
        revocation_handler: Callable[[str, int], bool],
        transport: UploadTransport,
        *,
        owner: str | None = None,
        poll_interval: float = 1.0,
        lease_for: timedelta = timedelta(seconds=30),
        base_backoff: float = 5.0,
        max_backoff: float = 300.0,
        random_uniform: Callable[[float, float], float] | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if (
            poll_interval <= 0
            or lease_for.total_seconds() < 2
            or lease_for.total_seconds() > 300
            or base_backoff < 1
            or max_backoff < base_backoff
        ):
            raise ValueError("invalid telemetry worker limits")
        transport_timeout = getattr(transport, "timeout_seconds", None)
        if (
            transport_timeout is not None
            and lease_for.total_seconds() <= float(transport_timeout) + 1
        ):
            raise ValueError("telemetry lease must exceed transport deadline")
        self.journal = journal
        self.identity_provider = identity_provider
        self.revocation_handler = revocation_handler
        self.transport = transport
        self.owner = owner or f"telemetry-{secrets.token_hex(12)}"
        self.poll_interval = poll_interval
        self.lease_for = lease_for
        self.base_backoff = base_backoff
        self.max_backoff = max_backoff
        self._uniform = random_uniform or secrets.SystemRandom().uniform
        self._clock = clock or (lambda: datetime.now(UTC))
        self._stop = asyncio.Event()
        self._task: asyncio.Task[None] | None = None
        self._blocked_identity: tuple[str, int] | None = None
        self.last_error: str | None = None

    def _identity(self) -> dict[str, Any] | None:
        try:
            identity = self.identity_provider()
            expiry = datetime.fromisoformat(identity["certificateNotAfter"].replace("Z", "+00:00"))
            now = self._clock()
            eligible = (
                identity.get("status") == "paired"
                and all(
                    identity.get(field)
                    for field in (
                        "installationId",
                        "credentialId",
                        "activeSpkiSha256",
                        "certificateSha256",
                        "certificatePem",
                        "privateKeyPem",
                    )
                )
                and type(identity.get("revision")) is int
                and expiry.tzinfo is not None
                and now.tzinfo is not None
                and expiry.astimezone(UTC) > now.astimezone(UTC)
            )
            if not eligible:
                return None
            identity_binding = (identity["credentialId"], identity["revision"])
            if self._blocked_identity == identity_binding:
                return None
            if self._blocked_identity is not None:
                self._blocked_identity = None
            return identity
        except (KeyError, TypeError, ValueError, OSError, UnicodeError, RuntimeError):
            return None

    def _retry_delay(self, attempt_count: int, code: str) -> timedelta:
        if code == "rate_limited":
            return timedelta(seconds=5)
        exponent = min(max(0, attempt_count - 1), 10)
        ceiling = min(self.max_backoff, self.base_backoff * (2**exponent))
        return timedelta(seconds=self._uniform(self.base_backoff, ceiling))

    def _release(self, batch_id: str, attempt_count: int, code: str) -> None:
        try:
            self.journal.release_for_retry(
                batch_id=batch_id,
                owner=self.owner,
                delay=self._retry_delay(attempt_count, code),
            )
        except TelemetryDeliveryError:
            pass

    def run_once(self) -> str:
        try:
            pending = self.journal.get_or_create_pending()
        except TelemetryDeliveryError as error:
            code = str(error)
            self.last_error = code
            if code == "identity_not_delivery_eligible":
                return "identity_ineligible"
            return "batch_unavailable"
        if pending is None:
            self.last_error = None
            return "idle"
        identity = self._identity()
        if identity is None:
            self.last_error = None
            return "identity_ineligible"
        batch = self.journal.acquire(owner=self.owner, lease_for=self.lease_for)
        if batch is None:
            self.last_error = None
            return "idle"
        try:
            if batch.protocol == "2.0":
                if batch.historical_receipt_sha256 is not None:
                    ack_bytes = self.transport.upload(
                        batch.request_bytes,
                        identity["certificatePem"],
                        identity["privateKeyPem"],
                        protocol="2.0",
                        authorization_mode="historical_backlog",
                        historical_receipt_sha256=batch.historical_receipt_sha256,
                    )
                else:
                    self.journal.mark_current_attempt(batch_id=batch.batch_id, owner=self.owner)
                    ack_bytes = self.transport.upload(
                        batch.request_bytes,
                        identity["certificatePem"],
                        identity["privateKeyPem"],
                        protocol="2.0",
                    )
            else:
                ack_bytes = self.transport.upload(
                    batch.request_bytes,
                    identity["certificatePem"],
                    identity["privateKeyPem"],
                )
            self.journal.acknowledge(
                batch_id=batch.batch_id,
                owner=self.owner,
                ack_bytes=ack_bytes,
            )
        except TelemetryTransportError as error:
            code = str(error)
            self.last_error = code
            if code in {"immutable_conflict", "expired_payload"}:
                try:
                    self.journal.quarantine(
                        batch_id=batch.batch_id,
                        owner=self.owner,
                        reason=code,
                    )
                except TelemetryDeliveryError as quarantine_error:
                    self.last_error = f"quarantine_{quarantine_error}"
                    return "quarantine_failed"
                return code
            if code == "revoked":
                credential_id = identity["credentialId"]
                revision = identity["revision"]
                try:
                    confirmed = self.revocation_handler(credential_id, revision)
                except Exception:
                    self._release(batch.batch_id, batch.attempt_count, code)
                    self.last_error = "revocation_unconfirmed"
                    return "revocation_unconfirmed"
                self._release(batch.batch_id, batch.attempt_count, code)
                if confirmed is not True:
                    self.last_error = "revocation_unconfirmed"
                    return "revocation_unconfirmed"
                self._blocked_identity = (credential_id, revision)
                return code
            self._release(batch.batch_id, batch.attempt_count, code)
            return code
        except TelemetryDeliveryError as error:
            self.last_error = str(error)
            self._release(batch.batch_id, batch.attempt_count, "protocol_error")
            return "invalid_ack"
        self.last_error = None
        return "acked"

    async def start(self) -> None:
        if self._task is not None and not self._task.done():
            return
        self._stop.clear()
        self._task = asyncio.create_task(self._run(), name="edge-telemetry-delivery-worker")

    async def stop(self) -> None:
        self._stop.set()
        task, self._task = self._task, None
        if task is not None:
            await task

    async def _wait(self) -> None:
        try:
            await asyncio.wait_for(self._stop.wait(), timeout=self.poll_interval)
        except TimeoutError:
            pass

    async def _run(self) -> None:
        while not self._stop.is_set():
            try:
                await asyncio.to_thread(self.run_once)
            except Exception as error:  # fail closed and keep the bounded worker alive
                self.last_error = type(error).__name__
            await self._wait()
