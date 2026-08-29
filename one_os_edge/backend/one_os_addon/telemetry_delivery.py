from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import stat
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

from sqlalchemy import select, text

from .models import (
    EdgeIdentity,
    Site,
    TelemetryAuthorityCut,
    TelemetryBatch,
    TelemetryBatchGap,
    TelemetryBatchRecord,
    TelemetryGap,
    TelemetryIngestState,
    TelemetryJournalState,
    TelemetryOutboxRecord,
    TelemetryOutboxSegment,
)
from .telemetry_authority import TelemetryAuthorityError
from .telemetry_contract_v1 import (
    MAX_RECORDS,
    TelemetryValidationError,
    canonical_json,
    parse_telemetry_ack,
    parse_telemetry_batch,
)
from .telemetry_contract_v2 import (
    TelemetryValidationError as TelemetryValidationErrorV2,
)
from .telemetry_contract_v2 import (
    canonical_json as canonical_json_v2,
)
from .telemetry_contract_v2 import parse_historical_receipt
from .telemetry_contract_v2 import (
    parse_telemetry_ack as parse_telemetry_ack_v2,
)
from .telemetry_contract_v2 import (
    parse_telemetry_batch as parse_telemetry_batch_v2,
)
from .telemetry_outbox import TelemetryOutbox, _fsync_directory

_PAYLOAD_DOMAIN = b"ONE.OS-TELEMETRY-BATCH-PAYLOAD-V1\0"
_MAX_CANDIDATES_PER_KIND = MAX_RECORDS + 1


class TelemetryDeliveryError(RuntimeError):
    pass


def _begin_write(session) -> str:
    dialect = session.get_bind().dialect.name
    if dialect == "sqlite":
        session.execute(text("BEGIN IMMEDIATE"))
    return dialect


def _locked(statement, dialect: str):
    return statement.with_for_update() if dialect == "postgresql" else statement


@dataclass(frozen=True)
class StoredTelemetryBatch:
    batch_id: str
    request_bytes: bytes
    request_sha256: str
    status: str
    lease_until: datetime | None
    attempt_count: int
    protocol: str
    historical_receipt_sha256: str | None = None
    ingest_authorization_revision: int | None = None


def _b64digest(value: bytes) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(value).digest()).rstrip(b"=").decode()


def _uuid4(value: str) -> str:
    try:
        parsed = UUID(value)
    except (TypeError, ValueError, AttributeError):
        raise TelemetryDeliveryError("invalid_uuid") from None
    canonical = str(parsed)
    if parsed.version != 4 or value != canonical:
        raise TelemetryDeliveryError("invalid_uuid")
    return canonical


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise TelemetryDeliveryError("naive_clock")
    rendered = value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    return rendered.replace(".000Z", "Z")


def _timestamp_millis(value: datetime) -> str:
    if value.tzinfo is None:
        raise TelemetryDeliveryError("naive_clock")
    return value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _v2_record(document: dict) -> dict:
    result = dict(document)
    for key in ("observedAt", "receivedAtEdge", "detectedAt"):
        value = result.get(key)
        if isinstance(value, str) and value.endswith("Z") and "." not in value:
            result[key] = value[:-1] + ".000Z"
    if "reason" in result:
        result["reason"] = "storage_failure"
    return result


class TelemetryDeliveryJournal:
    def __init__(
        self,
        session_factory,
        spool_dir: Path,
        *,
        uuid_factory=lambda: str(uuid4()),
        clock=lambda: datetime.now(UTC),
        authority_manager=None,
    ) -> None:
        self._session_factory = session_factory
        self._spool_dir = Path(spool_dir)
        self._uuid_factory = uuid_factory
        self._clock = clock
        self._authority_manager = authority_manager

    @staticmethod
    def _stored(
        batch: TelemetryBatch,
        *,
        historical_receipt_sha256: str | None = None,
        ingest_authorization_revision: int | None = None,
    ) -> StoredTelemetryBatch:
        try:
            parsed = parse_telemetry_batch(batch.request_bytes)
            protocol = "1.0"
        except TelemetryValidationError:
            try:
                parsed = parse_telemetry_batch_v2(batch.request_bytes)
                protocol = "2.0"
            except TelemetryValidationErrorV2:
                raise TelemetryDeliveryError("stored_batch_protocol_conflict") from None
        if (
            not hmac.compare_digest(parsed.request_sha256, batch.request_sha256)
            or not hmac.compare_digest(parsed.payload_sha256, batch.payload_sha256)
            or parsed.document["batchId"] != batch.batch_id
            or parsed.document["installationId"] != batch.installation_id
            or parsed.document["credentialId"] != batch.credential_id
            or (
                protocol == "2.0"
                and parsed.document["batchAuthorizationRevision"]
                != batch.batch_authorization_revision
            )
            or (
                protocol == "1.0"
                and parsed.document["installationRevision"] != batch.installation_revision
            )
        ):
            raise TelemetryDeliveryError("stored_batch_protocol_conflict")
        return StoredTelemetryBatch(
            batch_id=batch.batch_id,
            request_bytes=batch.request_bytes,
            request_sha256=batch.request_sha256,
            status=batch.status,
            lease_until=batch.lease_until,
            attempt_count=batch.attempt_count,
            protocol=protocol,
            historical_receipt_sha256=historical_receipt_sha256,
            ingest_authorization_revision=ingest_authorization_revision,
        )

    @staticmethod
    def _historical_authority(session, batch: TelemetryBatch) -> tuple[str | None, int | None]:
        cut = session.scalar(
            select(TelemetryAuthorityCut).where(
                TelemetryAuthorityCut.installation_id == batch.installation_id,
                TelemetryAuthorityCut.milestone == "receipt_stored",
                TelemetryAuthorityCut.cut_journal_max_id >= batch.journal_id,
            )
        )
        if cut is None:
            return None, None
        if cut.receipt_bytes is None or cut.receipt_sha256 is None:
            raise TelemetryDeliveryError("historical_authority_conflict")
        receipt, exact = parse_historical_receipt(cut.receipt_bytes)
        entry = next(
            (item for item in receipt["entries"] if item["journalId"] == batch.journal_id), None
        )
        if (
            exact != cut.receipt_bytes
            or not hmac.compare_digest(hashlib.sha256(exact).digest(), cut.receipt_sha256)
            or entry is None
            or entry["batchId"] != batch.batch_id
            or entry["requestSha256"] != batch.request_sha256
            or entry["requestLength"] != len(batch.request_bytes)
        ):
            raise TelemetryDeliveryError("historical_authority_conflict")
        return _b64digest(exact), cut.ingest_authorization_revision

    def acquire(
        self,
        *,
        owner: str,
        lease_for: timedelta,
    ) -> StoredTelemetryBatch | None:
        if not re.fullmatch(r"[A-Za-z0-9._:-]{1,64}", owner):
            raise TelemetryDeliveryError("invalid_lease_owner")
        lease_seconds = lease_for.total_seconds()
        if lease_seconds < 1 or lease_seconds > 300:
            raise TelemetryDeliveryError("invalid_lease_duration")
        if self.get_or_create_pending() is None:
            return None
        with self._session_factory() as session:
            dialect = _begin_write(session)
            now = self._clock()
            if now.tzinfo is None:
                raise TelemetryDeliveryError("naive_clock")
            now = now.astimezone(UTC)
            batch = session.scalar(
                _locked(
                    select(TelemetryBatch)
                    .where(TelemetryBatch.status.in_(("pending", "leased")))
                    .order_by(TelemetryBatch.created_at, TelemetryBatch.batch_id)
                    .limit(1),
                    dialect,
                )
            )
            if batch is None:
                session.rollback()
                return None
            if batch.status == "pending" and batch.next_attempt_at is not None:
                next_attempt = batch.next_attempt_at
                if next_attempt.tzinfo is None:
                    next_attempt = next_attempt.replace(tzinfo=UTC)
                if next_attempt > now:
                    session.rollback()
                    return None
            if batch.status == "leased":
                if batch.lease_until is None or batch.lease_owner is None:
                    raise TelemetryDeliveryError("invalid_lease_state")
                lease_until = batch.lease_until
                if lease_until.tzinfo is None:
                    lease_until = lease_until.replace(tzinfo=UTC)
                if lease_until > now:
                    if batch.lease_owner == owner:
                        receipt_sha, ingest_revision = self._historical_authority(session, batch)
                        session.rollback()
                        return self._stored(
                            batch,
                            historical_receipt_sha256=receipt_sha,
                            ingest_authorization_revision=ingest_revision,
                        )
                    session.rollback()
                    return None
            batch.status = "leased"
            batch.lease_owner = owner
            batch.lease_until = now + lease_for
            batch.attempt_count += 1
            batch.last_attempt_at = now
            batch.next_attempt_at = None
            receipt_sha, ingest_revision = self._historical_authority(session, batch)
            session.commit()
            return self._stored(
                batch,
                historical_receipt_sha256=receipt_sha,
                ingest_authorization_revision=ingest_revision,
            )

    def release_for_retry(
        self,
        *,
        batch_id: str,
        owner: str,
        delay: timedelta,
    ) -> None:
        _uuid4(batch_id)
        if not re.fullmatch(r"[A-Za-z0-9._:-]{1,64}", owner):
            raise TelemetryDeliveryError("invalid_lease_owner")
        delay_seconds = delay.total_seconds()
        if delay_seconds < 1 or delay_seconds > 3600:
            raise TelemetryDeliveryError("invalid_retry_delay")
        with self._session_factory() as session:
            dialect = _begin_write(session)
            now = self._clock()
            if now.tzinfo is None:
                raise TelemetryDeliveryError("naive_clock")
            now = now.astimezone(UTC)
            batch = session.scalar(
                _locked(select(TelemetryBatch).where(TelemetryBatch.batch_id == batch_id), dialect)
            )
            if batch is None:
                raise TelemetryDeliveryError("batch_missing")
            if batch.status != "leased" or batch.lease_owner != owner:
                raise TelemetryDeliveryError("lease_not_owned")
            if batch.lease_until is None:
                raise TelemetryDeliveryError("invalid_lease_state")
            lease_until = batch.lease_until
            if lease_until.tzinfo is None:
                lease_until = lease_until.replace(tzinfo=UTC)
            if lease_until <= now:
                raise TelemetryDeliveryError("lease_expired")
            batch.status = "pending"
            batch.lease_owner = None
            batch.lease_until = None
            batch.next_attempt_at = now + delay
            session.commit()

    def mark_current_attempt(self, *, batch_id: str, owner: str) -> None:
        """Persist exact current-authority send evidence before the network call."""
        _uuid4(batch_id)
        if not re.fullmatch(r"[A-Za-z0-9._:-]{1,64}", owner):
            raise TelemetryDeliveryError("invalid_lease_owner")
        with self._session_factory() as session:
            dialect = _begin_write(session)
            batch = session.scalar(
                _locked(select(TelemetryBatch).where(TelemetryBatch.batch_id == batch_id), dialect)
            )
            if batch is None:
                raise TelemetryDeliveryError("batch_missing")
            if batch.status != "leased" or batch.lease_owner != owner:
                raise TelemetryDeliveryError("lease_not_owned")
            if batch.lease_until is None:
                raise TelemetryDeliveryError("invalid_lease_state")
            now = self._clock()
            if now.tzinfo is None:
                raise TelemetryDeliveryError("naive_clock")
            now = now.astimezone(UTC)
            lease_until = batch.lease_until
            if lease_until.tzinfo is None:
                lease_until = lease_until.replace(tzinfo=UTC)
            if lease_until <= now:
                raise TelemetryDeliveryError("lease_expired")
            receipt_sha, _ingest_revision = self._historical_authority(session, batch)
            if receipt_sha is not None:
                raise TelemetryDeliveryError("historical_authority_required")
            self._stored(batch)
            batch.current_attempt_request_sha256 = batch.request_sha256
            batch.current_attempt_authorization_revision = batch.batch_authorization_revision
            batch.current_attempt_at = now
            session.commit()

    def acknowledge(
        self,
        *,
        batch_id: str,
        owner: str,
        ack_bytes: bytes,
    ) -> dict:
        _uuid4(batch_id)
        if not re.fullmatch(r"[A-Za-z0-9._:-]{1,64}", owner):
            raise TelemetryDeliveryError("invalid_lease_owner")
        cleanup_paths: list[Path] = []
        with self._session_factory() as session:
            dialect = _begin_write(session)
            batch = session.scalar(
                _locked(select(TelemetryBatch).where(TelemetryBatch.batch_id == batch_id), dialect)
            )
            if batch is None:
                raise TelemetryDeliveryError("batch_missing")
            if batch.status == "acked":
                if batch.ack_bytes is None or not hmac.compare_digest(batch.ack_bytes, ack_bytes):
                    raise TelemetryDeliveryError("invalid_ack")
                session.rollback()
                document = json.loads(batch.ack_bytes)
                if not isinstance(document, dict):
                    raise TelemetryDeliveryError("invalid_ack")
                return document
            if batch.status != "leased" or batch.lease_owner != owner:
                raise TelemetryDeliveryError("lease_not_owned")
            if batch.lease_until is None:
                raise TelemetryDeliveryError("invalid_lease_state")
            lease_until = batch.lease_until
            if lease_until.tzinfo is None:
                lease_until = lease_until.replace(tzinfo=UTC)
            accepted_at = self._clock()
            if accepted_at.tzinfo is None:
                raise TelemetryDeliveryError("naive_clock")
            accepted_at = accepted_at.astimezone(UTC)
            if lease_until <= accepted_at:
                raise TelemetryDeliveryError("lease_expired")
            stored = self._stored(batch)
            receipt_sha, ingest_revision = self._historical_authority(session, batch)
            state = session.get(TelemetryIngestState, batch.installation_id)
            previous_cursor = state.last_ingest_cursor if state is not None else -1
            try:
                if stored.protocol == "2.0":
                    parsed_batch = parse_telemetry_batch_v2(batch.request_bytes)
                    try:
                        ack = parse_telemetry_ack_v2(
                            ack_bytes,
                            expected_batch=parsed_batch.document,
                            expected_request_sha256=batch.request_sha256,
                            expected_ingest_authorization_revision=(
                                ingest_revision
                                if ingest_revision is not None
                                else batch.batch_authorization_revision
                            ),
                            previous_ingest_cursor=previous_cursor,
                            expected_historical_receipt_sha256=receipt_sha,
                        )
                    except TelemetryValidationErrorV2:
                        if receipt_sha is None:
                            raise
                        if (
                            batch.current_attempt_at is None
                            or batch.current_attempt_request_sha256 is None
                            or batch.current_attempt_authorization_revision is None
                            or not hmac.compare_digest(
                                batch.current_attempt_request_sha256, batch.request_sha256
                            )
                            or batch.current_attempt_authorization_revision
                            != batch.batch_authorization_revision
                        ):
                            raise
                        ack = parse_telemetry_ack_v2(
                            ack_bytes,
                            expected_batch=parsed_batch.document,
                            expected_request_sha256=batch.request_sha256,
                            expected_ingest_authorization_revision=(
                                batch.batch_authorization_revision
                            ),
                            previous_ingest_cursor=previous_cursor,
                        )
                else:
                    parsed_batch = parse_telemetry_batch(batch.request_bytes)
                    ack = parse_telemetry_ack(
                        ack_bytes,
                        expected_batch=parsed_batch.document,
                        expected_request_sha256=batch.request_sha256,
                        previous_ingest_cursor=previous_cursor,
                    )
            except (TelemetryValidationError, TelemetryValidationErrorV2):
                session.rollback()
                raise TelemetryDeliveryError("invalid_ack") from None

            record_memberships = session.scalars(
                select(TelemetryBatchRecord)
                .where(TelemetryBatchRecord.batch_id == batch_id)
                .order_by(TelemetryBatchRecord.record_kind, TelemetryBatchRecord.ordinal)
            ).all()
            for membership in record_memberships:
                record = session.get(TelemetryOutboxRecord, membership.sample_id)
                if record is None:
                    raise TelemetryDeliveryError("batch_record_missing")
                segment = session.get(TelemetryOutboxSegment, record.segment_id)
                if segment is None:
                    raise TelemetryDeliveryError("batch_segment_missing")
                cleanup_paths.append(self._spool_dir / segment.relative_path)
                session.delete(membership)
                session.flush()
                session.delete(record)
                session.flush()
                session.delete(segment)
                session.flush()
            gap_memberships = session.scalars(
                select(TelemetryBatchGap)
                .where(TelemetryBatchGap.batch_id == batch_id)
                .order_by(TelemetryBatchGap.ordinal)
            ).all()
            for membership in gap_memberships:
                gap = session.get(TelemetryGap, membership.gap_id)
                if gap is None:
                    raise TelemetryDeliveryError("batch_gap_missing")
                session.delete(membership)
                session.flush()
                session.delete(gap)
                session.flush()

            batch.status = "acked"
            batch.lease_owner = None
            batch.lease_until = None
            batch.ack_bytes = ack_bytes
            batch.ingest_cursor = ack["ingestCursor"]
            batch.acked_at = accepted_at
            if state is None:
                state = TelemetryIngestState(
                    installation_id=batch.installation_id,
                    last_ingest_cursor=ack["ingestCursor"],
                    updated_at=accepted_at,
                )
                session.add(state)
            else:
                state.last_ingest_cursor = ack["ingestCursor"]
                state.updated_at = accepted_at
            session.commit()

        removed = False
        for path in cleanup_paths:
            try:
                metadata = path.lstat()
            except FileNotFoundError:
                continue
            if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
                raise TelemetryDeliveryError("unsafe_segment_entry")
            path.unlink()
            removed = True
        if removed:
            _fsync_directory(self._spool_dir)
        return ack

    def quarantine(
        self,
        *,
        batch_id: str,
        owner: str,
        reason: str,
    ) -> None:
        _uuid4(batch_id)
        if not re.fullmatch(r"[A-Za-z0-9._:-]{1,64}", owner):
            raise TelemetryDeliveryError("invalid_lease_owner")
        if reason not in {"immutable_conflict", "expired_payload"}:
            raise TelemetryDeliveryError("invalid_terminal_reason")
        with self._session_factory() as session:
            dialect = _begin_write(session)
            now = self._clock()
            if now.tzinfo is None:
                raise TelemetryDeliveryError("naive_clock")
            now = now.astimezone(UTC)
            batch = session.scalar(
                _locked(select(TelemetryBatch).where(TelemetryBatch.batch_id == batch_id), dialect)
            )
            if batch is None:
                raise TelemetryDeliveryError("batch_missing")
            if batch.status != "leased" or batch.lease_owner != owner:
                raise TelemetryDeliveryError("lease_not_owned")
            if batch.lease_until is None:
                raise TelemetryDeliveryError("invalid_lease_state")
            lease_until = batch.lease_until
            if lease_until.tzinfo is None:
                lease_until = lease_until.replace(tzinfo=UTC)
            if lease_until <= now:
                raise TelemetryDeliveryError("lease_expired")
            batch.status = "quarantined"
            batch.lease_owner = None
            batch.lease_until = None
            batch.next_attempt_at = None
            batch.terminal_reason = reason
            batch.quarantined_at = now
            session.commit()

    def _read_record(
        self,
        record: TelemetryOutboxRecord,
        segment: TelemetryOutboxSegment,
    ) -> dict:
        relative_path = segment.relative_path
        if (
            Path(relative_path).name != relative_path
            or not relative_path.endswith(".seg")
            or len(relative_path) != 40
        ):
            raise TelemetryDeliveryError("unsafe_segment_path")
        path = self._spool_dir / relative_path
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            raise TelemetryDeliveryError("segment_missing") from None
        if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            raise TelemetryDeliveryError("unsafe_segment_entry")
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode) or opened.st_size != segment.committed_bytes:
                raise TelemetryDeliveryError("segment_size_mismatch")
            payload = os.pread(descriptor, record.record_length, record.segment_offset)
        finally:
            os.close(descriptor)
        if len(payload) != record.record_length or not TelemetryOutbox._record_bytes_are_valid(
            record, payload
        ):
            raise TelemetryDeliveryError("record_corrupt")
        try:
            document = json.loads(payload)
        except (UnicodeDecodeError, ValueError, TypeError):
            raise TelemetryDeliveryError("record_corrupt") from None
        if not isinstance(document, dict):
            raise TelemetryDeliveryError("record_corrupt")
        return document

    @staticmethod
    def _gap_document(gap: TelemetryGap) -> dict:
        detected_at = gap.detected_at
        if detected_at.tzinfo is None:
            detected_at = detected_at.replace(tzinfo=UTC)
        return {
            "schemaVersion": "1.0",
            "installationId": gap.installation_id,
            "configVersion": gap.config_version,
            "snapshotId": gap.snapshot_id,
            "projectionSha256": gap.projection_sha256,
            "pointId": gap.point_id,
            "streamEpochId": gap.stream_epoch_id,
            "firstMissingSequence": gap.first_missing_sequence,
            "lastMissingSequence": gap.last_missing_sequence,
            "detectedAt": _timestamp(detected_at),
            "reason": gap.reason,
        }

    def get_or_create_pending(self) -> StoredTelemetryBatch | None:
        try:
            enabled_revision = (
                self._authority_manager.enabled_revision()
                if self._authority_manager is not None
                else None
            )
        except TelemetryAuthorityError:
            raise TelemetryDeliveryError("activation_state_conflict") from None
        with self._session_factory() as session:
            dialect = _begin_write(session)
            journal_state = session.scalar(
                _locked(select(TelemetryJournalState).where(TelemetryJournalState.id == 1), dialect)
            )
            if journal_state is None:
                raise TelemetryDeliveryError("journal_state_missing")
            existing = session.scalar(
                select(TelemetryBatch)
                .where(TelemetryBatch.status.in_(("pending", "leased")))
                .order_by(TelemetryBatch.created_at, TelemetryBatch.batch_id)
                .limit(1)
            )
            if existing is not None:
                session.rollback()
                return self._stored(existing)
            open_cut = session.scalar(
                _locked(
                    select(TelemetryAuthorityCut)
                    .where(TelemetryAuthorityCut.milestone != "terminal")
                    .limit(1),
                    dialect,
                )
            )
            if open_cut is not None:
                session.rollback()
                raise TelemetryDeliveryError("renewal_cut_blocks_batch_formation")

            identity = session.get(EdgeIdentity, 1)
            site = session.scalar(select(Site).limit(1))
            if (
                identity is None
                or site is None
                or identity.status != "paired"
                or identity.installation_id != site.installation_id
                or identity.credential_id is None
                or identity.installation_revision is None
                or type(identity.installation_revision) is not int
                or not 0 <= identity.installation_revision <= 9_223_372_036_854_775_807
                or type(identity.telemetry_authorization_revision) is not int
                or not 1 <= identity.telemetry_authorization_revision <= 9_223_372_036_854_775_807
            ):
                raise TelemetryDeliveryError("identity_not_delivery_eligible")
            installation_id = _uuid4(site.installation_id)
            credential_id = _uuid4(identity.credential_id)
            installation_revision = identity.installation_revision
            batch_authorization_revision = identity.telemetry_authorization_revision
            use_v2 = enabled_revision is not None
            if use_v2 and enabled_revision != batch_authorization_revision:
                raise TelemetryDeliveryError("activation_revision_conflict")

            record_rows = session.execute(
                select(TelemetryOutboxRecord, TelemetryOutboxSegment)
                .join(
                    TelemetryOutboxSegment,
                    TelemetryOutboxSegment.segment_id == TelemetryOutboxRecord.segment_id,
                )
                .outerjoin(
                    TelemetryBatchRecord,
                    TelemetryBatchRecord.sample_id == TelemetryOutboxRecord.sample_id,
                )
                .where(TelemetryBatchRecord.sample_id.is_(None))
                .order_by(
                    TelemetryOutboxRecord.point_id,
                    TelemetryOutboxRecord.stream_epoch_id,
                    TelemetryOutboxRecord.sequence,
                    TelemetryOutboxRecord.sample_id,
                )
                .limit(_MAX_CANDIDATES_PER_KIND)
            ).all()
            gap_rows = session.scalars(
                select(TelemetryGap)
                .outerjoin(TelemetryBatchGap, TelemetryBatchGap.gap_id == TelemetryGap.gap_id)
                .where(TelemetryGap.status == "pending", TelemetryBatchGap.gap_id.is_(None))
                .order_by(
                    TelemetryGap.point_id,
                    TelemetryGap.stream_epoch_id,
                    TelemetryGap.first_missing_sequence,
                    TelemetryGap.gap_id,
                )
                .limit(_MAX_CANDIDATES_PER_KIND)
            ).all()

            candidates: list[tuple[tuple, str, object, dict]] = []
            for record, segment in record_rows:
                document = self._read_record(record, segment)
                kind = "sample" if record.record_kind == "sample" else "quality"
                candidates.append(
                    (
                        (
                            record.point_id,
                            record.stream_epoch_id,
                            record.sequence,
                            0 if kind == "sample" else 1,
                        ),
                        kind,
                        record,
                        document,
                    )
                )
            for gap in gap_rows:
                candidates.append(
                    (
                        (gap.point_id, gap.stream_epoch_id, gap.first_missing_sequence, 2),
                        "gap",
                        gap,
                        self._gap_document(gap),
                    )
                )
            chosen = sorted(candidates, key=lambda item: item[0])[:MAX_RECORDS]
            if not chosen:
                session.rollback()
                return None

            if not 0 <= journal_state.last_journal_id < 9_223_372_036_854_775_807:
                raise TelemetryDeliveryError("journal_id_saturated")
            journal_state.last_journal_id += 1
            journal_id = journal_state.last_journal_id

            samples = sorted(
                (item[3] for item in chosen if item[1] == "sample"),
                key=lambda value: (value["pointId"], value["streamEpochId"], value["sequence"]),
            )
            quality_events = sorted(
                (item[3] for item in chosen if item[1] == "quality"),
                key=lambda value: (value["pointId"], value["streamEpochId"], value["sequence"]),
            )
            gaps = sorted(
                (item[3] for item in chosen if item[1] == "gap"),
                key=lambda value: (
                    value["pointId"],
                    value["streamEpochId"],
                    value["firstMissingSequence"],
                ),
            )
            batch_id = _uuid4(self._uuid_factory())
            if use_v2:
                samples = [_v2_record(value) for value in samples]
                quality_events = [_v2_record(value) for value in quality_events]
                gaps = [_v2_record(value) for value in gaps]
                payload = {
                    "batchAuthorizationRevision": batch_authorization_revision,
                    "gaps": gaps,
                    "qualityEvents": quality_events,
                    "samples": samples,
                }
                document = {
                    "schemaVersion": "one-os-telemetry-batch/v2",
                    "batchId": batch_id,
                    "installationId": installation_id,
                    "batchAuthorizationRevision": batch_authorization_revision,
                    "credentialId": credential_id,
                    "createdAt": _timestamp_millis(self._clock()),
                    "payloadSha256": _b64digest(
                        b"ONE.OS-TELEMETRY-BATCH-PAYLOAD-V2\0" + canonical_json_v2(payload)
                    ),
                    "samples": samples,
                    "qualityEvents": quality_events,
                    "gaps": gaps,
                }
                request_bytes = canonical_json_v2(document)
                try:
                    parsed = parse_telemetry_batch_v2(request_bytes)
                except TelemetryValidationErrorV2 as error:
                    raise TelemetryDeliveryError(f"v2_batch_conflict:{error.code}") from None
            else:
                payload = {
                    "gaps": gaps,
                    "installationRevision": installation_revision,
                    "qualityEvents": quality_events,
                    "samples": samples,
                }
                document = {
                    "schemaVersion": "1.0",
                    "batchId": batch_id,
                    "installationId": installation_id,
                    "installationRevision": installation_revision,
                    "credentialId": credential_id,
                    "createdAt": _timestamp(self._clock()),
                    "payloadSha256": _b64digest(_PAYLOAD_DOMAIN + canonical_json(payload)),
                    **payload,
                }
                request_bytes = canonical_json(document)
                parsed = parse_telemetry_batch(request_bytes)
            batch = TelemetryBatch(
                batch_id=batch_id,
                installation_id=installation_id,
                installation_revision=installation_revision,
                batch_authorization_revision=batch_authorization_revision,
                journal_id=journal_id,
                credential_id=credential_id,
                payload_sha256=parsed.payload_sha256,
                request_sha256=parsed.request_sha256,
                request_bytes=request_bytes,
                sample_count=len(samples),
                quality_event_count=len(quality_events),
                gap_count=len(gaps),
                status="pending",
                lease_owner=None,
                lease_until=None,
                attempt_count=0,
                last_attempt_at=None,
                next_attempt_at=None,
                ack_bytes=None,
                ingest_cursor=None,
                acked_at=None,
                created_at=self._clock().astimezone(UTC),
            )
            session.add(batch)
            ordinals = {"sample": 0, "quality": 0, "gap": 0}
            for _key, kind, source, _document in chosen:
                ordinal = ordinals[kind]
                ordinals[kind] += 1
                if kind == "gap":
                    session.add(
                        TelemetryBatchGap(
                            gap_id=source.gap_id,
                            batch_id=batch_id,
                            ordinal=ordinal,
                        )
                    )
                else:
                    session.add(
                        TelemetryBatchRecord(
                            sample_id=source.sample_id,
                            batch_id=batch_id,
                            record_kind=kind,
                            ordinal=ordinal,
                        )
                    )
            session.commit()
            return self._stored(batch)
