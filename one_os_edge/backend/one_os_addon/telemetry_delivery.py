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
    TelemetryBatch,
    TelemetryBatchGap,
    TelemetryBatchRecord,
    TelemetryGap,
    TelemetryIngestState,
    TelemetryOutboxRecord,
    TelemetryOutboxSegment,
)
from .telemetry_contract_v1 import (
    MAX_RECORDS,
    TelemetryValidationError,
    canonical_json,
    parse_telemetry_ack,
    parse_telemetry_batch,
)
from .telemetry_outbox import TelemetryOutbox, _fsync_directory

_PAYLOAD_DOMAIN = b"ONE.OS-TELEMETRY-BATCH-PAYLOAD-V1\0"
_MAX_CANDIDATES_PER_KIND = MAX_RECORDS + 1


class TelemetryDeliveryError(RuntimeError):
    pass


@dataclass(frozen=True)
class StoredTelemetryBatch:
    batch_id: str
    request_bytes: bytes
    request_sha256: str
    status: str
    lease_until: datetime | None
    attempt_count: int


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


class TelemetryDeliveryJournal:
    def __init__(
        self,
        session_factory,
        spool_dir: Path,
        *,
        uuid_factory=lambda: str(uuid4()),
        clock=lambda: datetime.now(UTC),
    ) -> None:
        self._session_factory = session_factory
        self._spool_dir = Path(spool_dir)
        self._uuid_factory = uuid_factory
        self._clock = clock

    @staticmethod
    def _stored(batch: TelemetryBatch) -> StoredTelemetryBatch:
        return StoredTelemetryBatch(
            batch_id=batch.batch_id,
            request_bytes=batch.request_bytes,
            request_sha256=batch.request_sha256,
            status=batch.status,
            lease_until=batch.lease_until,
            attempt_count=batch.attempt_count,
        )

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
            session.execute(text("BEGIN IMMEDIATE"))
            now = self._clock()
            if now.tzinfo is None:
                raise TelemetryDeliveryError("naive_clock")
            now = now.astimezone(UTC)
            batch = session.scalar(
                select(TelemetryBatch)
                .where(TelemetryBatch.status.in_(("pending", "leased")))
                .order_by(TelemetryBatch.created_at, TelemetryBatch.batch_id)
                .limit(1)
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
                        session.rollback()
                        return self._stored(batch)
                    session.rollback()
                    return None
            batch.status = "leased"
            batch.lease_owner = owner
            batch.lease_until = now + lease_for
            batch.attempt_count += 1
            batch.last_attempt_at = now
            batch.next_attempt_at = None
            session.commit()
            return self._stored(batch)

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
            session.execute(text("BEGIN IMMEDIATE"))
            now = self._clock()
            if now.tzinfo is None:
                raise TelemetryDeliveryError("naive_clock")
            now = now.astimezone(UTC)
            batch = session.get(TelemetryBatch, batch_id)
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
            session.execute(text("BEGIN IMMEDIATE"))
            batch = session.get(TelemetryBatch, batch_id)
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
            parsed_batch = parse_telemetry_batch(batch.request_bytes)
            state = session.get(TelemetryIngestState, batch.installation_id)
            previous_cursor = state.last_ingest_cursor if state is not None else -1
            try:
                ack = parse_telemetry_ack(
                    ack_bytes,
                    expected_batch=parsed_batch.document,
                    expected_request_sha256=batch.request_sha256,
                    previous_ingest_cursor=previous_cursor,
                )
            except TelemetryValidationError:
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
        with self._session_factory() as session:
            session.execute(text("BEGIN IMMEDIATE"))
            existing = session.scalar(
                select(TelemetryBatch)
                .where(TelemetryBatch.status.in_(("pending", "leased")))
                .order_by(TelemetryBatch.created_at, TelemetryBatch.batch_id)
                .limit(1)
            )
            if existing is not None:
                session.rollback()
                return self._stored(existing)

            identity = session.get(EdgeIdentity, 1)
            site = session.scalar(select(Site).limit(1))
            if (
                identity is None
                or site is None
                or identity.status != "paired"
                or identity.installation_id != site.installation_id
                or identity.credential_id is None
            ):
                raise TelemetryDeliveryError("identity_not_delivery_eligible")
            installation_id = _uuid4(site.installation_id)
            credential_id = _uuid4(identity.credential_id)

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
            payload = {"gaps": gaps, "qualityEvents": quality_events, "samples": samples}
            batch_id = _uuid4(self._uuid_factory())
            document = {
                "schemaVersion": "1.0",
                "batchId": batch_id,
                "installationId": installation_id,
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
