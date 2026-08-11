from __future__ import annotations

import base64
import errno
import hashlib
import json
import os
import re
import stat
from contextlib import nullcontext
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal, InvalidOperation
from pathlib import Path
from threading import RLock
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import func, select

from .models import (
    ConfigurationSnapshot,
    EdgeIdentity,
    Point,
    Site,
    TelemetryGap,
    TelemetryOutboxRecord,
    TelemetryOutboxSegment,
    TelemetryStream,
)
from .telemetry_contract_v1 import MAX_RECORD_BYTES, MAX_SIGNED_INT64, canonical_json

_RECORD_DOMAIN = b"ONE.OS-TELEMETRY-RECORD-V1\0"
_CONTROL_RESERVE_NAME = ".telemetry-control-reserve"
_TIMESTAMP = re.compile(
    r"^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])"
    r"T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](?:\.[0-9]{1,3})?Z$",
    re.ASCII,
)


class TelemetryOutboxError(RuntimeError):
    pass


@dataclass(frozen=True)
class StoredTelemetryRecord:
    document: dict[str, Any]
    canonical_bytes: bytes
    cleanup_paths: tuple[str, ...] = ()
    created_paths: tuple[str, ...] = ()
    control_reserve_released: bool = False


def _b64digest(value: bytes) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(value).digest()).rstrip(b"=").decode("ascii")


def _uuid4(value: str) -> str:
    try:
        parsed = UUID(value)
    except (TypeError, ValueError, AttributeError):
        raise TelemetryOutboxError("invalid_generated_uuid") from None
    if parsed.version != 4 or str(parsed) != value:
        raise TelemetryOutboxError("invalid_generated_uuid")
    return value


def _timestamp(value: str) -> str:
    if not isinstance(value, str) or _TIMESTAMP.fullmatch(value) is None:
        raise TelemetryOutboxError("invalid_observed_at")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise TelemetryOutboxError("invalid_observed_at") from None
    if parsed.tzinfo is None:
        raise TelemetryOutboxError("invalid_observed_at")
    return value


def _edge_timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise TelemetryOutboxError("invalid_edge_clock")
    utc = value.astimezone(UTC)
    milliseconds = utc.microsecond // 1000
    if milliseconds:
        return utc.strftime("%Y-%m-%dT%H:%M:%S.") + f"{milliseconds:03d}Z"
    return utc.strftime("%Y-%m-%dT%H:%M:%SZ")


def _decimal(raw_value: str) -> str:
    if not isinstance(raw_value, str):
        raise TelemetryOutboxError("invalid_numeric_state")
    try:
        value = Decimal(raw_value)
    except InvalidOperation:
        raise TelemetryOutboxError("invalid_numeric_state") from None
    if not value.is_finite():
        raise TelemetryOutboxError("invalid_numeric_state")
    if value.is_zero():
        return "0"
    canonical = format(value, "f")
    if "." in canonical:
        canonical = canonical.rstrip("0").rstrip(".")
    unsigned = canonical.removeprefix("-")
    integer, separator, fraction = unsigned.partition(".")
    precision = len(integer.lstrip("0")) + len(fraction)
    if precision == 0:
        precision = 1
    if precision > 18 or (separator and len(fraction) > 9):
        raise TelemetryOutboxError("invalid_numeric_state")
    return canonical


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_new_file(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short telemetry segment write")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _fsync_directory(path.parent)


class TelemetryOutbox:
    def __init__(
        self,
        session_factory,
        spool_dir: Path,
        *,
        uuid_factory=lambda: str(uuid4()),
        clock=lambda: datetime.now(UTC),
        crash_hook=lambda _point: None,
        segment_writer=_write_new_file,
        max_bytes: int = 256 * 1024 * 1024,
        max_age: timedelta = timedelta(days=7),
        control_reserve_bytes: int = 4 * 1024 * 1024,
        minimum_free_bytes: int = 16 * 1024 * 1024,
    ) -> None:
        if max_bytes < MAX_RECORD_BYTES:
            raise ValueError("max_bytes must fit at least one maximum telemetry record")
        if max_age <= timedelta(0):
            raise ValueError("max_age must be positive")
        if control_reserve_bytes < 0 or minimum_free_bytes < 0:
            raise ValueError("storage reserve limits must be nonnegative")
        self._session_factory = session_factory
        self._spool_dir = Path(spool_dir)
        self._uuid_factory = uuid_factory
        self._clock = clock
        self._crash_hook = crash_hook
        self._segment_writer = segment_writer
        self._max_bytes = max_bytes
        self._max_age = max_age
        self._control_reserve_bytes = control_reserve_bytes
        self._minimum_free_bytes = minimum_free_bytes
        self._lock = RLock()

    def _ensure_spool(self) -> None:
        self._spool_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self._spool_dir.is_symlink() or not self._spool_dir.is_dir():
            raise TelemetryOutboxError("unsafe_telemetry_spool")
        os.chmod(self._spool_dir, 0o700)
        self._ensure_control_reserve()

    def _ensure_control_reserve(self) -> None:
        if self._control_reserve_bytes == 0:
            return
        path = self._spool_dir / _CONTROL_RESERVE_NAME
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            metadata = None
        if metadata is not None:
            if (
                path.is_symlink()
                or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_size != self._control_reserve_bytes
            ):
                raise TelemetryOutboxError("unsafe_control_reserve")
            return
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags, 0o600)
        try:
            if hasattr(os, "posix_fallocate"):
                os.posix_fallocate(descriptor, 0, self._control_reserve_bytes)
            else:
                remaining = self._control_reserve_bytes
                block = bytes(min(64 * 1024, remaining))
                while remaining:
                    written = os.write(descriptor, block[:remaining])
                    if written <= 0:
                        raise OSError(errno.ENOSPC, "control reserve write failed")
                    remaining -= written
            os.fsync(descriptor)
        except OSError:
            try:
                path.unlink()
            except OSError:
                pass
            raise TelemetryOutboxError("control_reserve_unavailable") from None
        finally:
            os.close(descriptor)
        _fsync_directory(self._spool_dir)

    def _has_data_space(self, incoming_bytes: int) -> bool:
        filesystem = os.statvfs(self._spool_dir)
        available = filesystem.f_bavail * filesystem.f_frsize
        return available >= self._minimum_free_bytes + incoming_bytes

    def _release_control_reserve(self) -> bool:
        if self._control_reserve_bytes == 0:
            return False
        path = self._spool_dir / _CONTROL_RESERVE_NAME
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            raise TelemetryOutboxError("control_reserve_missing") from None
        if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            raise TelemetryOutboxError("unsafe_control_reserve")
        path.unlink()
        _fsync_directory(self._spool_dir)
        return True

    def _restore_control_reserve_best_effort(self) -> None:
        try:
            self._ensure_control_reserve()
        except TelemetryOutboxError:
            pass

    @staticmethod
    def _record_bytes_are_valid(record: TelemetryOutboxRecord, payload: bytes) -> bool:
        try:
            document = json.loads(payload)
            if not isinstance(document, dict) or canonical_json(document) != payload:
                return False
            sample_id = document.get("sampleId")
            if sample_id != record.sample_id:
                return False
            without_id = dict(document)
            without_id.pop("sampleId", None)
            if _b64digest(_RECORD_DOMAIN + canonical_json(without_id)) != record.sample_id:
                return False
            return (
                document.get("pointId") == record.point_id
                and document.get("streamEpochId") == record.stream_epoch_id
                and document.get("sequence") == record.sequence
                and document.get("configVersion") == record.config_version
                and document.get("snapshotId") == record.snapshot_id
                and document.get("projectionSha256") == record.projection_sha256
            )
        except (TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError):
            return False

    def recover(self) -> dict[str, int]:
        with self._lock:
            self._ensure_spool()
            with self._session_factory() as session:
                segments = session.scalars(select(TelemetryOutboxSegment)).all()
                records = session.scalars(select(TelemetryOutboxRecord)).all()
                records_by_segment: dict[str, list[TelemetryOutboxRecord]] = {}
                for record in records:
                    records_by_segment.setdefault(record.segment_id, []).append(record)
                expected = {
                    segment.relative_path: (segment, records_by_segment.get(segment.segment_id, []))
                    for segment in segments
                }
            for relative_path in expected:
                if (
                    Path(relative_path).name != relative_path
                    or not relative_path.endswith(".seg")
                    or len(relative_path) != 40
                ):
                    raise TelemetryOutboxError("unsafe_segment_path")

            removed = 0
            truncated = 0
            failed_paths: set[str] = set()
            for path in self._spool_dir.iterdir():
                metadata = path.lstat()
                if path.name == _CONTROL_RESERVE_NAME:
                    if (
                        path.is_symlink()
                        or not stat.S_ISREG(metadata.st_mode)
                        or metadata.st_size != self._control_reserve_bytes
                    ):
                        raise TelemetryOutboxError("unsafe_control_reserve")
                    continue
                if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
                    raise TelemetryOutboxError("unsafe_segment_entry")
                if path.name not in expected:
                    path.unlink()
                    removed += 1

            for relative_path, (segment, segment_records) in expected.items():
                committed_bytes = segment.committed_bytes
                path = self._spool_dir / relative_path
                if not path.exists():
                    failed_paths.add(relative_path)
                    continue
                metadata = path.lstat()
                if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
                    raise TelemetryOutboxError("unsafe_segment_entry")
                if metadata.st_size < committed_bytes:
                    failed_paths.add(relative_path)
                    continue
                if metadata.st_size > committed_bytes:
                    flags = os.O_WRONLY
                    if hasattr(os, "O_NOFOLLOW"):
                        flags |= os.O_NOFOLLOW
                    descriptor = os.open(path, flags)
                    try:
                        os.ftruncate(descriptor, committed_bytes)
                        os.fsync(descriptor)
                    finally:
                        os.close(descriptor)
                    truncated += 1
                if len(segment_records) != 1:
                    failed_paths.add(relative_path)
                    continue
                record = segment_records[0]
                flags = os.O_RDONLY
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                descriptor = os.open(path, flags)
                try:
                    payload = os.pread(descriptor, record.record_length, record.segment_offset)
                finally:
                    os.close(descriptor)
                if len(payload) != record.record_length or not self._record_bytes_are_valid(
                    record, payload
                ):
                    failed_paths.add(relative_path)

            converted = 0
            if failed_paths:
                detected_at = self._clock().astimezone(UTC)
                with self._session_factory() as session:
                    for relative_path in sorted(failed_paths):
                        segment = session.scalar(
                            select(TelemetryOutboxSegment).where(
                                TelemetryOutboxSegment.relative_path == relative_path
                            )
                        )
                        if segment is None:
                            continue
                        records = session.scalars(
                            select(TelemetryOutboxRecord)
                            .where(TelemetryOutboxRecord.segment_id == segment.segment_id)
                            .order_by(TelemetryOutboxRecord.sequence)
                        ).all()
                        for record in records:
                            self._gap_for_record(
                                session,
                                record,
                                reason="storage_failure",
                                detected_at=detected_at,
                            )
                            session.delete(record)
                            session.flush()
                            converted += 1
                        session.delete(segment)
                        session.flush()
                    session.commit()
                for relative_path in failed_paths:
                    path = self._spool_dir / relative_path
                    try:
                        path.unlink()
                    except FileNotFoundError:
                        pass

            directory = os.open(self._spool_dir, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
            return {
                "removedOrphans": removed,
                "truncatedSegments": truncated,
                "convertedMissingRecords": converted,
            }

    def finalize_after_commit(self, stored: StoredTelemetryRecord) -> int:
        removed = 0
        if stored.cleanup_paths:
            self._crash_hook("after_retention_commit_before_cleanup")
            removed = self._remove_paths(stored.cleanup_paths)
        if stored.control_reserve_released:
            self._restore_control_reserve_best_effort()
        return removed

    def abort_before_commit(self, stored: StoredTelemetryRecord) -> int:
        try:
            return self._remove_paths(stored.created_paths)
        finally:
            if stored.control_reserve_released:
                self._restore_control_reserve_best_effort()

    def _remove_paths(self, relative_paths: tuple[str, ...]) -> int:
        removed = 0
        for relative_path in relative_paths:
            if (
                Path(relative_path).name != relative_path
                or not relative_path.endswith(".seg")
                or len(relative_path) != 40
            ):
                raise TelemetryOutboxError("unsafe_segment_path")
            path = self._spool_dir / relative_path
            try:
                metadata = path.lstat()
            except FileNotFoundError:
                continue
            if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
                raise TelemetryOutboxError("unsafe_segment_entry")
            path.unlink()
            removed += 1
        if removed:
            directory = os.open(self._spool_dir, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        return removed

    def _add_gap(
        self,
        session,
        *,
        installation_id: str,
        point_id: str,
        stream_epoch_id: str,
        config_version: int,
        snapshot_id: str,
        projection_sha256: str,
        first_sequence: int,
        last_sequence: int,
        reason: str,
        detected_at: datetime,
    ) -> TelemetryGap:
        prior_gap = session.scalar(
            select(TelemetryGap)
            .where(
                TelemetryGap.point_id == point_id,
                TelemetryGap.stream_epoch_id == stream_epoch_id,
                TelemetryGap.config_version == config_version,
                TelemetryGap.snapshot_id == snapshot_id,
                TelemetryGap.projection_sha256 == projection_sha256,
                TelemetryGap.reason == reason,
                TelemetryGap.status == "pending",
                TelemetryGap.last_missing_sequence == first_sequence - 1,
            )
            .limit(1)
        )
        if prior_gap is not None:
            prior_gap.last_missing_sequence = last_sequence
            return prior_gap
        gap = TelemetryGap(
            gap_id=_uuid4(self._uuid_factory()),
            installation_id=installation_id,
            point_id=point_id,
            stream_epoch_id=stream_epoch_id,
            config_version=config_version,
            snapshot_id=snapshot_id,
            projection_sha256=projection_sha256,
            first_missing_sequence=first_sequence,
            last_missing_sequence=last_sequence,
            detected_at=detected_at,
            reason=reason,
            status="pending",
        )
        session.add(gap)
        return gap

    def _consume_gap(
        self,
        session,
        *,
        snapshot: ConfigurationSnapshot,
        point: Point,
        stream: TelemetryStream,
        reason: str,
        detected_at: datetime,
        cleanup_paths: tuple[str, ...] = (),
        control_reserve_released: bool = False,
    ) -> StoredTelemetryRecord:
        gap = self._add_gap(
            session,
            installation_id=snapshot.installation_id,
            point_id=point.id,
            stream_epoch_id=stream.stream_epoch_id,
            config_version=snapshot.config_version,
            snapshot_id=snapshot.snapshot_id,
            projection_sha256=snapshot.projection_sha256,
            first_sequence=stream.next_sequence,
            last_sequence=stream.next_sequence,
            reason=reason,
            detected_at=detected_at,
        )
        gap_detected_at = gap.detected_at
        if gap_detected_at.tzinfo is None:
            gap_detected_at = gap_detected_at.replace(tzinfo=UTC)
        document = {
            "schemaVersion": "1.0",
            "installationId": gap.installation_id,
            "configVersion": gap.config_version,
            "snapshotId": gap.snapshot_id,
            "projectionSha256": gap.projection_sha256,
            "pointId": gap.point_id,
            "streamEpochId": gap.stream_epoch_id,
            "firstMissingSequence": gap.first_missing_sequence,
            "lastMissingSequence": gap.last_missing_sequence,
            "detectedAt": _edge_timestamp(gap_detected_at),
            "reason": gap.reason,
        }
        stream.next_sequence += 1
        stream.updated_at = detected_at
        return StoredTelemetryRecord(
            document=document,
            canonical_bytes=canonical_json(document),
            cleanup_paths=cleanup_paths,
            control_reserve_released=control_reserve_released,
        )

    def _gap_for_record(self, session, record, *, reason: str, detected_at: datetime) -> None:
        stream = session.get(TelemetryStream, record.point_id)
        if stream is None or stream.stream_epoch_id != record.stream_epoch_id:
            raise TelemetryOutboxError("gap_stream_missing")
        self._add_gap(
            session,
            installation_id=stream.installation_id,
            point_id=record.point_id,
            stream_epoch_id=record.stream_epoch_id,
            config_version=record.config_version,
            snapshot_id=record.snapshot_id,
            projection_sha256=record.projection_sha256,
            first_sequence=record.sequence,
            last_sequence=record.sequence,
            reason=reason,
            detected_at=detected_at,
        )

    def _prepare_retention(self, session, *, incoming_bytes: int, now: datetime) -> tuple[str, ...]:
        total = session.scalar(
            select(func.coalesce(func.sum(TelemetryOutboxSegment.live_bytes), 0))
        )
        current_bytes = int(total or 0)
        cutoff = now.replace(tzinfo=None) - self._max_age
        rows = session.execute(
            select(TelemetryOutboxRecord, TelemetryOutboxSegment)
            .join(
                TelemetryOutboxSegment,
                TelemetryOutboxSegment.segment_id == TelemetryOutboxRecord.segment_id,
            )
            .order_by(TelemetryOutboxRecord.created_at, TelemetryOutboxRecord.sequence)
        ).all()
        cleanup: list[str] = []
        for record, segment in rows:
            created_at = record.created_at
            if created_at.tzinfo is not None:
                created_at = created_at.astimezone(UTC).replace(tzinfo=None)
            too_old = created_at <= cutoff
            too_large = current_bytes + incoming_bytes > self._max_bytes
            if not too_old and not too_large:
                break
            reason = "retention_expired" if too_old else "outbox_capacity"
            self._gap_for_record(session, record, reason=reason, detected_at=now)
            cleanup.append(segment.relative_path)
            current_bytes -= segment.live_bytes
            session.delete(record)
            session.flush()
            session.delete(segment)
            session.flush()
        if current_bytes + incoming_bytes > self._max_bytes:
            raise TelemetryOutboxError("outbox_capacity_unavailable")
        return tuple(cleanup)

    @staticmethod
    def _binding(session, point: Point) -> tuple[ConfigurationSnapshot, dict[str, Any]]:
        site = session.scalar(select(Site).limit(1))
        if site is None:
            raise TelemetryOutboxError("installation_missing")
        identity = session.get(EdgeIdentity, 1)
        if (
            identity is None
            or identity.status != "paired"
            or identity.installation_id != site.installation_id
            or identity.credential_id is None
        ):
            raise TelemetryOutboxError("identity_not_telemetry_eligible")
        try:
            _uuid4(identity.credential_id)
        except TelemetryOutboxError:
            raise TelemetryOutboxError("identity_not_telemetry_eligible") from None
        snapshot = session.scalar(
            select(ConfigurationSnapshot)
            .where(
                ConfigurationSnapshot.installation_id == site.installation_id,
                ConfigurationSnapshot.status == "acked",
            )
            .order_by(ConfigurationSnapshot.config_version.desc())
            .limit(1)
        )
        if snapshot is None:
            raise TelemetryOutboxError("acked_snapshot_missing")
        try:
            projection = json.loads(snapshot.payload)
            point_nodes = projection["points"]
        except (TypeError, KeyError, json.JSONDecodeError, UnicodeDecodeError):
            raise TelemetryOutboxError("invalid_snapshot_projection") from None
        if (
            not isinstance(point_nodes, list)
            or projection.get("installationId") != snapshot.installation_id
            or projection.get("snapshotId") != snapshot.snapshot_id
            or projection.get("configVersion") != snapshot.config_version
            or projection.get("projectionSha256") != snapshot.projection_sha256
        ):
            raise TelemetryOutboxError("invalid_snapshot_projection")
        matches = [
            node for node in point_nodes if isinstance(node, dict) and node.get("id") == point.id
        ]
        if len(matches) != 1:
            raise TelemetryOutboxError("point_not_in_acked_snapshot")
        return snapshot, matches[0]

    def append_state(
        self,
        *,
        point_id: str,
        raw_value: str,
        quality: str,
        observed_at: str,
        db_session=None,
    ) -> StoredTelemetryRecord:
        with self._lock:
            self._ensure_spool()
            now = self._clock().astimezone(UTC)
            session_context = (
                self._session_factory() if db_session is None else nullcontext(db_session)
            )
            with session_context as session:
                point = session.get(Point, point_id)
                if (
                    point is None
                    or point.selection_intent != "include"
                    or point.review_status != "reviewed"
                    or point.lifecycle != "active"
                ):
                    raise TelemetryOutboxError("point_not_telemetry_eligible")
                snapshot, point_node = self._binding(session, point)
                stream = session.get(TelemetryStream, point.id)
                if stream is None:
                    stream = TelemetryStream(
                        point_id=point.id,
                        installation_id=snapshot.installation_id,
                        stream_epoch_id=_uuid4(self._uuid_factory()),
                        next_sequence=0,
                        created_at=now,
                        updated_at=now,
                    )
                    session.add(stream)
                if stream.installation_id != snapshot.installation_id:
                    raise TelemetryOutboxError("stream_installation_mismatch")
                if stream.next_sequence >= MAX_SIGNED_INT64:
                    raise TelemetryOutboxError("stream_sequence_exhausted")
                sample_quality = quality in {"good", "stale"}
                quality_event = quality in {"unknown", "unavailable", "invalid"}
                if not sample_quality and not quality_event:
                    raise TelemetryOutboxError("invalid_value_quality")
                if sample_quality and point_node.get("valueType") != "number":
                    raise TelemetryOutboxError("unsupported_point_value_type")
                decimal_value = _decimal(raw_value) if sample_quality else None
                canonical_observed_at = _timestamp(observed_at)
                received_at_edge = _edge_timestamp(now)
                observed_datetime = datetime.fromisoformat(
                    canonical_observed_at.replace("Z", "+00:00")
                )
                received_datetime = datetime.fromisoformat(received_at_edge.replace("Z", "+00:00"))
                if observed_datetime > received_datetime:
                    cleanup_paths = self._prepare_retention(session, incoming_bytes=0, now=now)
                    stored = self._consume_gap(
                        session,
                        snapshot=snapshot,
                        point=point,
                        stream=stream,
                        reason="clock_discontinuity",
                        detected_at=now,
                        cleanup_paths=cleanup_paths,
                    )
                    if db_session is None:
                        try:
                            session.commit()
                        except Exception:
                            session.rollback()
                            self.abort_before_commit(stored)
                            raise
                        self.finalize_after_commit(stored)
                    return stored
                document = {
                    "schemaVersion": "1.0",
                    "installationId": snapshot.installation_id,
                    "configVersion": snapshot.config_version,
                    "snapshotId": snapshot.snapshot_id,
                    "projectionSha256": snapshot.projection_sha256,
                    "pointId": point.id,
                    "streamEpochId": stream.stream_epoch_id,
                    "sequence": stream.next_sequence,
                    "observedAt": canonical_observed_at,
                    "receivedAtEdge": received_at_edge,
                    "valueQuality": quality,
                }
                record_kind = "quality"
                if decimal_value is not None:
                    document["decimalValue"] = decimal_value
                    record_kind = "sample"
                sample_id = _b64digest(_RECORD_DOMAIN + canonical_json(document))
                document["sampleId"] = sample_id
                payload = canonical_json(document)
                if len(payload) > MAX_RECORD_BYTES:
                    raise TelemetryOutboxError("record_too_large")
                cleanup_paths = self._prepare_retention(
                    session,
                    incoming_bytes=len(payload),
                    now=now,
                )
                if not self._has_data_space(len(payload)):
                    stored = self._consume_gap(
                        session,
                        snapshot=snapshot,
                        point=point,
                        stream=stream,
                        reason="storage_failure",
                        detected_at=now,
                        cleanup_paths=cleanup_paths,
                    )
                    if db_session is None:
                        try:
                            session.commit()
                        except Exception:
                            session.rollback()
                            self.abort_before_commit(stored)
                            raise
                        self.finalize_after_commit(stored)
                    return stored

                segment_id = _uuid4(self._uuid_factory())
                relative_path = f"{segment_id}.seg"
                segment_path = self._spool_dir / relative_path
                try:
                    self._segment_writer(segment_path, payload)
                except OSError as exc:
                    try:
                        segment_path.unlink()
                    except FileNotFoundError:
                        pass
                    except OSError:
                        raise TelemetryOutboxError("segment_cleanup_failed") from None
                    directory = os.open(self._spool_dir, os.O_RDONLY)
                    try:
                        os.fsync(directory)
                    finally:
                        os.close(directory)
                    if exc.errno != errno.ENOSPC:
                        raise TelemetryOutboxError("segment_write_failed") from None
                    control_reserve_released = self._release_control_reserve()
                    try:
                        stored = self._consume_gap(
                            session,
                            snapshot=snapshot,
                            point=point,
                            stream=stream,
                            reason="storage_failure",
                            detected_at=now,
                            cleanup_paths=cleanup_paths,
                            control_reserve_released=control_reserve_released,
                        )
                    except Exception:
                        if control_reserve_released:
                            self._restore_control_reserve_best_effort()
                        raise
                    if db_session is None:
                        try:
                            session.commit()
                        except Exception:
                            session.rollback()
                            self.abort_before_commit(stored)
                            raise
                        self.finalize_after_commit(stored)
                    return stored
                self._crash_hook("after_segment_fsync")

                segment = TelemetryOutboxSegment(
                    segment_id=segment_id,
                    relative_path=relative_path,
                    committed_bytes=len(payload),
                    live_bytes=len(payload),
                    sealed=True,
                    created_at=now,
                )
                session.add(segment)
                session.flush()
                session.add(
                    TelemetryOutboxRecord(
                        sample_id=sample_id,
                        point_id=point.id,
                        stream_epoch_id=stream.stream_epoch_id,
                        sequence=stream.next_sequence,
                        record_kind=record_kind,
                        config_version=snapshot.config_version,
                        snapshot_id=snapshot.snapshot_id,
                        projection_sha256=snapshot.projection_sha256,
                        segment_id=segment_id,
                        segment_offset=0,
                        record_length=len(payload),
                        created_at=now,
                    )
                )
                stream.next_sequence += 1
                stream.updated_at = now
                stored = StoredTelemetryRecord(
                    document=document,
                    canonical_bytes=payload,
                    cleanup_paths=cleanup_paths,
                    created_paths=(relative_path,),
                )
                if db_session is None:
                    try:
                        session.commit()
                    except Exception:
                        session.rollback()
                        self.abort_before_commit(stored)
                        raise
                    self.finalize_after_commit(stored)
                return stored
