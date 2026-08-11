from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


def uid(prefix: str):
    return f"{prefix}_{uuid4()}"


def now():
    return datetime.now(UTC)


class Site(Base):
    __tablename__ = "sites"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    installation_id: Mapped[str] = mapped_column(String, unique=True)
    name: Mapped[str] = mapped_column(String)


class Structure(Base):
    __tablename__ = "structures"
    __table_args__ = (
        CheckConstraint(
            "(site_id IS NOT NULL AND parent_id IS NULL) OR "
            "(site_id IS NULL AND parent_id IS NOT NULL)",
            name="ck_structure_exactly_one_parent",
        ),
    )
    id: Mapped[str] = mapped_column(String, primary_key=True)
    site_id: Mapped[str | None] = mapped_column(ForeignKey("sites.id"))
    parent_id: Mapped[str | None] = mapped_column(ForeignKey("structures.id"))
    type: Mapped[str] = mapped_column(String)
    name: Mapped[str] = mapped_column(String)
    source_key: Mapped[str] = mapped_column(String, unique=True)
    lifecycle: Mapped[str] = mapped_column(String, default="active")
    revision: Mapped[int] = mapped_column(Integer, default=1)


class Space(Base):
    __tablename__ = "spaces"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    structure_id: Mapped[str] = mapped_column(ForeignKey("structures.id"))
    type: Mapped[str] = mapped_column(String)
    name: Mapped[str] = mapped_column(String)
    source_key: Mapped[str] = mapped_column(String, unique=True)
    lifecycle: Mapped[str] = mapped_column(String, default="active")
    revision: Mapped[int] = mapped_column(Integer, default=1)


class PhysicalDevice(Base):
    __tablename__ = "physical_devices"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    name: Mapped[str] = mapped_column(String)
    source_key: Mapped[str] = mapped_column(String, unique=True)
    lifecycle: Mapped[str] = mapped_column(String, default="active")
    revision: Mapped[int] = mapped_column(Integer, default=1)


class Asset(Base):
    __tablename__ = "assets"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    space_id: Mapped[str] = mapped_column(ForeignKey("spaces.id"))
    source_space_id: Mapped[str | None] = mapped_column(ForeignKey("spaces.id"))
    physical_device_id: Mapped[str | None] = mapped_column(ForeignKey("physical_devices.id"))
    type: Mapped[str] = mapped_column(String, default="Equipment")
    name: Mapped[str] = mapped_column(String)
    source_key: Mapped[str] = mapped_column(String, unique=True)
    lifecycle: Mapped[str] = mapped_column(String, default="active")
    name_override: Mapped[bool] = mapped_column(Boolean, default=False)
    placement_override: Mapped[bool] = mapped_column(Boolean, default=False)
    placement_conflict: Mapped[bool] = mapped_column(Boolean, default=False)
    revision: Mapped[int] = mapped_column(Integer, default=1)


class Point(Base):
    __tablename__ = "points"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"))
    source_asset_id: Mapped[str | None] = mapped_column(ForeignKey("assets.id"))
    source_key: Mapped[str] = mapped_column(String, unique=True)
    registry_id: Mapped[str] = mapped_column(String)
    current_entity_id: Mapped[str] = mapped_column(String)
    source_name: Mapped[str] = mapped_column(String)
    source_unit: Mapped[str | None] = mapped_column(String)
    raw_value: Mapped[str | None] = mapped_column(Text)
    attributes_json: Mapped[str] = mapped_column(Text, default="{}")
    updated_at: Mapped[str | None] = mapped_column(String)
    lifecycle: Mapped[str] = mapped_column(String, default="active")
    quality: Mapped[str] = mapped_column(String, default="unknown")
    review_status: Mapped[str] = mapped_column(String, default="unreviewed")
    selection_intent: Mapped[str] = mapped_column(String, default="unset")
    display_name: Mapped[str | None] = mapped_column(String)
    display_unit: Mapped[str | None] = mapped_column(String)
    decimals: Mapped[int | None] = mapped_column(Integer)
    ontology_class: Mapped[str | None] = mapped_column(String)
    ontology_class_source: Mapped[str] = mapped_column(String, default="unset")
    tags_json: Mapped[str] = mapped_column(Text, default="[]")
    evidence_json: Mapped[str] = mapped_column(Text, default="{}")
    evidence_hash: Mapped[str] = mapped_column(String, default="")
    capability_json: Mapped[str] = mapped_column(Text, default="{}")
    cloud_control_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    capability_review_required: Mapped[bool] = mapped_column(Boolean, default=False)
    placement_override: Mapped[bool] = mapped_column(Boolean, default=False)
    placement_conflict: Mapped[bool] = mapped_column(Boolean, default=False)
    binding_stability: Mapped[str] = mapped_column(String, default="stable")
    temporary_accepted: Mapped[bool] = mapped_column(Boolean, default=False)
    revision: Mapped[int] = mapped_column(Integer, default=1)


class CapabilityEvidenceSnapshot(Base):
    __tablename__ = "capability_evidence"
    __table_args__ = (UniqueConstraint("point_id", "evidence_hash", name="uq_point_evidence_hash"),)
    id: Mapped[str] = mapped_column(String, primary_key=True)
    point_id: Mapped[str] = mapped_column(ForeignKey("points.id"), index=True)
    evidence_hash: Mapped[str] = mapped_column(String)
    evidence_json: Mapped[str] = mapped_column(Text)
    adapter_version: Mapped[str] = mapped_column(String)
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class SourceBinding(Base):
    __tablename__ = "source_bindings"
    __table_args__ = (
        Index(
            "uq_active_binding",
            "source_system",
            "registry_kind",
            "registry_id",
            unique=True,
            sqlite_where=text("active = 1"),
        ),
    )
    id: Mapped[str] = mapped_column(String, primary_key=True)
    source_system: Mapped[str] = mapped_column(String, default="home_assistant")
    registry_kind: Mapped[str] = mapped_column(String)
    registry_id: Mapped[str] = mapped_column(String)
    object_id: Mapped[str] = mapped_column(String)
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class Property(Base):
    __tablename__ = "properties"
    __table_args__ = (
        CheckConstraint(
            "(site_id IS NOT NULL) + (structure_id IS NOT NULL) + (space_id IS NOT NULL) + "
            "(asset_id IS NOT NULL) + (point_id IS NOT NULL) = 1",
            name="ck_property_exactly_one_owner",
        ),
    )
    id: Mapped[str] = mapped_column(String, primary_key=True)
    site_id: Mapped[str | None] = mapped_column(ForeignKey("sites.id"), index=True)
    structure_id: Mapped[str | None] = mapped_column(ForeignKey("structures.id"), index=True)
    space_id: Mapped[str | None] = mapped_column(ForeignKey("spaces.id"), index=True)
    asset_id: Mapped[str | None] = mapped_column(ForeignKey("assets.id"), index=True)
    point_id: Mapped[str | None] = mapped_column(ForeignKey("points.id"), index=True)
    key: Mapped[str] = mapped_column(String)
    value_type: Mapped[str] = mapped_column(String)
    value_json: Mapped[str] = mapped_column(Text)
    revision: Mapped[int] = mapped_column(Integer, default=1)


class CentralDestination(Base):
    __tablename__ = "central_destination"
    __table_args__ = (CheckConstraint("id = 1", name="ck_central_destination_singleton"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    revision: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    origin: Mapped[str] = mapped_column(String(2048), nullable=False)
    certificate_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    configured_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=now
    )


class EdgeIdentity(Base):
    __tablename__ = "edge_identity"
    __table_args__ = (CheckConstraint("id = 1", name="ck_edge_identity_singleton"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    installation_id: Mapped[str] = mapped_column(String(36), nullable=False, unique=True)
    status: Mapped[str] = mapped_column(String(40), nullable=False, default="unpaired")
    revision: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    active_spki_sha256: Mapped[str | None] = mapped_column(String(43))
    credential_id: Mapped[str | None] = mapped_column(String(36))
    certificate_sha256: Mapped[str | None] = mapped_column(String(43))
    certificate_not_after: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    installation_revision: Mapped[int | None] = mapped_column(Integer)
    renewal_status: Mapped[str | None] = mapped_column(String(24))
    renewal_request_id: Mapped[str | None] = mapped_column(String(36))
    renewal_issuance_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    renewal_ack_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class EdgePairing(Base):
    __tablename__ = "edge_pairing"
    __table_args__ = (CheckConstraint("id = 1", name="ck_edge_pairing_singleton"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    revision: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    central_session_revision: Mapped[int | None] = mapped_column(Integer)
    mode: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(40), nullable=False)
    registration_request_id: Mapped[str] = mapped_column(String(36), nullable=False, unique=True)
    session_id: Mapped[str | None] = mapped_column(String(36))
    token_generation: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    candidate_spki_sha256: Mapped[str] = mapped_column(String(43), nullable=False)
    csr_sha256: Mapped[str] = mapped_column(String(43), nullable=False)
    tenant_id: Mapped[str | None] = mapped_column(String(36))
    site_id: Mapped[str | None] = mapped_column(String(120))
    claim_revision: Mapped[int | None] = mapped_column(Integer)
    installation_revision: Mapped[int | None] = mapped_column(Integer)
    credential_id: Mapped[str | None] = mapped_column(String(36))
    certificate_sha256: Mapped[str | None] = mapped_column(String(43))
    registration_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    code_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    claim_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    issuance_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ack_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(String(80))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class ConfigurationSnapshot(Base):
    __tablename__ = "configuration_snapshots"
    __table_args__ = (
        UniqueConstraint("installation_id", "config_version", name="uq_config_snapshot_version"),
        Index(
            "uq_configuration_snapshot_pending",
            "installation_id",
            unique=True,
            sqlite_where=text("status = 'pending'"),
            postgresql_where=text("status = 'pending'"),
        ),
        CheckConstraint("status IN ('pending', 'acked')", name="ck_configuration_snapshot_status"),
    )
    snapshot_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    installation_id: Mapped[str] = mapped_column(String(36), nullable=False)
    config_version: Mapped[int] = mapped_column(Integer, nullable=False)
    projection_sha256: Mapped[str] = mapped_column(String(43), nullable=False)
    request_sha256: Mapped[str] = mapped_column(String(43), nullable=False)
    payload: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=now
    )
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    needs_status_check: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    acked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class TelemetryStream(Base):
    __tablename__ = "telemetry_streams"
    __table_args__ = (
        CheckConstraint(
            "next_sequence >= 0 AND next_sequence <= 9223372036854775807",
            name="ck_telemetry_stream_next_sequence",
        ),
        UniqueConstraint("stream_epoch_id", name="uq_telemetry_stream_epoch"),
    )
    point_id: Mapped[str] = mapped_column(ForeignKey("points.id"), primary_key=True)
    installation_id: Mapped[str] = mapped_column(String(36), nullable=False)
    stream_epoch_id: Mapped[str] = mapped_column(String(36), nullable=False)
    next_sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=now
    )


class TelemetryOutboxSegment(Base):
    __tablename__ = "telemetry_outbox_segments"
    __table_args__ = (
        CheckConstraint(
            "committed_bytes >= 0 AND live_bytes >= 0 AND live_bytes <= committed_bytes",
            name="ck_telemetry_segment_bytes",
        ),
        UniqueConstraint("relative_path", name="uq_telemetry_segment_path"),
    )
    segment_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    relative_path: Mapped[str] = mapped_column(String(80), nullable=False)
    committed_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    live_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    sealed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=now
    )


class TelemetryOutboxRecord(Base):
    __tablename__ = "telemetry_outbox_records"
    __table_args__ = (
        CheckConstraint(
            "sequence >= 0 AND sequence <= 9223372036854775807",
            name="ck_telemetry_record_sequence",
        ),
        CheckConstraint(
            "config_version >= 0 AND config_version <= 9223372036854775807",
            name="ck_telemetry_record_config_version",
        ),
        CheckConstraint("record_kind IN ('sample', 'quality')", name="ck_telemetry_record_kind"),
        CheckConstraint(
            "segment_offset >= 0 AND record_length > 0 AND record_length <= 1024",
            name="ck_telemetry_record_location",
        ),
        UniqueConstraint(
            "point_id",
            "stream_epoch_id",
            "sequence",
            name="uq_telemetry_record_stream_sequence",
        ),
        Index("ix_telemetry_outbox_records_created", "created_at", "sample_id"),
    )
    sample_id: Mapped[str] = mapped_column(String(43), primary_key=True)
    point_id: Mapped[str] = mapped_column(ForeignKey("points.id"), nullable=False)
    stream_epoch_id: Mapped[str] = mapped_column(String(36), nullable=False)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    record_kind: Mapped[str] = mapped_column(String(16), nullable=False)
    config_version: Mapped[int] = mapped_column(Integer, nullable=False)
    snapshot_id: Mapped[str] = mapped_column(String(36), nullable=False)
    projection_sha256: Mapped[str] = mapped_column(String(43), nullable=False)
    segment_id: Mapped[str] = mapped_column(
        ForeignKey("telemetry_outbox_segments.segment_id"), nullable=False
    )
    segment_offset: Mapped[int] = mapped_column(Integer, nullable=False)
    record_length: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=now
    )


class TelemetryGap(Base):
    __tablename__ = "telemetry_gaps"
    __table_args__ = (
        CheckConstraint(
            "first_missing_sequence >= 0 AND "
            "last_missing_sequence <= 9223372036854775807 AND "
            "first_missing_sequence <= last_missing_sequence",
            name="ck_telemetry_gap_range",
        ),
        CheckConstraint(
            "reason IN ('outbox_capacity', 'retention_expired', 'storage_failure', "
            "'clock_discontinuity', 'operator_reset')",
            name="ck_telemetry_gap_reason",
        ),
        CheckConstraint("status IN ('pending', 'acked')", name="ck_telemetry_gap_status"),
        UniqueConstraint(
            "point_id",
            "stream_epoch_id",
            "first_missing_sequence",
            "last_missing_sequence",
            "reason",
            name="uq_telemetry_gap_range_reason",
        ),
    )
    gap_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    installation_id: Mapped[str] = mapped_column(String(36), nullable=False)
    point_id: Mapped[str] = mapped_column(ForeignKey("points.id"), nullable=False)
    stream_epoch_id: Mapped[str] = mapped_column(String(36), nullable=False)
    config_version: Mapped[int] = mapped_column(Integer, nullable=False)
    snapshot_id: Mapped[str] = mapped_column(String(36), nullable=False)
    projection_sha256: Mapped[str] = mapped_column(String(43), nullable=False)
    first_missing_sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    last_missing_sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=now
    )
    reason: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)


class TelemetryBatch(Base):
    __tablename__ = "telemetry_batches"
    __table_args__ = (
        CheckConstraint(
            "sample_count >= 0 AND quality_event_count >= 0 AND gap_count >= 0 AND "
            "sample_count + quality_event_count + gap_count BETWEEN 1 AND 500",
            name="ck_telemetry_batch_counts",
        ),
        CheckConstraint(
            "length(request_bytes) BETWEEN 1 AND 1048576",
            name="ck_telemetry_batch_request_bytes",
        ),
        CheckConstraint(
            "status IN ('pending', 'leased', 'acked', 'quarantined')",
            name="ck_telemetry_batch_status",
        ),
        CheckConstraint(
            "attempt_count >= 0 AND attempt_count <= 9223372036854775807",
            name="ck_telemetry_batch_attempt_count",
        ),
        CheckConstraint(
            "(status = 'leased' AND lease_owner IS NOT NULL AND lease_until IS NOT NULL) OR "
            "(status != 'leased' AND lease_owner IS NULL AND lease_until IS NULL)",
            name="ck_telemetry_batch_lease",
        ),
        CheckConstraint(
            "(status = 'acked' AND ack_bytes IS NOT NULL AND ingest_cursor IS NOT NULL AND "
            "acked_at IS NOT NULL) OR (status != 'acked' AND ack_bytes IS NULL AND "
            "ingest_cursor IS NULL AND acked_at IS NULL)",
            name="ck_telemetry_batch_ack",
        ),
        CheckConstraint(
            "ingest_cursor IS NULL OR "
            "(ingest_cursor >= 0 AND ingest_cursor <= 9223372036854775807)",
            name="ck_telemetry_batch_ingest_cursor",
        ),
        CheckConstraint(
            "(status = 'quarantined' AND terminal_reason = 'immutable_conflict' AND "
            "quarantined_at IS NOT NULL) OR (status != 'quarantined' AND "
            "terminal_reason IS NULL AND quarantined_at IS NULL)",
            name="ck_telemetry_batch_quarantine",
        ),
        Index("ix_telemetry_batches_delivery", "status", "next_attempt_at", "created_at"),
    )
    batch_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    installation_id: Mapped[str] = mapped_column(String(36), nullable=False)
    credential_id: Mapped[str] = mapped_column(String(36), nullable=False)
    payload_sha256: Mapped[str] = mapped_column(String(43), nullable=False)
    request_sha256: Mapped[str] = mapped_column(String(43), nullable=False)
    request_bytes: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    sample_count: Mapped[int] = mapped_column(Integer, nullable=False)
    quality_event_count: Mapped[int] = mapped_column(Integer, nullable=False)
    gap_count: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    lease_owner: Mapped[str | None] = mapped_column(String(64))
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ack_bytes: Mapped[bytes | None] = mapped_column(LargeBinary)
    ingest_cursor: Mapped[int | None] = mapped_column(Integer)
    acked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    terminal_reason: Mapped[str | None] = mapped_column(String(32))
    quarantined_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=now
    )


class TelemetryBatchRecord(Base):
    __tablename__ = "telemetry_batch_records"
    __table_args__ = (
        CheckConstraint(
            "record_kind IN ('sample', 'quality')", name="ck_telemetry_batch_record_kind"
        ),
        CheckConstraint("ordinal >= 0 AND ordinal < 500", name="ck_telemetry_batch_record_ordinal"),
        UniqueConstraint(
            "batch_id", "record_kind", "ordinal", name="uq_telemetry_batch_record_ordinal"
        ),
    )
    sample_id: Mapped[str] = mapped_column(
        ForeignKey("telemetry_outbox_records.sample_id"), primary_key=True
    )
    batch_id: Mapped[str] = mapped_column(
        ForeignKey("telemetry_batches.batch_id", ondelete="CASCADE"), nullable=False
    )
    record_kind: Mapped[str] = mapped_column(String(16), nullable=False)
    ordinal: Mapped[int] = mapped_column(Integer, nullable=False)


class TelemetryBatchGap(Base):
    __tablename__ = "telemetry_batch_gaps"
    __table_args__ = (
        CheckConstraint("ordinal >= 0 AND ordinal < 500", name="ck_telemetry_batch_gap_ordinal"),
        UniqueConstraint("batch_id", "ordinal", name="uq_telemetry_batch_gap_ordinal"),
    )
    gap_id: Mapped[str] = mapped_column(ForeignKey("telemetry_gaps.gap_id"), primary_key=True)
    batch_id: Mapped[str] = mapped_column(
        ForeignKey("telemetry_batches.batch_id", ondelete="CASCADE"), nullable=False
    )
    ordinal: Mapped[int] = mapped_column(Integer, nullable=False)


class TelemetryIngestState(Base):
    __tablename__ = "telemetry_ingest_state"
    __table_args__ = (
        CheckConstraint(
            "last_ingest_cursor >= 0 AND last_ingest_cursor <= 9223372036854775807",
            name="ck_telemetry_ingest_cursor",
        ),
    )
    installation_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    last_ingest_cursor: Mapped[int] = mapped_column(Integer, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=now
    )


class Audit(Base):
    __tablename__ = "audit"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    actor_id: Mapped[str] = mapped_column(String)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    action: Mapped[str] = mapped_column(String)
    object_id: Mapped[str] = mapped_column(String)
    revision: Mapped[int] = mapped_column(Integer)
    fields_json: Mapped[str] = mapped_column(Text, default="[]")


class SyncRun(Base):
    __tablename__ = "sync_runs"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    status: Mapped[str] = mapped_column(String)
    counts_json: Mapped[str] = mapped_column(Text)
