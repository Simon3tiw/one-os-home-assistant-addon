from __future__ import annotations

import hashlib
import hmac
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    event,
    text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column


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
            "(CASE WHEN site_id IS NOT NULL THEN 1 ELSE 0 END) + "
            "(CASE WHEN structure_id IS NOT NULL THEN 1 ELSE 0 END) + "
            "(CASE WHEN space_id IS NOT NULL THEN 1 ELSE 0 END) + "
            "(CASE WHEN asset_id IS NOT NULL THEN 1 ELSE 0 END) + "
            "(CASE WHEN point_id IS NOT NULL THEN 1 ELSE 0 END) = 1",
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
    __table_args__ = (
        CheckConstraint("id = 1", name="ck_edge_identity_singleton"),
        CheckConstraint(
            "telemetry_authorization_revision BETWEEN 1 AND 9223372036854775807 AND "
            "telemetry_authorization_revision = CAST(telemetry_authorization_revision AS BIGINT)",
            name="ck_edge_identity_telemetry_authorization_revision",
        ),
        CheckConstraint(
            "installation_revision IS NULL OR (installation_revision BETWEEN 0 AND "
            "9223372036854775807 AND installation_revision = "
            "CAST(installation_revision AS BIGINT))",
            name="ck_edge_identity_installation_revision_i64",
        ),
        UniqueConstraint(
            "installation_id",
            "lineage_id",
            name="uq_edge_identity_installation_lineage",
        ),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    installation_id: Mapped[str] = mapped_column(String(36), nullable=False, unique=True)
    status: Mapped[str] = mapped_column(String(40), nullable=False, default="unpaired")
    revision: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    active_spki_sha256: Mapped[str | None] = mapped_column(String(43))
    credential_id: Mapped[str | None] = mapped_column(String(36))
    certificate_sha256: Mapped[str | None] = mapped_column(String(43))
    certificate_not_after: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    installation_revision: Mapped[int | None] = mapped_column(BigInteger)
    telemetry_authorization_revision: Mapped[int] = mapped_column(BigInteger, nullable=False)
    lineage_id: Mapped[str] = mapped_column(String(36), nullable=False)
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
        CheckConstraint(
            "config_version BETWEEN 0 AND 9223372036854775807 AND "
            "config_version = CAST(config_version AS BIGINT)",
            name="ck_config_snapshot_version_i64",
        ),
    )
    snapshot_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    installation_id: Mapped[str] = mapped_column(String(36), nullable=False)
    config_version: Mapped[int] = mapped_column(BigInteger, nullable=False)
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
            "next_sequence >= 0 AND next_sequence <= 9223372036854775807 AND "
            "next_sequence = CAST(next_sequence AS BIGINT)",
            name="ck_telemetry_stream_next_sequence",
        ),
        UniqueConstraint("stream_epoch_id", name="uq_telemetry_stream_epoch"),
    )
    point_id: Mapped[str] = mapped_column(ForeignKey("points.id"), primary_key=True)
    installation_id: Mapped[str] = mapped_column(String(36), nullable=False)
    stream_epoch_id: Mapped[str] = mapped_column(String(36), nullable=False)
    next_sequence: Mapped[int] = mapped_column(BigInteger, nullable=False)
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
            "sequence >= 0 AND sequence <= 9223372036854775807 AND "
            "sequence = CAST(sequence AS BIGINT)",
            name="ck_telemetry_record_sequence",
        ),
        CheckConstraint(
            "config_version >= 0 AND config_version <= 9223372036854775807 AND "
            "config_version = CAST(config_version AS BIGINT)",
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
    sequence: Mapped[int] = mapped_column(BigInteger, nullable=False)
    record_kind: Mapped[str] = mapped_column(String(16), nullable=False)
    config_version: Mapped[int] = mapped_column(BigInteger, nullable=False)
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
            "first_missing_sequence <= last_missing_sequence AND "
            "first_missing_sequence = CAST(first_missing_sequence AS BIGINT) AND "
            "last_missing_sequence = CAST(last_missing_sequence AS BIGINT)",
            name="ck_telemetry_gap_range",
        ),
        CheckConstraint(
            "config_version BETWEEN 0 AND 9223372036854775807 AND "
            "config_version = CAST(config_version AS BIGINT)",
            name="ck_telemetry_gap_config_version_i64",
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
    config_version: Mapped[int] = mapped_column(BigInteger, nullable=False)
    snapshot_id: Mapped[str] = mapped_column(String(36), nullable=False)
    projection_sha256: Mapped[str] = mapped_column(String(43), nullable=False)
    first_missing_sequence: Mapped[int] = mapped_column(BigInteger, nullable=False)
    last_missing_sequence: Mapped[int] = mapped_column(BigInteger, nullable=False)
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
            "installation_revision >= 0 AND installation_revision <= 9223372036854775807 AND "
            "installation_revision = CAST(installation_revision AS BIGINT)",
            name="ck_telemetry_batch_installation_revision",
        ),
        CheckConstraint(
            "batch_authorization_revision BETWEEN 1 AND 9223372036854775807 AND "
            "batch_authorization_revision = CAST(batch_authorization_revision AS BIGINT)",
            name="ck_telemetry_batch_authorization_revision",
        ),
        CheckConstraint(
            "journal_id BETWEEN 1 AND 9223372036854775807 AND "
            "journal_id = CAST(journal_id AS BIGINT)",
            name="ck_telemetry_batch_journal_id",
        ),
        CheckConstraint(
            "COALESCE(((current_attempt_request_sha256 IS NULL AND "
            "current_attempt_authorization_revision IS NULL AND current_attempt_at IS NULL) OR "
            "(current_attempt_request_sha256 IS NOT NULL AND "
            "current_attempt_authorization_revision IS NOT NULL AND "
            "current_attempt_at IS NOT NULL AND "
            "current_attempt_request_sha256 = request_sha256 AND "
            "length(current_attempt_request_sha256) = 43 AND "
            "current_attempt_authorization_revision = batch_authorization_revision AND "
            "current_attempt_authorization_revision = "
            "CAST(current_attempt_authorization_revision AS BIGINT))), FALSE)",
            name="ck_telemetry_batch_current_attempt",
        ),
        UniqueConstraint("journal_id", name="uq_telemetry_batch_journal_id"),
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
            "(ingest_cursor >= 0 AND ingest_cursor <= 9223372036854775807 AND "
            "ingest_cursor = CAST(ingest_cursor AS BIGINT))",
            name="ck_telemetry_batch_ingest_cursor",
        ),
        CheckConstraint(
            "(status = 'quarantined' AND terminal_reason IN "
            "('immutable_conflict', 'expired_payload', 'authority_terminalized') AND "
            "quarantined_at IS NOT NULL) OR "
            "(status != 'quarantined' AND terminal_reason IS NULL AND quarantined_at IS NULL)",
            name="ck_telemetry_batch_quarantine",
        ),
        Index("ix_telemetry_batches_delivery", "status", "next_attempt_at", "created_at"),
    )
    batch_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    installation_id: Mapped[str] = mapped_column(String(36), nullable=False)
    installation_revision: Mapped[int] = mapped_column(BigInteger, nullable=False)
    batch_authorization_revision: Mapped[int] = mapped_column(BigInteger, nullable=False)
    journal_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
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
    current_attempt_request_sha256: Mapped[str | None] = mapped_column(String(43))
    current_attempt_authorization_revision: Mapped[int | None] = mapped_column(BigInteger)
    current_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ack_bytes: Mapped[bytes | None] = mapped_column(LargeBinary)
    ingest_cursor: Mapped[int | None] = mapped_column(BigInteger)
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
            "last_ingest_cursor >= 0 AND last_ingest_cursor <= 9223372036854775807 AND "
            "last_ingest_cursor = CAST(last_ingest_cursor AS BIGINT)",
            name="ck_telemetry_ingest_cursor",
        ),
    )
    installation_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    last_ingest_cursor: Mapped[int] = mapped_column(BigInteger, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=now
    )


class TelemetryAuthorityActivation(Base):
    __tablename__ = "telemetry_authority_activation"
    __table_args__ = (
        CheckConstraint("id = 1", name="ck_telemetry_authority_activation_singleton"),
        CheckConstraint(
            "status IN ('capability_stored', 'enable_requested', 'enabled')",
            name="ck_telemetry_authority_activation_status",
        ),
        CheckConstraint(
            "length(capability_sha256) = 32 AND length(server_nonce) = 32 AND "
            "(request_sha256 IS NULL OR length(request_sha256) = 32) AND "
            "(response_sha256 IS NULL OR length(response_sha256) = 32)",
            name="ck_telemetry_authority_activation_hashes",
        ),
        CheckConstraint(
            "telemetry_authorization_revision BETWEEN 1 AND 9223372036854775807 AND "
            "telemetry_authorization_revision = CAST(telemetry_authorization_revision AS BIGINT)",
            name="ck_telemetry_authority_activation_revision",
        ),
        CheckConstraint(
            "(status = 'capability_stored' AND enable_request_bytes IS NULL "
            "AND request_sha256 IS NULL AND enable_response_bytes IS NULL "
            "AND response_sha256 IS NULL AND enabled_at IS NULL) OR "
            "(status = 'enable_requested' AND enable_request_bytes IS NOT NULL "
            "AND request_sha256 IS NOT NULL AND enable_response_bytes IS NULL "
            "AND response_sha256 IS NULL AND enabled_at IS NULL) OR "
            "(status = 'enabled' AND enable_request_bytes IS NOT NULL "
            "AND request_sha256 IS NOT NULL AND enable_response_bytes IS NOT NULL "
            "AND response_sha256 IS NOT NULL AND enabled_at IS NOT NULL)",
            name="ck_telemetry_authority_activation_tuple",
        ),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    installation_id: Mapped[str] = mapped_column(String(36), nullable=False)
    credential_id: Mapped[str] = mapped_column(String(36), nullable=False)
    certificate_sha256: Mapped[str] = mapped_column(String(43), nullable=False)
    telemetry_authorization_revision: Mapped[int] = mapped_column(BigInteger, nullable=False)
    capability_bytes: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    capability_sha256: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    server_nonce: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    enable_request_bytes: Mapped[bytes | None] = mapped_column(LargeBinary)
    request_sha256: Mapped[bytes | None] = mapped_column(LargeBinary(32))
    enable_response_bytes: Mapped[bytes | None] = mapped_column(LargeBinary)
    response_sha256: Mapped[bytes | None] = mapped_column(LargeBinary(32))
    status: Mapped[str] = mapped_column(String(24), nullable=False)
    enabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=now
    )


class TelemetryJournalState(Base):
    __tablename__ = "telemetry_journal_state"
    __table_args__ = (
        CheckConstraint("id = 1", name="ck_telemetry_journal_state_singleton"),
        CheckConstraint(
            "last_journal_id BETWEEN 0 AND 9223372036854775807 AND "
            "last_journal_id = CAST(last_journal_id AS BIGINT)",
            name="ck_telemetry_journal_state_last_id",
        ),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    last_journal_id: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)


class TelemetryAuthorityCut(Base):
    __tablename__ = "telemetry_authority_cuts"
    __table_args__ = (
        CheckConstraint(
            "historical_authorization_revision BETWEEN 1 AND 9223372036854775806 AND "
            "historical_authorization_revision = CAST(historical_authorization_revision AS BIGINT)",
            name="ck_telemetry_cut_historical_revision",
        ),
        CheckConstraint(
            "ingest_authorization_revision = historical_authorization_revision + 1 AND "
            "ingest_authorization_revision = CAST(ingest_authorization_revision AS BIGINT)",
            name="ck_telemetry_cut_revision_successor",
        ),
        CheckConstraint(
            "cut_journal_max_id BETWEEN 0 AND 9223372036854775807 AND "
            "cut_journal_max_id = CAST(cut_journal_max_id AS BIGINT)",
            name="ck_telemetry_cut_journal_max_id",
        ),
        CheckConstraint(
            "(backlog_mode = 'none' AND cut_journal_max_id = 0) OR "
            "(backlog_mode = 'historical' AND cut_journal_max_id >= 1)",
            name="ck_telemetry_cut_backlog_mode",
        ),
        CheckConstraint(
            "length(manifest_bytes) BETWEEN 1 AND 60256",
            name="ck_telemetry_cut_manifest_bytes",
        ),
        CheckConstraint(
            "length(manifest_sha256) = 32",
            name="ck_telemetry_cut_manifest_hash",
        ),
        CheckConstraint(
            "(receipt_bytes IS NULL AND receipt_sha256 IS NULL AND "
            "(receipt_stored_at IS NULL OR backlog_mode = 'none')) OR "
            "(receipt_bytes IS NOT NULL AND backlog_mode = 'historical' AND "
            "length(receipt_bytes) BETWEEN 1 AND 60628 AND "
            "length(receipt_sha256) = 32 AND receipt_stored_at IS NOT NULL)",
            name="ck_telemetry_cut_receipt_storage",
        ),
        CheckConstraint(
            "milestone IN ('cut_open', 'receipt_stored', 'identity_promoted', "
            "'backlog_drained', 'terminal')",
            name="ck_telemetry_cut_milestone",
        ),
        CheckConstraint(
            "(milestone = 'cut_open' AND receipt_stored_at IS NULL AND "
            "identity_promoted_at IS NULL AND backlog_drained_at IS NULL AND "
            "terminal_at IS NULL) OR "
            "(milestone = 'receipt_stored' AND receipt_stored_at IS NOT NULL AND "
            "identity_promoted_at IS NULL AND backlog_drained_at IS NULL AND "
            "terminal_at IS NULL) OR "
            "(milestone = 'identity_promoted' AND receipt_stored_at IS NOT NULL AND "
            "identity_promoted_at IS NOT NULL AND backlog_drained_at IS NULL AND "
            "terminal_at IS NULL) OR "
            "(milestone = 'backlog_drained' AND receipt_stored_at IS NOT NULL AND "
            "identity_promoted_at IS NOT NULL AND "
            "backlog_drained_at IS NOT NULL AND terminal_at IS NULL) OR "
            "(milestone = 'terminal' AND terminal_at IS NOT NULL)",
            name="ck_telemetry_cut_milestone_fields",
        ),
        ForeignKeyConstraint(
            ["installation_id", "lineage_id"],
            ["edge_identity.installation_id", "edge_identity.lineage_id"],
            name="fk_telemetry_cut_identity_lineage",
        ),
        UniqueConstraint("renewal_request_id", name="uq_telemetry_cut_renewal_request"),
        Index(
            "uq_telemetry_authority_cut_open",
            "installation_id",
            unique=True,
            sqlite_where=text("milestone != 'terminal'"),
            postgresql_where=text("milestone != 'terminal'"),
        ),
    )
    cut_marker_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    renewal_request_id: Mapped[str] = mapped_column(String(36), nullable=False)
    installation_id: Mapped[str] = mapped_column(String(36), nullable=False)
    lineage_id: Mapped[str] = mapped_column(String(36), nullable=False)
    historical_authorization_revision: Mapped[int] = mapped_column(BigInteger, nullable=False)
    ingest_authorization_revision: Mapped[int] = mapped_column(BigInteger, nullable=False)
    cut_journal_max_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    backlog_mode: Mapped[str] = mapped_column(String(16), nullable=False)
    manifest_bytes: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    manifest_sha256: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    receipt_bytes: Mapped[bytes | None] = mapped_column(LargeBinary)
    receipt_sha256: Mapped[bytes | None] = mapped_column(LargeBinary(32))
    milestone: Mapped[str] = mapped_column(String(24), nullable=False)
    cut_opened_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    receipt_stored_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    identity_promoted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    backlog_drained_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    terminal_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    def validate_exact_artifacts(self) -> None:
        if not hmac.compare_digest(
            hashlib.sha256(self.manifest_bytes).digest(), self.manifest_sha256
        ):
            raise ValueError("manifest_sha256_mismatch")
        if self.receipt_bytes is None:
            if self.receipt_sha256 is not None:
                raise ValueError("receipt_sha256_without_bytes")
        elif self.receipt_sha256 is None or not hmac.compare_digest(
            hashlib.sha256(self.receipt_bytes).digest(), self.receipt_sha256
        ):
            raise ValueError("receipt_sha256_mismatch")


@event.listens_for(Session, "before_flush")
def _validate_telemetry_authority_cut_artifacts(session, _flush_context, _instances) -> None:
    for value in session.new.union(session.dirty):
        if isinstance(value, TelemetryAuthorityCut):
            value.validate_exact_artifacts()


class TelemetryRenewalOperation(Base):
    __tablename__ = "telemetry_renewal_operation"
    __table_args__ = (
        CheckConstraint("id = 1", name="ck_renewal_v2_singleton"),
        CheckConstraint(
            "status IN ('start_requested', 'pending', 'issued', 'ack_requested', 'acked', "
            "'terminal', 'cancel_requested', 'cancelled', 'quarantined')",
            name="ck_renewal_v2_status",
        ),
        CheckConstraint(
            "installation_revision_before BETWEEN 0 AND 9223372036854775807 AND "
            "installation_revision_before = CAST(installation_revision_before AS BIGINT)",
            name="ck_renewal_v2_installation_revision",
        ),
        CheckConstraint(
            "telemetry_authorization_revision_before BETWEEN 1 AND 9223372036854775807 AND "
            "telemetry_authorization_revision_before = "
            "CAST(telemetry_authorization_revision_before AS BIGINT)",
            name="ck_renewal_v2_authority_before",
        ),
        CheckConstraint(
            "telemetry_authorization_revision_after = "
            "telemetry_authorization_revision_before + 1 AND "
            "telemetry_authorization_revision_after = "
            "CAST(telemetry_authorization_revision_after AS BIGINT)",
            name="ck_renewal_v2_authority_successor",
        ),
        CheckConstraint(
            "cut_journal_max_id BETWEEN 0 AND 9223372036854775807 AND "
            "cut_journal_max_id = CAST(cut_journal_max_id AS BIGINT)",
            name="ck_renewal_v2_cut_journal",
        ),
        CheckConstraint(
            "length(pending_spki_der) BETWEEN 1 AND 256 AND "
            "length(csr_der) BETWEEN 1 AND 380 AND "
            "length(manifest_bytes) BETWEEN 1 AND 60256 AND "
            "length(start_request_bytes) BETWEEN 1 AND 61703",
            name="ck_renewal_v2_raw_sizes",
        ),
        CheckConstraint(
            "length(pending_spki_sha256) = 32 AND length(csr_sha256) = 32 AND "
            "length(manifest_sha256) = 32 AND length(start_request_sha256) = 32 AND "
            "(pending_response_sha256 IS NULL OR length(pending_response_sha256) = 32) AND "
            "(receipt_sha256 IS NULL OR length(receipt_sha256) = 32) AND "
            "(cancel_request_sha256 IS NULL OR length(cancel_request_sha256) = 32) AND "
            "(cancel_response_sha256 IS NULL OR length(cancel_response_sha256) = 32) AND "
            "(issued_response_sha256 IS NULL OR length(issued_response_sha256) = 32) AND "
            "(ack_request_sha256 IS NULL OR length(ack_request_sha256) = 32) AND "
            "(ack_response_sha256 IS NULL OR length(ack_response_sha256) = 32)",
            name="ck_renewal_v2_hash_lengths",
        ),
        CheckConstraint(
            "(status = 'start_requested' AND pending_response_bytes IS NULL AND "
            "pending_response_sha256 IS NULL AND receipt_bytes IS NULL AND receipt_sha256 IS NULL "
            "AND cancel_request_id IS NULL AND cancel_request_bytes IS NULL AND "
            "cancel_request_sha256 IS NULL AND cancel_response_bytes IS NULL AND "
            "cancel_response_sha256 IS NULL) OR "
            "(status = 'pending' AND pending_response_bytes IS NOT NULL AND "
            "pending_response_sha256 IS NOT NULL AND "
            "(receipt_bytes IS NOT NULL OR "
            "(cut_journal_max_id = 0 AND receipt_sha256 IS NULL)) AND "
            "issued_response_bytes IS NULL AND "
            "ack_request_bytes IS NULL AND ack_response_bytes IS NULL AND "
            "cancel_request_id IS NULL AND cancel_request_bytes IS NULL AND "
            "cancel_request_sha256 IS NULL AND cancel_response_bytes IS NULL AND "
            "cancel_response_sha256 IS NULL) OR "
            "(status = 'issued' AND pending_response_bytes IS NOT NULL AND "
            "(receipt_bytes IS NOT NULL OR cut_journal_max_id = 0) "
            "AND issued_response_bytes IS NOT NULL AND ack_request_bytes IS NULL AND "
            "ack_response_bytes IS NULL AND cancel_request_id IS NULL) OR "
            "(status = 'ack_requested' AND pending_response_bytes IS NOT NULL AND "
            "(receipt_bytes IS NOT NULL OR cut_journal_max_id = 0) AND "
            "issued_response_bytes IS NOT NULL AND "
            "ack_request_bytes IS NOT NULL AND ack_response_bytes IS NULL AND "
            "cancel_request_id IS NULL) OR "
            "(status IN ('acked', 'terminal') AND pending_response_bytes IS NOT NULL AND "
            "(receipt_bytes IS NOT NULL OR cut_journal_max_id = 0) AND "
            "issued_response_bytes IS NOT NULL AND "
            "ack_request_bytes IS NOT NULL AND ack_response_bytes IS NOT NULL AND "
            "cancel_request_id IS NULL) OR "
            "(status = 'cancel_requested' AND pending_response_bytes IS NULL AND "
            "pending_response_sha256 IS NULL AND receipt_bytes IS NULL AND receipt_sha256 IS NULL "
            "AND cancel_request_id IS NOT NULL AND cancel_request_bytes IS NOT NULL AND "
            "cancel_request_sha256 IS NOT NULL AND cancel_response_bytes IS NULL AND "
            "cancel_response_sha256 IS NULL) OR "
            "(status = 'cancelled' AND pending_response_bytes IS NULL AND "
            "pending_response_sha256 IS NULL AND receipt_bytes IS NULL AND receipt_sha256 IS NULL "
            "AND cancel_request_id IS NOT NULL AND cancel_request_bytes IS NOT NULL AND "
            "cancel_request_sha256 IS NOT NULL AND cancel_response_bytes IS NOT NULL AND "
            "cancel_response_sha256 IS NOT NULL) OR "
            "(status = 'quarantined' AND "
            "((pending_response_bytes IS NULL AND pending_response_sha256 IS NULL) OR "
            "(pending_response_bytes IS NOT NULL AND pending_response_sha256 IS NOT NULL)) AND "
            "((receipt_bytes IS NULL AND receipt_sha256 IS NULL) OR "
            "(receipt_bytes IS NOT NULL AND receipt_sha256 IS NOT NULL)) AND "
            "((issued_response_bytes IS NULL AND issued_response_sha256 IS NULL) OR "
            "(issued_response_bytes IS NOT NULL AND issued_response_sha256 IS NOT NULL)) AND "
            "((ack_request_bytes IS NULL AND ack_request_sha256 IS NULL) OR "
            "(ack_request_bytes IS NOT NULL AND ack_request_sha256 IS NOT NULL)) AND "
            "((ack_response_bytes IS NULL AND ack_response_sha256 IS NULL) OR "
            "(ack_response_bytes IS NOT NULL AND ack_response_sha256 IS NOT NULL)) AND "
            "((cancel_request_id IS NULL AND cancel_request_bytes IS NULL AND "
            "cancel_request_sha256 IS NULL AND cancel_response_bytes IS NULL AND "
            "cancel_response_sha256 IS NULL) OR (cancel_request_id IS NOT NULL AND "
            "cancel_request_bytes IS NOT NULL AND cancel_request_sha256 IS NOT NULL AND "
            "((cancel_response_bytes IS NULL AND cancel_response_sha256 IS NULL) OR "
            "(cancel_response_bytes IS NOT NULL AND cancel_response_sha256 IS NOT NULL)))))",
            name="ck_renewal_v2_state_tuple",
        ),
        UniqueConstraint("request_id", name="uq_renewal_v2_request"),
        UniqueConstraint("pending_credential_id", name="uq_renewal_v2_pending_credential"),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    status: Mapped[str] = mapped_column(String(24), nullable=False)
    request_id: Mapped[str] = mapped_column(String(36), nullable=False)
    pending_credential_id: Mapped[str] = mapped_column(String(36), nullable=False)
    installation_revision_before: Mapped[int] = mapped_column(BigInteger, nullable=False)
    telemetry_authorization_revision_before: Mapped[int] = mapped_column(BigInteger, nullable=False)
    telemetry_authorization_revision_after: Mapped[int] = mapped_column(BigInteger, nullable=False)
    cut_marker_id: Mapped[str] = mapped_column(String(36), nullable=False)
    cut_journal_max_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    pending_spki_der: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    pending_spki_sha256: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    csr_der: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    csr_sha256: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    manifest_bytes: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    manifest_sha256: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    start_request_bytes: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    start_request_sha256: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    pending_response_bytes: Mapped[bytes | None] = mapped_column(LargeBinary)
    pending_response_sha256: Mapped[bytes | None] = mapped_column(LargeBinary(32))
    receipt_bytes: Mapped[bytes | None] = mapped_column(LargeBinary)
    receipt_sha256: Mapped[bytes | None] = mapped_column(LargeBinary(32))
    issued_response_bytes: Mapped[bytes | None] = mapped_column(LargeBinary)
    issued_response_sha256: Mapped[bytes | None] = mapped_column(LargeBinary(32))
    ack_request_bytes: Mapped[bytes | None] = mapped_column(LargeBinary)
    ack_request_sha256: Mapped[bytes | None] = mapped_column(LargeBinary(32))
    ack_response_bytes: Mapped[bytes | None] = mapped_column(LargeBinary)
    ack_response_sha256: Mapped[bytes | None] = mapped_column(LargeBinary(32))
    cancel_request_id: Mapped[str | None] = mapped_column(String(36))
    cancel_request_bytes: Mapped[bytes | None] = mapped_column(LargeBinary)
    cancel_request_sha256: Mapped[bytes | None] = mapped_column(LargeBinary(32))
    cancel_response_bytes: Mapped[bytes | None] = mapped_column(LargeBinary)
    cancel_response_sha256: Mapped[bytes | None] = mapped_column(LargeBinary(32))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=now
    )

    def validate_exact_artifacts(self) -> None:
        pairs = (
            ("pending_spki", self.pending_spki_der, self.pending_spki_sha256),
            ("csr", self.csr_der, self.csr_sha256),
            ("manifest", self.manifest_bytes, self.manifest_sha256),
            ("start_request", self.start_request_bytes, self.start_request_sha256),
            ("pending_response", self.pending_response_bytes, self.pending_response_sha256),
            ("receipt", self.receipt_bytes, self.receipt_sha256),
            ("issued_response", self.issued_response_bytes, self.issued_response_sha256),
            ("ack_request", self.ack_request_bytes, self.ack_request_sha256),
            ("ack_response", self.ack_response_bytes, self.ack_response_sha256),
            ("cancel_request", self.cancel_request_bytes, self.cancel_request_sha256),
            ("cancel_response", self.cancel_response_bytes, self.cancel_response_sha256),
        )
        for name, raw, digest in pairs:
            if raw is None:
                if digest is not None:
                    raise ValueError(f"{name}_sha256_without_bytes")
            elif digest is None or not hmac.compare_digest(hashlib.sha256(raw).digest(), digest):
                raise ValueError(f"{name}_sha256_mismatch")


@event.listens_for(Session, "before_flush")
def _validate_renewal_v2_artifacts(session, _flush_context, _instances) -> None:
    for value in session.new.union(session.dirty):
        if isinstance(value, TelemetryRenewalOperation):
            value.validate_exact_artifacts()


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
