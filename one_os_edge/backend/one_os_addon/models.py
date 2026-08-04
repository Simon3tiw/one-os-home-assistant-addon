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
