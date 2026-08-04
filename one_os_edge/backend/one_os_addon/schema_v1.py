"""Frozen prerelease schema used by Alembic revision 0001.

Do not edit this metadata after release; evolve the database through new revisions.
"""

import sqlalchemy as sa

V1_METADATA = sa.MetaData()

sa.Table(
    "sites",
    V1_METADATA,
    sa.Column("id", sa.String(), primary_key=True),
    sa.Column("installation_id", sa.String(), nullable=False, unique=True),
    sa.Column("name", sa.String(), nullable=False),
)
sa.Table(
    "structures",
    V1_METADATA,
    sa.Column("id", sa.String(), primary_key=True),
    sa.Column("site_id", sa.String(), sa.ForeignKey("sites.id"), nullable=False),
    sa.Column("parent_id", sa.String(), sa.ForeignKey("structures.id"), nullable=True),
    sa.Column("type", sa.String(), nullable=False, server_default="Building"),
    sa.Column("name", sa.String(), nullable=False),
    sa.Column("source_key", sa.String(), nullable=False, unique=True),
    sa.Column("lifecycle", sa.String(), nullable=False, server_default="active"),
)
sa.Table(
    "spaces",
    V1_METADATA,
    sa.Column("id", sa.String(), primary_key=True),
    sa.Column("structure_id", sa.String(), sa.ForeignKey("structures.id"), nullable=False),
    sa.Column("type", sa.String(), nullable=False, server_default="Room"),
    sa.Column("name", sa.String(), nullable=False),
    sa.Column("source_key", sa.String(), nullable=False, unique=True),
    sa.Column("lifecycle", sa.String(), nullable=False, server_default="active"),
)
sa.Table(
    "physical_devices",
    V1_METADATA,
    sa.Column("id", sa.String(), primary_key=True),
    sa.Column("name", sa.String(), nullable=False),
    sa.Column("source_key", sa.String(), nullable=False, unique=True),
    sa.Column("lifecycle", sa.String(), nullable=False, server_default="active"),
)
sa.Table(
    "assets",
    V1_METADATA,
    sa.Column("id", sa.String(), primary_key=True),
    sa.Column("space_id", sa.String(), sa.ForeignKey("spaces.id"), nullable=False),
    sa.Column(
        "physical_device_id",
        sa.String(),
        sa.ForeignKey("physical_devices.id"),
        nullable=True,
    ),
    sa.Column("type", sa.String(), nullable=False, server_default="Equipment"),
    sa.Column("name", sa.String(), nullable=False),
    sa.Column("source_key", sa.String(), nullable=False, unique=True),
    sa.Column("lifecycle", sa.String(), nullable=False, server_default="active"),
    sa.Column("revision", sa.Integer(), nullable=False, server_default="1"),
)
sa.Table(
    "points",
    V1_METADATA,
    sa.Column("id", sa.String(), primary_key=True),
    sa.Column("asset_id", sa.String(), sa.ForeignKey("assets.id"), nullable=False),
    sa.Column("source_key", sa.String(), nullable=False, unique=True),
    sa.Column("registry_id", sa.String(), nullable=False),
    sa.Column("current_entity_id", sa.String(), nullable=False),
    sa.Column("source_name", sa.String(), nullable=False),
    sa.Column("display_name", sa.String(), nullable=True),
    sa.Column("source_unit", sa.String(), nullable=True),
    sa.Column("display_unit", sa.String(), nullable=True),
    sa.Column("decimals", sa.Integer(), nullable=True),
    sa.Column("raw_value", sa.String(), nullable=True),
    sa.Column("attributes_json", sa.Text(), nullable=False, server_default="{}"),
    sa.Column("updated_at", sa.String(), nullable=True),
    sa.Column("quality", sa.String(), nullable=False, server_default="unknown"),
    sa.Column("lifecycle", sa.String(), nullable=False, server_default="active"),
    sa.Column("selection_intent", sa.String(), nullable=False, server_default="unset"),
    sa.Column("review_status", sa.String(), nullable=False, server_default="unreviewed"),
    sa.Column("cloud_control_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
    sa.Column(
        "capability_review_required", sa.Boolean(), nullable=False, server_default=sa.false()
    ),
    sa.Column("evidence_json", sa.Text(), nullable=False, server_default="{}"),
    sa.Column("evidence_hash", sa.String(), nullable=False, server_default=""),
    sa.Column("capability_json", sa.Text(), nullable=False, server_default="{}"),
    sa.Column("ontology_class", sa.String(), nullable=True),
    sa.Column("tags_json", sa.Text(), nullable=False, server_default="[]"),
    sa.Column("revision", sa.Integer(), nullable=False, server_default="1"),
)
sa.Table(
    "source_bindings",
    V1_METADATA,
    sa.Column("id", sa.String(), primary_key=True),
    sa.Column("source_system", sa.String(), nullable=False),
    sa.Column("registry_kind", sa.String(), nullable=False),
    sa.Column("registry_id", sa.String(), nullable=False),
    sa.Column("object_id", sa.String(), nullable=False),
    sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
    sa.UniqueConstraint(
        "source_system",
        "registry_kind",
        "registry_id",
        "active",
        name="uq_active_binding",
    ),
)
sa.Table(
    "properties",
    V1_METADATA,
    sa.Column("id", sa.String(), primary_key=True),
    sa.Column("object_id", sa.String(), nullable=False),
    sa.Column("key", sa.String(), nullable=False),
    sa.Column("value_type", sa.String(), nullable=False),
    sa.Column("value_json", sa.Text(), nullable=False),
)
sa.Table(
    "sync_runs",
    V1_METADATA,
    sa.Column("id", sa.String(), primary_key=True),
    sa.Column("at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("status", sa.String(), nullable=False),
    sa.Column("counts_json", sa.Text(), nullable=False),
)
sa.Table(
    "audit",
    V1_METADATA,
    sa.Column("id", sa.String(), primary_key=True),
    sa.Column("actor_id", sa.String(), nullable=False),
    sa.Column("at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("action", sa.String(), nullable=False),
    sa.Column("object_id", sa.String(), nullable=False),
    sa.Column("revision", sa.Integer(), nullable=False),
    sa.Column("fields_json", sa.Text(), nullable=False),
)
