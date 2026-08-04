"""Commissioning lifecycle, placement and typed properties.

Revision ID: 0002
"""

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def columns(table):
    return {column["name"] for column in sa.inspect(op.get_bind()).get_columns(table)}


def add_column(table, column):
    if column.name not in columns(table):
        op.add_column(table, column)


def upgrade():
    add_column(
        "structures", sa.Column("revision", sa.Integer(), nullable=False, server_default="1")
    )
    add_column("spaces", sa.Column("revision", sa.Integer(), nullable=False, server_default="1"))
    add_column(
        "physical_devices", sa.Column("revision", sa.Integer(), nullable=False, server_default="1")
    )
    add_column("assets", sa.Column("source_space_id", sa.String(), nullable=True))
    add_column(
        "assets",
        sa.Column("name_override", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    add_column(
        "assets",
        sa.Column("placement_override", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    add_column(
        "assets",
        sa.Column("placement_conflict", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    add_column("points", sa.Column("source_asset_id", sa.String(), nullable=True))
    add_column(
        "points",
        sa.Column("placement_override", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    add_column(
        "points",
        sa.Column("placement_conflict", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    add_column(
        "points",
        sa.Column("binding_stability", sa.String(), nullable=False, server_default="stable"),
    )
    add_column(
        "points",
        sa.Column("temporary_accepted", sa.Boolean(), nullable=False, server_default=sa.false()),
    )

    bind = op.get_bind()
    bind.execute(
        sa.text("UPDATE assets SET source_space_id = space_id WHERE source_space_id IS NULL")
    )
    bind.execute(
        sa.text("UPDATE points SET source_asset_id = asset_id WHERE source_asset_id IS NULL")
    )

    structure_checks = {
        item["name"] for item in sa.inspect(bind).get_check_constraints("structures")
    }
    if "ck_structure_exactly_one_parent" not in structure_checks:
        with op.batch_alter_table("structures") as batch:
            batch.alter_column("site_id", existing_type=sa.String(), nullable=True)
            batch.create_check_constraint(
                "ck_structure_exactly_one_parent",
                "(site_id IS NOT NULL AND parent_id IS NULL) OR "
                "(site_id IS NULL AND parent_id IS NOT NULL)",
            )

    asset_foreign_keys = {item["name"] for item in sa.inspect(bind).get_foreign_keys("assets")}
    if "fk_assets_source_space" not in asset_foreign_keys:
        with op.batch_alter_table("assets") as batch:
            batch.create_foreign_key(
                "fk_assets_source_space", "spaces", ["source_space_id"], ["id"]
            )
    point_foreign_keys = {item["name"] for item in sa.inspect(bind).get_foreign_keys("points")}
    if "fk_points_source_asset" not in point_foreign_keys:
        with op.batch_alter_table("points") as batch:
            batch.create_foreign_key(
                "fk_points_source_asset", "assets", ["source_asset_id"], ["id"]
            )

    if "capability_evidence" not in sa.inspect(bind).get_table_names():
        op.create_table(
            "capability_evidence",
            sa.Column("id", sa.String(), primary_key=True),
            sa.Column("point_id", sa.String(), sa.ForeignKey("points.id"), nullable=False),
            sa.Column("evidence_hash", sa.String(), nullable=False),
            sa.Column("evidence_json", sa.Text(), nullable=False),
            sa.Column("adapter_version", sa.String(), nullable=False),
            sa.Column("captured_at", sa.DateTime(timezone=True), nullable=False),
            sa.UniqueConstraint("point_id", "evidence_hash", name="uq_point_evidence_hash"),
        )
        op.create_index("ix_capability_evidence_point_id", "capability_evidence", ["point_id"])

    property_columns = columns("properties")
    if "object_id" in property_columns:
        invalid = bind.scalar(
            sa.text(
                "SELECT COUNT(*) FROM properties p WHERE "
                "(EXISTS(SELECT 1 FROM sites x WHERE x.id=p.object_id) + "
                " EXISTS(SELECT 1 FROM structures x WHERE x.id=p.object_id) + "
                " EXISTS(SELECT 1 FROM spaces x WHERE x.id=p.object_id) + "
                " EXISTS(SELECT 1 FROM assets x WHERE x.id=p.object_id) + "
                " EXISTS(SELECT 1 FROM points x WHERE x.id=p.object_id)) != 1"
            )
        )
        if invalid:
            raise RuntimeError("cannot migrate orphan or ambiguous v1 properties")
        op.rename_table("properties", "properties_v1")
        op.create_table(
            "properties",
            sa.Column("id", sa.String(), primary_key=True),
            sa.Column("site_id", sa.String(), sa.ForeignKey("sites.id"), nullable=True),
            sa.Column("structure_id", sa.String(), sa.ForeignKey("structures.id"), nullable=True),
            sa.Column("space_id", sa.String(), sa.ForeignKey("spaces.id"), nullable=True),
            sa.Column("asset_id", sa.String(), sa.ForeignKey("assets.id"), nullable=True),
            sa.Column("point_id", sa.String(), sa.ForeignKey("points.id"), nullable=True),
            sa.Column("key", sa.String(), nullable=False),
            sa.Column("value_type", sa.String(), nullable=False),
            sa.Column("value_json", sa.Text(), nullable=False),
            sa.Column("revision", sa.Integer(), nullable=False, server_default="1"),
            sa.CheckConstraint(
                "(site_id IS NOT NULL) + (structure_id IS NOT NULL) + "
                "(space_id IS NOT NULL) + (asset_id IS NOT NULL) + "
                "(point_id IS NOT NULL) = 1",
                name="ck_property_exactly_one_owner",
            ),
        )
        for owner in ("site", "structure", "space", "asset", "point"):
            op.create_index(f"ix_properties_{owner}_id", "properties", [f"{owner}_id"])
        property_migration_sql = """
            INSERT INTO properties (
                id, site_id, structure_id, space_id, asset_id, point_id,
                key, value_type, value_json, revision
            )
            SELECT
                p.id,
                CASE WHEN EXISTS(
                    SELECT 1 FROM sites x WHERE x.id=p.object_id
                ) THEN p.object_id END,
                CASE WHEN EXISTS(
                    SELECT 1 FROM structures x WHERE x.id=p.object_id
                ) THEN p.object_id END,
                CASE WHEN EXISTS(
                    SELECT 1 FROM spaces x WHERE x.id=p.object_id
                ) THEN p.object_id END,
                CASE WHEN EXISTS(
                    SELECT 1 FROM assets x WHERE x.id=p.object_id
                ) THEN p.object_id END,
                CASE WHEN EXISTS(
                    SELECT 1 FROM points x WHERE x.id=p.object_id
                ) THEN p.object_id END,
                p.key, p.value_type, p.value_json, 1
            FROM properties_v1 p
        """
        bind.execute(sa.text(property_migration_sql))
        op.drop_table("properties_v1")
    elif "revision" not in property_columns:
        op.add_column(
            "properties", sa.Column("revision", sa.Integer(), nullable=False, server_default="1")
        )

    inspector = sa.inspect(bind)
    unique_constraints = {
        item["name"] for item in inspector.get_unique_constraints("source_bindings")
    }
    indexes = {item["name"] for item in inspector.get_indexes("source_bindings")}
    if "uq_active_binding" in unique_constraints:
        with op.batch_alter_table("source_bindings") as batch:
            batch.drop_constraint("uq_active_binding", type_="unique")
    if "uq_active_binding" not in indexes:
        op.create_index(
            "uq_active_binding",
            "source_bindings",
            ["source_system", "registry_kind", "registry_id"],
            unique=True,
            sqlite_where=sa.text("active = 1"),
        )


def downgrade():
    raise RuntimeError("ONE.OS commissioning migrations are forward-only")
