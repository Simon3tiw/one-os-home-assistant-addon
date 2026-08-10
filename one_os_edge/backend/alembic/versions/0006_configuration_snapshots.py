"""Persist selected configuration snapshot outbox metadata.

Revision ID: 0006
"""

import sqlalchemy as sa
from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade():
    if "configuration_snapshots" in sa.inspect(op.get_bind()).get_table_names():
        raise RuntimeError("refusing to adopt pre-existing configuration_snapshots table")
    op.create_table(
        "configuration_snapshots",
        sa.Column("snapshot_id", sa.String(length=36), nullable=False),
        sa.Column("installation_id", sa.String(length=36), nullable=False),
        sa.Column("config_version", sa.Integer(), nullable=False),
        sa.Column("projection_sha256", sa.String(length=43), nullable=False),
        sa.Column("request_sha256", sa.String(length=43), nullable=False),
        sa.Column("payload", sa.LargeBinary(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("last_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("needs_status_check", sa.Boolean(), nullable=False),
        sa.Column("acked_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('pending', 'acked')", name="ck_configuration_snapshot_status"
        ),
        sa.PrimaryKeyConstraint("snapshot_id"),
        sa.UniqueConstraint("installation_id", "config_version", name="uq_config_snapshot_version"),
    )
    op.create_index(
        "uq_configuration_snapshot_pending",
        "configuration_snapshots",
        ["installation_id"],
        unique=True,
        sqlite_where=sa.text("status = 'pending'"),
        postgresql_where=sa.text("status = 'pending'"),
    )


def downgrade():
    bind = op.get_bind()
    if "configuration_snapshots" not in sa.inspect(bind).get_table_names():
        raise RuntimeError("configuration_snapshots table is missing")
    row_count = bind.execute(sa.text("SELECT COUNT(*) FROM configuration_snapshots")).scalar_one()
    if row_count:
        raise RuntimeError("refusing to drop non-empty configuration_snapshots table")
    op.drop_index("uq_configuration_snapshot_pending", table_name="configuration_snapshots")
    op.drop_table("configuration_snapshots")
