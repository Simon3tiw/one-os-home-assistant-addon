"""Add singleton ONE.OS Central destination configuration.

Revision ID: 0004
"""

import sqlalchemy as sa
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade():
    inspector = sa.inspect(op.get_bind())
    if "central_destination" not in inspector.get_table_names():
        op.create_table(
            "central_destination",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("revision", sa.Integer(), nullable=False),
            sa.Column("origin", sa.String(length=2048), nullable=False),
            sa.Column("certificate_fingerprint", sa.String(length=64), nullable=False),
            sa.Column("configured_at", sa.DateTime(timezone=True), nullable=False),
            sa.CheckConstraint("id = 1", name="ck_central_destination_singleton"),
            sa.PrimaryKeyConstraint("id"),
        )


def downgrade():
    if "central_destination" in sa.inspect(op.get_bind()).get_table_names():
        op.drop_table("central_destination")
