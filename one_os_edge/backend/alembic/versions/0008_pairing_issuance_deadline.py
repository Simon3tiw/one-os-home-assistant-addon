"""Persist the public pairing issuance deadline.

Revision ID: 0008
"""

import sqlalchemy as sa
from alembic import op

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade():
    columns = {item["name"] for item in sa.inspect(op.get_bind()).get_columns("edge_pairing")}
    if "issuance_expires_at" not in columns:
        op.add_column(
            "edge_pairing",
            sa.Column("issuance_expires_at", sa.DateTime(timezone=True), nullable=True),
        )


def downgrade():
    bind = op.get_bind()
    columns = {item["name"] for item in sa.inspect(bind).get_columns("edge_pairing")}
    if "issuance_expires_at" not in columns:
        return
    pairing = sa.table("edge_pairing", sa.column("issuance_expires_at"))
    if (
        bind.execute(
            sa.select(sa.literal(1))
            .select_from(pairing)
            .where(pairing.c.issuance_expires_at.is_not(None))
            .limit(1)
        ).first()
        is not None
    ):
        raise RuntimeError("Unsafe downgrade cannot preserve issuance deadlines; downgrade refused")
    op.drop_column("edge_pairing", "issuance_expires_at")
