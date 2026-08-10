"""Persist the authoritative Central pairing-session revision.

Revision ID: 0009
"""

import sqlalchemy as sa
from alembic import op

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade():
    columns = {item["name"] for item in sa.inspect(op.get_bind()).get_columns("edge_pairing")}
    if "central_session_revision" not in columns:
        op.add_column("edge_pairing", sa.Column("central_session_revision", sa.Integer()))


def downgrade():
    bind = op.get_bind()
    columns = {item["name"] for item in sa.inspect(bind).get_columns("edge_pairing")}
    if "central_session_revision" not in columns:
        return
    pairing = sa.table("edge_pairing", sa.column("central_session_revision"))
    if (
        bind.execute(
            sa.select(sa.literal(1))
            .select_from(pairing)
            .where(pairing.c.central_session_revision.is_not(None))
            .limit(1)
        ).first()
        is not None
    ):
        raise RuntimeError(
            "Unsafe downgrade cannot preserve Central session revisions; downgrade refused"
        )
    op.drop_column("edge_pairing", "central_session_revision")
