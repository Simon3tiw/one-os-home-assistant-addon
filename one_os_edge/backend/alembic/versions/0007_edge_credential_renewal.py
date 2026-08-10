"""Persist public Edge credential-renewal lifecycle metadata.

Revision ID: 0007
"""

import sqlalchemy as sa
from alembic import op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade():
    columns = {item["name"] for item in sa.inspect(op.get_bind()).get_columns("edge_identity")}
    additions = (
        ("installation_revision", sa.Integer()),
        ("renewal_status", sa.String(length=24)),
        ("renewal_request_id", sa.String(length=36)),
        ("renewal_issuance_expires_at", sa.DateTime(timezone=True)),
        ("renewal_ack_expires_at", sa.DateTime(timezone=True)),
    )
    for name, type_ in additions:
        if name not in columns:
            op.add_column("edge_identity", sa.Column(name, type_, nullable=True))


def downgrade():
    bind = op.get_bind()
    columns = {item["name"] for item in sa.inspect(bind).get_columns("edge_identity")}
    renewal_columns = (
        "renewal_ack_expires_at",
        "renewal_issuance_expires_at",
        "renewal_request_id",
        "renewal_status",
        "installation_revision",
    )
    present_columns = [name for name in renewal_columns if name in columns]
    if present_columns:
        identity_table = sa.table("edge_identity", *(sa.column(name) for name in present_columns))
        retained_row = bind.execute(
            sa.select(sa.literal(1))
            .select_from(identity_table)
            .where(sa.or_(*(identity_table.c[name].is_not(None) for name in present_columns)))
            .limit(1)
        ).first()
        if retained_row is not None:
            raise RuntimeError("Offline downgrade cannot preserve renewal data; downgrade refused")
    for name in renewal_columns:
        if name in columns:
            op.drop_column("edge_identity", name)
