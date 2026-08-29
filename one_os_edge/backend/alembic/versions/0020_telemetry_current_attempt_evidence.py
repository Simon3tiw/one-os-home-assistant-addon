"""Bind current-authority response-loss evidence to immutable telemetry batches.

Revision ID: 0020
Revises: 0019
"""

import sqlalchemy as sa
from alembic import context, op

revision = "0020"
down_revision = "0019"
branch_labels = None
depends_on = None

_PROOF_CHECK = (
    "(current_attempt_request_sha256 IS NULL AND "
    "current_attempt_authorization_revision IS NULL AND current_attempt_at IS NULL) OR "
    "(current_attempt_request_sha256 = request_sha256 AND "
    "length(current_attempt_request_sha256) = 43 AND "
    "current_attempt_authorization_revision = batch_authorization_revision AND "
    "current_attempt_authorization_revision = "
    "CAST(current_attempt_authorization_revision AS BIGINT) AND "
    "current_attempt_at IS NOT NULL)"
)


def upgrade() -> None:
    with op.batch_alter_table("telemetry_batches") as batch:
        batch.add_column(sa.Column("current_attempt_request_sha256", sa.String(43)))
        batch.add_column(sa.Column("current_attempt_authorization_revision", sa.BigInteger()))
        batch.add_column(sa.Column("current_attempt_at", sa.DateTime(timezone=True)))
        batch.create_check_constraint("ck_telemetry_batch_current_attempt", _PROOF_CHECK)


def downgrade() -> None:
    if context.is_offline_mode():
        raise RuntimeError("offline downgrade cannot prove current-attempt evidence is absent")
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        bind.execute(sa.text("LOCK TABLE telemetry_batches IN SHARE ROW EXCLUSIVE MODE"))
    elif bind.dialect.name == "sqlite":
        bind.execute(
            sa.text(
                "UPDATE alembic_version SET version_num = version_num WHERE version_num = '0020'"
            )
        )
    protected = bind.execute(
        sa.text(
            "SELECT 1 FROM telemetry_batches WHERE "
            "current_attempt_request_sha256 IS NOT NULL OR "
            "current_attempt_authorization_revision IS NOT NULL OR "
            "current_attempt_at IS NOT NULL LIMIT 1"
        )
    ).first()
    if protected is not None:
        raise RuntimeError("refusing to discard durable telemetry current-attempt evidence")
    with op.batch_alter_table("telemetry_batches") as batch:
        batch.drop_constraint("ck_telemetry_batch_current_attempt", type_="check")
        batch.drop_column("current_attempt_at")
        batch.drop_column("current_attempt_authorization_revision")
        batch.drop_column("current_attempt_request_sha256")
