"""Add durable terminal quarantine for immutable telemetry conflicts.

Revision ID: 0012
"""

import sqlalchemy as sa
from alembic import op

revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None


def _assert_columns(expected: set[str]) -> None:
    inspector = sa.inspect(op.get_bind())
    if "telemetry_batches" not in inspector.get_table_names():
        raise RuntimeError("required telemetry_batches table is missing")
    actual = {column["name"] for column in inspector.get_columns("telemetry_batches")}
    if not expected <= actual:
        missing = ", ".join(sorted(expected - actual))
        raise RuntimeError(f"required telemetry_batches columns are missing: {missing}")


def upgrade():
    _assert_columns({"status", "lease_owner", "lease_until", "ack_bytes", "acked_at"})
    existing = {
        column["name"] for column in sa.inspect(op.get_bind()).get_columns("telemetry_batches")
    }
    if {"terminal_reason", "quarantined_at"} & existing:
        raise RuntimeError("refusing to adopt pre-existing telemetry quarantine columns")
    with op.batch_alter_table("telemetry_batches") as batch:
        batch.drop_constraint("ck_telemetry_batch_status", type_="check")
        batch.add_column(sa.Column("terminal_reason", sa.String(length=32), nullable=True))
        batch.add_column(sa.Column("quarantined_at", sa.DateTime(timezone=True), nullable=True))
        batch.create_check_constraint(
            "ck_telemetry_batch_status",
            "status IN ('pending', 'leased', 'acked', 'quarantined')",
        )
        batch.create_check_constraint(
            "ck_telemetry_batch_quarantine",
            "(status = 'quarantined' AND terminal_reason = 'immutable_conflict' AND "
            "quarantined_at IS NOT NULL) OR (status != 'quarantined' AND "
            "terminal_reason IS NULL AND quarantined_at IS NULL)",
        )


def downgrade():
    _assert_columns({"status", "terminal_reason", "quarantined_at"})
    bind = op.get_bind()
    if (
        bind.execute(
            sa.text("SELECT 1 FROM telemetry_batches WHERE status = 'quarantined' LIMIT 1")
        ).first()
        is not None
    ):
        raise RuntimeError("refusing to discard quarantined telemetry batches")
    with op.batch_alter_table("telemetry_batches") as batch:
        batch.drop_constraint("ck_telemetry_batch_quarantine", type_="check")
        batch.drop_constraint("ck_telemetry_batch_status", type_="check")
        batch.drop_column("quarantined_at")
        batch.drop_column("terminal_reason")
        batch.create_check_constraint(
            "ck_telemetry_batch_status",
            "status IN ('pending', 'leased', 'acked')",
        )
