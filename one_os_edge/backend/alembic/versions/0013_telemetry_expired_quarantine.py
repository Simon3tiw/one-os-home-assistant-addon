"""Allow durable quarantine for permanently expired telemetry payloads.

Revision ID: 0013
"""

import sqlalchemy as sa
from alembic import op

revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None


def _assert_columns() -> None:
    inspector = sa.inspect(op.get_bind())
    if "telemetry_batches" not in inspector.get_table_names():
        raise RuntimeError("required telemetry_batches table is missing")
    required = {"status", "terminal_reason", "quarantined_at"}
    actual = {column["name"] for column in inspector.get_columns("telemetry_batches")}
    if not required <= actual:
        missing = ", ".join(sorted(required - actual))
        raise RuntimeError(f"required telemetry_batches columns are missing: {missing}")


def _replace_quarantine_constraint(expression: str) -> None:
    with op.batch_alter_table("telemetry_batches") as batch:
        batch.drop_constraint("ck_telemetry_batch_quarantine", type_="check")
        batch.create_check_constraint("ck_telemetry_batch_quarantine", expression)


def upgrade():
    _assert_columns()
    _replace_quarantine_constraint(
        "(status = 'quarantined' AND terminal_reason IN "
        "('immutable_conflict', 'expired_payload') AND quarantined_at IS NOT NULL) OR "
        "(status != 'quarantined' AND terminal_reason IS NULL AND quarantined_at IS NULL)"
    )


def downgrade():
    _assert_columns()
    if (
        op.get_bind()
        .execute(
            sa.text(
                "SELECT 1 FROM telemetry_batches "
                "WHERE status = 'quarantined' AND terminal_reason != 'immutable_conflict' LIMIT 1"
            )
        )
        .first()
        is not None
    ):
        raise RuntimeError("refusing to discard expired telemetry quarantine semantics")
    _replace_quarantine_constraint(
        "(status = 'quarantined' AND terminal_reason = 'immutable_conflict' AND "
        "quarantined_at IS NOT NULL) OR (status != 'quarantined' AND "
        "terminal_reason IS NULL AND quarantined_at IS NULL)"
    )
