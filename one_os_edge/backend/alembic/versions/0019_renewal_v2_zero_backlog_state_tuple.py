"""Allow durable Draft-4 renewal v2 zero-backlog issued/ack/acked/terminal state.

Revision ID: 0019
Revises: 0018
"""

import sqlalchemy as sa
from alembic import context, op

revision = "0019"
down_revision = "0018"
branch_labels = None
depends_on = None

_STALE_EXPRESSION = (
    "(status = 'start_requested' AND pending_response_bytes IS NULL AND "
    "pending_response_sha256 IS NULL AND receipt_bytes IS NULL AND receipt_sha256 IS NULL "
    "AND cancel_request_id IS NULL AND cancel_request_bytes IS NULL AND "
    "cancel_request_sha256 IS NULL AND cancel_response_bytes IS NULL AND "
    "cancel_response_sha256 IS NULL) OR "
    "(status = 'pending' AND pending_response_bytes IS NOT NULL AND "
    "pending_response_sha256 IS NOT NULL AND "
    "(receipt_bytes IS NOT NULL OR (cut_journal_max_id = 0 AND receipt_sha256 IS NULL)) AND "
    "issued_response_bytes IS NULL AND "
    "ack_request_bytes IS NULL AND ack_response_bytes IS NULL AND "
    "cancel_request_id IS NULL AND cancel_request_bytes IS NULL AND "
    "cancel_request_sha256 IS NULL AND cancel_response_bytes IS NULL AND "
    "cancel_response_sha256 IS NULL) OR "
    "(status = 'issued' AND pending_response_bytes IS NOT NULL AND "
    "receipt_bytes IS NOT NULL "
    "AND issued_response_bytes IS NOT NULL AND ack_request_bytes IS NULL AND "
    "ack_response_bytes IS NULL AND cancel_request_id IS NULL) OR "
    "(status = 'ack_requested' AND pending_response_bytes IS NOT NULL AND "
    "receipt_bytes IS NOT NULL AND issued_response_bytes IS NOT NULL AND "
    "ack_request_bytes IS NOT NULL AND ack_response_bytes IS NULL AND "
    "cancel_request_id IS NULL) OR "
    "(status IN ('acked', 'terminal') AND pending_response_bytes IS NOT NULL AND "
    "receipt_bytes IS NOT NULL AND issued_response_bytes IS NOT NULL AND "
    "ack_request_bytes IS NOT NULL AND ack_response_bytes IS NOT NULL AND "
    "cancel_request_id IS NULL) OR "
    "(status = 'cancel_requested' AND pending_response_bytes IS NULL AND "
    "pending_response_sha256 IS NULL AND receipt_bytes IS NULL AND receipt_sha256 IS NULL "
    "AND cancel_request_id IS NOT NULL AND cancel_request_bytes IS NOT NULL AND "
    "cancel_request_sha256 IS NOT NULL AND cancel_response_bytes IS NULL AND "
    "cancel_response_sha256 IS NULL) OR "
    "(status = 'cancelled' AND pending_response_bytes IS NULL AND "
    "pending_response_sha256 IS NULL AND receipt_bytes IS NULL AND receipt_sha256 IS NULL "
    "AND cancel_request_id IS NOT NULL AND cancel_request_bytes IS NOT NULL AND "
    "cancel_request_sha256 IS NOT NULL AND cancel_response_bytes IS NOT NULL AND "
    "cancel_response_sha256 IS NOT NULL) OR "
    "(status = 'quarantined' AND "
    "((pending_response_bytes IS NULL AND pending_response_sha256 IS NULL) OR "
    "(pending_response_bytes IS NOT NULL AND pending_response_sha256 IS NOT NULL)) AND "
    "((receipt_bytes IS NULL AND receipt_sha256 IS NULL) OR "
    "(receipt_bytes IS NOT NULL AND receipt_sha256 IS NOT NULL)) AND "
    "((issued_response_bytes IS NULL AND issued_response_sha256 IS NULL) OR "
    "(issued_response_bytes IS NOT NULL AND issued_response_sha256 IS NOT NULL)) AND "
    "((ack_request_bytes IS NULL AND ack_request_sha256 IS NULL) OR "
    "(ack_request_bytes IS NOT NULL AND ack_request_sha256 IS NOT NULL)) AND "
    "((ack_response_bytes IS NULL AND ack_response_sha256 IS NULL) OR "
    "(ack_response_bytes IS NOT NULL AND ack_response_sha256 IS NOT NULL)) AND "
    "((cancel_request_id IS NULL AND cancel_request_bytes IS NULL AND "
    "cancel_request_sha256 IS NULL AND cancel_response_bytes IS NULL AND "
    "cancel_response_sha256 IS NULL) OR (cancel_request_id IS NOT NULL AND "
    "cancel_request_bytes IS NOT NULL AND cancel_request_sha256 IS NOT NULL AND "
    "((cancel_response_bytes IS NULL AND cancel_response_sha256 IS NULL) OR "
    "(cancel_response_bytes IS NOT NULL AND cancel_response_sha256 IS NOT NULL)))))"
)

_FIXED_EXPRESSION = (
    "(status = 'start_requested' AND pending_response_bytes IS NULL AND "
    "pending_response_sha256 IS NULL AND receipt_bytes IS NULL AND receipt_sha256 IS NULL "
    "AND cancel_request_id IS NULL AND cancel_request_bytes IS NULL AND "
    "cancel_request_sha256 IS NULL AND cancel_response_bytes IS NULL AND "
    "cancel_response_sha256 IS NULL) OR "
    "(status = 'pending' AND pending_response_bytes IS NOT NULL AND "
    "pending_response_sha256 IS NOT NULL AND "
    "(receipt_bytes IS NOT NULL OR (cut_journal_max_id = 0 AND receipt_sha256 IS NULL)) AND "
    "issued_response_bytes IS NULL AND "
    "ack_request_bytes IS NULL AND ack_response_bytes IS NULL AND "
    "cancel_request_id IS NULL AND cancel_request_bytes IS NULL AND "
    "cancel_request_sha256 IS NULL AND cancel_response_bytes IS NULL AND "
    "cancel_response_sha256 IS NULL) OR "
    "(status = 'issued' AND pending_response_bytes IS NOT NULL AND "
    "(receipt_bytes IS NOT NULL OR cut_journal_max_id = 0) "
    "AND issued_response_bytes IS NOT NULL AND ack_request_bytes IS NULL AND "
    "ack_response_bytes IS NULL AND cancel_request_id IS NULL) OR "
    "(status = 'ack_requested' AND pending_response_bytes IS NOT NULL AND "
    "(receipt_bytes IS NOT NULL OR cut_journal_max_id = 0) AND "
    "issued_response_bytes IS NOT NULL AND "
    "ack_request_bytes IS NOT NULL AND ack_response_bytes IS NULL AND "
    "cancel_request_id IS NULL) OR "
    "(status IN ('acked', 'terminal') AND pending_response_bytes IS NOT NULL AND "
    "(receipt_bytes IS NOT NULL OR cut_journal_max_id = 0) AND "
    "issued_response_bytes IS NOT NULL AND "
    "ack_request_bytes IS NOT NULL AND ack_response_bytes IS NOT NULL AND "
    "cancel_request_id IS NULL) OR "
    "(status = 'cancel_requested' AND pending_response_bytes IS NULL AND "
    "pending_response_sha256 IS NULL AND receipt_bytes IS NULL AND receipt_sha256 IS NULL "
    "AND cancel_request_id IS NOT NULL AND cancel_request_bytes IS NOT NULL AND "
    "cancel_request_sha256 IS NOT NULL AND cancel_response_bytes IS NULL AND "
    "cancel_response_sha256 IS NULL) OR "
    "(status = 'cancelled' AND pending_response_bytes IS NULL AND "
    "pending_response_sha256 IS NULL AND receipt_bytes IS NULL AND receipt_sha256 IS NULL "
    "AND cancel_request_id IS NOT NULL AND cancel_request_bytes IS NOT NULL AND "
    "cancel_request_sha256 IS NOT NULL AND cancel_response_bytes IS NOT NULL AND "
    "cancel_response_sha256 IS NOT NULL) OR "
    "(status = 'quarantined' AND "
    "((pending_response_bytes IS NULL AND pending_response_sha256 IS NULL) OR "
    "(pending_response_bytes IS NOT NULL AND pending_response_sha256 IS NOT NULL)) AND "
    "((receipt_bytes IS NULL AND receipt_sha256 IS NULL) OR "
    "(receipt_bytes IS NOT NULL AND receipt_sha256 IS NOT NULL)) AND "
    "((issued_response_bytes IS NULL AND issued_response_sha256 IS NULL) OR "
    "(issued_response_bytes IS NOT NULL AND issued_response_sha256 IS NOT NULL)) AND "
    "((ack_request_bytes IS NULL AND ack_request_sha256 IS NULL) OR "
    "(ack_request_bytes IS NOT NULL AND ack_request_sha256 IS NOT NULL)) AND "
    "((ack_response_bytes IS NULL AND ack_response_sha256 IS NULL) OR "
    "(ack_response_bytes IS NOT NULL AND ack_response_sha256 IS NOT NULL)) AND "
    "((cancel_request_id IS NULL AND cancel_request_bytes IS NULL AND "
    "cancel_request_sha256 IS NULL AND cancel_response_bytes IS NULL AND "
    "cancel_response_sha256 IS NULL) OR (cancel_request_id IS NOT NULL AND "
    "cancel_request_bytes IS NOT NULL AND cancel_request_sha256 IS NOT NULL AND "
    "((cancel_response_bytes IS NULL AND cancel_response_sha256 IS NULL) OR "
    "(cancel_response_bytes IS NOT NULL AND cancel_response_sha256 IS NOT NULL)))))"
)


def _replace_constraint(expression: str) -> None:
    with op.batch_alter_table("telemetry_renewal_operation") as batch:
        batch.drop_constraint("ck_renewal_v2_state_tuple", type_="check")
        batch.create_check_constraint("ck_renewal_v2_state_tuple", expression)


def upgrade() -> None:
    _replace_constraint(_FIXED_EXPRESSION)


def downgrade() -> None:
    if context.is_offline_mode():
        raise RuntimeError("offline downgrade cannot prove renewal v2 zero-backlog rows are absent")
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        bind.execute(sa.text("LOCK TABLE telemetry_renewal_operation IN SHARE ROW EXCLUSIVE MODE"))
    elif bind.dialect.name == "sqlite":
        bind.execute(
            sa.text(
                "UPDATE alembic_version SET version_num = version_num WHERE version_num = '0019'"
            )
        )
    if (
        bind.execute(
            sa.text(
                "SELECT 1 FROM telemetry_renewal_operation WHERE "
                "status IN ('issued', 'ack_requested', 'acked', 'terminal') AND "
                "cut_journal_max_id = 0 AND receipt_bytes IS NULL LIMIT 1"
            )
        ).first()
        is not None
    ):
        raise RuntimeError("refusing to discard durable zero-backlog renewal v2 state")
    _replace_constraint(_STALE_EXPRESSION)
