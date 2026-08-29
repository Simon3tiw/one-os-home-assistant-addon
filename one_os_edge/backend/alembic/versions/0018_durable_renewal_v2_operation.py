"""Add durable Edge Draft-4 renewal start and cancel operation state.

Revision ID: 0018
Revises: 0017
"""

import sqlalchemy as sa
from alembic import context, op

revision = "0018"
down_revision = "0017"
branch_labels = None
depends_on = None

_MAX_INT64 = 9_223_372_036_854_775_807


def _integral(name: str, lower: int = 0) -> str:
    return f"{name} BETWEEN {lower} AND {_MAX_INT64} AND {name} = CAST({name} AS BIGINT)"


def upgrade() -> None:
    op.create_table(
        "telemetry_renewal_operation",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("request_id", sa.String(length=36), nullable=False),
        sa.Column("pending_credential_id", sa.String(length=36), nullable=False),
        sa.Column("installation_revision_before", sa.BigInteger(), nullable=False),
        sa.Column("telemetry_authorization_revision_before", sa.BigInteger(), nullable=False),
        sa.Column("telemetry_authorization_revision_after", sa.BigInteger(), nullable=False),
        sa.Column("cut_marker_id", sa.String(length=36), nullable=False),
        sa.Column("cut_journal_max_id", sa.BigInteger(), nullable=False),
        sa.Column("pending_spki_der", sa.LargeBinary(), nullable=False),
        sa.Column("pending_spki_sha256", sa.LargeBinary(length=32), nullable=False),
        sa.Column("csr_der", sa.LargeBinary(), nullable=False),
        sa.Column("csr_sha256", sa.LargeBinary(length=32), nullable=False),
        sa.Column("manifest_bytes", sa.LargeBinary(), nullable=False),
        sa.Column("manifest_sha256", sa.LargeBinary(length=32), nullable=False),
        sa.Column("start_request_bytes", sa.LargeBinary(), nullable=False),
        sa.Column("start_request_sha256", sa.LargeBinary(length=32), nullable=False),
        sa.Column("pending_response_bytes", sa.LargeBinary(), nullable=True),
        sa.Column("pending_response_sha256", sa.LargeBinary(length=32), nullable=True),
        sa.Column("receipt_bytes", sa.LargeBinary(), nullable=True),
        sa.Column("receipt_sha256", sa.LargeBinary(length=32), nullable=True),
        sa.Column("issued_response_bytes", sa.LargeBinary(), nullable=True),
        sa.Column("issued_response_sha256", sa.LargeBinary(length=32), nullable=True),
        sa.Column("ack_request_bytes", sa.LargeBinary(), nullable=True),
        sa.Column("ack_request_sha256", sa.LargeBinary(length=32), nullable=True),
        sa.Column("ack_response_bytes", sa.LargeBinary(), nullable=True),
        sa.Column("ack_response_sha256", sa.LargeBinary(length=32), nullable=True),
        sa.Column("cancel_request_id", sa.String(length=36), nullable=True),
        sa.Column("cancel_request_bytes", sa.LargeBinary(), nullable=True),
        sa.Column("cancel_request_sha256", sa.LargeBinary(length=32), nullable=True),
        sa.Column("cancel_response_bytes", sa.LargeBinary(), nullable=True),
        sa.Column("cancel_response_sha256", sa.LargeBinary(length=32), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("id = 1", name="ck_renewal_v2_singleton"),
        sa.CheckConstraint(
            "status IN ('start_requested', 'pending', 'issued', 'ack_requested', 'acked', "
            "'terminal', 'cancel_requested', 'cancelled', 'quarantined')",
            name="ck_renewal_v2_status",
        ),
        sa.CheckConstraint(
            _integral("installation_revision_before"),
            name="ck_renewal_v2_installation_revision",
        ),
        sa.CheckConstraint(
            _integral("telemetry_authorization_revision_before", 1),
            name="ck_renewal_v2_authority_before",
        ),
        sa.CheckConstraint(
            "telemetry_authorization_revision_after = "
            "telemetry_authorization_revision_before + 1 AND "
            "telemetry_authorization_revision_after = "
            "CAST(telemetry_authorization_revision_after AS BIGINT)",
            name="ck_renewal_v2_authority_successor",
        ),
        sa.CheckConstraint(
            _integral("cut_journal_max_id"),
            name="ck_renewal_v2_cut_journal",
        ),
        sa.CheckConstraint(
            "length(pending_spki_der) BETWEEN 1 AND 256 AND "
            "length(csr_der) BETWEEN 1 AND 380 AND "
            "length(manifest_bytes) BETWEEN 1 AND 60256 AND "
            "length(start_request_bytes) BETWEEN 1 AND 61703",
            name="ck_renewal_v2_raw_sizes",
        ),
        sa.CheckConstraint(
            "length(pending_spki_sha256) = 32 AND length(csr_sha256) = 32 AND "
            "length(manifest_sha256) = 32 AND length(start_request_sha256) = 32 AND "
            "(pending_response_sha256 IS NULL OR length(pending_response_sha256) = 32) AND "
            "(receipt_sha256 IS NULL OR length(receipt_sha256) = 32) AND "
            "(cancel_request_sha256 IS NULL OR length(cancel_request_sha256) = 32) AND "
            "(cancel_response_sha256 IS NULL OR length(cancel_response_sha256) = 32) AND "
            "(issued_response_sha256 IS NULL OR length(issued_response_sha256) = 32) AND "
            "(ack_request_sha256 IS NULL OR length(ack_request_sha256) = 32) AND "
            "(ack_response_sha256 IS NULL OR length(ack_response_sha256) = 32)",
            name="ck_renewal_v2_hash_lengths",
        ),
        sa.CheckConstraint(
            "(status = 'start_requested' AND pending_response_bytes IS NULL AND "
            "pending_response_sha256 IS NULL AND receipt_bytes IS NULL AND receipt_sha256 IS NULL "
            "AND cancel_request_id IS NULL AND cancel_request_bytes IS NULL AND "
            "cancel_request_sha256 IS NULL AND cancel_response_bytes IS NULL AND "
            "cancel_response_sha256 IS NULL) OR "
            "(status = 'pending' AND pending_response_bytes IS NOT NULL AND "
            "pending_response_sha256 IS NOT NULL AND "
            "(receipt_bytes IS NOT NULL OR "
            "(cut_journal_max_id = 0 AND receipt_sha256 IS NULL)) AND "
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
            "(cancel_response_bytes IS NOT NULL AND cancel_response_sha256 IS NOT NULL)))))",
            name="ck_renewal_v2_state_tuple",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("request_id", name="uq_renewal_v2_request"),
        sa.UniqueConstraint("pending_credential_id", name="uq_renewal_v2_pending_credential"),
    )


def downgrade() -> None:
    if context.is_offline_mode():
        raise RuntimeError("offline downgrade cannot prove renewal v2 state is empty")
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        bind.execute(sa.text("LOCK TABLE telemetry_renewal_operation IN SHARE ROW EXCLUSIVE MODE"))
    elif bind.dialect.name == "sqlite":
        bind.execute(
            sa.text(
                "UPDATE alembic_version SET version_num = version_num WHERE version_num = '0018'"
            )
        )
    table = sa.Table("telemetry_renewal_operation", sa.MetaData(), autoload_with=bind)
    if bind.execute(sa.select(sa.literal(1)).select_from(table).limit(1)).first() is not None:
        raise RuntimeError("refusing to discard durable renewal v2 state")
    op.drop_table("telemetry_renewal_operation")
