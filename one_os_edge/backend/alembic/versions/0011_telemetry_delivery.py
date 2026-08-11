"""Add durable telemetry delivery journal.

Revision ID: 0011
"""

import sqlalchemy as sa
from alembic import op

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None

_MAX_INT64 = 9223372036854775807


def upgrade():
    inspector = sa.inspect(op.get_bind())
    names = {
        "telemetry_batches",
        "telemetry_batch_records",
        "telemetry_batch_gaps",
        "telemetry_ingest_state",
    }
    if set(inspector.get_table_names()) & names:
        raise RuntimeError("refusing to adopt pre-existing telemetry delivery tables")

    op.create_table(
        "telemetry_batches",
        sa.Column("batch_id", sa.String(length=36), nullable=False),
        sa.Column("installation_id", sa.String(length=36), nullable=False),
        sa.Column("credential_id", sa.String(length=36), nullable=False),
        sa.Column("payload_sha256", sa.String(length=43), nullable=False),
        sa.Column("request_sha256", sa.String(length=43), nullable=False),
        sa.Column("request_bytes", sa.LargeBinary(), nullable=False),
        sa.Column("sample_count", sa.Integer(), nullable=False),
        sa.Column("quality_event_count", sa.Integer(), nullable=False),
        sa.Column("gap_count", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("lease_owner", sa.String(length=64), nullable=True),
        sa.Column("lease_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("last_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ack_bytes", sa.LargeBinary(), nullable=True),
        sa.Column("ingest_cursor", sa.Integer(), nullable=True),
        sa.Column("acked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "sample_count >= 0 AND quality_event_count >= 0 AND gap_count >= 0 AND "
            "sample_count + quality_event_count + gap_count BETWEEN 1 AND 500",
            name="ck_telemetry_batch_counts",
        ),
        sa.CheckConstraint(
            "length(request_bytes) BETWEEN 1 AND 1048576",
            name="ck_telemetry_batch_request_bytes",
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'leased', 'acked')", name="ck_telemetry_batch_status"
        ),
        sa.CheckConstraint(
            f"attempt_count >= 0 AND attempt_count <= {_MAX_INT64}",
            name="ck_telemetry_batch_attempt_count",
        ),
        sa.CheckConstraint(
            "(status = 'leased' AND lease_owner IS NOT NULL AND lease_until IS NOT NULL) OR "
            "(status != 'leased' AND lease_owner IS NULL AND lease_until IS NULL)",
            name="ck_telemetry_batch_lease",
        ),
        sa.CheckConstraint(
            "(status = 'acked' AND ack_bytes IS NOT NULL AND ingest_cursor IS NOT NULL AND "
            "acked_at IS NOT NULL) OR (status != 'acked' AND ack_bytes IS NULL AND "
            "ingest_cursor IS NULL AND acked_at IS NULL)",
            name="ck_telemetry_batch_ack",
        ),
        sa.CheckConstraint(
            f"ingest_cursor IS NULL OR (ingest_cursor >= 0 AND ingest_cursor <= {_MAX_INT64})",
            name="ck_telemetry_batch_ingest_cursor",
        ),
        sa.PrimaryKeyConstraint("batch_id"),
    )
    op.create_index(
        "ix_telemetry_batches_delivery",
        "telemetry_batches",
        ["status", "next_attempt_at", "created_at"],
    )

    op.create_table(
        "telemetry_batch_records",
        sa.Column("sample_id", sa.String(length=43), nullable=False),
        sa.Column("batch_id", sa.String(length=36), nullable=False),
        sa.Column("record_kind", sa.String(length=16), nullable=False),
        sa.Column("ordinal", sa.Integer(), nullable=False),
        sa.CheckConstraint(
            "record_kind IN ('sample', 'quality')", name="ck_telemetry_batch_record_kind"
        ),
        sa.CheckConstraint(
            "ordinal >= 0 AND ordinal < 500", name="ck_telemetry_batch_record_ordinal"
        ),
        sa.ForeignKeyConstraint(["sample_id"], ["telemetry_outbox_records.sample_id"]),
        sa.ForeignKeyConstraint(["batch_id"], ["telemetry_batches.batch_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("sample_id"),
        sa.UniqueConstraint(
            "batch_id", "record_kind", "ordinal", name="uq_telemetry_batch_record_ordinal"
        ),
    )

    op.create_table(
        "telemetry_batch_gaps",
        sa.Column("gap_id", sa.String(length=36), nullable=False),
        sa.Column("batch_id", sa.String(length=36), nullable=False),
        sa.Column("ordinal", sa.Integer(), nullable=False),
        sa.CheckConstraint("ordinal >= 0 AND ordinal < 500", name="ck_telemetry_batch_gap_ordinal"),
        sa.ForeignKeyConstraint(["gap_id"], ["telemetry_gaps.gap_id"]),
        sa.ForeignKeyConstraint(["batch_id"], ["telemetry_batches.batch_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("gap_id"),
        sa.UniqueConstraint("batch_id", "ordinal", name="uq_telemetry_batch_gap_ordinal"),
    )

    op.create_table(
        "telemetry_ingest_state",
        sa.Column("installation_id", sa.String(length=36), nullable=False),
        sa.Column("last_ingest_cursor", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            f"last_ingest_cursor >= 0 AND last_ingest_cursor <= {_MAX_INT64}",
            name="ck_telemetry_ingest_cursor",
        ),
        sa.PrimaryKeyConstraint("installation_id"),
    )


def downgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = (
        "telemetry_batch_gaps",
        "telemetry_batch_records",
        "telemetry_ingest_state",
        "telemetry_batches",
    )
    existing_tables = set(inspector.get_table_names())
    for table in tables:
        if table not in existing_tables:
            raise RuntimeError(f"required telemetry delivery table is missing: {table}")
    expected_index_columns = ["status", "next_attempt_at", "created_at"]
    indexes = {index["name"]: index for index in inspector.get_indexes("telemetry_batches")}
    delivery_index = indexes.get("ix_telemetry_batches_delivery")
    if (
        delivery_index is None
        or delivery_index.get("column_names") != expected_index_columns
        or bool(delivery_index.get("unique"))
    ):
        raise RuntimeError(
            "required telemetry delivery index is missing or has an unexpected binding"
        )
    for table in tables:
        reflected = sa.Table(table, sa.MetaData(), autoload_with=bind)
        if (
            bind.execute(sa.select(sa.literal(1)).select_from(reflected).limit(1)).first()
            is not None
        ):
            raise RuntimeError(f"refusing to drop non-empty telemetry delivery table: {table}")
    op.drop_table("telemetry_batch_gaps")
    op.drop_table("telemetry_batch_records")
    op.drop_table("telemetry_ingest_state")
    op.drop_index("ix_telemetry_batches_delivery", table_name="telemetry_batches")
    op.drop_table("telemetry_batches")
