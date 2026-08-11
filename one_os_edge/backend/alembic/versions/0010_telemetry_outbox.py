"""Add durable telemetry outbox metadata.

Revision ID: 0010
"""

import sqlalchemy as sa
from alembic import op

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None

_MAX_INT64 = 9223372036854775807


def upgrade():
    inspector = sa.inspect(op.get_bind())
    existing = set(inspector.get_table_names())
    names = {
        "telemetry_streams",
        "telemetry_outbox_segments",
        "telemetry_outbox_records",
        "telemetry_gaps",
    }
    if existing & names:
        raise RuntimeError("refusing to adopt pre-existing telemetry outbox tables")

    op.create_table(
        "telemetry_streams",
        sa.Column("point_id", sa.String(), nullable=False),
        sa.Column("installation_id", sa.String(length=36), nullable=False),
        sa.Column("stream_epoch_id", sa.String(length=36), nullable=False),
        sa.Column("next_sequence", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            f"next_sequence >= 0 AND next_sequence <= {_MAX_INT64}",
            name="ck_telemetry_stream_next_sequence",
        ),
        sa.ForeignKeyConstraint(["point_id"], ["points.id"]),
        sa.PrimaryKeyConstraint("point_id"),
        sa.UniqueConstraint("stream_epoch_id", name="uq_telemetry_stream_epoch"),
    )

    op.create_table(
        "telemetry_outbox_segments",
        sa.Column("segment_id", sa.String(length=36), nullable=False),
        sa.Column("relative_path", sa.String(length=80), nullable=False),
        sa.Column("committed_bytes", sa.Integer(), nullable=False),
        sa.Column("live_bytes", sa.Integer(), nullable=False),
        sa.Column("sealed", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "committed_bytes >= 0 AND live_bytes >= 0 AND live_bytes <= committed_bytes",
            name="ck_telemetry_segment_bytes",
        ),
        sa.PrimaryKeyConstraint("segment_id"),
        sa.UniqueConstraint("relative_path", name="uq_telemetry_segment_path"),
    )

    op.create_table(
        "telemetry_outbox_records",
        sa.Column("sample_id", sa.String(length=43), nullable=False),
        sa.Column("point_id", sa.String(), nullable=False),
        sa.Column("stream_epoch_id", sa.String(length=36), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("record_kind", sa.String(length=16), nullable=False),
        sa.Column("config_version", sa.Integer(), nullable=False),
        sa.Column("snapshot_id", sa.String(length=36), nullable=False),
        sa.Column("projection_sha256", sa.String(length=43), nullable=False),
        sa.Column("segment_id", sa.String(length=36), nullable=False),
        sa.Column("segment_offset", sa.Integer(), nullable=False),
        sa.Column("record_length", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            f"sequence >= 0 AND sequence <= {_MAX_INT64}", name="ck_telemetry_record_sequence"
        ),
        sa.CheckConstraint(
            f"config_version >= 0 AND config_version <= {_MAX_INT64}",
            name="ck_telemetry_record_config_version",
        ),
        sa.CheckConstraint("record_kind IN ('sample', 'quality')", name="ck_telemetry_record_kind"),
        sa.CheckConstraint(
            "segment_offset >= 0 AND record_length > 0 AND record_length <= 1024",
            name="ck_telemetry_record_location",
        ),
        sa.ForeignKeyConstraint(["point_id"], ["points.id"]),
        sa.ForeignKeyConstraint(["segment_id"], ["telemetry_outbox_segments.segment_id"]),
        sa.PrimaryKeyConstraint("sample_id"),
        sa.UniqueConstraint(
            "point_id",
            "stream_epoch_id",
            "sequence",
            name="uq_telemetry_record_stream_sequence",
        ),
    )
    op.create_index(
        "ix_telemetry_outbox_records_created",
        "telemetry_outbox_records",
        ["created_at", "sample_id"],
    )

    op.create_table(
        "telemetry_gaps",
        sa.Column("gap_id", sa.String(length=36), nullable=False),
        sa.Column("installation_id", sa.String(length=36), nullable=False),
        sa.Column("point_id", sa.String(), nullable=False),
        sa.Column("stream_epoch_id", sa.String(length=36), nullable=False),
        sa.Column("config_version", sa.Integer(), nullable=False),
        sa.Column("snapshot_id", sa.String(length=36), nullable=False),
        sa.Column("projection_sha256", sa.String(length=43), nullable=False),
        sa.Column("first_missing_sequence", sa.Integer(), nullable=False),
        sa.Column("last_missing_sequence", sa.Integer(), nullable=False),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reason", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.CheckConstraint(
            f"first_missing_sequence >= 0 AND last_missing_sequence <= {_MAX_INT64} "
            "AND first_missing_sequence <= last_missing_sequence",
            name="ck_telemetry_gap_range",
        ),
        sa.CheckConstraint(
            "reason IN ('outbox_capacity', 'retention_expired', 'storage_failure', "
            "'clock_discontinuity', 'operator_reset')",
            name="ck_telemetry_gap_reason",
        ),
        sa.CheckConstraint("status IN ('pending', 'acked')", name="ck_telemetry_gap_status"),
        sa.ForeignKeyConstraint(["point_id"], ["points.id"]),
        sa.PrimaryKeyConstraint("gap_id"),
        sa.UniqueConstraint(
            "point_id",
            "stream_epoch_id",
            "first_missing_sequence",
            "last_missing_sequence",
            "reason",
            name="uq_telemetry_gap_range_reason",
        ),
    )


def downgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    for table in (
        "telemetry_gaps",
        "telemetry_outbox_records",
        "telemetry_outbox_segments",
        "telemetry_streams",
    ):
        if table not in inspector.get_table_names():
            raise RuntimeError(f"required telemetry table is missing: {table}")
        reflected = sa.Table(table, sa.MetaData(), autoload_with=bind)
        if (
            bind.execute(sa.select(sa.literal(1)).select_from(reflected).limit(1)).first()
            is not None
        ):
            raise RuntimeError(f"refusing to drop non-empty telemetry table: {table}")
    op.drop_table("telemetry_gaps")
    op.drop_index("ix_telemetry_outbox_records_created", table_name="telemetry_outbox_records")
    op.drop_table("telemetry_outbox_records")
    op.drop_table("telemetry_outbox_segments")
    op.drop_table("telemetry_streams")
