"""Close Edge protocol signed-int64 storage across durable wire positions.

Revision ID: 0017
Revises: 0016
"""

import sqlalchemy as sa
from alembic import context, op

revision = "0017"
down_revision = "0016"
branch_labels = None
depends_on = None

_MAX_INT64 = 9_223_372_036_854_775_807
_COLUMNS = {
    "configuration_snapshots": ("config_version",),
    "telemetry_streams": ("next_sequence",),
    "telemetry_outbox_records": ("sequence", "config_version"),
    "telemetry_gaps": ("config_version", "first_missing_sequence", "last_missing_sequence"),
    "telemetry_batches": ("installation_revision", "ingest_cursor"),
    "telemetry_ingest_state": ("last_ingest_cursor",),
    "edge_identity": ("installation_revision",),
}
_LOCK_TABLES = tuple(_COLUMNS)


def _integral(column: str, *, nullable: bool = False) -> str:
    predicate = f"{column} BETWEEN 0 AND {_MAX_INT64} AND {column} = CAST({column} AS BIGINT)"
    return f"{column} IS NULL OR ({predicate})" if nullable else predicate


def _lock_and_preflight(*, downgrade: bool = False) -> None:
    if context.is_offline_mode():
        if downgrade:
            raise RuntimeError("offline downgrade cannot prove signed-int64 narrowing safety")
        return
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing = set(inspector.get_table_names())
    missing = set(_COLUMNS) - existing
    if missing:
        raise RuntimeError(
            f"signed-int64 closure predecessor tables missing: {', '.join(sorted(missing))}"
        )
    for table_name, column_names in _COLUMNS.items():
        actual = {column["name"] for column in inspector.get_columns(table_name)}
        absent = set(column_names) - actual
        if absent:
            raise RuntimeError(
                f"signed-int64 closure predecessor columns missing from {table_name}: "
                f"{', '.join(sorted(absent))}"
            )
    if bind.dialect.name == "postgresql":
        bind.execute(
            sa.text("LOCK TABLE " + ", ".join(_LOCK_TABLES) + " IN SHARE ROW EXCLUSIVE MODE")
        )
    elif bind.dialect.name == "sqlite":
        bind.execute(
            sa.text(
                "UPDATE alembic_version SET version_num = version_num WHERE version_num = :revision"
            ),
            {"revision": "0017" if downgrade else "0016"},
        )
    for table_name, column_names in _COLUMNS.items():
        predicates = []
        nullable = {
            column["name"]: column["nullable"] for column in inspector.get_columns(table_name)
        }
        for column_name in column_names:
            valid = _integral(column_name, nullable=nullable[column_name])
            if downgrade and bind.dialect.name == "postgresql":
                valid = f"({valid}) AND ({column_name} IS NULL OR {column_name} <= 2147483647)"
            predicates.append(f"NOT ({valid})")
        invalid = bind.execute(
            sa.text(
                f"SELECT 1 FROM {table_name} WHERE "  # noqa: S608 - fixed internal manifest
                + " OR ".join(predicates)
                + " LIMIT 1"
            )
        ).first()
        if invalid is not None:
            raise RuntimeError(f"signed-int64 closure found dirty values in {table_name}")


def upgrade() -> None:
    _lock_and_preflight()

    with op.batch_alter_table("configuration_snapshots") as batch:
        batch.alter_column("config_version", existing_type=sa.Integer(), type_=sa.BigInteger())
        batch.create_check_constraint("ck_config_snapshot_version_i64", _integral("config_version"))

    with op.batch_alter_table("telemetry_streams") as batch:
        batch.drop_constraint("ck_telemetry_stream_next_sequence", type_="check")
        batch.alter_column("next_sequence", existing_type=sa.Integer(), type_=sa.BigInteger())
        batch.create_check_constraint(
            "ck_telemetry_stream_next_sequence", _integral("next_sequence")
        )

    with op.batch_alter_table("telemetry_outbox_records") as batch:
        batch.drop_constraint("ck_telemetry_record_sequence", type_="check")
        batch.drop_constraint("ck_telemetry_record_config_version", type_="check")
        batch.alter_column("sequence", existing_type=sa.Integer(), type_=sa.BigInteger())
        batch.alter_column("config_version", existing_type=sa.Integer(), type_=sa.BigInteger())
        batch.create_check_constraint("ck_telemetry_record_sequence", _integral("sequence"))
        batch.create_check_constraint(
            "ck_telemetry_record_config_version", _integral("config_version")
        )

    with op.batch_alter_table("telemetry_gaps") as batch:
        batch.drop_constraint("ck_telemetry_gap_range", type_="check")
        batch.alter_column("config_version", existing_type=sa.Integer(), type_=sa.BigInteger())
        batch.alter_column(
            "first_missing_sequence", existing_type=sa.Integer(), type_=sa.BigInteger()
        )
        batch.alter_column(
            "last_missing_sequence", existing_type=sa.Integer(), type_=sa.BigInteger()
        )
        batch.create_check_constraint(
            "ck_telemetry_gap_config_version_i64", _integral("config_version")
        )
        batch.create_check_constraint(
            "ck_telemetry_gap_range",
            _integral("first_missing_sequence")
            + " AND "
            + _integral("last_missing_sequence")
            + " AND first_missing_sequence <= last_missing_sequence",
        )

    with op.batch_alter_table("telemetry_batches") as batch:
        batch.drop_constraint("ck_telemetry_batch_installation_revision", type_="check")
        batch.drop_constraint("ck_telemetry_batch_ingest_cursor", type_="check")
        batch.alter_column(
            "installation_revision", existing_type=sa.Integer(), type_=sa.BigInteger()
        )
        batch.alter_column("ingest_cursor", existing_type=sa.Integer(), type_=sa.BigInteger())
        batch.create_check_constraint(
            "ck_telemetry_batch_installation_revision", _integral("installation_revision")
        )
        batch.create_check_constraint(
            "ck_telemetry_batch_ingest_cursor", _integral("ingest_cursor", nullable=True)
        )

    with op.batch_alter_table("telemetry_ingest_state") as batch:
        batch.drop_constraint("ck_telemetry_ingest_cursor", type_="check")
        batch.alter_column("last_ingest_cursor", existing_type=sa.Integer(), type_=sa.BigInteger())
        batch.create_check_constraint("ck_telemetry_ingest_cursor", _integral("last_ingest_cursor"))

    with op.batch_alter_table("edge_identity") as batch:
        batch.alter_column(
            "installation_revision", existing_type=sa.Integer(), type_=sa.BigInteger()
        )
        batch.create_check_constraint(
            "ck_edge_identity_installation_revision_i64",
            _integral("installation_revision", nullable=True),
        )


def downgrade() -> None:
    _lock_and_preflight(downgrade=True)
    with op.batch_alter_table("edge_identity") as batch:
        batch.drop_constraint("ck_edge_identity_installation_revision_i64", type_="check")
        batch.alter_column(
            "installation_revision", existing_type=sa.BigInteger(), type_=sa.Integer()
        )
    with op.batch_alter_table("telemetry_ingest_state") as batch:
        batch.drop_constraint("ck_telemetry_ingest_cursor", type_="check")
        batch.alter_column("last_ingest_cursor", existing_type=sa.BigInteger(), type_=sa.Integer())
        batch.create_check_constraint(
            "ck_telemetry_ingest_cursor",
            f"last_ingest_cursor BETWEEN 0 AND {_MAX_INT64}",
        )
    with op.batch_alter_table("telemetry_batches") as batch:
        batch.drop_constraint("ck_telemetry_batch_ingest_cursor", type_="check")
        batch.drop_constraint("ck_telemetry_batch_installation_revision", type_="check")
        batch.alter_column("ingest_cursor", existing_type=sa.BigInteger(), type_=sa.Integer())
        batch.alter_column(
            "installation_revision", existing_type=sa.BigInteger(), type_=sa.Integer()
        )
        batch.create_check_constraint(
            "ck_telemetry_batch_installation_revision",
            f"installation_revision BETWEEN 0 AND {_MAX_INT64}",
        )
        batch.create_check_constraint(
            "ck_telemetry_batch_ingest_cursor",
            f"ingest_cursor IS NULL OR ingest_cursor BETWEEN 0 AND {_MAX_INT64}",
        )
    with op.batch_alter_table("telemetry_gaps") as batch:
        batch.drop_constraint("ck_telemetry_gap_range", type_="check")
        batch.drop_constraint("ck_telemetry_gap_config_version_i64", type_="check")
        for name in ("config_version", "first_missing_sequence", "last_missing_sequence"):
            batch.alter_column(name, existing_type=sa.BigInteger(), type_=sa.Integer())
        batch.create_check_constraint(
            "ck_telemetry_gap_range",
            f"first_missing_sequence >= 0 AND last_missing_sequence <= {_MAX_INT64} "
            "AND first_missing_sequence <= last_missing_sequence",
        )
    with op.batch_alter_table("telemetry_outbox_records") as batch:
        batch.drop_constraint("ck_telemetry_record_config_version", type_="check")
        batch.drop_constraint("ck_telemetry_record_sequence", type_="check")
        batch.alter_column("config_version", existing_type=sa.BigInteger(), type_=sa.Integer())
        batch.alter_column("sequence", existing_type=sa.BigInteger(), type_=sa.Integer())
        batch.create_check_constraint(
            "ck_telemetry_record_sequence", f"sequence BETWEEN 0 AND {_MAX_INT64}"
        )
        batch.create_check_constraint(
            "ck_telemetry_record_config_version",
            f"config_version BETWEEN 0 AND {_MAX_INT64}",
        )
    with op.batch_alter_table("telemetry_streams") as batch:
        batch.drop_constraint("ck_telemetry_stream_next_sequence", type_="check")
        batch.alter_column("next_sequence", existing_type=sa.BigInteger(), type_=sa.Integer())
        batch.create_check_constraint(
            "ck_telemetry_stream_next_sequence",
            f"next_sequence BETWEEN 0 AND {_MAX_INT64}",
        )
    with op.batch_alter_table("configuration_snapshots") as batch:
        batch.drop_constraint("ck_config_snapshot_version_i64", type_="check")
        batch.alter_column("config_version", existing_type=sa.BigInteger(), type_=sa.Integer())
