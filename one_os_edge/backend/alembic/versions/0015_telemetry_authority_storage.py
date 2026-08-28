"""Add durable Edge telemetry-authority and renewal-cut storage.

Revision ID: 0015
Revises: 0014
"""

import sqlalchemy as sa
from alembic import context, op

revision = "0015"
down_revision = "0014"
branch_labels = None
depends_on = None

_MAX_INT64 = 9_223_372_036_854_775_807
_DELIVERY_TABLES = (
    "telemetry_batches",
    "telemetry_batch_records",
    "telemetry_batch_gaps",
    "telemetry_ingest_state",
)
_TARGET_TABLES = ("telemetry_journal_state", "telemetry_authority_cuts")
_QUARANTINE_CONSTRAINT = "ck_telemetry_batch_quarantine"
_PRE_AUTHORITY_QUARANTINE = (
    "(status = 'quarantined' AND terminal_reason IN "
    "('immutable_conflict', 'expired_payload') AND quarantined_at IS NOT NULL) OR "
    "(status != 'quarantined' AND terminal_reason IS NULL AND quarantined_at IS NULL)"
)
_AUTHORITY_QUARANTINE = (
    "(status = 'quarantined' AND terminal_reason IN "
    "('immutable_conflict', 'expired_payload', 'authority_terminalized') AND "
    "quarantined_at IS NOT NULL) OR "
    "(status != 'quarantined' AND terminal_reason IS NULL AND quarantined_at IS NULL)"
)


def _integral(column: str) -> str:
    return f"{column} = CAST({column} AS BIGINT)"


def _row_exists(bind, table_name: str) -> bool:
    table = sa.Table(table_name, sa.MetaData(), autoload_with=bind)
    return bind.execute(sa.select(sa.literal(1)).select_from(table).limit(1)).first() is not None


def _replace_quarantine_constraint(expression: str) -> None:
    with op.batch_alter_table("telemetry_batches") as batch:
        batch.drop_constraint(_QUARANTINE_CONSTRAINT, type_="check")
        batch.create_check_constraint(_QUARANTINE_CONSTRAINT, expression)


def _upgrade_preflight() -> None:
    if context.is_offline_mode():
        return
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())
    required = {"edge_identity", *_DELIVERY_TABLES}
    if not required <= tables:
        missing = ", ".join(sorted(required - tables))
        raise RuntimeError(
            f"required telemetry authority predecessor tables are missing: {missing}"
        )
    unexpected = set(_TARGET_TABLES) & tables
    if unexpected:
        names = ", ".join(sorted(unexpected))
        raise RuntimeError(f"refusing to adopt pre-existing telemetry authority tables: {names}")

    identity_columns = {column["name"] for column in inspector.get_columns("edge_identity")}
    batch_columns = {column["name"] for column in inspector.get_columns("telemetry_batches")}
    target_identity_columns = {"telemetry_authorization_revision", "lineage_id"}
    target_batch_columns = {"batch_authorization_revision", "journal_id"}
    if target_identity_columns & identity_columns or target_batch_columns & batch_columns:
        raise RuntimeError("refusing to adopt pre-existing telemetry authority columns")

    if bind.dialect.name == "postgresql":
        tables_to_lock = ", ".join(("edge_identity", *_DELIVERY_TABLES))
        bind.execute(sa.text(f"LOCK TABLE {tables_to_lock} IN SHARE ROW EXCLUSIVE MODE"))
    elif bind.dialect.name == "sqlite":
        bind.execute(
            sa.text(
                "UPDATE alembic_version SET version_num = version_num WHERE version_num = '0014'"
            )
        )
    for table_name in _DELIVERY_TABLES:
        if _row_exists(bind, table_name):
            raise RuntimeError(
                "telemetry authority migration requires empty telemetry delivery state: "
                f"{table_name}"
            )
    identity = sa.Table("edge_identity", sa.MetaData(), autoload_with=bind)
    invalid_identity = bind.execute(
        sa.select(sa.literal(1))
        .select_from(identity)
        .where(
            sa.or_(
                identity.c.status != "unpaired",
                identity.c.revision != 0,
                identity.c.active_spki_sha256.is_not(None),
                identity.c.credential_id.is_not(None),
                identity.c.certificate_sha256.is_not(None),
                identity.c.certificate_not_after.is_not(None),
                identity.c.installation_revision.is_not(None),
                identity.c.renewal_status.is_not(None),
                identity.c.renewal_request_id.is_not(None),
                identity.c.renewal_issuance_expires_at.is_not(None),
                identity.c.renewal_ack_expires_at.is_not(None),
            )
        )
        .limit(1)
    ).first()
    if invalid_identity is not None:
        raise RuntimeError(
            "telemetry authority migration refuses non-fresh or paired edge identity state"
        )


def _downgrade_preflight() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())
    required = {"edge_identity", "telemetry_batches", *_TARGET_TABLES}
    if not required <= tables:
        missing = ", ".join(sorted(required - tables))
        raise RuntimeError(f"required telemetry authority tables are missing: {missing}")
    if bind.dialect.name == "postgresql":
        bind.execute(
            sa.text(
                "LOCK TABLE telemetry_batches, telemetry_journal_state, "
                "telemetry_authority_cuts, edge_identity IN SHARE ROW EXCLUSIVE MODE"
            )
        )
    elif bind.dialect.name == "sqlite":
        bind.execute(
            sa.text(
                "UPDATE alembic_version SET version_num = version_num WHERE version_num = '0015'"
            )
        )
    if _row_exists(bind, "telemetry_batches") or _row_exists(bind, "telemetry_authority_cuts"):
        raise RuntimeError("refusing to discard durable telemetry authority state")
    journal_state = sa.Table("telemetry_journal_state", sa.MetaData(), autoload_with=bind)
    if bind.scalar(sa.select(journal_state.c.last_journal_id).where(journal_state.c.id == 1)) != 0:
        raise RuntimeError("refusing to discard a non-baseline telemetry journal counter")
    identity = sa.Table("edge_identity", sa.MetaData(), autoload_with=bind)
    divergent = bind.execute(
        sa.select(sa.literal(1))
        .select_from(identity)
        .where(
            sa.or_(
                identity.c.telemetry_authorization_revision != 1,
                identity.c.lineage_id != identity.c.installation_id,
            )
        )
        .limit(1)
    ).first()
    if divergent is not None:
        raise RuntimeError("refusing to discard non-baseline telemetry identity authority")


def upgrade() -> None:
    _upgrade_preflight()
    bind = op.get_bind()
    _replace_quarantine_constraint(_AUTHORITY_QUARANTINE)

    op.add_column(
        "edge_identity",
        sa.Column("telemetry_authorization_revision", sa.BigInteger(), nullable=True),
    )
    op.add_column("edge_identity", sa.Column("lineage_id", sa.String(length=36), nullable=True))
    bind.execute(
        sa.text(
            "UPDATE edge_identity SET telemetry_authorization_revision = 1, "
            "lineage_id = installation_id"
        )
    )
    with op.batch_alter_table("edge_identity") as batch:
        batch.alter_column(
            "telemetry_authorization_revision", existing_type=sa.BigInteger(), nullable=False
        )
        batch.alter_column("lineage_id", existing_type=sa.String(length=36), nullable=False)
        batch.create_check_constraint(
            "ck_edge_identity_telemetry_authorization_revision",
            f"telemetry_authorization_revision BETWEEN 1 AND {_MAX_INT64} AND "
            + _integral("telemetry_authorization_revision"),
        )
        batch.create_unique_constraint(
            "uq_edge_identity_installation_lineage", ["installation_id", "lineage_id"]
        )

    with op.batch_alter_table("telemetry_batches") as batch:
        batch.add_column(sa.Column("batch_authorization_revision", sa.BigInteger(), nullable=False))
        batch.add_column(sa.Column("journal_id", sa.BigInteger(), nullable=False))
        batch.create_check_constraint(
            "ck_telemetry_batch_authorization_revision",
            f"batch_authorization_revision BETWEEN 1 AND {_MAX_INT64} AND "
            + _integral("batch_authorization_revision"),
        )
        batch.create_check_constraint(
            "ck_telemetry_batch_journal_id",
            f"journal_id BETWEEN 1 AND {_MAX_INT64} AND " + _integral("journal_id"),
        )
        batch.create_unique_constraint("uq_telemetry_batch_journal_id", ["journal_id"])

    op.create_table(
        "telemetry_journal_state",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("last_journal_id", sa.BigInteger(), nullable=False),
        sa.CheckConstraint("id = 1", name="ck_telemetry_journal_state_singleton"),
        sa.CheckConstraint(
            f"last_journal_id BETWEEN 0 AND {_MAX_INT64} AND " + _integral("last_journal_id"),
            name="ck_telemetry_journal_state_last_id",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.bulk_insert(
        sa.table(
            "telemetry_journal_state",
            sa.column("id", sa.Integer()),
            sa.column("last_journal_id", sa.BigInteger()),
        ),
        [{"id": 1, "last_journal_id": 0}],
    )

    op.create_table(
        "telemetry_authority_cuts",
        sa.Column("cut_marker_id", sa.String(length=36), nullable=False),
        sa.Column("renewal_request_id", sa.String(length=36), nullable=False),
        sa.Column("installation_id", sa.String(length=36), nullable=False),
        sa.Column("lineage_id", sa.String(length=36), nullable=False),
        sa.Column("historical_authorization_revision", sa.BigInteger(), nullable=False),
        sa.Column("ingest_authorization_revision", sa.BigInteger(), nullable=False),
        sa.Column("cut_journal_max_id", sa.BigInteger(), nullable=False),
        sa.Column("backlog_mode", sa.String(length=16), nullable=False),
        sa.Column("manifest_bytes", sa.LargeBinary(), nullable=False),
        sa.Column("manifest_sha256", sa.LargeBinary(length=32), nullable=False),
        sa.Column("receipt_bytes", sa.LargeBinary(), nullable=True),
        sa.Column("receipt_sha256", sa.LargeBinary(length=32), nullable=True),
        sa.Column("milestone", sa.String(length=24), nullable=False),
        sa.Column("cut_opened_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("receipt_stored_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("identity_promoted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("backlog_drained_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("terminal_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            f"historical_authorization_revision BETWEEN 1 AND {_MAX_INT64 - 1} AND "
            + _integral("historical_authorization_revision"),
            name="ck_telemetry_cut_historical_revision",
        ),
        sa.CheckConstraint(
            "ingest_authorization_revision = historical_authorization_revision + 1 AND "
            + _integral("ingest_authorization_revision"),
            name="ck_telemetry_cut_revision_successor",
        ),
        sa.CheckConstraint(
            f"cut_journal_max_id BETWEEN 0 AND {_MAX_INT64} AND " + _integral("cut_journal_max_id"),
            name="ck_telemetry_cut_journal_max_id",
        ),
        sa.CheckConstraint(
            "(backlog_mode = 'none' AND cut_journal_max_id = 0) OR "
            "(backlog_mode = 'historical' AND cut_journal_max_id >= 1)",
            name="ck_telemetry_cut_backlog_mode",
        ),
        sa.CheckConstraint(
            "length(manifest_bytes) BETWEEN 1 AND 60256",
            name="ck_telemetry_cut_manifest_bytes",
        ),
        sa.CheckConstraint("length(manifest_sha256) = 32", name="ck_telemetry_cut_manifest_hash"),
        sa.CheckConstraint(
            "(receipt_bytes IS NULL AND receipt_sha256 IS NULL AND "
            "(receipt_stored_at IS NULL OR backlog_mode = 'none')) OR "
            "(receipt_bytes IS NOT NULL AND backlog_mode = 'historical' AND "
            "length(receipt_bytes) BETWEEN 1 AND 60628 AND "
            "length(receipt_sha256) = 32 AND receipt_stored_at IS NOT NULL)",
            name="ck_telemetry_cut_receipt_storage",
        ),
        sa.CheckConstraint(
            "milestone IN ('cut_open', 'receipt_stored', 'identity_promoted', "
            "'backlog_drained', 'terminal')",
            name="ck_telemetry_cut_milestone",
        ),
        sa.CheckConstraint(
            "(milestone = 'cut_open' AND receipt_stored_at IS NULL AND "
            "identity_promoted_at IS NULL AND backlog_drained_at IS NULL AND "
            "terminal_at IS NULL) OR "
            "(milestone = 'receipt_stored' AND receipt_stored_at IS NOT NULL AND "
            "identity_promoted_at IS NULL AND backlog_drained_at IS NULL AND "
            "terminal_at IS NULL) OR "
            "(milestone = 'identity_promoted' AND receipt_stored_at IS NOT NULL AND "
            "identity_promoted_at IS NOT NULL AND "
            "backlog_drained_at IS NULL AND terminal_at IS NULL) OR "
            "(milestone = 'backlog_drained' AND receipt_stored_at IS NOT NULL AND "
            "identity_promoted_at IS NOT NULL AND "
            "backlog_drained_at IS NOT NULL AND terminal_at IS NULL) OR "
            "(milestone = 'terminal' AND terminal_at IS NOT NULL)",
            name="ck_telemetry_cut_milestone_fields",
        ),
        sa.ForeignKeyConstraint(
            ["installation_id", "lineage_id"],
            ["edge_identity.installation_id", "edge_identity.lineage_id"],
            name="fk_telemetry_cut_identity_lineage",
        ),
        sa.PrimaryKeyConstraint("cut_marker_id"),
        sa.UniqueConstraint("renewal_request_id", name="uq_telemetry_cut_renewal_request"),
    )
    op.create_index(
        "uq_telemetry_authority_cut_open",
        "telemetry_authority_cuts",
        ["installation_id"],
        unique=True,
        sqlite_where=sa.text("milestone != 'terminal'"),
        postgresql_where=sa.text("milestone != 'terminal'"),
    )


def downgrade() -> None:
    _downgrade_preflight()
    _replace_quarantine_constraint(_PRE_AUTHORITY_QUARANTINE)
    op.drop_index("uq_telemetry_authority_cut_open", table_name="telemetry_authority_cuts")
    op.drop_table("telemetry_authority_cuts")
    op.drop_table("telemetry_journal_state")
    with op.batch_alter_table("telemetry_batches") as batch:
        batch.drop_constraint("uq_telemetry_batch_journal_id", type_="unique")
        batch.drop_constraint("ck_telemetry_batch_journal_id", type_="check")
        batch.drop_constraint("ck_telemetry_batch_authorization_revision", type_="check")
        batch.drop_column("journal_id")
        batch.drop_column("batch_authorization_revision")
    with op.batch_alter_table("edge_identity") as batch:
        batch.drop_constraint("uq_edge_identity_installation_lineage", type_="unique")
        batch.drop_constraint("ck_edge_identity_telemetry_authorization_revision", type_="check")
        batch.drop_column("lineage_id")
        batch.drop_column("telemetry_authorization_revision")
