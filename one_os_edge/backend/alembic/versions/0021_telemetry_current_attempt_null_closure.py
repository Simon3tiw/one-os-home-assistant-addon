"""Close nullable telemetry current-attempt tuple CHECK semantics.

Revision ID: 0021
Revises: 0020
"""

import sqlalchemy as sa
from alembic import context, op

revision = "0021"
down_revision = "0020"
branch_labels = None
depends_on = None

_CONSTRAINT = "ck_telemetry_batch_current_attempt"
_HISTORICAL_CHECK = (
    "(current_attempt_request_sha256 IS NULL AND "
    "current_attempt_authorization_revision IS NULL AND current_attempt_at IS NULL) OR "
    "(current_attempt_request_sha256 = request_sha256 AND "
    "length(current_attempt_request_sha256) = 43 AND "
    "current_attempt_authorization_revision = batch_authorization_revision AND "
    "current_attempt_authorization_revision = "
    "CAST(current_attempt_authorization_revision AS BIGINT) AND "
    "current_attempt_at IS NOT NULL)"
)
_CLOSED_PREDICATE = (
    "((current_attempt_request_sha256 IS NULL AND "
    "current_attempt_authorization_revision IS NULL AND current_attempt_at IS NULL) OR "
    "(current_attempt_request_sha256 IS NOT NULL AND "
    "current_attempt_authorization_revision IS NOT NULL AND current_attempt_at IS NOT NULL AND "
    "current_attempt_request_sha256 = request_sha256 AND "
    "length(current_attempt_request_sha256) = 43 AND "
    "current_attempt_authorization_revision = batch_authorization_revision AND "
    "current_attempt_authorization_revision = "
    "CAST(current_attempt_authorization_revision AS BIGINT)))"
)
_CLOSED_CHECK = f"COALESCE({_CLOSED_PREDICATE}, FALSE)"
_INVALID_QUERY = (
    "SELECT 1 FROM telemetry_batches WHERE "  # noqa: S608 - fixed migration SQL
    f"NOT COALESCE({_CLOSED_PREDICATE}, FALSE) LIMIT 1"
)


def _bind_and_lock(expected_revision: str):
    bind = op.get_bind()
    dialect = bind.dialect.name
    if dialect == "postgresql":
        bind.execute(sa.text("LOCK TABLE telemetry_batches IN SHARE ROW EXCLUSIVE MODE"))
    elif dialect == "sqlite":
        bind.execute(
            sa.text(
                "UPDATE alembic_version SET version_num = version_num "
                "WHERE version_num = :expected_revision"
            ),
            {"expected_revision": expected_revision},
        )
    else:
        raise RuntimeError(f"unsupported database dialect for revision 0021: {dialect}")
    return bind, dialect


def _replace_constraint(*, dialect: str, expression: str) -> None:
    if dialect == "postgresql":
        op.drop_constraint(_CONSTRAINT, "telemetry_batches", type_="check")
        op.create_check_constraint(_CONSTRAINT, "telemetry_batches", expression)
    else:
        with op.batch_alter_table("telemetry_batches") as batch:
            batch.drop_constraint(_CONSTRAINT, type_="check")
            batch.create_check_constraint(_CONSTRAINT, expression)


def upgrade() -> None:
    if context.is_offline_mode():
        dialect = op.get_bind().dialect.name
        if dialect != "postgresql":
            raise RuntimeError(
                "offline upgrade cannot prove telemetry current-attempt tuples are closed"
            )
        op.execute(sa.text("LOCK TABLE telemetry_batches IN SHARE ROW EXCLUSIVE MODE"))
        op.execute(
            sa.text(
                "DO $$ BEGIN IF EXISTS ("
                + _INVALID_QUERY.replace(" LIMIT 1", "")
                + ") THEN RAISE EXCEPTION "
                "'refusing partial telemetry current-attempt evidence'; "
                "END IF; END $$"
            )
        )
        _replace_constraint(dialect=dialect, expression=_CLOSED_CHECK)
        return
    bind, dialect = _bind_and_lock("0020")
    invalid = bind.execute(sa.text(_INVALID_QUERY)).first()
    if invalid is not None:
        raise RuntimeError(
            "refusing partial telemetry current-attempt evidence before constraint DDL"
        )
    _replace_constraint(dialect=dialect, expression=_CLOSED_CHECK)


def downgrade() -> None:
    if context.is_offline_mode():
        dialect = op.get_bind().dialect.name
        if dialect != "postgresql":
            raise RuntimeError(
                "offline downgrade cannot safely replace telemetry current-attempt constraint"
            )
        _replace_constraint(dialect=dialect, expression=_HISTORICAL_CHECK)
        return
    _, dialect = _bind_and_lock("0021")
    _replace_constraint(dialect=dialect, expression=_HISTORICAL_CHECK)
