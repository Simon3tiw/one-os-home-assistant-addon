"""Bind durable telemetry batches to installation revisions.

Revision ID: 0014
Revises: 0013
"""

import sqlalchemy as sa
from alembic import context, op

revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None

_INT64 = "9223372036854775807"
_TABLE = "telemetry_batches"
_COLUMN = "installation_revision"
_CONSTRAINT = "ck_telemetry_batch_installation_revision"


def _preflight(*, require_column: bool) -> None:
    if context.is_offline_mode():
        return
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if _TABLE not in inspector.get_table_names():
        raise RuntimeError("required telemetry_batches table is missing")
    columns = {column["name"] for column in inspector.get_columns(_TABLE)}
    if (_COLUMN in columns) != require_column:
        state = "missing" if require_column else "already exists"
        raise RuntimeError(f"telemetry installation revision column {state}")
    if bind.execute(sa.text("SELECT 1 FROM telemetry_batches LIMIT 1")).first() is not None:
        raise RuntimeError("telemetry revision migration requires an empty batch table")


def upgrade():
    _preflight(require_column=False)
    with op.batch_alter_table(_TABLE) as batch:
        batch.add_column(sa.Column(_COLUMN, sa.Integer(), nullable=False))
        batch.create_check_constraint(
            _CONSTRAINT,
            f"{_COLUMN} >= 0 AND {_COLUMN} <= {_INT64}",
        )


def downgrade():
    _preflight(require_column=True)
    with op.batch_alter_table(_TABLE) as batch:
        batch.drop_constraint(_CONSTRAINT, type_="check")
        batch.drop_column(_COLUMN)
