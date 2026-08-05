"""Track ontology class provenance.

Revision ID: 0003
"""

import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade():
    columns = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("points")}
    if "ontology_class_source" not in columns:
        op.add_column(
            "points",
            sa.Column(
                "ontology_class_source",
                sa.String(),
                nullable=False,
                server_default="unset",
            ),
        )
    op.get_bind().execute(
        sa.text(
            "UPDATE points SET ontology_class_source = 'one_os_override' "
            "WHERE ontology_class IS NOT NULL AND ontology_class_source = 'unset'"
        )
    )


def downgrade():
    columns = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("points")}
    if "ontology_class_source" in columns:
        op.drop_column("points", "ontology_class_source")
