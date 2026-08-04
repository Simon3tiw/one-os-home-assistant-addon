"""Initial commissioning database.

Revision ID: 0001
"""

from alembic import op
from one_os_addon.schema_v1 import V1_METADATA

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    V1_METADATA.create_all(bind=op.get_bind())


def downgrade():
    V1_METADATA.drop_all(bind=op.get_bind())
