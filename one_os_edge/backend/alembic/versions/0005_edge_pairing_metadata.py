"""Add public Edge identity and pairing metadata.

Revision ID: 0005
"""

import sqlalchemy as sa
from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade():
    inspector = sa.inspect(op.get_bind())
    tables = inspector.get_table_names()
    if "edge_identity" not in tables:
        op.create_table(
            "edge_identity",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("installation_id", sa.String(length=36), nullable=False),
            sa.Column("status", sa.String(length=40), nullable=False),
            sa.Column("revision", sa.Integer(), nullable=False),
            sa.Column("active_spki_sha256", sa.String(length=43), nullable=True),
            sa.Column("credential_id", sa.String(length=36), nullable=True),
            sa.Column("certificate_sha256", sa.String(length=43), nullable=True),
            sa.Column("certificate_not_after", sa.DateTime(timezone=True), nullable=True),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.CheckConstraint("id = 1", name="ck_edge_identity_singleton"),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("installation_id"),
        )
    if "edge_pairing" not in tables:
        op.create_table(
            "edge_pairing",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("revision", sa.Integer(), nullable=False),
            sa.Column("mode", sa.String(length=16), nullable=False),
            sa.Column("status", sa.String(length=40), nullable=False),
            sa.Column("registration_request_id", sa.String(length=36), nullable=False),
            sa.Column("session_id", sa.String(length=36), nullable=True),
            sa.Column("token_generation", sa.Integer(), nullable=False),
            sa.Column("candidate_spki_sha256", sa.String(length=43), nullable=False),
            sa.Column("csr_sha256", sa.String(length=43), nullable=False),
            sa.Column("tenant_id", sa.String(length=36), nullable=True),
            sa.Column("site_id", sa.String(length=120), nullable=True),
            sa.Column("claim_revision", sa.Integer(), nullable=True),
            sa.Column("installation_revision", sa.Integer(), nullable=True),
            sa.Column("credential_id", sa.String(length=36), nullable=True),
            sa.Column("certificate_sha256", sa.String(length=43), nullable=True),
            sa.Column("registration_expires_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("code_expires_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("claim_expires_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("ack_expires_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_error", sa.String(length=80), nullable=True),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.CheckConstraint("id = 1", name="ck_edge_pairing_singleton"),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("registration_request_id"),
        )


def downgrade():
    tables = sa.inspect(op.get_bind()).get_table_names()
    if "edge_pairing" in tables:
        op.drop_table("edge_pairing")
    if "edge_identity" in tables:
        op.drop_table("edge_identity")
