"""Add durable telemetry v2 capability activation barrier.

Revision ID: 0016
Revises: 0015
"""

import sqlalchemy as sa
from alembic import op

revision = "0016"
down_revision = "0015"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "telemetry_authority_activation",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("installation_id", sa.String(length=36), nullable=False),
        sa.Column("credential_id", sa.String(length=36), nullable=False),
        sa.Column("certificate_sha256", sa.String(length=43), nullable=False),
        sa.Column("telemetry_authorization_revision", sa.BigInteger(), nullable=False),
        sa.Column("capability_bytes", sa.LargeBinary(), nullable=False),
        sa.Column("capability_sha256", sa.LargeBinary(length=32), nullable=False),
        sa.Column("server_nonce", sa.LargeBinary(length=32), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("enable_request_bytes", sa.LargeBinary(), nullable=True),
        sa.Column("request_sha256", sa.LargeBinary(length=32), nullable=True),
        sa.Column("enable_response_bytes", sa.LargeBinary(), nullable=True),
        sa.Column("response_sha256", sa.LargeBinary(length=32), nullable=True),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("enabled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("id = 1", name="ck_telemetry_authority_activation_singleton"),
        sa.CheckConstraint(
            "status IN ('capability_stored', 'enable_requested', 'enabled')",
            name="ck_telemetry_authority_activation_status",
        ),
        sa.CheckConstraint(
            "length(capability_sha256) = 32 AND length(server_nonce) = 32 AND "
            "(request_sha256 IS NULL OR length(request_sha256) = 32) AND "
            "(response_sha256 IS NULL OR length(response_sha256) = 32)",
            name="ck_telemetry_authority_activation_hashes",
        ),
        sa.CheckConstraint(
            "telemetry_authorization_revision BETWEEN 1 AND 9223372036854775807 AND "
            "telemetry_authorization_revision = CAST(telemetry_authorization_revision AS BIGINT)",
            name="ck_telemetry_authority_activation_revision",
        ),
        sa.CheckConstraint(
            "(status = 'capability_stored' AND enable_request_bytes IS NULL "
            "AND request_sha256 IS NULL AND enable_response_bytes IS NULL "
            "AND response_sha256 IS NULL AND enabled_at IS NULL) OR "
            "(status = 'enable_requested' AND enable_request_bytes IS NOT NULL "
            "AND request_sha256 IS NOT NULL AND enable_response_bytes IS NULL "
            "AND response_sha256 IS NULL AND enabled_at IS NULL) OR "
            "(status = 'enabled' AND enable_request_bytes IS NOT NULL "
            "AND request_sha256 IS NOT NULL AND enable_response_bytes IS NOT NULL "
            "AND response_sha256 IS NOT NULL AND enabled_at IS NOT NULL)",
            name="ck_telemetry_authority_activation_tuple",
        ),
        sa.ForeignKeyConstraint(
            ["installation_id"],
            ["edge_identity.installation_id"],
            name="fk_telemetry_authority_activation_identity",
        ),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        bind.execute(
            sa.text("LOCK TABLE telemetry_authority_activation IN SHARE ROW EXCLUSIVE MODE")
        )
    elif bind.dialect.name == "sqlite":
        bind.execute(
            sa.text(
                "UPDATE alembic_version SET version_num = version_num WHERE version_num = '0016'"
            )
        )
    table = sa.Table("telemetry_authority_activation", sa.MetaData(), autoload_with=bind)
    if bind.execute(sa.select(sa.literal(1)).select_from(table).limit(1)).first() is not None:
        raise RuntimeError("refusing to discard durable telemetry v2 activation state")
    op.drop_table("telemetry_authority_activation")
