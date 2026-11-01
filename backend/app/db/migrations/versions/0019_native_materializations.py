"""Atomic ordinary drafts and immutable generated origin for native candidates."""

import sqlalchemy as sa
from alembic import op

revision = "0019_native_materializations"
down_revision = "0018_native_patch_candidates"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "native_materializations",
        sa.Column(
            "candidate_id",
            sa.String(36),
            sa.ForeignKey("native_patch_candidates.id"),
            primary_key=True,
        ),
        sa.Column(
            "before_configuration_id",
            sa.String(36),
            sa.ForeignKey("configurations.id"),
            nullable=False,
        ),
        sa.Column(
            "after_configuration_id",
            sa.String(36),
            sa.ForeignKey("configurations.id"),
            nullable=False,
            unique=True,
        ),
        sa.Column(
            "patch_id",
            sa.String(36),
            sa.ForeignKey("patch_proposals.id"),
            nullable=False,
            unique=True,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("public_sha256", sa.String(64), nullable=False),
        sa.Column("payload", sa.Text(), nullable=False),
    )


def downgrade() -> None:
    raise RuntimeError("destructive schema downgrade is intentionally unsupported")
