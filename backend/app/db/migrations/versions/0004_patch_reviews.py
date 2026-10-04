"""Encrypted immutable normalized drafts and their local-only verification history."""

import sqlalchemy as sa
from alembic import op

revision = "0004_patch_reviews"
down_revision = "0003_finding_feedback"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "patch_proposals",
        sa.Column("id", sa.String(36), primary_key=True),
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
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("payload", sa.Text(), nullable=False),
    )
    op.create_index(
        "ix_patch_proposals_after_created_at",
        "patch_proposals",
        ["after_configuration_id", "created_at"],
    )
    op.create_table(
        "verification_runs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("patch_id", sa.String(36), sa.ForeignKey("patch_proposals.id"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("payload", sa.Text(), nullable=False),
    )
    op.create_index(
        "ix_verification_runs_patch_created_at", "verification_runs", ["patch_id", "created_at"]
    )


def downgrade() -> None:
    raise RuntimeError("destructive schema downgrade is intentionally unsupported")
