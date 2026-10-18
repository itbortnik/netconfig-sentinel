"""Add separate exact-source paired ML attempts without rewriting network history."""

import sqlalchemy as sa
from alembic import op

revision = "0012_source_ml_rechecks"
down_revision = "0011_source_patch_reviews"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "patch_ml_recheck_intents",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("patch_id", sa.String(36), sa.ForeignKey("patch_proposals.id"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("payload", sa.Text(), nullable=False),
    )
    op.create_index(
        "ix_patch_ml_recheck_intents_parent_created",
        "patch_ml_recheck_intents",
        ["patch_id", "created_at", "id"],
    )
    op.create_table(
        "patch_ml_recheck_outcomes",
        sa.Column(
            "recheck_id",
            sa.String(36),
            sa.ForeignKey("patch_ml_recheck_intents.id"),
            primary_key=True,
        ),
        sa.Column("payload", sa.Text(), nullable=False),
    )


def downgrade() -> None:
    raise RuntimeError("destructive schema downgrade is intentionally unsupported")
