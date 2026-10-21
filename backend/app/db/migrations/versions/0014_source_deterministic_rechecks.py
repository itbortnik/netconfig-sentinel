"""Add independent ordinary original-deterministic attempts without rewriting prior reviews."""

import sqlalchemy as sa
from alembic import op

revision = "0014_deterministic_rechecks"
down_revision = "0013_source_forest_rechecks"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "patch_deterministic_recheck_intents",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("patch_id", sa.String(36), sa.ForeignKey("patch_proposals.id"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("payload", sa.Text(), nullable=False),
    )
    op.create_index(
        "ix_patch_deterministic_recheck_intents_parent_created",
        "patch_deterministic_recheck_intents",
        ["patch_id", "created_at", "id"],
    )
    op.create_table(
        "patch_deterministic_recheck_outcomes",
        sa.Column(
            "recheck_id",
            sa.String(36),
            sa.ForeignKey("patch_deterministic_recheck_intents.id"),
            primary_key=True,
        ),
        sa.Column("payload", sa.Text(), nullable=False),
    )


def downgrade() -> None:
    raise RuntimeError("destructive schema downgrade is intentionally unsupported")
