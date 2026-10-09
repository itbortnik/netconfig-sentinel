"""Separate append-only model generation requests and terminal results."""

import sqlalchemy as sa
from alembic import op

revision = "0007_model_patch_intents"
down_revision = "0006_configuration_sources"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "model_patch_intents",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("analysis_id", sa.String(36), sa.ForeignKey("analyses.id"), nullable=False),
        sa.Column(
            "configuration_id", sa.String(36), sa.ForeignKey("configurations.id"), nullable=False
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("payload", sa.Text(), nullable=False),
    )
    op.create_index(
        "ix_model_patch_intents_analysis_created_at",
        "model_patch_intents",
        ["analysis_id", "created_at", "id"],
    )
    op.create_table(
        "model_patch_outcomes",
        sa.Column(
            "patch_id", sa.String(36), sa.ForeignKey("model_patch_intents.id"), primary_key=True
        ),
        sa.Column("payload", sa.Text(), nullable=False),
    )


def downgrade() -> None:
    raise RuntimeError("destructive schema downgrade is intentionally unsupported")
