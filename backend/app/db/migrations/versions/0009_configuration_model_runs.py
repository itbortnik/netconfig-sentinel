"""Append-only single-source experimental model attempts, independent of analyses."""

import sqlalchemy as sa
from alembic import op

revision = "0009_configuration_model_runs"
down_revision = "0008_model_patch_reviews"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "configuration_model_intents",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("analysis_id", sa.String(36), sa.ForeignKey("analyses.id"), nullable=False),
        sa.Column(
            "configuration_id", sa.String(36), sa.ForeignKey("configurations.id"), nullable=False
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("payload", sa.Text(), nullable=False),
    )
    op.create_index(
        "ix_configuration_model_intents_analysis_created_at",
        "configuration_model_intents",
        ["analysis_id", "created_at", "id"],
    )
    op.create_table(
        "configuration_model_outcomes",
        sa.Column(
            "inference_id",
            sa.String(36),
            sa.ForeignKey("configuration_model_intents.id"),
            primary_key=True,
        ),
        sa.Column("payload", sa.Text(), nullable=False),
    )


def downgrade() -> None:
    raise RuntimeError("destructive schema downgrade is intentionally unsupported")
