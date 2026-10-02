"""Append-only encrypted finding assessments and their analysis scope."""

import sqlalchemy as sa
from alembic import op

revision = "0003_finding_feedback"
down_revision = "0002_model_registry"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "finding_feedback",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("analysis_id", sa.String(36), sa.ForeignKey("analyses.id"), nullable=False),
        sa.Column("finding_id", sa.String(36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("payload", sa.Text(), nullable=False),
    )
    op.create_index(
        "ix_finding_feedback_target_created_at",
        "finding_feedback",
        ["analysis_id", "finding_id", "created_at"],
    )


def downgrade() -> None:
    raise RuntimeError("destructive schema downgrade is intentionally unsupported")
