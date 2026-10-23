"""Add immutable priority assessments without rewriting reports or detector evidence."""

import sqlalchemy as sa
from alembic import op

revision = "0017_source_risk_assessments"
down_revision = "0016_source_evidence_decisions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "patch_risk_assessments",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("patch_id", sa.String(36), sa.ForeignKey("patch_proposals.id"), nullable=False),
        sa.Column(
            "report_id", sa.String(36), sa.ForeignKey("patch_evidence_reports.id"), nullable=False
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("payload", sa.Text(), nullable=False),
    )
    op.create_index(
        "ix_patch_risk_assessments_parent_report_created",
        "patch_risk_assessments",
        ["patch_id", "report_id", "created_at", "id"],
    )


def downgrade() -> None:
    raise RuntimeError("destructive schema downgrade is intentionally unsupported")
