"""Add immutable selected-evidence reports without rewriting any earlier result."""

import sqlalchemy as sa
from alembic import op

revision = "0015_source_evidence_reports"
down_revision = "0014_deterministic_rechecks"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "patch_evidence_reports",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("patch_id", sa.String(36), sa.ForeignKey("patch_proposals.id"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("payload", sa.Text(), nullable=False),
    )
    op.create_index(
        "ix_patch_evidence_reports_parent_created",
        "patch_evidence_reports",
        ["patch_id", "created_at", "id"],
    )


def downgrade() -> None:
    raise RuntimeError("destructive schema downgrade is intentionally unsupported")
