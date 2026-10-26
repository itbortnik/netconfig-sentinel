"""Retain immutable encrypted native candidates without materializing after snapshots."""

import sqlalchemy as sa
from alembic import op

revision = "0018_native_patch_candidates"
down_revision = "0017_source_risk_assessments"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "native_patch_candidates",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "configuration_id", sa.String(36), sa.ForeignKey("configurations.id"), nullable=False
        ),
        sa.Column("analysis_id", sa.String(36), sa.ForeignKey("analyses.id"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("public_sha256", sa.String(64), nullable=False),
        sa.Column("payload", sa.Text(), nullable=False),
    )
    op.create_index(
        "ix_native_patch_candidates_configuration_created",
        "native_patch_candidates",
        ["configuration_id", "created_at", "id"],
    )


def downgrade() -> None:
    raise RuntimeError("destructive schema downgrade is intentionally unsupported")
