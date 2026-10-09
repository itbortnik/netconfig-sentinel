"""Append-only selected candidate verification and engineer decisions."""

import sqlalchemy as sa
from alembic import op

revision = "0008_model_patch_reviews"
down_revision = "0007_model_patch_intents"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "model_patch_review_intents",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "patch_id", sa.String(36), sa.ForeignKey("model_patch_intents.id"), nullable=False
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("payload", sa.Text(), nullable=False),
    )
    op.create_index(
        "ix_model_patch_review_intents_patch_created_at",
        "model_patch_review_intents",
        ["patch_id", "created_at", "id"],
    )
    op.create_table(
        "model_patch_review_outcomes",
        sa.Column(
            "verification_id",
            sa.String(36),
            sa.ForeignKey("model_patch_review_intents.id"),
            primary_key=True,
        ),
        sa.Column("payload", sa.Text(), nullable=False),
    )
    op.create_table(
        "model_patch_decisions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "patch_id", sa.String(36), sa.ForeignKey("model_patch_intents.id"), nullable=False
        ),
        sa.Column(
            "verification_id",
            sa.String(36),
            sa.ForeignKey("model_patch_review_intents.id"),
            nullable=False,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("payload", sa.Text(), nullable=False),
    )
    op.create_index(
        "ix_model_patch_decisions_patch_created_at",
        "model_patch_decisions",
        ["patch_id", "created_at", "id"],
    )


def downgrade() -> None:
    raise RuntimeError("destructive schema downgrade is intentionally unsupported")
