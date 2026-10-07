"""Encrypted immutable request receipts and response completions, not raw request logging."""

import sqlalchemy as sa
from alembic import op

revision = "0005_operation_journal"
down_revision = "0004_patch_reviews"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "operation_receipts",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("payload", sa.Text(), nullable=False),
    )
    op.create_index("ix_operation_receipts_created_at", "operation_receipts", ["created_at", "id"])
    op.create_table(
        "operation_completions",
        sa.Column(
            "operation_id", sa.String(36), sa.ForeignKey("operation_receipts.id"), primary_key=True
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("payload", sa.Text(), nullable=False),
    )


def downgrade() -> None:
    raise RuntimeError("destructive schema downgrade is intentionally unsupported")
