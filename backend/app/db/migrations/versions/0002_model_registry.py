"""Immutable authenticated numeric models and training manifests."""

import sqlalchemy as sa
from alembic import op

revision = "0002_model_registry"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "models",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("artifact_sha256", sa.String(64), nullable=False),
        sa.Column("payload", sa.Text(), nullable=False),
    )
    op.create_index("ix_models_created_at", "models", ["created_at"])


def downgrade() -> None:
    raise RuntimeError("destructive schema downgrade is intentionally unsupported")
