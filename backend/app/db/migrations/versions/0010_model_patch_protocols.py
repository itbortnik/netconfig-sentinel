"""Separate persisted generation protocols without rewriting encrypted history."""

import sqlalchemy as sa
from alembic import op

revision = "0010_model_patch_protocols"
down_revision = "0009_configuration_model_runs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "model_patch_intents",
        sa.Column(
            "protocol",
            sa.String(64),
            nullable=False,
            server_default="legacy-model-patch-0.1.0",
        ),
    )
    op.create_index(
        "ix_model_patch_intents_protocol_analysis_created",
        "model_patch_intents",
        ["protocol", "analysis_id", "created_at", "id"],
    )


def downgrade() -> None:
    raise RuntimeError("destructive schema downgrade is intentionally unsupported")
