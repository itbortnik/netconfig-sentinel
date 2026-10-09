"""Optional encrypted exact originals; existing snapshots are not reconstructed."""

import sqlalchemy as sa
from alembic import op

revision = "0006_configuration_sources"
down_revision = "0005_operation_journal"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "configuration_sources",
        sa.Column(
            "configuration_id", sa.String(36), sa.ForeignKey("configurations.id"), primary_key=True
        ),
        sa.Column("payload", sa.Text(), nullable=False),
    )


def downgrade() -> None:
    raise RuntimeError("destructive schema downgrade is intentionally unsupported")
