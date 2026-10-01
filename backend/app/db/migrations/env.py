"""Alembic environment uses the caller-provided connection, never logs credentials."""

from alembic import context
from app.db.tables import Base

connection = context.config.attributes["connection"]
context.configure(connection=connection, target_metadata=Base.metadata)
with context.begin_transaction():
    context.run_migrations()
