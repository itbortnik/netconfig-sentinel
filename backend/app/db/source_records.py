"""Explicit internal original-source read; no raw HTTP export or model/engine call."""

import re
from uuid import UUID

from app.db.store import StorageIntegrityError, Store
from app.db.tables import ConfigurationRow, ConfigurationSourceRow
from app.ingestion.source_retention import (
    MAX_SOURCE_CIPHERTEXT_BYTES,
    MAX_SOURCE_PAYLOAD_BYTES,
    StoredOriginalSource,
    validate_original_binding,
)


class OriginalSourceUnavailable(ValueError):
    """Absent consent, retained source or selected identity; no private diagnostics."""


class SourceRecords:
    def __init__(self, store: Store) -> None:
        self.store = store

    def get(
        self, configuration_id: UUID, *, expected_source_sha256: str, allow_local_read: bool = False
    ) -> StoredOriginalSource:
        if (
            allow_local_read is not True
            or type(expected_source_sha256) is not str
            or (re.fullmatch(r"[0-9a-f]{64}", expected_source_sha256) is None)
        ):
            raise OriginalSourceUnavailable("Original source is unavailable.")
        with self.store._sessions() as session:
            parent = session.get(ConfigurationRow, str(configuration_id))
            if parent is None:
                raise OriginalSourceUnavailable("Original source is unavailable.")
            snapshot = self.store._snapshot(parent)
            if snapshot.canonical.source.sha256 != expected_source_sha256:
                raise OriginalSourceUnavailable("Original source is unavailable.")
            row = session.get(ConfigurationSourceRow, str(configuration_id))
            if row is None:
                raise OriginalSourceUnavailable("Original source is unavailable.")
            try:
                if len(row.payload) > MAX_SOURCE_CIPHERTEXT_BYTES:
                    raise ValueError("oversized encrypted source")
                plain = self.store._decode(
                    row.payload, kind="configuration_source", row_id=parent.id
                )
                if len(plain.encode()) > MAX_SOURCE_PAYLOAD_BYTES:
                    raise ValueError("oversized source payload")
                record = StoredOriginalSource.model_validate_json(plain)
                validate_original_binding(record, snapshot)
                return record
            except ValueError:
                raise StorageIntegrityError("Stored data is unavailable.") from None
