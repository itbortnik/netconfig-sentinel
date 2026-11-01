"""One narrow atomic writer and pure historical reader for native materializations."""

import json
from datetime import UTC, datetime
from uuid import UUID, uuid4

from pydantic import ValidationError
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.contracts import ConfigurationSnapshot
from app.api.native_materialization_contracts import (
    MAX_NATIVE_MATERIALIZATION_CIPHERTEXT_BYTES,
    MAX_NATIVE_MATERIALIZATION_PUBLIC_BYTES,
    NativeMaterialization,
    NativeMaterializationBudgetError,
    validate_native_materialization_parent,
)
from app.api.patch_contracts import MAX_RECORD_BYTES, PatchDraft
from app.db.native_patch_records import NativePatchInputNotFound, NativePatchRecords
from app.db.patch_records import PatchConflict, PatchRecords
from app.db.store import StorageIntegrityError, Store
from app.db.tables import (
    AnalysisRow,
    AuditRow,
    ConfigurationRow,
    ConfigurationSourceRow,
    DeviceRow,
    NativeMaterializationRow,
    NativePatchCandidateRow,
    PatchRow,
)
from app.ingestion.source_retention import (
    MAX_SOURCE_CIPHERTEXT_BYTES,
    MAX_SOURCE_PAYLOAD_BYTES,
    StoredOriginalSource,
    validate_original_binding,
)
from app.patching.native_materialization_preparation import PreparedNativeMaterialization

MAX_MATERIALIZATION_PLAINTEXT_BYTES = 16 * 1024 * 1024
MAX_MATERIALIZATION_CIPHERTEXT_BYTES = 32 * 1024 * 1024
MAX_DRAFT_CIPHERTEXT_BYTES = 8 * 1024 * 1024


class NativeMaterializationTooLarge(ValueError):
    """A fresh materialization exceeds an individual or combined storage budget."""


class NativeMaterializationRecords:
    def __init__(self, store: Store) -> None:
        self.store = store
        self.native_records = NativePatchRecords(store)

    def _sql_time(self, value: datetime) -> datetime:
        if value.utcoffset() is None:
            if self.store.engine.dialect.name != "sqlite":
                raise StorageIntegrityError("Stored data is unavailable.")
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    def _record(self, session: Session, row: NativeMaterializationRow) -> NativeMaterialization:
        try:
            if len(row.payload.encode()) > MAX_NATIVE_MATERIALIZATION_CIPHERTEXT_BYTES:
                raise ValueError("oversized materialization ciphertext")
            raw = self.store._decode(
                row.payload, kind="native_materialization", row_id=row.candidate_id
            )
            if len(raw.encode()) > MAX_NATIVE_MATERIALIZATION_PUBLIC_BYTES:
                raise ValueError("oversized materialization payload")
            result = NativeMaterialization.model_validate_json(raw)
            if (
                str(result.candidate_id),
                str(result.before.configuration_id),
                str(result.after.configuration_id),
                str(result.patch_id),
                result.created_at,
                result.review_sha256,
            ) != (
                row.candidate_id,
                row.before_configuration_id,
                row.after_configuration_id,
                row.patch_id,
                self._sql_time(row.created_at),
                row.public_sha256,
            ):
                raise ValueError("materialization SQL bindings differ")
            native = self.native_records._get(session, result.candidate_id)
            before_row = session.get(ConfigurationRow, row.before_configuration_id)
            after_row = session.get(ConfigurationRow, row.after_configuration_id)
            draft_row = session.get(PatchRow, row.patch_id)
            if native is None or before_row is None or after_row is None or draft_row is None:
                raise ValueError("materialization saved dependency is missing")
            before = self._snapshot(before_row)
            after = self._snapshot(after_row)
            draft = self._draft(session, draft_row)
            self._device(session, before.device_id, before.canonical.device)
            validate_native_materialization_parent(result, native, before, after, draft)
            return result
        except (ValueError, TypeError, AttributeError):
            raise StorageIntegrityError("Stored data is unavailable.") from None

    def _snapshot(self, row: ConfigurationRow) -> ConfigurationSnapshot:
        # Legacy readers normalize some scalar values. Inspect serialized data before
        # invoking them so a stored numeric bool cannot become trusted history here.
        raw = self.store._decode(row.payload, kind="configuration", row_id=row.id)
        result = ConfigurationSnapshot.model_validate_json(raw, strict=True)
        if result != self.native_records._snapshot(row):
            raise ValueError("materialization snapshot differs")
        return result

    def _draft(self, session: Session, row: PatchRow) -> PatchDraft:
        if len(row.payload.encode()) > MAX_DRAFT_CIPHERTEXT_BYTES:
            raise ValueError("oversized materialization draft ciphertext")
        raw = self.store._decode(row.payload, kind="patch", row_id=row.id)
        if len(raw.encode()) > MAX_RECORD_BYTES:
            raise ValueError("oversized materialization draft")
        data = json.loads(raw)
        if data.get("requires_human_review") is not True or (
            isinstance(data.get("diff"), dict) and data["diff"].get("source_changed") is not True
        ):
            raise ValueError("materialization draft flags differ")
        result = PatchDraft.model_validate_json(raw, strict=True)
        if result != PatchRecords(self.store)._draft(session, row):
            raise ValueError("materialization draft differs")
        return result

    def _get(self, session: Session, candidate_id: UUID) -> NativeMaterialization | None:
        row = session.get(NativeMaterializationRow, str(candidate_id))
        return self._record(session, row) if row is not None else None

    def get(self, candidate_id: UUID) -> NativeMaterialization | None:
        with self.store._sessions() as session:
            return self._get(session, candidate_id)

    def get_origin(self, after_configuration_id: UUID) -> NativeMaterialization | None:
        with self.store._sessions() as session:
            row = session.scalar(
                select(NativeMaterializationRow).where(
                    NativeMaterializationRow.after_configuration_id == str(after_configuration_id)
                )
            )
            return self._record(session, row) if row is not None else None

    @staticmethod
    def _same(stored: NativeMaterialization, incoming: NativeMaterialization) -> None:
        if (stored.configuration_id, stored.candidate_id, stored.request) != (
            incoming.configuration_id,
            incoming.candidate_id,
            incoming.request,
        ):
            raise PatchConflict("Native materialization identity is already bound.")

    def _device(self, session: Session, device_id: UUID, device: object) -> None:
        row = session.get(DeviceRow, str(device_id))
        if row is None:
            raise ValueError("materialization device is missing")
        # Decode identity as data, without assuming historical JSON whitespace.
        actual = json.loads(self.store._decode(row.identity_payload, kind="device", row_id=row.id))
        expected = [device.vendor.value, device.platform, device.hostname]  # type: ignore[attr-defined]
        if actual != expected:
            raise ValueError("materialization device differs")

    def _lock_parents(self, session: Session, record: NativeMaterialization) -> None:
        """Acquire admission locks before fresh reads; SQLite needs a real write lock."""
        if self.store.engine.dialect.name == "sqlite":
            session.execute(text("BEGIN IMMEDIATE"))
            return
        native = session.scalar(
            select(NativePatchCandidateRow)
            .where(NativePatchCandidateRow.id == str(record.candidate_id))
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if native is None:
            raise PatchConflict("Selected native candidate is unavailable.")
        for model, identity in (
            (DeviceRow, str(record.before.device_id)),
            (ConfigurationRow, str(record.configuration_id)),
            (AnalysisRow, native.analysis_id),
        ):
            session.execute(
                select(model)
                .where(model.id == identity)
                .with_for_update()
                .execution_options(populate_existing=True)
            ).all()
        session.execute(
            select(ConfigurationSourceRow)
            .where(ConfigurationSourceRow.configuration_id == str(record.configuration_id))
            .with_for_update()
            .execution_options(populate_existing=True)
        ).all()

    def _source(self, session: Session, retained: StoredOriginalSource) -> StoredOriginalSource:
        row = session.get(ConfigurationSourceRow, str(retained.snapshot.configuration_id))
        if row is None:
            raise PatchConflict("Retained original source is required.")
        try:
            if len(row.payload.encode()) > MAX_SOURCE_CIPHERTEXT_BYTES:
                raise ValueError("oversized original source ciphertext")
            raw = self.store._decode(
                row.payload, kind="configuration_source", row_id=row.configuration_id
            )
            if len(raw.encode()) > MAX_SOURCE_PAYLOAD_BYTES:
                raise ValueError("oversized original source payload")
            actual = StoredOriginalSource.model_validate_json(raw, strict=True)
            if actual != retained:
                raise PatchConflict("Retained original source changed.")
            return actual
        except (TypeError, AttributeError, ValueError) as exc:
            if isinstance(exc, PatchConflict):
                raise
            raise StorageIntegrityError("Stored data is unavailable.") from None

    @staticmethod
    def _audit(session: Session, action: str, key: str, created_at: datetime) -> None:
        session.add(
            AuditRow(
                id=str(uuid4()),
                action=action,
                resource_id=key,
                created_at=created_at.astimezone(UTC),
            )
        )
        session.flush()

    def save(
        self,
        record: NativeMaterialization,
        prepared: PreparedNativeMaterialization,
        retained_before: StoredOriginalSource,
    ) -> tuple[NativeMaterialization, bool]:
        # Reconcile a previously committed intent before checking fresh inputs/budgets.
        existing = self.get(record.candidate_id)
        if existing is not None:
            self._same(existing, record)
            return existing, False
        try:
            record = NativeMaterialization.model_validate_json(record.model_dump_json())
            if prepared.draft.requires_human_review is not True:
                raise ValueError("materialization draft requires exact human review")
            retained_before = StoredOriginalSource.model_validate_json(
                retained_before.model_dump_json(), strict=True
            )
            after = ConfigurationSnapshot.model_validate_json(
                prepared.after.model_dump_json(), strict=True
            )
            retained_after = StoredOriginalSource.model_validate_json(
                prepared.retained_after.model_dump_json(), strict=True
            )
            draft = PatchDraft.model_validate_json(
                prepared.draft.model_dump_json(), strict=True
            )
            validate_original_binding(retained_after, after)
            raw = tuple(value.model_dump_json() for value in (after, retained_after, draft, record))
            sizes = tuple(len(value.encode()) for value in raw)
            if (
                sizes[1] > MAX_SOURCE_PAYLOAD_BYTES
                or sizes[2] > MAX_RECORD_BYTES
                or (
                    sizes[3] > MAX_NATIVE_MATERIALIZATION_PUBLIC_BYTES
                    or sum(sizes) > MAX_MATERIALIZATION_PLAINTEXT_BYTES
                )
            ):
                raise NativeMaterializationTooLarge("Materialization exceeds its payload budget.")
            after_key, patch_key, key = (
                str(after.configuration_id),
                str(draft.patch_id),
                str(record.candidate_id),
            )
            payloads = tuple(
                self.store._encode(value, kind=kind, row_id=identity)
                for value, kind, identity in zip(
                    raw,
                    ("configuration", "configuration_source", "patch", "native_materialization"),
                    (after_key, after_key, patch_key, key),
                    strict=True,
                )
            )
            cipher_sizes = tuple(len(value.encode()) for value in payloads)
            if (
                cipher_sizes[1] > MAX_SOURCE_CIPHERTEXT_BYTES
                or cipher_sizes[2] > MAX_DRAFT_CIPHERTEXT_BYTES
                or (
                    cipher_sizes[3] > MAX_NATIVE_MATERIALIZATION_CIPHERTEXT_BYTES
                    or sum(cipher_sizes) > MAX_MATERIALIZATION_CIPHERTEXT_BYTES
                )
            ):
                raise NativeMaterializationTooLarge(
                    "Materialization exceeds its encryption budget."
                )
        except NativeMaterializationBudgetError:
            raise NativeMaterializationTooLarge(
                "Materialization exceeds its artifact budget."
            ) from None
        except ValidationError as exc:
            if any(
                isinstance(error.get("ctx", {}).get("error"), NativeMaterializationBudgetError)
                for error in exc.errors(include_input=False, include_url=False)
            ):
                raise NativeMaterializationTooLarge(
                    "Materialization exceeds its artifact budget."
                ) from None
            raise PatchConflict("Materialization bindings conflict.") from None
        except (ValueError, TypeError, AttributeError) as exc:
            if isinstance(exc, NativeMaterializationTooLarge):
                raise
            raise PatchConflict("Materialization bindings conflict.") from None
        try:
            with self.store._sessions.begin() as session:
                self._lock_parents(session, record)
                existing = self._get(session, record.candidate_id)
                if existing is not None:
                    self._same(existing, record)
                    return existing, False
                try:
                    native = self.native_records._get(session, record.candidate_id)
                    before_row = session.get(ConfigurationRow, str(record.configuration_id))
                    if native is None or before_row is None:
                        raise PatchConflict("Selected materialization inputs are unavailable.")
                    before = self._snapshot(before_row)
                    self._device(session, before.device_id, before.canonical.device)
                    actual_before = self._source(session, retained_before)
                    validate_original_binding(actual_before, before)
                    if actual_before.content.encode() != native.before_text.encode() or (
                        retained_after.content.encode() != native.candidate_text.encode()
                    ):
                        raise ValueError("materialization retained bytes differ")
                    validate_native_materialization_parent(record, native, before, after, draft)
                except (NativePatchInputNotFound, ValueError, TypeError, AttributeError):
                    raise PatchConflict("Selected materialization bindings conflict.") from None
                if (
                    session.get(ConfigurationRow, after_key) is not None
                    or session.get(PatchRow, patch_key) is not None
                ):
                    raise PatchConflict("Materialization output identity is already used.")
                session.add(
                    ConfigurationRow(
                        id=after_key,
                        device_id=str(after.device_id),
                        source_sha256=after.canonical.source.sha256,
                        created_at=after.created_at.astimezone(UTC),
                        payload=payloads[0],
                    )
                )
                session.flush()
                self._audit(session, "configuration.created", after_key, record.created_at)
                session.add(ConfigurationSourceRow(configuration_id=after_key, payload=payloads[1]))
                session.flush()
                self._audit(session, "configuration.source_retained", after_key, record.created_at)
                session.add(
                    PatchRow(
                        id=patch_key,
                        before_configuration_id=str(record.configuration_id),
                        after_configuration_id=after_key,
                        created_at=draft.created_at.astimezone(UTC),
                        payload=payloads[2],
                    )
                )
                session.flush()
                self._audit(session, "patch.draft_created", patch_key, record.created_at)
                session.add(
                    NativeMaterializationRow(
                        candidate_id=key,
                        before_configuration_id=str(record.configuration_id),
                        after_configuration_id=after_key,
                        patch_id=patch_key,
                        created_at=record.created_at.astimezone(UTC),
                        public_sha256=record.review_sha256,
                        payload=payloads[3],
                    )
                )
                session.flush()
                self._audit(session, "native_patch.materialized", key, record.created_at)
            return record, True
        except IntegrityError:
            winner = self.get(record.candidate_id)
            if winner is not None:
                self._same(winner, record)
                return winner, False
            raise PatchConflict("Materialization output identity is already used.") from None
