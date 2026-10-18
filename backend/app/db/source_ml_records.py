"""Encrypted immutable pair attempts with parent binding and atomic domain audit."""

from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.contracts import SnapshotBinding
from app.api.source_ml_contracts import (
    MAX_SOURCE_ML_BYTES,
    SourceMlIntent,
    SourceMlOutcome,
    SourceMlRecheck,
)
from app.db.patch_records import PatchConflict, PatchRecords
from app.db.store import StorageIntegrityError, Store
from app.db.tables import (
    AuditRow,
    ConfigurationRow,
    PatchRow,
    SourceMlIntentRow,
    SourceMlOutcomeRow,
)
from app.detection.config_model_contracts import require_complete
from app.ingestion.source_retention import canonical_fingerprint


class SourceMlRecords:
    def __init__(self, store: Store) -> None:
        self.store = store

    def _plain(self, value: str, kind: str, key: str) -> str:
        if len(value) > MAX_SOURCE_ML_BYTES * 4:
            raise ValueError("oversized pair ciphertext")
        raw = self.store._decode(value, kind=kind, row_id=key)
        if len(raw.encode()) > MAX_SOURCE_ML_BYTES:
            raise ValueError("oversized pair record")
        return raw

    def _encode(self, value: str, kind: str, key: str) -> str:
        if len(value.encode()) > MAX_SOURCE_ML_BYTES:
            raise StorageIntegrityError("Stored data is unavailable.")
        return self.store._encode(value, kind=kind, row_id=key)

    def _intent(self, session: Session, row: SourceMlIntentRow) -> SourceMlIntent:
        try:
            intent = SourceMlIntent.model_validate_json(
                self._plain(row.payload, "source_ml_intent", row.id)
            )
            stamp = row.created_at if row.created_at.tzinfo else row.created_at.replace(tzinfo=UTC)
            if (str(intent.request.recheck_id), str(intent.patch_id), intent.created_at) != (
                row.id,
                row.patch_id,
                stamp,
            ):
                raise ValueError("ML recheck metadata differs")
            parent = session.get(PatchRow, row.patch_id)
            if parent is None:
                raise ValueError("ML recheck parent missing")
            draft = PatchRecords(self.store)._draft(session, parent)
            if (
                draft.draft_sha256 != intent.request.draft_sha256
                or intent.created_at < draft.created_at
                or (intent.before.configuration_id, intent.after.configuration_id)
                != (draft.diff.before.configuration_id, draft.diff.after.configuration_id)
            ):
                raise ValueError("ML recheck parent differs")
            for member in (intent.before, intent.after):
                saved = session.get(ConfigurationRow, str(member.configuration_id))
                if saved is None:
                    raise ValueError("ML recheck snapshot missing")
                snapshot = self.store._snapshot(saved)
                require_complete(snapshot)
                if member.model_dump(
                    exclude={"canonical_sha256", "total_lines"}
                ) != SnapshotBinding.from_snapshot(
                    snapshot
                ).model_dump() or member.canonical_sha256 != canonical_fingerprint(snapshot):
                    raise ValueError("ML recheck snapshot binding differs")
            return intent
        except ValueError:
            raise StorageIntegrityError("Stored data is unavailable.") from None

    def _outcome(self, row: SourceMlOutcomeRow, intent: SourceMlIntent) -> SourceMlOutcome:
        try:
            outcome = SourceMlOutcome.model_validate_json(
                self._plain(row.payload, "source_ml_outcome", row.recheck_id)
            )
            if str(outcome.recheck_id) != row.recheck_id:
                raise ValueError("ML outcome metadata differs")
            SourceMlRecheck.from_records(intent, outcome)
            return outcome
        except ValueError:
            raise StorageIntegrityError("Stored data is unavailable.") from None

    def _get(
        self, session: Session, key: UUID
    ) -> tuple[SourceMlIntent, SourceMlOutcome | None] | None:
        row = session.get(SourceMlIntentRow, str(key))
        if row is None:
            return None
        intent = self._intent(session, row)
        outcome = session.get(SourceMlOutcomeRow, row.id)
        return intent, self._outcome(outcome, intent) if outcome is not None else None

    def get(self, key: UUID) -> tuple[SourceMlIntent, SourceMlOutcome | None] | None:
        with self.store._sessions() as session:
            return self._get(session, key)

    @staticmethod
    def _same(old: SourceMlIntent, new: SourceMlIntent) -> None:
        if old.patch_id != new.patch_id or old.request != new.request:
            raise PatchConflict("ML recheck identity conflicts.")

    @staticmethod
    def _audit(session: Session, action: str, key: str) -> None:
        session.add(
            AuditRow(id=str(uuid4()), action=action, resource_id=key, created_at=datetime.now(UTC))
        )

    def reserve(self, intent: SourceMlIntent) -> bool:
        intent = SourceMlIntent.model_validate(intent.model_dump(warnings=False))
        key = str(intent.request.recheck_id)
        try:
            with self.store._sessions.begin() as session:
                existing = session.get(SourceMlIntentRow, key)
                if existing is not None:
                    self._same(self._intent(session, existing), intent)
                    return False
                row = SourceMlIntentRow(
                    id=key,
                    patch_id=str(intent.patch_id),
                    created_at=intent.created_at,
                    payload=self._encode(intent.model_dump_json(), "source_ml_intent", key),
                )
                self._intent(session, row)
                session.add(row)
                self._audit(session, "patch.ml_recheck_requested", key)
            return True
        except IntegrityError:
            raced = self.get(intent.request.recheck_id)
            if raced is None:
                raise
            self._same(raced[0], intent)
            return False

    def complete(self, outcome: SourceMlOutcome) -> None:
        outcome = SourceMlOutcome.model_validate(outcome.model_dump(warnings=False))
        key = str(outcome.recheck_id)
        with self.store._sessions.begin() as session:
            saved = self._get(session, outcome.recheck_id)
            if saved is None:
                raise StorageIntegrityError("Stored data is unavailable.")
            intent, existing = saved
            if existing is not None:
                if existing != outcome:
                    raise PatchConflict("ML recheck outcome conflicts.")
                return
            row = SourceMlOutcomeRow(
                recheck_id=key,
                payload=self._encode(outcome.model_dump_json(), "source_ml_outcome", key),
            )
            self._outcome(row, intent)
            session.add(row)
            self._audit(session, "patch.ml_recheck_completed", key)

    def list_ids(self, patch_id: UUID, *, limit: int, offset: int) -> list[UUID]:
        query = (
            select(SourceMlIntentRow.id)
            .where(SourceMlIntentRow.patch_id == str(patch_id))
            .order_by(SourceMlIntentRow.created_at.desc(), SourceMlIntentRow.id.desc())
        )
        with self.store._sessions() as session:
            return [UUID(key) for key in session.scalars(query.limit(limit).offset(offset))]
