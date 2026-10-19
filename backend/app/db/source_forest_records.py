"""Separate encrypted original-Forest attempts; history never loads or executes models."""

from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.contracts import SnapshotBinding
from app.api.model_patch_contracts import fingerprint
from app.api.source_forest_contracts import (
    MAX_SOURCE_FOREST_BYTES,
    SourceForestIntent,
    SourceForestOutcome,
    SourceForestRecheck,
)
from app.db.patch_records import PatchConflict, PatchRecords
from app.db.store import StorageIntegrityError, Store
from app.db.tables import (
    AnalysisRow,
    AuditRow,
    ConfigurationRow,
    PatchRow,
    SourceForestIntentRow,
    SourceForestOutcomeRow,
)
from app.detection.statistical.pair import require_forest_target
from app.ingestion.source_retention import canonical_fingerprint


class SourceForestRecords:
    def __init__(self, store: Store) -> None:
        self.store = store

    def _plain(self, value: str, kind: str, key: str) -> str:
        if len(value) > MAX_SOURCE_FOREST_BYTES * 4:
            raise ValueError("oversized statistical ciphertext")
        raw = self.store._decode(value, kind=kind, row_id=key)
        if len(raw.encode()) > MAX_SOURCE_FOREST_BYTES:
            raise ValueError("oversized statistical record")
        return raw

    def _encode(self, value: str, kind: str, key: str) -> str:
        if len(value.encode()) > MAX_SOURCE_FOREST_BYTES:
            raise StorageIntegrityError("Stored data is unavailable.")
        return self.store._encode(value, kind=kind, row_id=key)

    def _intent(self, session: Session, row: SourceForestIntentRow) -> SourceForestIntent:
        try:
            intent = SourceForestIntent.model_validate_json(
                self._plain(row.payload, "source_forest_intent", row.id)
            )
            stamp = row.created_at if row.created_at.tzinfo else row.created_at.replace(tzinfo=UTC)
            if (str(intent.request.recheck_id), str(intent.patch_id), intent.created_at) != (
                row.id,
                row.patch_id,
                stamp,
            ):
                raise ValueError("statistical record metadata differs")
            parent = session.get(PatchRow, row.patch_id)
            if parent is None:
                raise ValueError("statistical record parent missing")
            draft = PatchRecords(self.store)._draft(session, parent)
            if (
                draft.draft_sha256 != intent.request.draft_sha256
                or intent.created_at < draft.created_at
                or (intent.before.configuration_id, intent.after.configuration_id)
                != (draft.diff.before.configuration_id, draft.diff.after.configuration_id)
            ):
                raise ValueError("statistical record parent differs")
            for member in (intent.before, intent.after):
                saved = session.get(ConfigurationRow, str(member.configuration_id))
                if saved is None:
                    raise ValueError("statistical snapshot missing")
                snapshot = self.store._snapshot(saved)
                require_forest_target(snapshot, intent.selection.original.model)
                if member.model_dump(exclude={"canonical_sha256"}) != SnapshotBinding.from_snapshot(
                    snapshot
                ).model_dump() or member.canonical_sha256 != canonical_fingerprint(snapshot):
                    raise ValueError("statistical snapshot binding differs")
            saved_analysis = session.get(AnalysisRow, str(intent.request.before_analysis_id))
            if saved_analysis is None:
                raise ValueError("original statistical analysis missing")
            analysis = self.store._analysis(saved_analysis)
            selection = intent.selection
            if (
                fingerprint(analysis) != intent.request.before_analysis_sha256
                or analysis.statistical is None
                or analysis.statistical != selection.original
                or analysis.created_at != selection.before_analysis_created_at
                or (analysis.configuration_id, analysis.device_id, analysis.source_sha256)
                != (
                    intent.before.configuration_id,
                    intent.before.device_id,
                    intent.before.source_sha256,
                )
            ):
                raise ValueError("original statistical analysis binding differs")
            return intent
        except ValueError:
            raise StorageIntegrityError("Stored data is unavailable.") from None

    def _outcome(
        self, row: SourceForestOutcomeRow, intent: SourceForestIntent
    ) -> SourceForestOutcome:
        try:
            outcome = SourceForestOutcome.model_validate_json(
                self._plain(row.payload, "source_forest_outcome", row.recheck_id)
            )
            if str(outcome.recheck_id) != row.recheck_id:
                raise ValueError("statistical outcome metadata differs")
            SourceForestRecheck.from_records(intent, outcome)
            return outcome
        except ValueError:
            raise StorageIntegrityError("Stored data is unavailable.") from None

    def _get(
        self, session: Session, key: UUID
    ) -> tuple[SourceForestIntent, SourceForestOutcome | None] | None:
        row = session.get(SourceForestIntentRow, str(key))
        if row is None:
            return None
        intent = self._intent(session, row)
        saved = session.get(SourceForestOutcomeRow, row.id)
        return intent, self._outcome(saved, intent) if saved is not None else None

    def get(self, key: UUID) -> tuple[SourceForestIntent, SourceForestOutcome | None] | None:
        with self.store._sessions() as session:
            return self._get(session, key)

    @staticmethod
    def _same(old: SourceForestIntent, new: SourceForestIntent) -> None:
        if old.patch_id != new.patch_id or old.request != new.request:
            raise PatchConflict("Original statistical recheck identity conflicts.")

    @staticmethod
    def _audit(session: Session, action: str, key: str) -> None:
        session.add(
            AuditRow(id=str(uuid4()), action=action, resource_id=key, created_at=datetime.now(UTC))
        )

    def reserve(self, intent: SourceForestIntent) -> bool:
        intent = SourceForestIntent.model_validate(intent.model_dump(warnings=False))
        key = str(intent.request.recheck_id)
        try:
            with self.store._sessions.begin() as session:
                existing = session.get(SourceForestIntentRow, key)
                if existing is not None:
                    self._same(self._intent(session, existing), intent)
                    return False
                row = SourceForestIntentRow(
                    id=key,
                    patch_id=str(intent.patch_id),
                    created_at=intent.created_at,
                    payload=self._encode(intent.model_dump_json(), "source_forest_intent", key),
                )
                self._intent(session, row)
                session.add(row)
                self._audit(session, "patch.statistical_recheck_requested", key)
            return True
        except IntegrityError:
            raced = self.get(intent.request.recheck_id)
            if raced is None:
                raise
            self._same(raced[0], intent)
            return False

    def complete(self, outcome: SourceForestOutcome) -> None:
        outcome = SourceForestOutcome.model_validate(outcome.model_dump(warnings=False))
        key = str(outcome.recheck_id)
        with self.store._sessions.begin() as session:
            saved = self._get(session, outcome.recheck_id)
            if saved is None:
                raise StorageIntegrityError("Stored data is unavailable.")
            intent, existing = saved
            if existing is not None:
                if existing != outcome:
                    raise PatchConflict("Original statistical outcome conflicts.")
                return
            row = SourceForestOutcomeRow(
                recheck_id=key,
                payload=self._encode(outcome.model_dump_json(), "source_forest_outcome", key),
            )
            self._outcome(row, intent)
            session.add(row)
            self._audit(session, "patch.statistical_recheck_completed", key)

    def list_ids(self, patch_id: UUID, *, limit: int, offset: int) -> list[UUID]:
        query = (
            select(SourceForestIntentRow.id)
            .where(SourceForestIntentRow.patch_id == str(patch_id))
            .order_by(SourceForestIntentRow.created_at.desc(), SourceForestIntentRow.id.desc())
        )
        with self.store._sessions() as session:
            return [UUID(key) for key in session.scalars(query.limit(limit).offset(offset))]
