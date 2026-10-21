"""Frozen deterministic attempts; historical reads do not execute source detectors."""

from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.contracts import SnapshotBinding
from app.api.model_patch_contracts import fingerprint
from app.api.source_deterministic_contracts import (
    MAX_SOURCE_DETERMINISTIC_BYTES,
    OriginalDeterministicContext,
    SourceDeterministicIntent,
    SourceDeterministicOutcome,
    SourceDeterministicRecheck,
)
from app.api.source_ml_contracts import ml_json
from app.db.patch_records import PatchConflict, PatchRecords
from app.db.store import StorageIntegrityError, Store
from app.db.tables import (
    AnalysisRow,
    AuditRow,
    ConfigurationRow,
    PatchRow,
    SourceDeterministicIntentRow,
    SourceDeterministicOutcomeRow,
)
from app.detection.config_model_contracts import require_complete
from app.ingestion.source_retention import canonical_fingerprint


class SourceDeterministicRecords:
    def __init__(self, store: Store) -> None:
        self.store = store

    def _plain(self, value: str, kind: str, key: str) -> str:
        if len(value) > MAX_SOURCE_DETERMINISTIC_BYTES * 4:
            raise ValueError("oversized deterministic ciphertext")
        raw = self.store._decode(value, kind=kind, row_id=key)
        if len(raw.encode()) > MAX_SOURCE_DETERMINISTIC_BYTES:
            raise ValueError("oversized deterministic record")
        return raw

    def _encode(self, value: str, kind: str, key: str) -> str:
        if len(value.encode()) > MAX_SOURCE_DETERMINISTIC_BYTES:
            raise StorageIntegrityError("Stored data is unavailable.")
        return self.store._encode(value, kind=kind, row_id=key)

    def _intent(
        self, session: Session, row: SourceDeterministicIntentRow
    ) -> SourceDeterministicIntent:
        try:
            intent = SourceDeterministicIntent.model_validate_json(
                self._plain(row.payload, "source_deterministic_intent", row.id)
            )
            stamp = row.created_at if row.created_at.tzinfo else row.created_at.replace(tzinfo=UTC)
            if (str(intent.request.recheck_id), str(intent.patch_id), intent.created_at) != (
                row.id,
                row.patch_id,
                stamp,
            ):
                raise ValueError("deterministic record metadata differs")
            parent = session.get(PatchRow, row.patch_id)
            if parent is None:
                raise ValueError("deterministic record parent missing")
            draft = PatchRecords(self.store)._draft(session, parent)
            if (
                draft.draft_sha256 != intent.request.draft_sha256
                or intent.created_at < draft.created_at
                or (intent.before.configuration_id, intent.after.configuration_id)
                != (draft.diff.before.configuration_id, draft.diff.after.configuration_id)
            ):
                raise ValueError("deterministic record parent differs")
            for member in (intent.before, intent.after):
                saved = session.get(ConfigurationRow, str(member.configuration_id))
                if saved is None:
                    raise ValueError("deterministic snapshot missing")
                snapshot = self.store._snapshot(saved)
                require_complete(snapshot)
                if member.model_dump(exclude={"canonical_sha256"}) != SnapshotBinding.from_snapshot(
                    snapshot
                ).model_dump() or member.canonical_sha256 != canonical_fingerprint(snapshot):
                    raise ValueError("deterministic snapshot binding differs")
            saved_analysis = session.get(AnalysisRow, str(intent.request.before_analysis_id))
            if saved_analysis is None:
                raise ValueError("original deterministic analysis missing")
            analysis = self.store._analysis(saved_analysis)
            selection = intent.selection
            if (
                fingerprint(analysis) != intent.request.before_analysis_sha256
                or ml_json(
                    OriginalDeterministicContext.from_analysis(analysis).model_dump(mode="json")
                )
                != ml_json(selection.original.model_dump(mode="json"))
                or analysis.created_at != selection.before_analysis_created_at
                or (analysis.configuration_id, analysis.device_id, analysis.source_sha256)
                != (
                    intent.before.configuration_id,
                    intent.before.device_id,
                    intent.before.source_sha256,
                )
            ):
                raise ValueError("original deterministic analysis binding differs")
            return intent
        except ValueError:
            raise StorageIntegrityError("Stored data is unavailable.") from None

    def _outcome(
        self, row: SourceDeterministicOutcomeRow, intent: SourceDeterministicIntent
    ) -> SourceDeterministicOutcome:
        try:
            outcome = SourceDeterministicOutcome.model_validate_json(
                self._plain(row.payload, "source_deterministic_outcome", row.recheck_id)
            )
            if str(outcome.recheck_id) != row.recheck_id:
                raise ValueError("deterministic outcome metadata differs")
            SourceDeterministicRecheck.from_records(intent, outcome)
            return outcome
        except ValueError:
            raise StorageIntegrityError("Stored data is unavailable.") from None

    def _get(
        self, session: Session, key: UUID
    ) -> tuple[SourceDeterministicIntent, SourceDeterministicOutcome | None] | None:
        row = session.get(SourceDeterministicIntentRow, str(key))
        if row is None:
            return None
        intent = self._intent(session, row)
        saved = session.get(SourceDeterministicOutcomeRow, row.id)
        return intent, self._outcome(saved, intent) if saved is not None else None

    def get(
        self, key: UUID
    ) -> tuple[SourceDeterministicIntent, SourceDeterministicOutcome | None] | None:
        with self.store._sessions() as session:
            return self._get(session, key)

    @staticmethod
    def _same(old: SourceDeterministicIntent, new: SourceDeterministicIntent) -> None:
        if old.patch_id != new.patch_id or old.request != new.request:
            raise PatchConflict("Original deterministic recheck identity conflicts.")

    @staticmethod
    def _audit(session: Session, action: str, key: str) -> None:
        session.add(
            AuditRow(id=str(uuid4()), action=action, resource_id=key, created_at=datetime.now(UTC))
        )

    def reserve(self, intent: SourceDeterministicIntent) -> bool:
        intent = SourceDeterministicIntent.model_validate(intent.model_dump(warnings=False))
        key = str(intent.request.recheck_id)
        try:
            with self.store._sessions.begin() as session:
                existing = session.get(SourceDeterministicIntentRow, key)
                if existing is not None:
                    self._same(self._intent(session, existing), intent)
                    return False
                row = SourceDeterministicIntentRow(
                    id=key,
                    patch_id=str(intent.patch_id),
                    created_at=intent.created_at,
                    payload=self._encode(
                        intent.model_dump_json(), "source_deterministic_intent", key
                    ),
                )
                self._intent(session, row)
                session.add(row)
                self._audit(session, "patch.deterministic_recheck_requested", key)
            return True
        except IntegrityError:
            raced = self.get(intent.request.recheck_id)
            if raced is None:
                raise
            self._same(raced[0], intent)
            return False

    def complete(self, outcome: SourceDeterministicOutcome) -> None:
        outcome = SourceDeterministicOutcome.model_validate(outcome.model_dump(warnings=False))
        key = str(outcome.recheck_id)
        try:
            with self.store._sessions.begin() as session:
                saved = self._get(session, outcome.recheck_id)
                if saved is None:
                    raise StorageIntegrityError("Stored data is unavailable.")
                intent, existing = saved
                if existing is not None:
                    self._same_outcome(existing, outcome)
                    return
                row = SourceDeterministicOutcomeRow(
                    recheck_id=key,
                    payload=self._encode(
                        outcome.model_dump_json(), "source_deterministic_outcome", key
                    ),
                )
                self._outcome(row, intent)
                session.add(row)
                self._audit(session, "patch.deterministic_recheck_completed", key)
        except IntegrityError:
            # A concurrent terminal insert must retain its own audit atomically.
            raced = self.get(outcome.recheck_id)
            if raced is None or raced[1] is None:
                raise
            self._same_outcome(raced[1], outcome)

    @staticmethod
    def _same_outcome(old: SourceDeterministicOutcome, new: SourceDeterministicOutcome) -> None:
        if ml_json(old.model_dump(mode="json")) != ml_json(new.model_dump(mode="json")):
            raise PatchConflict("Original deterministic outcome conflicts.")

    def list_ids(self, patch_id: UUID, *, limit: int, offset: int) -> list[UUID]:
        query = (
            select(SourceDeterministicIntentRow.id)
            .where(SourceDeterministicIntentRow.patch_id == str(patch_id))
            .order_by(
                SourceDeterministicIntentRow.created_at.desc(),
                SourceDeterministicIntentRow.id.desc(),
            )
        )
        with self.store._sessions() as session:
            return [UUID(key) for key in session.scalars(query.limit(limit).offset(offset))]
