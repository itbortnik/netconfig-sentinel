"""Reserve before inference; completion and domain audit commit atomically."""

from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.contracts import SnapshotBinding
from app.api.model_patch_contracts import (
    MAX_MODEL_PATCH_BYTES,
    ModelPatchIntent,
    ModelPatchOutcome,
    fingerprint,
)
from app.db.store import StorageIntegrityError, Store
from app.db.tables import (
    AnalysisRow,
    AuditRow,
    ConfigurationRow,
    ModelPatchIntentRow,
    ModelPatchOutcomeRow,
)
from app.domain.fingerprints import finding_fingerprint


class ModelPatchConflict(ValueError):
    pass


class ModelPatchRecords:
    def __init__(self, store: Store) -> None:
        self.store = store

    def _plain(self, ciphertext: str, kind: str, key: str) -> str:
        if len(ciphertext) > MAX_MODEL_PATCH_BYTES * 4:
            raise ValueError("oversized model patch ciphertext")
        value = self.store._decode(ciphertext, kind=kind, row_id=key)
        if len(value.encode()) > MAX_MODEL_PATCH_BYTES:
            raise ValueError("oversized model patch record")
        return value

    def _intent(self, session: Session, row: ModelPatchIntentRow) -> ModelPatchIntent:
        try:
            intent = ModelPatchIntent.model_validate_json(
                self._plain(row.payload, "model_patch_intent", row.id)
            )
            timestamp = (
                row.created_at if row.created_at.tzinfo else row.created_at.replace(tzinfo=UTC)
            )
            if (
                str(intent.request.patch_id),
                str(intent.request.analysis_id),
                str(intent.source.configuration_id),
                intent.created_at,
            ) != (
                row.id,
                row.analysis_id,
                row.configuration_id,
                timestamp,
            ):
                raise ValueError("model patch row binding differs")
            analysis_row = session.get(AnalysisRow, row.analysis_id)
            source_row = session.get(ConfigurationRow, row.configuration_id)
            if analysis_row is None or source_row is None:
                raise ValueError("model patch parent missing")
            analysis = self.store._analysis(analysis_row)
            snapshot = self.store._snapshot(source_row)
            if (
                SnapshotBinding.from_snapshot(snapshot) != intent.source
                or analysis.configuration_id != intent.source.configuration_id
                or analysis.device_id != intent.source.device_id
                or analysis.source_sha256 != intent.source.source_sha256
                or analysis.created_at > intent.created_at
                or not any(
                    finding.finding_id == intent.request.finding_id
                    and finding_fingerprint(finding) == intent.request.finding_sha256
                    for finding in analysis.findings
                )
            ):
                raise ValueError("model patch selected facts differ")
            return intent
        except ValueError:
            raise StorageIntegrityError("Stored data is unavailable.") from None

    def _outcome(self, row: ModelPatchOutcomeRow, intent: ModelPatchIntent) -> ModelPatchOutcome:
        try:
            outcome = ModelPatchOutcome.model_validate_json(
                self._plain(row.payload, "model_patch_outcome", row.patch_id)
            )
            if (
                outcome.patch_id != intent.request.patch_id
                or str(outcome.patch_id) != row.patch_id
                or outcome.intent_sha256 != fingerprint(intent)
                or outcome.completed_at < intent.created_at
            ):
                raise ValueError("model patch completion binding differs")
            return outcome
        except ValueError:
            raise StorageIntegrityError("Stored data is unavailable.") from None

    def get(self, patch_id: UUID) -> tuple[ModelPatchIntent, ModelPatchOutcome | None] | None:
        with self.store._sessions() as session:
            row = session.get(ModelPatchIntentRow, str(patch_id))
            if row is None:
                return None
            intent = self._intent(session, row)
            outcome = session.get(ModelPatchOutcomeRow, str(patch_id))
            return intent, self._outcome(outcome, intent) if outcome else None

    @staticmethod
    def _same_intent(stored: ModelPatchIntent, incoming: ModelPatchIntent) -> None:
        # Alias/context already selected by the first request, never replaced on replay.
        if stored.request != incoming.request:
            raise ModelPatchConflict("Model patch identity conflicts.")

    def reserve(self, intent: ModelPatchIntent) -> bool:
        intent = ModelPatchIntent.model_validate_json(intent.model_dump_json())
        key = str(intent.request.patch_id)
        try:
            with self.store._sessions.begin() as session:
                existing = session.get(ModelPatchIntentRow, key)
                if existing is not None:
                    self._same_intent(self._intent(session, existing), intent)
                    return False
                row = ModelPatchIntentRow(
                    id=key,
                    analysis_id=str(intent.request.analysis_id),
                    configuration_id=str(intent.source.configuration_id),
                    created_at=intent.created_at,
                    payload=self.store._encode(
                        intent.model_dump_json(), kind="model_patch_intent", row_id=key
                    ),
                )
                self._intent(session, row)
                session.add(row)
                session.add(
                    AuditRow(
                        id=str(uuid4()),
                        action="model_patch.requested",
                        resource_id=key,
                        created_at=datetime.now(UTC),
                    )
                )
            return True
        except IntegrityError:
            stored = self.get(intent.request.patch_id)
            if stored is None:
                raise
            self._same_intent(stored[0], intent)
            return False

    def complete(self, outcome: ModelPatchOutcome) -> None:
        outcome = ModelPatchOutcome.model_validate_json(outcome.model_dump_json())
        key = str(outcome.patch_id)
        with self.store._sessions.begin() as session:
            parent = session.get(ModelPatchIntentRow, key)
            if parent is None:
                raise StorageIntegrityError("Stored data is unavailable.")
            intent = self._intent(session, parent)
            existing = session.get(ModelPatchOutcomeRow, key)
            if existing is not None:
                if self._outcome(existing, intent) != outcome:
                    raise ModelPatchConflict("Model patch outcome conflicts.")
                return
            row = ModelPatchOutcomeRow(
                patch_id=key,
                payload=self.store._encode(
                    outcome.model_dump_json(),
                    kind="model_patch_outcome",
                    row_id=key,
                ),
            )
            self._outcome(row, intent)
            session.add(row)
            session.add(
                AuditRow(
                    id=str(uuid4()),
                    action="model_patch.completed",
                    resource_id=key,
                    created_at=datetime.now(UTC),
                )
            )

    def list_ids(self, *, analysis_id: UUID, limit: int, offset: int) -> list[UUID]:
        query = (
            select(ModelPatchIntentRow.id)
            .where(ModelPatchIntentRow.analysis_id == str(analysis_id))
            .order_by(ModelPatchIntentRow.created_at.desc(), ModelPatchIntentRow.id.desc())
        )
        with self.store._sessions() as session:
            return [UUID(value) for value in session.scalars(query.limit(limit).offset(offset))]
