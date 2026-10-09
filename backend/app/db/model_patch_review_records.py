"""Encrypted immutable verification attempts/results/decisions with atomic domain audit."""

from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.contracts import SnapshotBinding
from app.api.model_patch_contracts import fingerprint
from app.api.model_patch_review_contracts import (
    SavedPatchDecision,
    SavedPatchReviewIntent,
    SavedPatchReviewOutcome,
    SavedPatchVerification,
    validate_decision,
)
from app.db.model_patch_records import ModelPatchConflict, ModelPatchRecords
from app.db.store import StorageIntegrityError, Store
from app.db.tables import (
    AuditRow,
    ConfigurationRow,
    ModelPatchDecisionRow,
    ModelPatchIntentRow,
    ModelPatchOutcomeRow,
    ModelPatchReviewIntentRow,
    ModelPatchReviewOutcomeRow,
)

MAX_REVIEW_BYTES = 4 * 1024 * 1024


class ModelPatchReviewRecords:
    def __init__(self, store: Store) -> None:
        self.store = store

    def _plain(self, payload: str, kind: str, key: str) -> str:
        if len(payload) > MAX_REVIEW_BYTES * 4:
            raise ValueError("oversized review ciphertext")
        value = self.store._decode(payload, kind=kind, row_id=key)
        if len(value.encode()) > MAX_REVIEW_BYTES:
            raise ValueError("oversized review record")
        return value

    def _encode(self, value: str, kind: str, key: str) -> str:
        if len(value.encode()) > MAX_REVIEW_BYTES:
            raise StorageIntegrityError("Stored data is unavailable.")
        return self.store._encode(value, kind=kind, row_id=key)

    def _intent(self, session: Session, row: ModelPatchReviewIntentRow) -> SavedPatchReviewIntent:
        try:
            intent = SavedPatchReviewIntent.model_validate_json(
                self._plain(row.payload, "model_patch_review_intent", row.id)
            )
            timestamp = (
                row.created_at if row.created_at.tzinfo else row.created_at.replace(tzinfo=UTC)
            )
            if (str(intent.request.verification_id), str(intent.patch_id), intent.created_at) != (
                row.id,
                row.patch_id,
                timestamp,
            ):
                raise ValueError("review row binding differs")
            parent = session.get(ModelPatchIntentRow, row.patch_id)
            result = session.get(ModelPatchOutcomeRow, row.patch_id)
            if parent is None or result is None:
                raise ValueError("review parent missing")
            records = ModelPatchRecords(self.store)
            generation = records._intent(session, parent)
            outcome = records._outcome(result, generation)
            from app.api.model_patch_contracts import ModelPatchProposal

            proposal = ModelPatchProposal.from_records(generation, outcome)
            if (
                proposal.status != "draft"
                or proposal.proposal_sha256 != intent.request.proposal_sha256
                or (
                    outcome.completed_at > intent.created_at
                    or generation.source not in intent.network
                )
            ):
                raise ValueError("review proposal binding differs")
            for binding in intent.network:
                source = session.get(ConfigurationRow, str(binding.configuration_id))
                if (
                    source is None
                    or SnapshotBinding.from_snapshot(self.store._snapshot(source)) != binding
                    or (binding.created_at > generation.created_at)
                ):
                    raise ValueError("review network differs or was created after generation")
            return intent
        except ValueError:
            raise StorageIntegrityError("Stored data is unavailable.") from None

    def _outcome(
        self, row: ModelPatchReviewOutcomeRow, intent: SavedPatchReviewIntent
    ) -> SavedPatchReviewOutcome:
        try:
            result = SavedPatchReviewOutcome.model_validate_json(
                self._plain(row.payload, "model_patch_review_outcome", row.verification_id)
            )
            if str(result.verification_id) != row.verification_id or (
                result.verification_id != intent.request.verification_id
                or result.intent_sha256 != fingerprint(intent)
                or result.completed_at < intent.created_at
            ):
                raise ValueError("review outcome binding differs")
            SavedPatchVerification.from_records(intent, result)
            return result
        except ValueError:
            raise StorageIntegrityError("Stored data is unavailable.") from None

    def _get(
        self, session: Session, key: UUID
    ) -> tuple[SavedPatchReviewIntent, SavedPatchReviewOutcome | None] | None:
        row = session.get(ModelPatchReviewIntentRow, str(key))
        if row is None:
            return None
        intent = self._intent(session, row)
        outcome = session.get(ModelPatchReviewOutcomeRow, row.id)
        return intent, self._outcome(outcome, intent) if outcome else None

    def get(
        self, key: UUID
    ) -> tuple[SavedPatchReviewIntent, SavedPatchReviewOutcome | None] | None:
        with self.store._sessions() as session:
            return self._get(session, key)

    @staticmethod
    def _same(stored: SavedPatchReviewIntent, incoming: SavedPatchReviewIntent) -> None:
        if stored.patch_id != incoming.patch_id or stored.request != incoming.request:
            raise ModelPatchConflict("Review identity conflicts.")

    @staticmethod
    def _audit(session: Session, action: str, key: str) -> None:
        session.add(
            AuditRow(id=str(uuid4()), action=action, resource_id=key, created_at=datetime.now(UTC))
        )

    def reserve(self, intent: SavedPatchReviewIntent) -> bool:
        intent = SavedPatchReviewIntent.model_validate_json(intent.model_dump_json())
        key = str(intent.request.verification_id)
        try:
            with self.store._sessions.begin() as session:
                existing = session.get(ModelPatchReviewIntentRow, key)
                if existing:
                    self._same(self._intent(session, existing), intent)
                    return False
                row = ModelPatchReviewIntentRow(
                    id=key,
                    patch_id=str(intent.patch_id),
                    created_at=intent.created_at,
                    payload=self._encode(
                        intent.model_dump_json(), "model_patch_review_intent", key
                    ),
                )
                self._intent(session, row)
                session.add(row)
                self._audit(session, "model_patch.verification_requested", key)
            return True
        except IntegrityError:
            existing_pair = self.get(intent.request.verification_id)
            if existing_pair is None:
                raise
            self._same(existing_pair[0], intent)
            return False

    def complete(self, outcome: SavedPatchReviewOutcome) -> None:
        outcome = SavedPatchReviewOutcome.model_validate_json(outcome.model_dump_json())
        key = str(outcome.verification_id)
        with self.store._sessions.begin() as session:
            saved = self._get(session, outcome.verification_id)
            if saved is None:
                raise StorageIntegrityError("Stored data is unavailable.")
            intent, existing = saved
            if existing:
                if existing != outcome:
                    raise ModelPatchConflict("Review result conflicts.")
                return
            row = ModelPatchReviewOutcomeRow(
                verification_id=key,
                payload=self._encode(outcome.model_dump_json(), "model_patch_review_outcome", key),
            )
            self._outcome(row, intent)
            session.add(row)
            self._audit(session, "model_patch.verification_completed", key)

    def _decision(self, session: Session, row: ModelPatchDecisionRow) -> SavedPatchDecision:
        try:
            decision = SavedPatchDecision.model_validate_json(
                self._plain(row.payload, "model_patch_decision", row.id)
            )
            timestamp = (
                row.created_at if row.created_at.tzinfo else row.created_at.replace(tzinfo=UTC)
            )
            if (
                str(decision.request.decision_id),
                str(decision.patch_id),
                str(decision.request.verification_id),
                decision.created_at,
            ) != (row.id, row.patch_id, row.verification_id, timestamp):
                raise ValueError("decision row binding differs")
            saved = self._get(session, decision.request.verification_id)
            if saved is None:
                raise ValueError("decision review missing")
            validate_decision(decision, SavedPatchVerification.from_records(*saved))
            return decision
        except ValueError:
            raise StorageIntegrityError("Stored data is unavailable.") from None

    def get_decision(self, key: UUID) -> SavedPatchDecision | None:
        with self.store._sessions() as session:
            row = session.get(ModelPatchDecisionRow, str(key))
            return self._decision(session, row) if row else None

    def decide(self, decision: SavedPatchDecision) -> tuple[SavedPatchDecision, bool]:
        decision = SavedPatchDecision.model_validate_json(decision.model_dump_json())
        key = str(decision.request.decision_id)
        try:
            with self.store._sessions.begin() as session:
                existing = session.get(ModelPatchDecisionRow, key)
                if existing:
                    stored = self._decision(session, existing)
                    if stored.request != decision.request or stored.patch_id != decision.patch_id:
                        raise ModelPatchConflict("Decision identity conflicts.")
                    return stored, False
                row = ModelPatchDecisionRow(
                    id=key,
                    patch_id=str(decision.patch_id),
                    verification_id=str(decision.request.verification_id),
                    created_at=decision.created_at,
                    payload=self._encode(decision.model_dump_json(), "model_patch_decision", key),
                )
                self._decision(session, row)
                session.add(row)
                self._audit(session, "model_patch.engineer_decision", key)
            return decision, True
        except IntegrityError:
            raced = self.get_decision(decision.request.decision_id)
            if raced is None:
                raise
            if raced.request != decision.request or raced.patch_id != decision.patch_id:
                raise ModelPatchConflict("Decision identity conflicts.") from None
            return raced, False

    def list_ids(self, patch_id: UUID, *, decisions: bool, limit: int, offset: int) -> list[UUID]:
        table = ModelPatchDecisionRow if decisions else ModelPatchReviewIntentRow
        query = (
            select(table.id)
            .where(table.patch_id == str(patch_id))
            .order_by(table.created_at.desc(), table.id.desc())
        )
        with self.store._sessions() as session:
            return [UUID(value) for value in session.scalars(query.limit(limit).offset(offset))]
