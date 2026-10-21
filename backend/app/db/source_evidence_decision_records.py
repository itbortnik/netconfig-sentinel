"""Encrypted append-only report dispositions with exact parent validation and atomic audit."""

from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api import source_evidence_decision_contracts
from app.api.source_evidence_contracts import SourceEvidenceReport
from app.api.source_evidence_decision_contracts import (
    MAX_SOURCE_EVIDENCE_DECISION_BYTES,
    ReviewSourceEvidenceReport,
    SourceEvidenceDecision,
    SourceEvidenceDecisionProjectionTooLarge,
)
from app.core.permissions import Role
from app.db.patch_records import PatchConflict
from app.db.source_evidence_records import SourceEvidenceRecords
from app.db.store import StorageIntegrityError, Store
from app.db.tables import AuditRow, SourceEvidenceDecisionRow

MAX_SOURCE_EVIDENCE_DECISION_CIPHERTEXT_BYTES = 128 * 1024


class SourceEvidenceDecisionInputNotFound(ValueError):
    """The explicitly selected parent report does not exist."""


class SourceEvidenceDecisionTooLarge(ValueError):
    """The decision exceeds its bounded proof or stored payload."""


class SourceEvidenceDecisionRecords:
    def __init__(self, store: Store) -> None:
        self.store = store

    def _parent(self, session: Session, patch_id: UUID, report_id: UUID) -> SourceEvidenceReport:
        # The report reader verifies its draft, proof and selected child records in this same
        # session. A self-consistent report DTO alone does not establish its saved dependencies.
        report = SourceEvidenceRecords(self.store)._get(session, report_id)
        if report is None:
            raise SourceEvidenceDecisionInputNotFound("Selected evidence report is unavailable.")
        if report.patch_id != patch_id or report.report_id != report_id:
            raise PatchConflict("Selected evidence report belongs to a different patch.")
        return report

    def prepare(
        self,
        patch_id: UUID,
        report_id: UUID,
        request: ReviewSourceEvidenceReport,
        service_role: Role,
    ) -> SourceEvidenceDecision:
        request = ReviewSourceEvidenceReport.model_validate(request.model_dump(warnings=False))
        with self.store._sessions() as session:
            report = self._parent(session, patch_id, report_id)
            try:
                decision = SourceEvidenceDecision.from_report(
                    report, request, service_role=service_role, created_at=datetime.now(UTC)
                )
            except SourceEvidenceDecisionProjectionTooLarge:
                raise SourceEvidenceDecisionTooLarge(
                    "Evidence decision exceeds the proof budget."
                ) from None
            except ValueError:
                raise PatchConflict("Selected evidence decision bindings conflict.") from None
            self._payload(decision)
            return decision

    @staticmethod
    def _payload(decision: SourceEvidenceDecision) -> str:
        if (
            len(decision.decision_json.encode("utf-8"))
            > source_evidence_decision_contracts.MAX_SOURCE_EVIDENCE_DECISION_BYTES
        ):
            raise SourceEvidenceDecisionTooLarge("Evidence decision exceeds the proof budget.")
        raw = decision.model_dump_json(warnings=False)
        if len(raw.encode("utf-8")) > MAX_SOURCE_EVIDENCE_DECISION_BYTES:
            raise SourceEvidenceDecisionTooLarge("Evidence decision exceeds the payload budget.")
        return raw

    def _decision(self, session: Session, row: SourceEvidenceDecisionRow) -> SourceEvidenceDecision:
        try:
            if len(row.payload) > MAX_SOURCE_EVIDENCE_DECISION_CIPHERTEXT_BYTES:
                raise ValueError("oversized decision ciphertext")
            raw = self.store._decode(row.payload, kind="source_evidence_decision", row_id=row.id)
            if len(raw.encode("utf-8")) > MAX_SOURCE_EVIDENCE_DECISION_BYTES:
                raise ValueError("oversized evidence decision")
            decision = SourceEvidenceDecision.model_validate_json(raw)
            stamp = row.created_at if row.created_at.tzinfo else row.created_at.replace(tzinfo=UTC)
            if (
                str(decision.decision_id),
                str(decision.patch_id),
                str(decision.report_id),
                decision.created_at,
            ) != (row.id, row.patch_id, row.report_id, stamp):
                raise ValueError("evidence decision metadata differs")
            decision.validate_report(self._parent(session, decision.patch_id, decision.report_id))
            return decision
        except ValueError:
            raise StorageIntegrityError("Stored data is unavailable.") from None

    def _get(self, session: Session, decision_id: UUID) -> SourceEvidenceDecision | None:
        row = session.get(SourceEvidenceDecisionRow, str(decision_id))
        return self._decision(session, row) if row is not None else None

    def get(self, decision_id: UUID) -> SourceEvidenceDecision | None:
        with self.store._sessions() as session:
            return self._get(session, decision_id)

    @staticmethod
    def _same(stored: SourceEvidenceDecision, incoming: SourceEvidenceDecision) -> None:
        # Role and timestamp come from the winning insertion. A replay under another
        # authorized service key must preserve the original captured role and proof.
        if (stored.patch_id, stored.report_id, stored.request) != (
            incoming.patch_id,
            incoming.report_id,
            incoming.request,
        ):
            raise PatchConflict("Evidence decision identity conflicts.")

    @staticmethod
    def _audit(session: Session, key: str) -> None:
        session.add(
            AuditRow(
                id=str(uuid4()),
                action="patch.evidence_decision_recorded",
                resource_id=key,
                created_at=datetime.now(UTC),
            )
        )

    def add(self, decision: SourceEvidenceDecision) -> tuple[SourceEvidenceDecision, bool]:
        raw = self._payload(decision)
        decision = SourceEvidenceDecision.model_validate_json(raw)
        key = str(decision.decision_id)
        try:
            with self.store._sessions.begin() as session:
                existing = self._get(session, decision.decision_id)
                if existing is not None:
                    self._same(existing, decision)
                    return existing, False
                report = self._parent(session, decision.patch_id, decision.report_id)
                try:
                    decision.validate_report(report)
                except SourceEvidenceDecisionProjectionTooLarge:
                    raise SourceEvidenceDecisionTooLarge(
                        "Evidence decision exceeds the proof budget."
                    ) from None
                except ValueError:
                    raise PatchConflict("Selected evidence decision bindings conflict.") from None
                payload = self.store._encode(raw, kind="source_evidence_decision", row_id=key)
                if len(payload) > MAX_SOURCE_EVIDENCE_DECISION_CIPHERTEXT_BYTES:
                    raise SourceEvidenceDecisionTooLarge(
                        "Evidence decision exceeds the storage budget."
                    )
                session.add(
                    SourceEvidenceDecisionRow(
                        id=key,
                        patch_id=str(decision.patch_id),
                        report_id=str(decision.report_id),
                        created_at=decision.created_at.astimezone(UTC),
                        payload=payload,
                    )
                )
                self._audit(session, key)
            return decision, True
        except IntegrityError:
            raced = self.get(decision.decision_id)
            if raced is None:
                raise
            self._same(raced, decision)
            return raced, False

    def list_ids(self, patch_id: UUID, report_id: UUID, *, limit: int, offset: int) -> list[UUID]:
        query = (
            select(SourceEvidenceDecisionRow.id)
            .where(
                SourceEvidenceDecisionRow.patch_id == str(patch_id),
                SourceEvidenceDecisionRow.report_id == str(report_id),
            )
            .order_by(
                SourceEvidenceDecisionRow.created_at.desc(), SourceEvidenceDecisionRow.id.desc()
            )
        )
        with self.store._sessions() as session:
            return [UUID(key) for key in session.scalars(query.limit(limit).offset(offset))]
