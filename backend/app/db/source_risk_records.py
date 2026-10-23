"""Append-only encrypted priority records, recomposed from their complete saved evidence."""

from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api import source_risk_contracts
from app.api.source_evidence_direction_contracts import SourceEvidenceReportRecord
from app.api.source_risk_contracts import (
    CreateSourceRiskAssessment,
    SourceRiskAssessment,
    SourceRiskProjectionTooLarge,
)
from app.core.permissions import Role
from app.db.patch_records import PatchConflict
from app.db.source_evidence_records import SourceEvidenceRecords
from app.db.store import StorageIntegrityError, Store
from app.db.tables import AuditRow, SourceRiskAssessmentRow

MAX_SOURCE_RISK_CIPHERTEXT_BYTES = 4 * 1024 * 1024


class SourceRiskInputNotFound(ValueError):
    """The explicitly selected parent report does not exist."""


class SourceRiskTooLarge(ValueError):
    """A new assessment exceeds a proof, payload or encryption budget."""


class SourceRiskRecords:
    def __init__(self, store: Store) -> None:
        self.store = store
        self.reports = SourceEvidenceRecords(store)

    def _parent(
        self, session: Session, patch_id: UUID, report_id: UUID
    ) -> SourceEvidenceReportRecord:
        report = self.reports._get(session, report_id)
        if report is None:
            raise SourceRiskInputNotFound("Selected evidence report is unavailable.")
        if report.patch_id != patch_id or report.report_id != report_id:
            raise PatchConflict("Selected evidence report belongs to a different patch.")
        return report

    def _validate(self, session: Session, assessment: SourceRiskAssessment) -> None:
        report = self._parent(session, assessment.patch_id, assessment.report_id)
        inputs = self.reports._inputs(session, report.patch_id, report.request)
        assessment.validate_evidence(
            inputs.draft,
            report,
            inputs.deterministic,
            forest=inputs.forest,
            neural=inputs.neural,
            network=inputs.network,
        )

    def prepare(
        self,
        patch_id: UUID,
        report_id: UUID,
        request: CreateSourceRiskAssessment,
        service_role: Role,
    ) -> SourceRiskAssessment:
        request = CreateSourceRiskAssessment.model_validate(request.model_dump(warnings=False))
        with self.store._sessions() as session:
            report = self._parent(session, patch_id, report_id)
            inputs = self.reports._inputs(session, report.patch_id, report.request)
            try:
                assessment = SourceRiskAssessment.from_evidence(
                    inputs.draft,
                    report,
                    request,
                    inputs.deterministic,
                    forest=inputs.forest,
                    neural=inputs.neural,
                    network=inputs.network,
                    service_role=service_role,
                    created_at=datetime.now(UTC),
                )
            except SourceRiskProjectionTooLarge:
                raise SourceRiskTooLarge("Priority assessment exceeds its proof budget.") from None
            except ValueError:
                raise PatchConflict("Selected assessment bindings conflict.") from None
            self._payload(assessment)
            return assessment

    @staticmethod
    def _payload(assessment: SourceRiskAssessment) -> str:
        if len(assessment.review_json.encode()) > source_risk_contracts.MAX_SOURCE_RISK_PROOF_BYTES:
            raise SourceRiskTooLarge("Priority assessment exceeds its proof budget.")
        raw = assessment.model_dump_json(warnings=False)
        if len(raw.encode()) > source_risk_contracts.MAX_SOURCE_RISK_BYTES:
            raise SourceRiskTooLarge("Priority assessment exceeds its payload budget.")
        return raw

    def _assessment(self, session: Session, row: SourceRiskAssessmentRow) -> SourceRiskAssessment:
        try:
            if len(row.payload) > MAX_SOURCE_RISK_CIPHERTEXT_BYTES:
                raise ValueError("oversized assessment ciphertext")
            raw = self.store._decode(row.payload, kind="source_risk_assessment", row_id=row.id)
            if len(raw.encode()) > source_risk_contracts.MAX_SOURCE_RISK_BYTES:
                raise ValueError("oversized assessment payload")
            assessment = SourceRiskAssessment.model_validate_json(raw)
            stamp = row.created_at if row.created_at.tzinfo else row.created_at.replace(tzinfo=UTC)
            if (
                str(assessment.assessment_id),
                str(assessment.patch_id),
                str(assessment.report_id),
                assessment.created_at,
            ) != (row.id, row.patch_id, row.report_id, stamp):
                raise ValueError("assessment metadata differs")
            self._validate(session, assessment)
            return assessment
        except ValueError:
            raise StorageIntegrityError("Stored data is unavailable.") from None

    def _get(self, session: Session, assessment_id: UUID) -> SourceRiskAssessment | None:
        row = session.get(SourceRiskAssessmentRow, str(assessment_id))
        return self._assessment(session, row) if row is not None else None

    def get(self, assessment_id: UUID) -> SourceRiskAssessment | None:
        with self.store._sessions() as session:
            return self._get(session, assessment_id)

    @staticmethod
    def _same(stored: SourceRiskAssessment, incoming: SourceRiskAssessment) -> None:
        # Replay preserves the first insertion's server role, timestamp and normative proof.
        if (stored.patch_id, stored.report_id, stored.request) != (
            incoming.patch_id,
            incoming.report_id,
            incoming.request,
        ):
            raise PatchConflict("Priority assessment identity conflicts.")

    @staticmethod
    def _audit(session: Session, key: str) -> None:
        session.add(
            AuditRow(
                id=str(uuid4()),
                action="patch.risk_assessment_created",
                resource_id=key,
                created_at=datetime.now(UTC),
            )
        )

    def add(self, assessment: SourceRiskAssessment) -> tuple[SourceRiskAssessment, bool]:
        raw = self._payload(assessment)
        assessment = SourceRiskAssessment.model_validate_json(raw)
        key = str(assessment.assessment_id)
        try:
            with self.store._sessions.begin() as session:
                existing = self._get(session, assessment.assessment_id)
                if existing is not None:
                    self._same(existing, assessment)
                    return existing, False
                try:
                    self._validate(session, assessment)
                except SourceRiskProjectionTooLarge:
                    raise SourceRiskTooLarge(
                        "Priority assessment exceeds its proof budget."
                    ) from None
                except (SourceRiskInputNotFound, StorageIntegrityError):
                    raise
                except ValueError:
                    raise PatchConflict("Selected assessment bindings conflict.") from None
                payload = self.store._encode(raw, kind="source_risk_assessment", row_id=key)
                if len(payload) > MAX_SOURCE_RISK_CIPHERTEXT_BYTES:
                    raise SourceRiskTooLarge("Priority assessment exceeds its storage budget.")
                session.add(
                    SourceRiskAssessmentRow(
                        id=key,
                        patch_id=str(assessment.patch_id),
                        report_id=str(assessment.report_id),
                        created_at=assessment.created_at.astimezone(UTC),
                        payload=payload,
                    )
                )
                self._audit(session, key)
            return assessment, True
        except IntegrityError:
            raced = self.get(assessment.assessment_id)
            if raced is None:
                raise
            self._same(raced, assessment)
            return raced, False

    def list_ids(self, patch_id: UUID, report_id: UUID, *, limit: int, offset: int) -> list[UUID]:
        query = (
            select(SourceRiskAssessmentRow.id)
            .where(
                SourceRiskAssessmentRow.patch_id == str(patch_id),
                SourceRiskAssessmentRow.report_id == str(report_id),
            )
            .order_by(SourceRiskAssessmentRow.created_at.desc(), SourceRiskAssessmentRow.id.desc())
        )
        with self.store._sessions() as session:
            return [UUID(key) for key in session.scalars(query.limit(limit).offset(offset))]
