"""Compose a separate saved engineering priority without executing or changing its evidence."""

from uuid import UUID

from app.api.source_risk_partial_contracts import (
    SourceRiskRecord,
    SourceRiskRequest,
    parse_source_risk_request,
)
from app.core.permissions import Role
from app.db.patch_records import PatchConflict
from app.db.source_risk_records import SourceRiskRecords
from app.db.store import Store
from app.patching.persistent import PatchNotFound
from app.patching.source_evidence import SourceEvidenceWorkflow


class SourceRiskWorkflow:
    def __init__(self, store: Store) -> None:
        self.reports = SourceEvidenceWorkflow(store)
        self.records = SourceRiskRecords(store)

    def get(self, patch_id: UUID, report_id: UUID, assessment_id: UUID) -> SourceRiskRecord:
        assessment = self.records.get(assessment_id)
        if assessment is None or (assessment.patch_id, assessment.report_id) != (
            patch_id,
            report_id,
        ):
            raise PatchNotFound()
        return assessment

    def create(
        self,
        patch_id: UUID,
        report_id: UUID,
        options: SourceRiskRequest,
        service_role: Role,
    ) -> tuple[SourceRiskRecord, bool]:
        options = parse_source_risk_request(options)
        existing = self.records.get(options.assessment_id)
        if existing is not None:
            if (existing.patch_id, existing.report_id) != (patch_id, report_id) or (
                existing.request != options
            ):
                raise PatchConflict("Saved assessment identity conflicts.")
            return existing, False
        assessment = self.records.prepare(patch_id, report_id, options, service_role)
        return self.records.add(assessment)
