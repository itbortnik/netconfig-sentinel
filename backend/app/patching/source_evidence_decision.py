"""Append a service-role disposition without executing checks or changing its report."""

from uuid import UUID

from app.api.source_evidence_decision_contracts import (
    MAX_SOURCE_EVIDENCE_DECISION_BYTES,
)
from app.api.source_evidence_decision_sdk_contracts import (
    SourceEvidenceDecisionRecord,
    SourceEvidenceDecisionRequest,
    parse_source_evidence_decision_request,
)
from app.core.permissions import Role
from app.db.patch_records import PatchConflict
from app.db.source_evidence_decision_records import (
    SourceEvidenceDecisionRecords,
    SourceEvidenceDecisionTooLarge,
)
from app.db.store import Store
from app.patching.persistent import PatchNotFound
from app.patching.source_evidence import SourceEvidenceWorkflow


class SourceEvidenceDecisionWorkflow:
    def __init__(self, store: Store) -> None:
        self.reports = SourceEvidenceWorkflow(store)
        self.records = SourceEvidenceDecisionRecords(store)

    @staticmethod
    def _view(decision: SourceEvidenceDecisionRecord) -> SourceEvidenceDecisionRecord:
        if len(decision.model_dump_json().encode()) > MAX_SOURCE_EVIDENCE_DECISION_BYTES * 4:
            raise SourceEvidenceDecisionTooLarge()
        return decision

    def get(
        self, patch_id: UUID, report_id: UUID, decision_id: UUID
    ) -> SourceEvidenceDecisionRecord:
        decision = self.records.get(decision_id)
        if decision is None or (decision.patch_id, decision.report_id) != (patch_id, report_id):
            raise PatchNotFound()
        return self._view(decision)

    def create(
        self,
        patch_id: UUID,
        report_id: UUID,
        options: SourceEvidenceDecisionRequest,
        service_role: Role,
    ) -> tuple[SourceEvidenceDecisionRecord, bool]:
        options = parse_source_evidence_decision_request(options)
        existing = self.records.get(options.decision_id)
        if existing is not None:
            if (existing.patch_id, existing.report_id) != (
                patch_id,
                report_id,
            ) or existing.request != options:
                raise PatchConflict("Saved decision identity conflicts.")
            return self._view(existing), False
        decision = self.records.prepare(patch_id, report_id, options, service_role)
        self._view(decision)
        saved, created = self.records.add(decision)
        return self._view(saved), created
