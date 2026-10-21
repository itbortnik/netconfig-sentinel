"""Save an explicit data-only composition of existing ordinary draft results."""

from uuid import UUID

from app.api.source_evidence_contracts import (
    MAX_SOURCE_EVIDENCE_BYTES,
    CreateSourceEvidenceReport,
    SourceEvidenceReport,
)
from app.db.patch_records import PatchConflict
from app.db.source_evidence_records import SourceEvidenceRecords, SourceEvidenceTooLarge
from app.db.store import Store
from app.patching.persistent import PatchNotFound, PatchWorkflow


class SourceEvidenceWorkflow:
    def __init__(self, store: Store) -> None:
        self.drafts = PatchWorkflow(store)
        self.records = SourceEvidenceRecords(store)

    @staticmethod
    def _view(report: SourceEvidenceReport) -> SourceEvidenceReport:
        if len(report.model_dump_json().encode()) > MAX_SOURCE_EVIDENCE_BYTES * 4:
            raise SourceEvidenceTooLarge()
        return report

    def get(self, patch_id: UUID, report_id: UUID) -> SourceEvidenceReport:
        report = self.records.get(report_id)
        if report is None or report.patch_id != patch_id:
            raise PatchNotFound()
        return self._view(report)

    def create(
        self, patch_id: UUID, options: CreateSourceEvidenceReport
    ) -> tuple[SourceEvidenceReport, bool]:
        options = CreateSourceEvidenceReport.model_validate(options.model_dump(warnings=False))
        existing = self.records.get(options.report_id)
        if existing is not None:
            if existing.patch_id != patch_id or existing.request != options:
                raise PatchConflict("Saved evidence report identity conflicts.")
            return self._view(existing), False
        report = self.records.prepare(patch_id, options)
        self._view(report)
        saved, created = self.records.add(report)
        return self._view(saved), created
