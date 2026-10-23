"""Atomic encrypted ordinary reports over explicitly selected immutable child records."""

from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api import source_evidence_contracts
from app.api.patch_contracts import PatchDraft
from app.api.source_deterministic_contracts import SourceDeterministicRecheck
from app.api.source_evidence_contracts import (
    MAX_SOURCE_EVIDENCE_BYTES,
    SourceEvidenceProjectionTooLarge,
)
from app.api.source_evidence_direction_contracts import (
    CreateSourceEvidenceReportV3,
    SourceEvidenceReportRecord,
    SourceEvidenceRequest,
    parse_source_evidence_report_json,
    parse_source_evidence_request,
    source_evidence_report,
    validate_source_evidence_report,
)
from app.api.source_evidence_sdk_contracts import CreateSourceEvidenceReportV2
from app.api.source_forest_contracts import SourceForestRecheck
from app.api.source_ml_contracts import SourceMlRecheck
from app.api.source_patch_contracts import SourcePatchVerification
from app.api.source_patch_direction_contracts import (
    SourcePatchReview,
    SourcePatchVerificationV3,
    source_patch_view,
)
from app.db.patch_records import PatchConflict, PatchRecords
from app.db.source_deterministic_records import SourceDeterministicRecords
from app.db.source_forest_records import SourceForestRecords
from app.db.source_ml_records import SourceMlRecords
from app.db.source_patch_records import SourcePatchRecords
from app.db.store import StorageIntegrityError, Store
from app.db.tables import AuditRow, PatchRow, SourceEvidenceReportRow

MAX_SOURCE_EVIDENCE_INPUT_BYTES = 32 * 1024 * 1024
MAX_SOURCE_EVIDENCE_CIPHERTEXT_BYTES = 16 * 1024 * 1024


class SourceEvidenceInputNotFound(ValueError):
    """The explicitly selected parent or child record does not exist."""


class SourceEvidenceTooLarge(ValueError):
    """Creation exceeds the bounded selected inputs or report payload."""


@dataclass(frozen=True)
class _SelectedInputs:
    draft: PatchDraft
    deterministic: SourceDeterministicRecheck
    forest: SourceForestRecheck | None
    neural: SourceMlRecheck | None
    network: SourcePatchReview | None


class SourceEvidenceRecords:
    def __init__(self, store: Store) -> None:
        self.store = store

    def _inputs(
        self, session: Session, patch_id: UUID, request: SourceEvidenceRequest
    ) -> _SelectedInputs:
        try:
            return self._load_inputs(session, patch_id, request)
        except (SourceEvidenceInputNotFound, SourceEvidenceTooLarge, PatchConflict):
            raise
        except ValueError:
            # A stored child that cannot form its existing public DTO is corrupted, rather
            # than an invalid new report request. Its detail must not escape as a client error.
            raise StorageIntegrityError("Stored data is unavailable.") from None

    def _load_inputs(
        self, session: Session, patch_id: UUID, request: SourceEvidenceRequest
    ) -> _SelectedInputs:
        # Reuse integrity-checked readers in this session. History needs neither retained raw
        # sources nor model artifacts, reference snapshots, a policy catalog or an engine.
        parent = session.get(PatchRow, str(patch_id))
        if parent is None:
            raise SourceEvidenceInputNotFound("Selected patch draft is unavailable.")
        draft = PatchRecords(self.store)._draft(session, parent)
        deterministic_records = SourceDeterministicRecords(self.store)._get(
            session, request.deterministic.record_id
        )
        if deterministic_records is None:
            raise SourceEvidenceInputNotFound("Selected deterministic result is unavailable.")
        deterministic = SourceDeterministicRecheck.from_records(*deterministic_records)
        forest = None
        if request.forest is not None:
            forest_records = SourceForestRecords(self.store)._get(session, request.forest.record_id)
            if forest_records is None:
                raise SourceEvidenceInputNotFound("Selected statistical result is unavailable.")
            forest = SourceForestRecheck.from_records(*forest_records)
        neural = None
        if request.neural is not None:
            neural_records = SourceMlRecords(self.store)._get(session, request.neural.record_id)
            if neural_records is None:
                raise SourceEvidenceInputNotFound("Selected neural result is unavailable.")
            neural = SourceMlRecheck.from_records(*neural_records)
        network = None
        if request.network is not None:
            network_records = SourcePatchRecords(self.store)._get(
                session, request.network.record_id
            )
            if network_records is None:
                raise SourceEvidenceInputNotFound("Selected network result is unavailable.")
            selected_network = source_patch_view(*network_records)
            if (
                isinstance(selected_network, SourcePatchVerificationV3)
                and not isinstance(request, CreateSourceEvidenceReportV3)
            ) or (
                not isinstance(
                    request, (CreateSourceEvidenceReportV2, CreateSourceEvidenceReportV3)
                )
                and not isinstance(selected_network, SourcePatchVerification)
            ):
                raise PatchConflict("Selected network result requires a newer report protocol.")
            network = selected_network
        # Admission is on the complete selected DTOs, including their proof strings, before
        # constructing a joint proof or inserting anything. Do not truncate selected evidence.
        size = 0
        for record in (deterministic, forest, neural, network):
            if record is not None:
                size += len(record.model_dump_json(warnings=False).encode("utf-8"))
                if size > MAX_SOURCE_EVIDENCE_INPUT_BYTES:
                    raise SourceEvidenceTooLarge("Selected evidence exceeds the report budget.")
        return _SelectedInputs(draft, deterministic, forest, neural, network)

    def prepare(self, patch_id: UUID, request: SourceEvidenceRequest) -> SourceEvidenceReportRecord:
        request = parse_source_evidence_request(request)
        with self.store._sessions() as session:
            inputs = self._inputs(session, patch_id, request)
            try:
                report = source_evidence_report(
                    inputs.draft,
                    request,
                    inputs.deterministic,
                    forest=inputs.forest,
                    neural=inputs.neural,
                    network=inputs.network,
                    created_at=datetime.now(UTC),
                )
            except SourceEvidenceProjectionTooLarge:
                raise SourceEvidenceTooLarge(
                    "Selected evidence report exceeds the proof budget."
                ) from None
            except ValueError:
                raise PatchConflict("Selected evidence bindings conflict.") from None
            self._payload(report)
            return report

    @staticmethod
    def _payload(report: SourceEvidenceReportRecord) -> str:
        if (
            len(report.review_json.encode("utf-8"))
            > source_evidence_contracts.MAX_SOURCE_EVIDENCE_BYTES
        ):
            raise SourceEvidenceTooLarge("Selected evidence report exceeds the proof budget.")
        raw = report.model_dump_json(warnings=False)
        if len(raw.encode("utf-8")) > MAX_SOURCE_EVIDENCE_BYTES:
            raise SourceEvidenceTooLarge("Selected evidence report exceeds the payload budget.")
        return raw

    def _report(self, session: Session, row: SourceEvidenceReportRow) -> SourceEvidenceReportRecord:
        try:
            if len(row.payload) > MAX_SOURCE_EVIDENCE_CIPHERTEXT_BYTES:
                raise ValueError("oversized evidence ciphertext")
            raw = self.store._decode(row.payload, kind="source_evidence_report", row_id=row.id)
            if len(raw.encode("utf-8")) > MAX_SOURCE_EVIDENCE_BYTES:
                raise ValueError("oversized evidence report")
            report = parse_source_evidence_report_json(raw)
            stamp = row.created_at if row.created_at.tzinfo else row.created_at.replace(tzinfo=UTC)
            if (str(report.report_id), str(report.patch_id), report.created_at) != (
                row.id,
                row.patch_id,
                stamp,
            ):
                raise ValueError("evidence metadata differs")
            inputs = self._inputs(session, report.patch_id, report.request)
            validate_source_evidence_report(
                report,
                inputs.draft,
                inputs.deterministic,
                forest=inputs.forest,
                neural=inputs.neural,
                network=inputs.network,
            )
            return report
        except ValueError:
            raise StorageIntegrityError("Stored data is unavailable.") from None

    def _get(self, session: Session, report_id: UUID) -> SourceEvidenceReportRecord | None:
        row = session.get(SourceEvidenceReportRow, str(report_id))
        return self._report(session, row) if row is not None else None

    def get(self, report_id: UUID) -> SourceEvidenceReportRecord | None:
        with self.store._sessions() as session:
            return self._get(session, report_id)

    @staticmethod
    def _same(stored: SourceEvidenceReportRecord, incoming: SourceEvidenceReportRecord) -> None:
        if stored.patch_id != incoming.patch_id or stored.request != incoming.request:
            raise PatchConflict("Evidence report identity conflicts.")

    @staticmethod
    def _audit(session: Session, key: str) -> None:
        session.add(
            AuditRow(
                id=str(uuid4()),
                action="patch.evidence_report_created",
                resource_id=key,
                created_at=datetime.now(UTC),
            )
        )

    def add(self, report: SourceEvidenceReportRecord) -> tuple[SourceEvidenceReportRecord, bool]:
        raw = self._payload(report)
        report = parse_source_evidence_report_json(raw)
        key = str(report.report_id)
        try:
            with self.store._sessions.begin() as session:
                existing = self._get(session, report.report_id)
                if existing is not None:
                    self._same(existing, report)
                    return existing, False
                # Re-read all selected bindings inside the insertion transaction, so a caller
                # cannot insert an unchecked projection by bypassing prepare().
                inputs = self._inputs(session, report.patch_id, report.request)
                try:
                    validate_source_evidence_report(
                        report,
                        inputs.draft,
                        inputs.deterministic,
                        forest=inputs.forest,
                        neural=inputs.neural,
                        network=inputs.network,
                    )
                except SourceEvidenceProjectionTooLarge:
                    raise SourceEvidenceTooLarge(
                        "Selected evidence report exceeds the proof budget."
                    ) from None
                except ValueError:
                    raise PatchConflict("Selected evidence bindings conflict.") from None
                payload = self.store._encode(raw, kind="source_evidence_report", row_id=key)
                if len(payload) > MAX_SOURCE_EVIDENCE_CIPHERTEXT_BYTES:
                    raise SourceEvidenceTooLarge(
                        "Selected evidence report exceeds the storage budget."
                    )
                session.add(
                    SourceEvidenceReportRow(
                        id=key,
                        patch_id=str(report.patch_id),
                        created_at=report.created_at.astimezone(UTC),
                        payload=payload,
                    )
                )
                self._audit(session, key)
            return report, True
        except IntegrityError:
            raced = self.get(report.report_id)
            if raced is None:
                raise
            self._same(raced, report)
            return raced, False

    def list_ids(self, patch_id: UUID, *, limit: int, offset: int) -> list[UUID]:
        query = (
            select(SourceEvidenceReportRow.id)
            .where(SourceEvidenceReportRow.patch_id == str(patch_id))
            .order_by(SourceEvidenceReportRow.created_at.desc(), SourceEvidenceReportRow.id.desc())
        )
        with self.store._sessions() as session:
            return [UUID(key) for key in session.scalars(query.limit(limit).offset(offset))]
