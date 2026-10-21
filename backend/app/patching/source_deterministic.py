"""Explicit original policy/reference/peer context on a retained ordinary source pair."""

from datetime import UTC, datetime
from uuid import UUID

from app.api.contracts import ConfigurationSnapshot, SnapshotBinding
from app.api.model_patch_contracts import fingerprint
from app.api.source_deterministic_contracts import (
    MAX_SOURCE_DETERMINISTIC_BYTES,
    OriginalDeterministicContext,
    RunSourceDeterministicRecheck,
    SourceDeterministicIntent,
    SourceDeterministicMember,
    SourceDeterministicOutcome,
    SourceDeterministicRecheck,
    SourceDeterministicReport,
    SourceDeterministicSelection,
)
from app.api.source_ml_contracts import ml_json, source_ml_fingerprint
from app.db.patch_records import PatchConflict
from app.db.source_deterministic_records import SourceDeterministicRecords
from app.db.source_records import OriginalSourceUnavailable, SourceRecords
from app.db.store import Store
from app.detection.baseline.pair import (
    prepare_original_reference,
    recheck_original_deterministic,
    require_original_deterministic_context,
)
from app.detection.config_model_contracts import require_complete
from app.ingestion.source_retention import (
    StoredOriginalSource,
    canonical_fingerprint,
    prepare_original_source,
)
from app.patching.persistent import PatchNotFound, PatchWorkflow

MAX_DETERMINISTIC_INPUT_BYTES = 32 * 1024 * 1024
MAX_DETERMINISTIC_REPORT_BYTES = 2 * 1024 * 1024


class SourceDeterministicConsentRequired(Exception):
    pass


class SourceDeterministicTooLarge(Exception):
    pass


class SourceDeterministicWorkflow:
    def __init__(self, store: Store) -> None:
        self.store = store
        self.drafts = PatchWorkflow(store)
        self.records = SourceDeterministicRecords(store)

    @staticmethod
    def _view(
        pair: tuple[SourceDeterministicIntent, SourceDeterministicOutcome | None],
    ) -> SourceDeterministicRecheck:
        view = SourceDeterministicRecheck.from_records(*pair)
        if len(view.model_dump_json().encode()) > MAX_SOURCE_DETERMINISTIC_BYTES * 4:
            raise SourceDeterministicTooLarge()
        return view

    def get(self, patch_id: UUID, recheck_id: UUID) -> SourceDeterministicRecheck:
        saved = self.records.get(recheck_id)
        if saved is None or saved[0].patch_id != patch_id:
            raise PatchNotFound()
        return self._view(saved)

    def selection(self, patch_id: UUID, analysis_id: UUID) -> SourceDeterministicSelection:
        draft = self.drafts.draft(patch_id)
        analysis = self.store.get_analysis(analysis_id)
        if analysis is None:
            raise PatchNotFound()
        before = draft.diff.before
        if (
            analysis.configuration_id,
            analysis.device_id,
            analysis.source_sha256,
        ) != (before.configuration_id, before.device_id, before.source_sha256):
            raise PatchConflict("Selected original deterministic analysis differs.")
        reference = None
        if analysis.comparison is not None and analysis.comparison.reference is not None:
            selected = analysis.comparison.reference
            snapshot = self.store.get_configuration(selected.configuration_id)
            if snapshot is None:
                raise PatchNotFound()
            if SnapshotBinding.from_snapshot(snapshot) != selected:
                raise PatchConflict("Original reference binding differs.")
            reference = SourceDeterministicMember.model_validate(
                selected.model_dump() | {"canonical_sha256": canonical_fingerprint(snapshot)}
            )
        return SourceDeterministicSelection(
            patch_id=patch_id,
            draft_sha256=draft.draft_sha256,
            before=SnapshotBinding(
                configuration_id=before.configuration_id,
                device_id=before.device_id,
                source_sha256=before.source_sha256,
                created_at=before.created_at,
            ),
            before_analysis_id=analysis_id,
            before_analysis_sha256=fingerprint(analysis),
            before_analysis_created_at=analysis.created_at,
            original=OriginalDeterministicContext.from_analysis(analysis),
            reference=reference,
        )

    def _source(
        self, snapshot: ConfigurationSnapshot
    ) -> tuple[SourceDeterministicMember, StoredOriginalSource]:
        require_complete(snapshot)
        source = SourceRecords(self.store).get(
            snapshot.configuration_id,
            expected_source_sha256=snapshot.canonical.source.sha256,
            allow_local_read=True,
        )
        if prepare_original_source(snapshot, source.content) != source:
            raise ValueError("retained deterministic source differs")
        member = SourceDeterministicMember.model_validate(
            SnapshotBinding.from_snapshot(snapshot).model_dump()
            | {"canonical_sha256": source.canonical_sha256}
        )
        return member, source

    def run(
        self, patch_id: UUID, options: RunSourceDeterministicRecheck
    ) -> tuple[SourceDeterministicRecheck, bool]:
        options = RunSourceDeterministicRecheck.model_validate(options.model_dump(warnings=False))
        existing = self.records.get(options.recheck_id)
        if existing is not None:
            if existing[0].patch_id != patch_id or existing[0].request != options:
                raise PatchConflict("Original deterministic recheck identity conflicts.")
            return self._view(existing), False
        if not options.allow_local_analysis_context:
            raise SourceDeterministicConsentRequired()
        selected = self.selection(patch_id, options.before_analysis_id)
        if (
            options.draft_sha256 != selected.draft_sha256
            or options.before_analysis_sha256 != selected.before_analysis_sha256
            or options.reference_canonical_sha256
            != (selected.reference.canonical_sha256 if selected.reference else None)
        ):
            raise PatchConflict("Original deterministic analysis or reference pin differs.")
        draft = self.drafts.draft(patch_id)
        before = self.store.get_configuration(draft.diff.before.configuration_id)
        after = self.store.get_configuration(draft.diff.after.configuration_id)
        analysis = self.store.get_analysis(options.before_analysis_id)
        reference = (
            self.store.get_configuration(selected.reference.configuration_id)
            if selected.reference is not None
            else None
        )
        if before is None or after is None or analysis is None:
            raise PatchNotFound()
        if selected.reference is not None and reference is None:
            raise PatchNotFound()
        try:
            require_original_deterministic_context(analysis)
            old, old_source = self._source(before)
            new, new_source = self._source(after)
            projection = prepare_original_reference(before, analysis, reference)
            if reference is not None and (
                selected.reference is None
                or canonical_fingerprint(reference) != selected.reference.canonical_sha256
            ):
                raise ValueError("original reference canonical binding differs")
            if (
                len(
                    ml_json(
                        [snapshot.model_dump(mode="json") for snapshot in (before, after)]
                        + [source.model_dump(mode="json") for source in (old_source, new_source)]
                        + ([reference.model_dump(mode="json")] if reference is not None else [])
                    ).encode()
                )
                > MAX_DETERMINISTIC_INPUT_BYTES
            ):
                raise SourceDeterministicTooLarge()
            intent = SourceDeterministicIntent(
                patch_id=patch_id,
                request=options,
                before=old,
                after=new,
                selection=selected,
                reference_projection=projection,
                created_at=datetime.now(UTC),
            )
        except (OriginalSourceUnavailable, ValueError):
            raise PatchConflict(
                "Selected original deterministic source pair or context is unavailable or differs."
            ) from None
        if len(ml_json(intent.model_dump(mode="json")).encode()) > (
            MAX_SOURCE_DETERMINISTIC_BYTES - MAX_DETERMINISTIC_REPORT_BYTES - 8192
        ):
            raise SourceDeterministicTooLarge()
        self._view((intent, None))
        if not self.records.reserve(intent):
            return self.get(patch_id, options.recheck_id), False
        try:
            pair = recheck_original_deterministic(before, after, analysis, reference)
            report = SourceDeterministicReport.from_pair(intent, pair)
            if len(ml_json(report.model_dump(mode="json")).encode()) > (
                MAX_DETERMINISTIC_REPORT_BYTES
            ):
                raise ValueError("oversized deterministic result")
            outcome = SourceDeterministicOutcome(
                recheck_id=options.recheck_id,
                intent_sha256=source_ml_fingerprint(intent),
                completed_at=datetime.now(UTC),
                execution_status="completed",
                report=report,
            )
            self._view((intent, outcome))
        except Exception:
            outcome = SourceDeterministicOutcome(
                recheck_id=options.recheck_id,
                intent_sha256=source_ml_fingerprint(intent),
                completed_at=datetime.now(UTC),
                execution_status="failed",
                report=None,
                failure_reason="original_context_or_deterministic_result_unavailable",
            )
        self.records.complete(outcome)
        return self._view((intent, outcome)), True
