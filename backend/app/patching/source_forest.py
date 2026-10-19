"""Explicit original statistical model -> separately saved ordinary source-pair attempt."""

from datetime import UTC, datetime
from uuid import UUID

from app.api.contracts import ConfigurationSnapshot, SnapshotBinding
from app.api.model_patch_contracts import fingerprint
from app.api.source_forest_contracts import (
    MAX_SOURCE_FOREST_BYTES,
    RunSourceForestRecheck,
    SourceForestIntent,
    SourceForestMember,
    SourceForestOutcome,
    SourceForestRecheck,
    SourceForestReport,
    SourceForestSelection,
)
from app.api.source_ml_contracts import ml_json, source_ml_fingerprint
from app.db.patch_records import PatchConflict
from app.db.source_forest_records import SourceForestRecords
from app.db.source_records import OriginalSourceUnavailable, SourceRecords
from app.db.store import Store
from app.detection.statistical.pair import recheck_original_forest, require_forest_target
from app.ingestion.source_retention import StoredOriginalSource, prepare_original_source
from app.patching.persistent import PatchNotFound, PatchWorkflow

MAX_FOREST_INPUT_BYTES = 32 * 1024 * 1024
MAX_FOREST_REPORT_BYTES = 1024 * 1024


class SourceForestConsentRequired(Exception):
    pass


class SourceForestTooLarge(Exception):
    pass


class SourceForestWorkflow:
    def __init__(self, store: Store) -> None:
        self.store = store
        self.drafts = PatchWorkflow(store)
        self.records = SourceForestRecords(store)

    @staticmethod
    def _view(pair: tuple[SourceForestIntent, SourceForestOutcome | None]) -> SourceForestRecheck:
        view = SourceForestRecheck.from_records(*pair)
        if len(view.model_dump_json().encode()) > MAX_SOURCE_FOREST_BYTES * 4:
            raise SourceForestTooLarge()
        return view

    def get(self, patch_id: UUID, recheck_id: UUID) -> SourceForestRecheck:
        saved = self.records.get(recheck_id)
        if saved is None or saved[0].patch_id != patch_id:
            raise PatchNotFound()
        return self._view(saved)

    def selection(self, patch_id: UUID, analysis_id: UUID) -> SourceForestSelection:
        draft = self.drafts.draft(patch_id)
        analysis = self.store.get_analysis(analysis_id)
        if analysis is None:
            raise PatchNotFound()
        before = draft.diff.before
        if analysis.statistical is None or (
            analysis.configuration_id,
            analysis.device_id,
            analysis.source_sha256,
        ) != (before.configuration_id, before.device_id, before.source_sha256):
            raise PatchConflict("Selected original statistical analysis differs.")
        return SourceForestSelection(
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
            original=analysis.statistical,
        )

    def _source(
        self, snapshot: ConfigurationSnapshot
    ) -> tuple[SourceForestMember, StoredOriginalSource]:
        source = SourceRecords(self.store).get(
            snapshot.configuration_id,
            expected_source_sha256=snapshot.canonical.source.sha256,
            allow_local_read=True,
        )
        if prepare_original_source(snapshot, source.content) != source:
            raise ValueError("retained statistical source differs")
        member = SourceForestMember.model_validate(
            SnapshotBinding.from_snapshot(snapshot).model_dump()
            | {"canonical_sha256": source.canonical_sha256}
        )
        return member, source

    def run(
        self, patch_id: UUID, options: RunSourceForestRecheck
    ) -> tuple[SourceForestRecheck, bool]:
        options = RunSourceForestRecheck.model_validate(options.model_dump(warnings=False))
        existing = self.records.get(options.recheck_id)
        if existing is not None:
            if existing[0].patch_id != patch_id or existing[0].request != options:
                raise PatchConflict("Original statistical recheck identity conflicts.")
            return self._view(existing), False
        if not options.allow_local_model_context:
            raise SourceForestConsentRequired()
        selected = self.selection(patch_id, options.before_analysis_id)
        if (
            options.draft_sha256 != selected.draft_sha256
            or options.before_analysis_sha256 != selected.before_analysis_sha256
            or options.model_id != selected.original.model.model_id
            or options.artifact_sha256 != selected.original.model.artifact_sha256
        ):
            raise PatchConflict("Original statistical model or analysis pin differs.")
        registered = self.store.get_model(options.model_id)
        if registered is None or registered.summary != selected.original.model:
            raise PatchConflict("Original statistical model is unavailable or differs.")
        draft = self.drafts.draft(patch_id)
        before = self.store.get_configuration(draft.diff.before.configuration_id)
        after = self.store.get_configuration(draft.diff.after.configuration_id)
        analysis = self.store.get_analysis(options.before_analysis_id)
        if before is None or after is None or analysis is None:
            raise PatchNotFound()
        try:
            require_forest_target(before, registered.summary)
            require_forest_target(after, registered.summary)
            old, old_source = self._source(before)
            new, new_source = self._source(after)
            if (
                len(
                    ml_json(
                        [snapshot.model_dump(mode="json") for snapshot in (before, after)]
                        + [source.model_dump(mode="json") for source in (old_source, new_source)]
                    ).encode()
                )
                > MAX_FOREST_INPUT_BYTES
            ):
                raise SourceForestTooLarge()
            intent = SourceForestIntent(
                patch_id=patch_id,
                request=options,
                before=old,
                after=new,
                selection=selected,
                created_at=datetime.now(UTC),
            )
        except (OriginalSourceUnavailable, ValueError):
            raise PatchConflict(
                "Selected original statistical source pair is unavailable or differs."
            ) from None
        if (
            len(ml_json(intent.model_dump(mode="json")).encode())
            > MAX_SOURCE_FOREST_BYTES - MAX_FOREST_REPORT_BYTES - 8192
        ):
            raise SourceForestTooLarge()
        self._view((intent, None))
        if not self.records.reserve(intent):
            return self.get(patch_id, options.recheck_id), False
        try:
            scores = recheck_original_forest(before, after, analysis, registered)
            report = SourceForestReport(model=registered.summary, scores=scores)
            if len(ml_json(report.model_dump(mode="json")).encode()) > MAX_FOREST_REPORT_BYTES:
                raise ValueError("oversized numeric Forest result")
            outcome = SourceForestOutcome(
                recheck_id=options.recheck_id,
                intent_sha256=source_ml_fingerprint(intent),
                completed_at=datetime.now(UTC),
                execution_status="completed",
                report=report,
            )
            self._view((intent, outcome))
        except Exception:
            outcome = SourceForestOutcome(
                recheck_id=options.recheck_id,
                intent_sha256=source_ml_fingerprint(intent),
                completed_at=datetime.now(UTC),
                execution_status="failed",
                report=None,
                failure_reason="original_baseline_or_numeric_result_unavailable",
            )
        self.records.complete(outcome)
        return self._view((intent, outcome)), True
