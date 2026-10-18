"""Explicit paired ML diagnostics on an ordinary saved draft's exact originals."""

from datetime import UTC, datetime
from uuid import UUID

from app.api.contracts import ConfigurationSnapshot, SnapshotBinding
from app.api.source_ml_contracts import (
    MAX_SOURCE_ML_BYTES,
    RunSourceMlRecheck,
    SourceMlIntent,
    SourceMlMember,
    SourceMlOutcome,
    SourceMlRecheck,
    ml_json,
    source_ml_fingerprint,
)
from app.db.patch_records import PatchConflict
from app.db.source_ml_records import SourceMlRecords
from app.db.source_records import OriginalSourceUnavailable, SourceRecords
from app.db.store import Store
from app.detection.config_model_contracts import require_complete
from app.detection.config_model_runtime import ConfigurationModelDisabled, ConfigurationModelRuntime
from app.detection.config_pair_contracts import MAX_PAIR_RESULT_BYTES
from app.detection.config_pair_runtime import (
    ConfigurationPairTooLarge,
    prepare_configuration_pair_job,
    run_configuration_pair_job,
)
from app.ingestion.source_retention import StoredOriginalSource, prepare_original_source
from app.patching.persistent import PatchNotFound, PatchWorkflow
from ml.inference.pair_contracts import ConfigurationPairReport


class SourceMlConsentRequired(Exception):
    pass


class SourceMlWorkflow:
    def __init__(self, store: Store) -> None:
        self.store = store
        self.drafts = PatchWorkflow(store)
        self.records = SourceMlRecords(store)

    @staticmethod
    def _view(pair: tuple[SourceMlIntent, SourceMlOutcome | None]) -> SourceMlRecheck:
        view = SourceMlRecheck.from_records(*pair)
        if len(view.model_dump_json().encode()) > MAX_SOURCE_ML_BYTES * 4:
            raise ConfigurationPairTooLarge()
        return view

    def get(self, patch_id: UUID, recheck_id: UUID) -> SourceMlRecheck:
        pair = self.records.get(recheck_id)
        if pair is None or pair[0].patch_id != patch_id:
            raise PatchNotFound()
        return self._view(pair)

    def _source(
        self, snapshot: ConfigurationSnapshot
    ) -> tuple[SourceMlMember, StoredOriginalSource]:
        require_complete(snapshot)
        source = SourceRecords(self.store).get(
            snapshot.configuration_id,
            expected_source_sha256=snapshot.canonical.source.sha256,
            allow_local_read=True,
        )
        if prepare_original_source(snapshot, source.content) != source:
            raise ValueError("retained source differs")
        return SourceMlMember.model_validate(
            SnapshotBinding.from_snapshot(snapshot).model_dump()
            | {
                "canonical_sha256": source.canonical_sha256,
                "total_lines": len(source.content.splitlines()),
            }
        ), source

    def run(
        self, patch_id: UUID, options: RunSourceMlRecheck, runtime: ConfigurationModelRuntime
    ) -> tuple[SourceMlRecheck, bool]:
        options = RunSourceMlRecheck.model_validate(options.model_dump(warnings=False))
        existing = self.records.get(options.recheck_id)
        if existing is not None:
            if existing[0].patch_id != patch_id or existing[0].request != options:
                raise PatchConflict("ML recheck identity conflicts.")
            return self._view(existing), False
        if not options.allow_local_model_context:
            raise SourceMlConsentRequired()
        settings = runtime.settings
        if settings.registry_root is None:
            raise ConfigurationModelDisabled()
        if settings.model_sha256 != options.model_sha256:
            raise PatchConflict("Selected operator model pin differs.")
        with runtime.selected_worker():
            draft = self.drafts.draft(patch_id)
            if draft.draft_sha256 != options.draft_sha256:
                raise PatchConflict("Selected draft differs.")
            before = self.store.get_configuration(draft.diff.before.configuration_id)
            after = self.store.get_configuration(draft.diff.after.configuration_id)
            if before is None or after is None:
                raise PatchNotFound()
            try:
                old, old_source = self._source(before)
                new, new_source = self._source(after)
                job = prepare_configuration_pair_job(
                    settings, before, after, old_source, new_source, options.model_sha256
                )
                intent = SourceMlIntent(
                    patch_id=patch_id,
                    request=options,
                    before=old,
                    after=new,
                    created_at=datetime.now(UTC),
                )
            except (OriginalSourceUnavailable, ValueError):
                raise PatchConflict(
                    "Selected retained source pair differs or parsing is partial."
                ) from None
            # Both the private job and the worst allowed completion fit before reservation.
            if len(ml_json(intent.model_dump(mode="json")).encode()) > (
                MAX_SOURCE_ML_BYTES - MAX_PAIR_RESULT_BYTES - 8192
            ):
                raise ConfigurationPairTooLarge()
            self._view((intent, None))
            if not self.records.reserve(intent):
                return self.get(patch_id, options.recheck_id), False
            try:
                report = run_configuration_pair_job(settings, job)
                report = ConfigurationPairReport.model_validate(report.model_dump(warnings=False))
                if len(ml_json(report.model_dump(mode="json")).encode()) > MAX_PAIR_RESULT_BYTES:
                    raise ValueError("oversized canonical paired result")
                outcome = SourceMlOutcome(
                    recheck_id=options.recheck_id,
                    intent_sha256=source_ml_fingerprint(intent),
                    completed_at=datetime.now(UTC),
                    execution_status="completed",
                    report=report,
                )
                self._view((intent, outcome))
            except Exception:
                outcome = SourceMlOutcome(
                    recheck_id=options.recheck_id,
                    intent_sha256=source_ml_fingerprint(intent),
                    completed_at=datetime.now(UTC),
                    execution_status="failed",
                    report=None,
                    failure_reason="worker_failed_or_unavailable",
                )
            self.records.complete(outcome)
            return self._view((intent, outcome)), True
