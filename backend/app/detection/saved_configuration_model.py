"""One consented, source-bound inference on an already saved analysis."""

from datetime import UTC, datetime
from uuid import UUID

from app.api.configuration_model_contracts import (
    ConfigurationModelIntent,
    ConfigurationModelOutcome,
    ConfigurationModelRun,
    RunConfigurationModel,
    fingerprint,
)
from app.api.contracts import SnapshotBinding
from app.api.service import AnalysisService
from app.db.configuration_model_records import ConfigurationModelConflict, ConfigurationModelRecords
from app.db.source_records import OriginalSourceUnavailable, SourceRecords
from app.detection.config_model_contracts import require_complete
from app.detection.config_model_runtime import (
    ConfigurationModelDisabled,
    ConfigurationModelRuntime,
    ConfigurationModelUnavailable,
)
from app.ingestion.source_retention import prepare_original_source


class SavedConfigurationModelNotFound(Exception):
    pass


class SavedConfigurationModelFailed(Exception):
    pass


class SavedConfigurationModelWorkflow:
    def __init__(self, service: AnalysisService) -> None:
        self.service = service
        self.records = ConfigurationModelRecords(service.store)

    def get(self, inference_id: UUID) -> ConfigurationModelRun:
        saved = self.records.get(inference_id)
        if saved is None:
            raise SavedConfigurationModelNotFound()
        return ConfigurationModelRun.from_records(*saved)

    def run(
        self, options: RunConfigurationModel, runtime: ConfigurationModelRuntime
    ) -> tuple[ConfigurationModelRun, bool]:
        options = RunConfigurationModel.model_validate_json(options.model_dump_json())
        if options.allow_local_model_context is not True:
            raise ConfigurationModelConflict("Explicit local model context consent required.")
        saved = self.records.get(options.inference_id)
        if saved is not None:
            if saved[0].request != options:
                raise ConfigurationModelConflict("Configuration model identity conflicts.")
            return ConfigurationModelRun.from_records(*saved), False
        if runtime.settings.registry_root is None:
            raise ConfigurationModelDisabled()
        if runtime.settings.model_sha256 != options.model_sha256:
            raise ConfigurationModelConflict("Operator model pin differs.")
        with runtime.selected_worker():
            analysis = self.service.store.get_analysis(options.analysis_id)
            if analysis is None:
                raise SavedConfigurationModelNotFound()
            if analysis.source_sha256 != options.source_sha256:
                raise ConfigurationModelConflict("Selected source pin differs.")
            snapshot = self.service.store.get_configuration(analysis.configuration_id)
            if snapshot is None:
                raise SavedConfigurationModelNotFound()
            try:
                require_complete(snapshot)
            except ValueError:
                raise ConfigurationModelConflict("Complete parsing required.") from None
            source = SourceRecords(self.service.store).get(
                analysis.configuration_id,
                expected_source_sha256=options.source_sha256,
                allow_local_read=True,
            )
            try:
                if prepare_original_source(snapshot, source.content) != source:
                    raise ValueError("original source differs")
            except ValueError:
                raise OriginalSourceUnavailable() from None
            intent = ConfigurationModelIntent(
                request=options,
                source=SnapshotBinding.from_snapshot(snapshot),
                analysis_sha256=fingerprint(analysis),
                total_lines=len(source.content.splitlines()),
                created_at=datetime.now(UTC),
            )
            if not self.records.reserve(intent):
                return self.get(options.inference_id), False
            try:
                report = runtime.infer(snapshot, source, options.model_sha256)
                outcome = ConfigurationModelOutcome(
                    inference_id=options.inference_id,
                    intent_sha256=fingerprint(intent),
                    completed_at=datetime.now(UTC),
                    status="completed",
                    report=report,
                )
                result = ConfigurationModelRun.from_records(intent, outcome)
            except (ConfigurationModelUnavailable, ConfigurationModelDisabled, ValueError):
                self.records.complete(
                    ConfigurationModelOutcome(
                        inference_id=options.inference_id,
                        intent_sha256=fingerprint(intent),
                        completed_at=datetime.now(UTC),
                        status="failed",
                    )
                )
                raise SavedConfigurationModelFailed() from None
            self.records.complete(outcome)
            return result, True
