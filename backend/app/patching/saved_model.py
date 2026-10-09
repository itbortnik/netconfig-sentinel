"""Saved selected finding + exact retained original -> one durable model attempt."""

import json
from datetime import UTC, datetime
from uuid import UUID

from app.api.contracts import SnapshotBinding
from app.api.model_patch_contracts import (
    GenerateModelPatch,
    ModelPatchIntent,
    ModelPatchOutcome,
    ModelPatchProposal,
    fingerprint,
)
from app.api.service import AnalysisService, FeedbackTargetNotFound
from app.audit.contracts import metadata_hash
from app.db.model_patch_records import ModelPatchConflict, ModelPatchRecords
from app.db.source_records import OriginalSourceUnavailable, SourceRecords
from app.db.store import StorageIntegrityError
from app.domain.fingerprints import finding_fingerprint
from app.explanation.knowledge import text_sha256
from app.explanation.local_model import LocalModelRuntime, ModelPatchDisabled
from app.explanation.patch_provider import (
    PreparedPatchPrompt,
    build_patch_prompt,
    generate_patch_draft,
    validate_patch_answer,
)
from app.explanation.provider import InvalidProviderAnswer


class SavedModelPatchNotFound(Exception):
    pass


class SavedModelPatchUnavailable(ValueError):
    pass


class SavedModelPatchGenerationFailed(Exception):
    pass


class SavedModelPatchWorkflow:
    def __init__(self, service: AnalysisService) -> None:
        self.service = service
        self.records = ModelPatchRecords(service.store)

    def prepare(
        self, options: GenerateModelPatch
    ) -> tuple[PreparedPatchPrompt, SnapshotBinding, SnapshotBinding | None]:
        """No reconstruction from IR; consent and independent pins precede the read."""
        if options.allow_local_model_context is not True:
            raise SavedModelPatchUnavailable("Explicit local model context permission is required.")
        try:
            analysis, finding = self.service.feedback_target(
                options.analysis_id, options.finding_id
            )
        except FeedbackTargetNotFound:
            raise SavedModelPatchNotFound() from None
        if (
            finding_fingerprint(finding) != options.finding_sha256
            or analysis.source_sha256 != options.source_sha256
        ):
            raise ModelPatchConflict("Model patch selected facts conflict.")
        try:
            source = SourceRecords(self.service.store).get(
                analysis.configuration_id,
                expected_source_sha256=options.source_sha256,
                allow_local_read=True,
            )
            if (
                source.snapshot.device_id != analysis.device_id
                or finding.device_id != analysis.device_id
            ):
                raise StorageIntegrityError("Stored data is unavailable.")
            baseline = None
            if options.baseline_configuration_id is not None:
                if options.baseline_source_sha256 is None:
                    raise ValueError("missing baseline pin")
                baseline = SourceRecords(self.service.store).get(
                    options.baseline_configuration_id,
                    expected_source_sha256=options.baseline_source_sha256,
                    allow_local_read=True,
                )
                if (
                    baseline.snapshot.device_id != source.snapshot.device_id
                    or baseline.snapshot.configuration_id == source.snapshot.configuration_id
                    or baseline.snapshot.created_at > source.snapshot.created_at
                ):
                    raise ValueError("baseline selection differs")
            prepared = build_patch_prompt(
                source.content,
                finding=finding,
                source_sha256=options.source_sha256,
                reference_id=str(source.snapshot.configuration_id),
                allow_local_context=True,
                baseline=baseline.content if baseline else None,
            )
            return prepared, source.snapshot, baseline.snapshot if baseline else None
        except (ValueError, OriginalSourceUnavailable):
            raise SavedModelPatchUnavailable(
                "Exact retained source or supported patch context is unavailable."
            ) from None

    def _validated(
        self, intent: ModelPatchIntent, outcome: ModelPatchOutcome | None
    ) -> ModelPatchProposal:
        try:
            prepared, source, baseline = self.prepare(intent.request)
            context = json.loads(prepared.prompt.context_json)
            if (
                source != intent.source
                or baseline != intent.baseline
                or prepared.prompt.context_sha256 != intent.context_sha256
                or context["knowledge_version"] != intent.knowledge_version
                or context["knowledge_sha256"] != intent.knowledge_sha256
            ):
                raise ValueError("stored prompt binding differs")
            if outcome is not None and outcome.answer is not None:
                checked = validate_patch_answer(outcome.answer.model_dump_json().encode(), prepared)
                candidate_hash = (
                    text_sha256(checked.candidate_text)
                    if checked.candidate_text is not None
                    else None
                )
                if candidate_hash != outcome.candidate_sha256:
                    raise ValueError("stored candidate binding differs")
            return ModelPatchProposal.from_records(intent, outcome)
        except (ValueError, SavedModelPatchNotFound, InvalidProviderAnswer):
            raise StorageIntegrityError("Stored data is unavailable.") from None

    def get(self, patch_id: UUID) -> ModelPatchProposal:
        saved = self.records.get(patch_id)
        if saved is None:
            raise SavedModelPatchNotFound()
        return self._validated(*saved)

    def generate(
        self, options: GenerateModelPatch, runtime: LocalModelRuntime | None
    ) -> tuple[ModelPatchProposal, bool]:
        options = GenerateModelPatch.model_validate_json(options.model_dump_json())
        if options.allow_local_model_context is not True:
            raise SavedModelPatchUnavailable("Explicit local model context permission is required.")
        saved = self.records.get(options.patch_id)
        if saved is not None:
            if saved[0].request != options:
                raise ModelPatchConflict("Model patch identity conflicts.")
            return self._validated(*saved), False
        if runtime is None:
            raise ModelPatchDisabled()
        with runtime.patch_provider() as provider:
            prepared, source, baseline = self.prepare(options)
            context = json.loads(prepared.prompt.context_json)
            intent = ModelPatchIntent(
                request=options,
                source=source,
                baseline=baseline,
                created_at=datetime.now(UTC),
                context_sha256=prepared.prompt.context_sha256,
                knowledge_version=context["knowledge_version"],
                knowledge_sha256=context["knowledge_sha256"],
                model_alias_sha256=metadata_hash(runtime.settings.model),
            )
            if not self.records.reserve(intent):
                # Another worker reserved this ID. Never run an additional provider call.
                return self.get(options.patch_id), False
            try:
                generated = generate_patch_draft(provider, prepared, allow_local_context=True)
            except InvalidProviderAnswer:
                self.records.complete(
                    ModelPatchOutcome(
                        patch_id=options.patch_id,
                        intent_sha256=fingerprint(intent),
                        completed_at=datetime.now(UTC),
                        status="failed",
                    )
                )
                raise SavedModelPatchGenerationFailed() from None
            outcome = ModelPatchOutcome(
                patch_id=options.patch_id,
                intent_sha256=fingerprint(intent),
                completed_at=datetime.now(UTC),
                status="draft" if generated.candidate_text is not None else "declined",
                answer=generated.answer,
                candidate_sha256=text_sha256(generated.candidate_text)
                if generated.candidate_text is not None
                else None,
            )
            self.records.complete(outcome)
            return self._validated(intent, outcome), True
