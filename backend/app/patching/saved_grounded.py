"""Explicit persisted grounded policy; no legacy prompt reinterpretation or model retry."""

import json
from datetime import UTC, datetime
from uuid import UUID

from app.api.grounded_patch_contracts import (
    GroundedModelPatchIntent,
    GroundedModelPatchOutcome,
    GroundedModelPatchProposal,
    presentation_digest,
)
from app.api.model_patch_contracts import GenerateModelPatch, fingerprint
from app.api.service import AnalysisService
from app.audit.contracts import metadata_hash
from app.db.model_patch_records import ModelPatchConflict, ModelPatchRecords
from app.db.store import StorageIntegrityError
from app.explanation.grounded_patch import (
    RENDERER_VERSION,
    GeneratedGroundedPatch,
    PreparedGroundedPatch,
    build_grounded_patch_prompt,
    generate_grounded_patch_draft,
    renderer_policy_sha256,
    validate_grounded_patch_answer,
)
from app.explanation.knowledge import text_sha256
from app.explanation.local_model import LocalModelRuntime, ModelPatchDisabled
from app.explanation.provider import InvalidProviderAnswer
from app.patching.saved_model import (
    SavedModelPatchGenerationFailed,
    SavedModelPatchNotFound,
    SavedModelPatchWorkflow,
)


class SavedGroundedPatchWorkflow:
    def __init__(self, service: AnalysisService) -> None:
        self.legacy = SavedModelPatchWorkflow(service)
        self.records = ModelPatchRecords(service.store)

    def prepare(self, options: GenerateModelPatch) -> PreparedGroundedPatch:
        selected, _, _ = self.legacy.prepare(options)
        return build_grounded_patch_prompt(
            selected.before,
            finding=selected.finding,
            source_sha256=selected.source_sha256,
            reference_id=selected.reference_id,
            allow_local_context=True,
            baseline=selected.baseline,
            chunks=selected.chunks,
        )

    def replay(
        self, intent: GroundedModelPatchIntent, outcome: GroundedModelPatchOutcome | None
    ) -> tuple[PreparedGroundedPatch, GeneratedGroundedPatch | None, GroundedModelPatchProposal]:
        try:
            # Exact retained selection is rechecked by the existing source reader.
            selected, source, baseline = self.legacy.prepare(intent.request)
            prepared = build_grounded_patch_prompt(
                selected.before,
                finding=selected.finding,
                source_sha256=selected.source_sha256,
                reference_id=selected.reference_id,
                baseline=selected.baseline,
                chunks=selected.chunks,
                allow_local_context=True,
            )
            context = json.loads(selected.prompt.context_json)
            if (
                source != intent.source
                or baseline != intent.baseline
                or prepared.prompt.context_sha256 != intent.context_sha256
                or selected.prompt.context_sha256 != intent.edit_context_sha256
                or text_sha256(prepared.prompt.instructions) != intent.instructions_sha256
                or text_sha256(prepared.prompt.answer_schema_json) != intent.answer_schema_sha256
                or prepared.source_facts != intent.source_facts
                or prepared.facts_binding_sha256 != intent.facts_binding_sha256
                or intent.renderer_version != RENDERER_VERSION
                or intent.renderer_policy_sha256 != renderer_policy_sha256()
                or context["knowledge_version"] != intent.knowledge_version
                or context["knowledge_sha256"] != intent.knowledge_sha256
            ):
                raise ValueError("grounded stored policy/input binding differs")
            generated = None
            if outcome is not None and outcome.model_answer is not None:
                generated = validate_grounded_patch_answer(
                    outcome.model_answer.model_dump_json(warnings=False).encode(), prepared
                )
                projected = generated.generated
                if (
                    projected.answer != outcome.answer
                    or presentation_digest(projected.answer) != outcome.projection_sha256
                    or (
                        text_sha256(projected.candidate_text)
                        if projected.candidate_text is not None
                        else None
                    )
                    != outcome.candidate_sha256
                ):
                    raise ValueError("grounded stored projection differs from exact replay")
            return prepared, generated, GroundedModelPatchProposal.from_records(intent, outcome)
        except (ValueError, SavedModelPatchNotFound, InvalidProviderAnswer):
            raise StorageIntegrityError("Stored data is unavailable.") from None

    def get(self, patch_id: UUID) -> GroundedModelPatchProposal:
        saved = self.records.get(patch_id)
        if saved is None:
            raise SavedModelPatchNotFound()
        intent, outcome = saved
        if not isinstance(intent, GroundedModelPatchIntent) or (
            outcome is not None and not isinstance(outcome, GroundedModelPatchOutcome)
        ):
            raise SavedModelPatchNotFound()
        return self.replay(intent, outcome)[2]

    def generate(
        self, options: GenerateModelPatch, runtime: LocalModelRuntime | None
    ) -> tuple[GroundedModelPatchProposal, bool]:
        options = GenerateModelPatch.model_validate_json(options.model_dump_json())
        if options.allow_local_model_context is not True:
            # Keep the same permission boundary before reading a saved attempt.
            from app.patching.saved_model import SavedModelPatchUnavailable

            raise SavedModelPatchUnavailable("Explicit local model context permission is required.")
        saved = self.records.get(options.patch_id)
        if saved is not None:
            intent, outcome = saved
            if (
                not isinstance(intent, GroundedModelPatchIntent)
                or (outcome is not None and not isinstance(outcome, GroundedModelPatchOutcome))
                or intent.request != options
            ):
                raise ModelPatchConflict("Model patch identity conflicts.")
            return self.replay(intent, outcome)[2], False
        if runtime is None:
            raise ModelPatchDisabled()
        with runtime.grounded_patch_provider() as provider:
            selected, source, baseline = self.legacy.prepare(options)
            prepared = build_grounded_patch_prompt(
                selected.before,
                finding=selected.finding,
                source_sha256=selected.source_sha256,
                reference_id=selected.reference_id,
                baseline=selected.baseline,
                chunks=selected.chunks,
                allow_local_context=True,
            )
            context = json.loads(selected.prompt.context_json)
            intent = GroundedModelPatchIntent(
                request=options,
                source=source,
                baseline=baseline,
                created_at=datetime.now(UTC),
                context_sha256=prepared.prompt.context_sha256,
                edit_context_sha256=selected.prompt.context_sha256,
                knowledge_version=context["knowledge_version"],
                knowledge_sha256=context["knowledge_sha256"],
                model_alias_sha256=metadata_hash(runtime.settings.model),
                instructions_sha256=text_sha256(prepared.prompt.instructions),
                answer_schema_sha256=text_sha256(prepared.prompt.answer_schema_json),
                source_facts=prepared.source_facts,
                facts_binding_sha256=prepared.facts_binding_sha256,
                renderer_policy_sha256=renderer_policy_sha256(),
            )
            if not self.records.reserve(intent):
                return self.get(options.patch_id), False
            try:
                generated = generate_grounded_patch_draft(
                    provider, prepared, allow_local_context=True
                )
            except InvalidProviderAnswer:
                self.records.complete(
                    GroundedModelPatchOutcome(
                        patch_id=options.patch_id,
                        intent_sha256=fingerprint(intent),
                        completed_at=datetime.now(UTC),
                        status="failed",
                    )
                )
                raise SavedModelPatchGenerationFailed() from None
            projected = generated.generated
            outcome = GroundedModelPatchOutcome(
                patch_id=options.patch_id,
                intent_sha256=fingerprint(intent),
                completed_at=datetime.now(UTC),
                status="draft" if projected.candidate_text is not None else "declined",
                answer=projected.answer,
                model_answer=generated.model_answer,
                projection_sha256=presentation_digest(projected.answer),
                candidate_sha256=text_sha256(projected.candidate_text)
                if projected.candidate_text is not None
                else None,
            )
            self.records.complete(outcome)
            return self.replay(intent, outcome)[2], True
