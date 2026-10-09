"""Exact saved model candidate -> immutable verification -> explicit engineer decision."""

from contextlib import nullcontext
from datetime import UTC, datetime
from uuid import UUID

from app.api.model_patch_contracts import ModelPatchIntent, fingerprint
from app.api.model_patch_review_contracts import (
    ReviewSavedModelPatch,
    SavedPatchDecision,
    SavedPatchReviewIntent,
    SavedPatchReviewOutcome,
    SavedPatchVerification,
    StatisticalRecheck,
    VerifySavedModelPatch,
    validate_decision,
)
from app.api.service import AnalysisService
from app.core.permissions import Role
from app.db.model_patch_records import ModelPatchConflict
from app.db.model_patch_review_records import ModelPatchReviewRecords
from app.db.source_records import OriginalSourceUnavailable, SourceRecords
from app.db.store import StorageIntegrityError
from app.detection.statistical.features import extract_structured_features
from app.explanation.patch_provider import (
    GeneratedModelPatch,
    PreparedPatchPrompt,
    validate_patch_answer,
)
from app.patching.candidate_review import CandidateReviewUnavailable, build_candidate_review
from app.patching.saved_model import SavedModelPatchNotFound, SavedModelPatchWorkflow
from app.verification.model_patch import check_model_patch_with_batfish
from app.verification.patch_runtime import (
    PatchMLUnavailable,
    PatchVerificationDisabled,
    PatchVerificationRuntime,
)
from app.verification.snapshots import NetworkSnapshot, prepare_snapshot
from ml.inference.change_contracts import MLChangeReview


class SavedPatchReviewFailed(Exception):
    pass


class SavedPatchReviewWorkflow:
    def __init__(self, service: AnalysisService) -> None:
        self.service = service
        self.generation = SavedModelPatchWorkflow(service)
        self.records = ModelPatchReviewRecords(service.store)

    def _prepare(
        self, patch_id: UUID, options: VerifySavedModelPatch
    ) -> tuple[
        ModelPatchIntent,
        GeneratedModelPatch,
        PreparedPatchPrompt,
        NetworkSnapshot,
        SavedPatchReviewIntent,
    ]:
        proposal = self.generation.get(patch_id)
        if proposal.status != "draft" or proposal.proposal_sha256 != options.proposal_sha256:
            raise ModelPatchConflict("Selected proposal is unavailable or differs.")
        saved = self.generation.records.get(patch_id)
        if saved is None or saved[1] is None or saved[1].answer is None:
            raise SavedModelPatchNotFound()
        generation, outcome = saved
        assert outcome is not None and outcome.answer is not None
        prepared, _, _ = self.generation.prepare(generation.request)
        generated = validate_patch_answer(outcome.answer.model_dump_json().encode(), prepared)
        bindings, contents = [], {}
        try:
            for selected in options.network:
                original = SourceRecords(self.service.store).get(
                    selected.configuration_id,
                    expected_source_sha256=selected.source_sha256,
                    allow_local_read=True,
                )
                if (
                    original.snapshot.created_at > generation.created_at
                    or original.snapshot.device_id in contents
                ):
                    raise ValueError("future or duplicate device selection")
                bindings.append(original.snapshot)
                contents[original.snapshot.device_id] = original.content
            if generation.source not in bindings:
                raise ValueError("selected original is absent")
            before = prepare_snapshot(contents)
            if options.scope.start_node not in {item.hostname for item in before.configs}:
                raise ValueError("scope start absent")
            intent = SavedPatchReviewIntent(
                patch_id=patch_id,
                request=options,
                created_at=datetime.now(UTC),
                network=tuple(bindings),
            )
            return generation, generated, prepared, before, intent
        except (ValueError, OriginalSourceUnavailable):
            raise ModelPatchConflict(
                "Selected retained network is unavailable or differs."
            ) from None

    def _statistical(
        self, generation: ModelPatchIntent, generated: GeneratedModelPatch
    ) -> StatisticalRecheck | None:
        analysis = self.service.store.get_analysis(generation.request.analysis_id)
        if analysis is None:
            raise StorageIntegrityError("Stored data is unavailable.")
        if analysis.statistical is None:
            return None
        original = self.service.store.get_configuration(generation.source.configuration_id)
        model = self.service.store.get_model(analysis.statistical.model.model_id)
        if (
            original is None
            or model is None
            or model.summary != analysis.statistical.model
            or generated.metadata is None
        ):
            raise StorageIntegrityError("Stored data is unavailable.")
        # Freshly re-parsed candidate; preserve inventory grouping labels from the saved source.
        from app.parsers import parse_configuration

        candidate = parse_configuration(generated.candidate_text or "", filename="candidate.cfg")
        candidate = candidate.model_copy(
            update={
                "device": candidate.device.model_copy(
                    update={
                        "role": original.canonical.device.role,
                        "site": original.canonical.device.site,
                        "site_class": original.canonical.device.site_class,
                        "service_profile": original.canonical.device.service_profile,
                    }
                )
            }
        )
        rows = [
            extract_structured_features(config).as_row()
            for config in (original.canonical, candidate)
        ]
        scores = model.artifact.score_samples(rows)
        decisions = model.artifact.decision_function(rows)
        predictions = model.artifact.predict(rows)
        if (scores[0], decisions[0], predictions[0]) != (
            analysis.statistical.score_samples,
            analysis.statistical.decision_function,
            analysis.statistical.prediction,
        ):
            raise StorageIntegrityError("Stored data is unavailable.")
        return StatisticalRecheck(
            model_id=model.summary.model_id,
            artifact_sha256=model.summary.artifact_sha256,
            before_score_samples=scores[0],
            after_score_samples=scores[1],
            before_decision_function=decisions[0],
            after_decision_function=decisions[1],
            before_prediction=predictions[0],
            after_prediction=predictions[1],
        )

    def get(self, patch_id: UUID, verification_id: UUID) -> SavedPatchVerification:
        saved = self.records.get(verification_id)
        if saved is None or saved[0].patch_id != patch_id:
            raise SavedModelPatchNotFound()
        intent, outcome = saved
        try:
            generation, generated, prepared, before, fresh_intent = self._prepare(
                patch_id, intent.request
            )
            if fresh_intent.network != intent.network:
                raise ValueError("saved network differs")
            if outcome is not None and outcome.report is not None:
                report = build_candidate_review(
                    generated,
                    prepared=prepared,
                    before=before,
                    scope=intent.request.scope,
                    network_result=outcome.report.network_result,
                    ml_reviews=outcome.report.ml_reviews,
                    expected_model_sha256s=outcome.report.expected_model_sha256s,
                )
                if report != outcome.report or outcome.statistical_recheck != self._statistical(
                    generation, generated
                ):
                    raise ValueError("saved verification differs from exact candidate")
            return SavedPatchVerification.from_records(intent, outcome)
        except (ValueError, CandidateReviewUnavailable, SavedModelPatchNotFound):
            raise StorageIntegrityError("Stored data is unavailable.") from None

    def verify(
        self, patch_id: UUID, options: VerifySavedModelPatch, runtime: PatchVerificationRuntime
    ) -> tuple[SavedPatchVerification, bool]:
        options = VerifySavedModelPatch.model_validate_json(options.model_dump_json())
        existing = self.records.get(options.verification_id)
        if existing is not None:
            if existing[0].patch_id != patch_id or existing[0].request != options:
                raise ModelPatchConflict("Review identity conflicts.")
            return self.get(patch_id, options.verification_id), False
        if options.mode == "batfish" and (
            not options.allow_local_engine_upload or not runtime.settings.allow_engine_upload
        ):
            raise PatchVerificationDisabled()
        if options.transformer_sha256 is not None and (
            not options.allow_local_model_context
            or runtime.settings.registry_root is None
            or runtime.settings.transformer_sha256 != options.transformer_sha256
        ):
            raise PatchVerificationDisabled()
        selected = options.mode == "batfish" or options.transformer_sha256 is not None
        with runtime.selected_worker() if selected else nullcontext():
            generation, generated, prepared, before, intent = self._prepare(patch_id, options)
            if not self.records.reserve(intent):
                return self.get(patch_id, options.verification_id), False
            try:
                network = (
                    check_model_patch_with_batfish(
                        generated,
                        prepared=prepared,
                        before=before,
                        scope=options.scope,
                        allow_local_upload=True,
                        timeout_seconds=runtime.settings.engine_timeout_seconds,
                    )
                    if options.mode == "batfish"
                    else None
                )
                reviews: tuple[MLChangeReview, ...] = ()
                ml_execution = "not_requested"
                if options.transformer_sha256 is not None:
                    try:
                        assert (
                            generated.metadata is not None and generated.candidate_text is not None
                        )
                        reviews = (
                            runtime.review_ml(
                                generated.metadata.review,
                                prepared.before,
                                generated.candidate_text,
                                options.transformer_sha256,
                            ),
                        )
                        ml_execution = (
                            "completed"
                            if reviews[0].transformer.status == "completed"
                            else "unavailable"
                        )
                    except PatchMLUnavailable:
                        ml_execution = "unavailable"
                report = build_candidate_review(
                    generated,
                    prepared=prepared,
                    before=before,
                    scope=options.scope,
                    network_result=network,
                    ml_reviews=reviews,
                    expected_model_sha256s=(options.transformer_sha256,) if reviews else (),
                )
                outcome = SavedPatchReviewOutcome.model_validate(
                    {
                        "verification_id": options.verification_id,
                        "intent_sha256": fingerprint(intent),
                        "completed_at": datetime.now(UTC),
                        "execution_status": "completed",
                        "report": report,
                        "ml_execution": ml_execution,
                        "statistical_recheck": self._statistical(generation, generated),
                    }
                )
            except (ValueError, CandidateReviewUnavailable):
                self.records.complete(
                    SavedPatchReviewOutcome(
                        verification_id=options.verification_id,
                        intent_sha256=fingerprint(intent),
                        completed_at=datetime.now(UTC),
                        execution_status="failed",
                    )
                )
                raise SavedPatchReviewFailed() from None
            self.records.complete(outcome)
            return self.get(patch_id, options.verification_id), True

    def decide(
        self, patch_id: UUID, options: ReviewSavedModelPatch, role: Role
    ) -> tuple[SavedPatchDecision, bool]:
        options = ReviewSavedModelPatch.model_validate_json(options.model_dump_json())
        run = self.get(patch_id, options.verification_id)
        decision = SavedPatchDecision(
            patch_id=patch_id, request=options, created_at=datetime.now(UTC), service_role=role
        )
        try:
            validate_decision(decision, run)
        except ValueError:
            raise ModelPatchConflict(
                "Decision lacks matching completed evidence or required attestations."
            ) from None
        return self.records.decide(decision)

    def get_decision(self, patch_id: UUID, decision_id: UUID) -> SavedPatchDecision:
        record = self.records.get_decision(decision_id)
        if record is None or record.patch_id != patch_id:
            raise SavedModelPatchNotFound()
        self.get(patch_id, record.request.verification_id)
        return record
