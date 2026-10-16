"""Explicit read-only closed-fact explanation of one saved finding."""

import json
from typing import cast
from uuid import UUID

from fastapi import APIRouter, HTTPException, Request
from starlette.concurrency import run_in_threadpool

from app.api.access import authorize
from app.api.configurations import Service, _request_body, _request_schema, _unique_keys
from app.api.contracts import AnalysisResult
from app.api.explanation_contracts import ExplainFinding, ExplanationCapabilities
from app.api.explanations import saved_explanation_facts, selected_explanation_context
from app.api.grounded_explanation_contracts import (
    GroundedExplanationBundle,
    GroundedExplanationCapabilities,
)
from app.api.service import AnalysisService, FeedbackTargetNotFound
from app.audit.results import capture_result
from app.db.store import StorageIntegrityError
from app.detection.baseline import ExpandedPeerBaseline, MeasuredPeerBaseline
from app.domain import Finding
from app.domain.fingerprints import finding_fingerprint
from app.explanation.grounded_explanation import (
    GroundedSelectionFacts,
    PeerSelectionFacts,
    PeerVersion,
    ReferenceSelectionFacts,
    StatisticalSelectionFacts,
    generate_grounded_explanation,
    prepare_grounded_explanation,
)
from app.explanation.knowledge import KnowledgeUnavailable
from app.explanation.local_model import (
    GroundedExplanationDisabled,
    LocalModelRuntime,
    ModelBusy,
)
from app.explanation.provider import InvalidProviderAnswer
from app.explanation.retrieval_runtime import DocumentRetrievalRuntime, RetrievalBusy
from app.explanation.vector_index import RetrievalUnavailable

router = APIRouter(prefix="/api/v2", tags=["grounded explanation"])


def saved_selection_facts(analysis: AnalysisResult, finding: Finding) -> GroundedSelectionFacts:
    comparison = analysis.comparison
    if finding.detector == "expected_configuration":
        if comparison is None or comparison.reference is None:
            raise StorageIntegrityError("Stored reference is unavailable.")
        return GroundedSelectionFacts(
            reference=ReferenceSelectionFacts(source_sha256=comparison.reference.source_sha256)
        )
    if finding.detector == "peer_baseline":
        if comparison is None or comparison.peer_baseline is None:
            raise StorageIntegrityError("Stored peer profile is unavailable.")
        baseline = comparison.peer_baseline
        return GroundedSelectionFacts(
            peer=PeerSelectionFacts(
                baseline_version=cast(PeerVersion, baseline.model_version),
                selected_peer_count=len(comparison.peers),
                profile_feature_count=len(
                    baseline.properties.features
                    if isinstance(baseline, MeasuredPeerBaseline)
                    else baseline.features
                ),
                baseline_sha256=baseline.fingerprint()
                if isinstance(baseline, (ExpandedPeerBaseline, MeasuredPeerBaseline))
                else None,
            )
        )
    if finding.detector == "isolation_forest":
        statistical = analysis.statistical
        if statistical is None:
            raise StorageIntegrityError("Stored statistical model is unavailable.")
        return GroundedSelectionFacts(
            statistical=StatisticalSelectionFacts(
                training_sample_count=statistical.model.metadata.sample_count,
                raw_anomaly_score=-statistical.score_samples,
                decision_function=statistical.decision_function,
                artifact_sha256=statistical.model.artifact_sha256,
            )
        )
    return GroundedSelectionFacts()


def explain_grounded(
    service: AnalysisService,
    finding_id: UUID,
    options: ExplainFinding,
    runtime: LocalModelRuntime | None,
    retrieval_runtime: DocumentRetrievalRuntime | None,
) -> GroundedExplanationBundle:
    if options.provider != "llm":
        raise HTTPException(
            status_code=400, detail="Explicit grounded model selection is required."
        )
    if options.allow_local_model_context is not True:
        raise HTTPException(status_code=403, detail="Local model context permission is required.")
    if runtime is None or runtime.settings.allow_grounded_explanation is not True:
        raise HTTPException(status_code=503, detail="Grounded explanation is disabled.")
    analysis, finding = service.feedback_target(options.analysis_id, finding_id)
    if finding_fingerprint(finding) != options.finding_sha256:
        raise HTTPException(status_code=409, detail="Finding binding conflicts.")
    common, snapshot = selected_explanation_context(
        service, analysis, finding, options, retrieval_runtime
    )
    config = snapshot.canonical
    facts, invocation = saved_explanation_facts(analysis, finding)
    required = (
        common.semantic_retrieval.required_citations
        if common.semantic_retrieval
        else tuple(chunk.citation for chunk in common.documents)
    )
    try:
        prepared = prepare_grounded_explanation(
            finding,
            common.explanation,
            common.documents,
            vendor=config.device.vendor,
            platform=config.device.platform,
            parser_confidence=config.parser_confidence,
            warning_count=len(config.parse_warnings),
            unparsed_count=len(config.unparsed_fragments),
            knowledge_version=common.knowledge_version,
            knowledge_sha256=common.knowledge_sha256,
            required_citations=required,
            analysis_facts=facts,
            invocation_facts=invocation,
            selection_facts=saved_selection_facts(analysis, finding),
            protocol="grounded-model-explanation-0.2.0",
        )
    except ValueError:
        raise HTTPException(
            status_code=413, detail="Grounded explanation context is unavailable or exceeds limits."
        ) from None
    try:
        with runtime.grounded_explanation_provider() as provider:
            generated = generate_grounded_explanation(
                provider, prepared, allow_local_context=options.allow_local_model_context
            )
    except GroundedExplanationDisabled:
        raise HTTPException(status_code=503, detail="Grounded explanation is disabled.") from None
    except ModelBusy:
        raise HTTPException(status_code=429, detail="Local model worker is busy.") from None
    except (InvalidProviderAnswer, ValueError):
        raise HTTPException(
            status_code=503, detail="Grounded explanation answer is unavailable or rejected."
        ) from None
    return GroundedExplanationBundle(
        **common.model_dump(exclude={"limitations"}),
        version=prepared.protocol,
        limitations=(
            *common.limitations,
            "The model selected closed references and codes; presentation is server-derived.",
            "Recorded facts and citations are not independent evidence of truth or safety.",
            "Only explicitly authorized pseudonymized context was sent to literal loopback.",
            "Numbers, hashes and line numbers remain potentially confidential.",
            "No detector rerun, patch, approval, application or saved-analysis mutation occurred.",
            "The configured alias does not attest to weights or model checkpoint identity.",
        ),
        model_alias=runtime.settings.model,
        context_sha256=prepared.prompt.context_sha256,
        source_facts_json=generated.source_facts_json,
        facts_binding_sha256=generated.facts_binding_sha256,
        model_answer=generated.model_answer,
        model_answer_sha256=generated.model_answer_sha256,
        instructions_sha256=prepared.instructions_sha256,
        answer_schema_sha256=prepared.answer_schema_sha256,
        renderer_policy_sha256=prepared.renderer_policy_sha256,
        projection_json=generated.projection_json,
        projection_sha256=generated.projection_sha256,
    )


@router.get(
    "/explanation-capabilities",
    response_model=GroundedExplanationCapabilities,
    name="explanation_capabilities",
)
def grounded_explanation_capabilities(
    request: Request, service: Service
) -> GroundedExplanationCapabilities:
    runtime = cast(LocalModelRuntime | None, request.app.state.local_model)
    return capture_result(
        request,
        GroundedExplanationCapabilities(
            legacy=ExplanationCapabilities(
                local_model="configured" if runtime is not None else "disabled",
                semantic_retrieval="configured"
                if request.app.state.document_retrieval is not None
                else "disabled",
            ),
            grounded_explanation="configured"
            if runtime and runtime.settings.allow_grounded_explanation is True
            else "disabled",
        ),
    )


@router.post(
    "/findings/{finding_id}/explain",
    response_model=GroundedExplanationBundle,
    name="explain_finding",
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {"application/json": {"schema": _request_schema(ExplainFinding)}},
        }
    },
)
async def explain_grounded_finding(
    finding_id: UUID, request: Request, service: Service
) -> GroundedExplanationBundle:
    authorize(request, "model_explanation")
    body = await _request_body(request, maximum=16 * 1024)
    try:
        options = ExplainFinding.model_validate(
            json.loads(body.decode("utf-8"), object_pairs_hook=_unique_keys)
        )
    except (ValueError, RecursionError):
        raise HTTPException(status_code=400, detail="Invalid explanation request.") from None
    try:
        return capture_result(
            request,
            await run_in_threadpool(
                explain_grounded,
                service,
                finding_id,
                options,
                request.app.state.local_model,
                request.app.state.document_retrieval,
            ),
        )
    except FeedbackTargetNotFound:
        raise HTTPException(status_code=404, detail="Analysis finding not found.") from None
    except KnowledgeUnavailable:
        raise HTTPException(status_code=503, detail="Reviewed knowledge is unavailable.") from None
    except RetrievalUnavailable:
        raise HTTPException(status_code=503, detail="Document retrieval is unavailable.") from None
    except RetrievalBusy:
        raise HTTPException(status_code=429, detail="Document retrieval worker is busy.") from None
