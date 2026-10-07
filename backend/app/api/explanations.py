"""Bound source retrieval and explicitly authorized redacted loopback model drafts."""

import json
from uuid import UUID

from fastapi import APIRouter, HTTPException, Request
from starlette.concurrency import run_in_threadpool

from app.api.access import authorize
from app.api.configurations import Service, _request_body, _request_schema, _unique_keys
from app.api.explanation_contracts import (
    ExplainFinding,
    ExplanationBundle,
    ExplanationCapabilities,
    ExplanationContext,
    ModelExplanationBundle,
)
from app.api.service import AnalysisService, FeedbackTargetNotFound
from app.audit.results import capture_result
from app.db.store import StorageIntegrityError
from app.domain.fingerprints import finding_fingerprint
from app.explanation.knowledge import (
    KnowledgeUnavailable,
    knowledge_version_for_finding,
    load_knowledge_catalog,
)
from app.explanation.local_model import LocalModelRuntime, ModelBusy
from app.explanation.provider import InvalidProviderAnswer, build_prompt
from app.explanation.retrieval_contracts import SemanticMatch, SemanticRetrievalContext
from app.explanation.retrieval_runtime import (
    DocumentRetrievalRuntime,
    RetrievalBusy,
    public_retrieval_query,
)
from app.explanation.vector_index import RetrievalUnavailable

router = APIRouter(prefix="/api/v1", tags=["explanation"])


def _explain(
    service: AnalysisService,
    finding_id: UUID,
    options: ExplainFinding,
    runtime: LocalModelRuntime | None = None,
    retrieval_runtime: DocumentRetrievalRuntime | None = None,
) -> ExplanationBundle | ModelExplanationBundle:
    analysis, finding = service.feedback_target(options.analysis_id, finding_id)
    if finding_fingerprint(finding) != options.finding_sha256:
        raise HTTPException(status_code=409, detail="Finding binding conflicts.")
    if options.provider == "llm":
        if runtime is None:
            raise HTTPException(status_code=503, detail="Language model provider is unavailable.")
        if not options.allow_local_model_context:
            raise HTTPException(
                status_code=403, detail="Local model context permission is required."
            )
    snapshot = service.store.get_configuration(analysis.configuration_id)
    if (
        snapshot is None
        or snapshot.device_id != analysis.device_id
        or (snapshot.canonical.source.sha256 != analysis.source_sha256)
    ):
        raise StorageIntegrityError("Stored data is unavailable.")
    catalog = load_knowledge_catalog(knowledge_version_for_finding(finding))
    documents = catalog.retrieve(finding)
    semantic = None
    if options.retrieval == "semantic_supplement":
        if retrieval_runtime is None:
            raise HTTPException(status_code=503, detail="Document retrieval is unavailable.")
        selected = retrieval_runtime.search(catalog, public_retrieval_query(finding))
        mandatory = {chunk.citation for chunk in documents}
        supplements = tuple(
            item for item in selected.matches if item.document.citation not in mandatory
        )[: 4 - len(documents)]
        semantic = SemanticRetrievalContext(
            index_sha256=selected.index_sha256,
            encoder=selected.encoder,
            query_sha256=selected.query_sha256,
            required_citations=tuple(chunk.citation for chunk in documents),
            matches=tuple(
                SemanticMatch(
                    citation=item.document.citation,
                    content_sha256=item.document.content_sha256,
                    cosine_similarity=item.cosine_similarity,
                )
                for item in supplements
            ),
        )
        documents = (*documents, *(item.document for item in supplements))
    explanation = next(item for item in analysis.explanations if item.finding_id == finding_id)
    common = ExplanationContext(
        analysis_id=analysis.analysis_id,
        configuration_id=analysis.configuration_id,
        device_id=analysis.device_id,
        source_sha256=analysis.source_sha256,
        finding_id=finding_id,
        finding_sha256=options.finding_sha256,
        knowledge_version=catalog.version,
        knowledge_sha256=catalog.sha256,
        explanation=explanation,
        retrieval=options.retrieval,
        semantic_retrieval=semantic,
        documents=documents,
        limitations=(
            "The saved deterministic explanation and detector scores are unchanged.",
            (
                "Required detector references are retained; local semantic matches "
                "only supplement context. Similarity is not confidence or semantic truth."
                if semantic is not None
                else "Retrieval follows explicit detector references, "
                "not semantic search or a vector index."
            ),
            "Sources are internal project documents, not vendor guidance or an approved baseline.",
            "Document and chunk hashes identify contents; they are not publisher signatures.",
            "Retrieved text does not prove network impact, "
            "formal verification or safe remediation.",
            "Unknown source fragments are not retrieved or sent to a provider; parser limitations "
            "remain in the original explanation.",
        ),
    )
    if options.provider == "local":
        return ExplanationBundle(
            **common.model_dump(),
            version="finding-context-0.2.0" if semantic else "finding-context-0.1.0",
        )
    assert runtime is not None
    config = snapshot.canonical
    try:
        prompt = build_prompt(
            finding,
            explanation,
            common.documents,
            vendor=config.device.vendor,
            platform=config.device.platform,
            parser_confidence=config.parser_confidence,
            warning_count=len(config.parse_warnings),
            unparsed_count=len(config.unparsed_fragments),
        )
        answer, context_sha = runtime.explain(prompt, common.documents)
    except ModelBusy:
        raise HTTPException(status_code=429, detail="Local model worker is busy.") from None
    except InvalidProviderAnswer:
        raise HTTPException(
            status_code=503, detail="Language model answer is unavailable or rejected."
        ) from None
    except ValueError:
        raise HTTPException(
            status_code=413, detail="Language model context exceeds supported limits."
        ) from None
    model_limitations = (
        *common.limitations,
        "This model answer is an untrusted draft, not semantic truth or formal verification.",
        "Only a redacted context was sent to an explicitly configured literal loopback endpoint.",
        "Numbers, booleans, hashes and line numbers remain potentially confidential.",
        "No patch, approval, application or saved-analysis mutation is available.",
        "The configured model alias does not attest to actual weights or checkpoint identity.",
    )
    return ModelExplanationBundle(
        **common.model_dump(exclude={"limitations"}),
        limitations=model_limitations,
        context_sha256=context_sha,
        model_alias=runtime.settings.model,
        answer=answer,
        version="model-explanation-0.2.0" if semantic else "model-explanation-0.1.0",
    )


@router.get("/explanation-capabilities", response_model=ExplanationCapabilities)
def explanation_capabilities(request: Request, service: Service) -> ExplanationCapabilities:
    return capture_result(
        request,
        ExplanationCapabilities(
            local_model="configured" if request.app.state.local_model is not None else "disabled",
            semantic_retrieval=(
                "configured" if request.app.state.document_retrieval is not None else "disabled"
            ),
        ),
    )


@router.post(
    "/findings/{finding_id}/explain",
    response_model=ExplanationBundle | ModelExplanationBundle,
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {"application/json": {"schema": _request_schema(ExplainFinding)}},
        }
    },
)
async def explain_finding(
    finding_id: UUID, request: Request, service: Service
) -> ExplanationBundle | ModelExplanationBundle:
    body = await _request_body(request, maximum=16 * 1024)
    try:
        options = ExplainFinding.model_validate(
            json.loads(body.decode("utf-8"), object_pairs_hook=_unique_keys)
        )
    except (ValueError, RecursionError):
        raise HTTPException(status_code=400, detail="Invalid explanation request.") from None
    try:
        if options.provider == "llm":
            authorize(request, "model_explanation")
        return capture_result(
            request,
            await run_in_threadpool(
                _explain,
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
