"""Authenticated local sources; unavailable LLM requests never silently fall back."""

import json
from uuid import UUID

from fastapi import APIRouter, HTTPException, Request
from starlette.concurrency import run_in_threadpool

from app.api.configurations import Service, _request_body, _request_schema, _unique_keys
from app.api.explanation_contracts import ExplainFinding, ExplanationBundle
from app.api.service import AnalysisService, FeedbackTargetNotFound
from app.db.store import StorageIntegrityError
from app.domain.fingerprints import finding_fingerprint
from app.explanation.knowledge import KnowledgeUnavailable, load_knowledge_catalog

router = APIRouter(prefix="/api/v1", tags=["explanation"])


def _explain(
    service: AnalysisService, finding_id: UUID, options: ExplainFinding
) -> ExplanationBundle:
    analysis, finding = service.feedback_target(options.analysis_id, finding_id)
    if finding_fingerprint(finding) != options.finding_sha256:
        raise HTTPException(status_code=409, detail="Finding binding conflicts.")
    if options.provider == "llm":
        raise HTTPException(status_code=503, detail="Language model provider is unavailable.")
    snapshot = service.store.get_configuration(analysis.configuration_id)
    if (
        snapshot is None
        or snapshot.device_id != analysis.device_id
        or (snapshot.canonical.source.sha256 != analysis.source_sha256)
    ):
        raise StorageIntegrityError("Stored data is unavailable.")
    catalog = load_knowledge_catalog()
    explanation = next(item for item in analysis.explanations if item.finding_id == finding_id)
    return ExplanationBundle(
        analysis_id=analysis.analysis_id,
        configuration_id=analysis.configuration_id,
        device_id=analysis.device_id,
        source_sha256=analysis.source_sha256,
        finding_id=finding_id,
        finding_sha256=options.finding_sha256,
        knowledge_sha256=catalog.sha256,
        explanation=explanation,
        documents=catalog.retrieve(finding),
        limitations=(
            "No language model was called; the saved deterministic explanation is unchanged.",
            "Retrieval follows explicit detector references, "
            "not semantic search or a vector index.",
            "Sources are internal project documents, not vendor guidance or an approved baseline.",
            "Document and chunk hashes identify contents; they are not publisher signatures.",
            "Retrieved text does not prove network impact, "
            "formal verification or safe remediation.",
            "Unknown source fragments are not retrieved or sent to a provider; parser limitations "
            "remain in the original explanation.",
        ),
    )


@router.post(
    "/findings/{finding_id}/explain",
    response_model=ExplanationBundle,
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {"application/json": {"schema": _request_schema(ExplainFinding)}},
        }
    },
)
async def explain_finding(
    finding_id: UUID, request: Request, service: Service
) -> ExplanationBundle:
    body = await _request_body(request, maximum=16 * 1024)
    try:
        options = ExplainFinding.model_validate(
            json.loads(body.decode("utf-8"), object_pairs_hook=_unique_keys)
        )
    except (ValueError, RecursionError):
        raise HTTPException(status_code=400, detail="Invalid explanation request.") from None
    try:
        return await run_in_threadpool(_explain, service, finding_id, options)
    except FeedbackTargetNotFound:
        raise HTTPException(status_code=404, detail="Analysis finding not found.") from None
    except KnowledgeUnavailable:
        raise HTTPException(status_code=503, detail="Reviewed knowledge is unavailable.") from None
