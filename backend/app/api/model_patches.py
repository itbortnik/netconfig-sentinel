"""Opt-in source-bound model drafts, separate from normalized snapshot proposals."""

import json
from typing import Annotated, cast
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from starlette.concurrency import run_in_threadpool

from app.api.access import authorize, require_access
from app.api.configurations import (
    Limit,
    Offset,
    Service,
    _request_body,
    _request_schema,
    _unique_keys,
)
from app.api.model_patch_contracts import GenerateModelPatch, ModelPatchProposal
from app.api.service import AnalysisService
from app.audit.results import capture_result
from app.db.model_patch_records import ModelPatchConflict
from app.explanation.local_model import LocalModelRuntime, ModelBusy, ModelPatchDisabled
from app.patching.saved_model import (
    SavedModelPatchGenerationFailed,
    SavedModelPatchNotFound,
    SavedModelPatchUnavailable,
    SavedModelPatchWorkflow,
)

router = APIRouter(prefix="/api/v1/model-patches", tags=["source-bound model patch drafts"])
DraftService = Annotated[AnalysisService, Depends(require_access("draft"))]


@router.post(
    "",
    response_model=ModelPatchProposal,
    status_code=201,
    responses={
        200: {"model": ModelPatchProposal, "description": "Existing attempt; no new generation."}
    },
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {"application/json": {"schema": _request_schema(GenerateModelPatch)}},
        }
    },
)
async def generate_model_patch(
    request: Request, response: Response, service: DraftService
) -> ModelPatchProposal:
    authorize(request, "model_explanation")
    body = await _request_body(request, maximum=16 * 1024)
    try:
        options = GenerateModelPatch.model_validate(
            json.loads(body.decode(), object_pairs_hook=_unique_keys)
        )
    except (ValueError, RecursionError):
        raise HTTPException(status_code=400, detail="Invalid model patch request.") from None
    if options.allow_local_model_context is not True:
        raise HTTPException(
            status_code=403, detail="Explicit local model context permission is required."
        )
    runtime = cast(LocalModelRuntime | None, request.app.state.local_model)
    try:
        result, created = await run_in_threadpool(
            SavedModelPatchWorkflow(service).generate, options, runtime
        )
    except SavedModelPatchNotFound:
        raise HTTPException(
            status_code=404, detail="Selected analysis or finding not found."
        ) from None
    except (ModelPatchConflict, SavedModelPatchUnavailable):
        raise HTTPException(
            status_code=409,
            detail="Selected identity, retained original or patch context is unavailable.",
        ) from None
    except ModelPatchDisabled:
        raise HTTPException(status_code=503, detail="Model patch generation is disabled.") from None
    except ModelBusy:
        raise HTTPException(
            status_code=429, detail="Local model is busy; no attempt was started."
        ) from None
    except SavedModelPatchGenerationFailed:
        raise HTTPException(
            status_code=503,
            detail="Model patch generation failed; inspect the saved intent before retrying.",
        ) from None
    response.status_code = 201 if created else 200
    return capture_result(request, result)


@router.get("", response_model=list[ModelPatchProposal])
def list_model_patches(
    analysis_id: UUID, request: Request, service: Service, limit: Limit = 20, offset: Offset = 0
) -> list[ModelPatchProposal]:
    if service.store.get_analysis(analysis_id) is None:
        raise HTTPException(status_code=404, detail="Selected analysis not found.")
    workflow = SavedModelPatchWorkflow(service)
    return capture_result(
        request,
        [
            workflow.get(key)
            for key in workflow.records.list_ids(
                analysis_id=analysis_id, limit=limit, offset=offset
            )
        ],
    )


@router.get("/{patch_id}", response_model=ModelPatchProposal)
def get_model_patch(patch_id: UUID, request: Request, service: Service) -> ModelPatchProposal:
    try:
        return capture_result(request, SavedModelPatchWorkflow(service).get(patch_id))
    except SavedModelPatchNotFound:
        raise HTTPException(status_code=404, detail="Model patch intent not found.") from None
