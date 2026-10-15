"""V2 adds a separately authorized grounded writer and explicit mixed-version readers."""

import json
from typing import cast
from uuid import UUID

from fastapi import APIRouter, HTTPException, Request, Response
from starlette.concurrency import run_in_threadpool

from app.api.access import authorize
from app.api.configurations import (
    Limit,
    Offset,
    Service,
    _request_body,
    _request_schema,
    _unique_keys,
)
from app.api.grounded_patch_contracts import (
    GroundedModelPatchProposal,
    SavedModelPatchCapabilities,
    SavedModelPatchProposal,
)
from app.api.model_patch_contracts import GenerateModelPatch
from app.api.model_patches import DraftService, configured_patch_capabilities
from app.audit.results import capture_result
from app.db.model_patch_records import ModelPatchConflict
from app.explanation.local_model import LocalModelRuntime, ModelBusy, ModelPatchDisabled
from app.patching.saved_grounded import SavedGroundedPatchWorkflow
from app.patching.saved_model import (
    SavedModelPatchGenerationFailed,
    SavedModelPatchNotFound,
    SavedModelPatchUnavailable,
)
from app.patching.saved_patch_access import SavedModelPatchAccess

router = APIRouter(prefix="/api/v2/model-patches", tags=["version-bound model patch drafts"])


@router.post(
    "",
    response_model=GroundedModelPatchProposal,
    status_code=201,
    name="generate_model_patch",
    responses={
        200: {"model": GroundedModelPatchProposal, "description": "Existing grounded attempt."}
    },
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {"application/json": {"schema": _request_schema(GenerateModelPatch)}},
        }
    },
)
async def generate_grounded_model_patch(
    request: Request, response: Response, service: DraftService
) -> GroundedModelPatchProposal:
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
            SavedGroundedPatchWorkflow(service).generate, options, runtime
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
        raise HTTPException(
            status_code=503, detail="Grounded model patch generation is disabled."
        ) from None
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


@router.get("", response_model=list[SavedModelPatchProposal], name="list_model_patches")
def list_saved_model_patches(
    analysis_id: UUID, request: Request, service: Service, limit: Limit = 20, offset: Offset = 0
) -> list[SavedModelPatchProposal]:
    if service.store.get_analysis(analysis_id) is None:
        raise HTTPException(status_code=404, detail="Selected analysis not found.")
    access = SavedModelPatchAccess(service)
    return capture_result(
        request,
        [
            access.get(key)
            for key in access.records.list_ids(
                analysis_id=analysis_id,
                limit=limit,
                offset=offset,
                protocol=None,
            )
        ],
    )


@router.get(
    "/capabilities", response_model=SavedModelPatchCapabilities, name="model_patch_capabilities"
)
def saved_model_patch_capabilities(
    request: Request, service: Service
) -> SavedModelPatchCapabilities:
    runtime = cast(LocalModelRuntime | None, request.app.state.local_model)
    return capture_result(
        request,
        SavedModelPatchCapabilities(
            legacy=configured_patch_capabilities(request),
            grounded_generation="configured"
            if runtime and runtime.settings.allow_grounded_patch_draft
            else "disabled",
        ),
    )


@router.get("/{patch_id}", response_model=SavedModelPatchProposal, name="get_model_patch")
def get_saved_model_patch(
    patch_id: UUID, request: Request, service: Service
) -> SavedModelPatchProposal:
    try:
        return capture_result(request, SavedModelPatchAccess(service).get(patch_id))
    except SavedModelPatchNotFound:
        raise HTTPException(status_code=404, detail="Model patch intent not found.") from None
