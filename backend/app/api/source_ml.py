"""Explicit separately persisted ordinary-source paired ML attempts."""

import json
from typing import Annotated, cast
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from starlette.concurrency import run_in_threadpool

from app.api.access import require_access
from app.api.configurations import (
    Limit,
    Offset,
    Service,
    _request_body,
    _request_schema,
    _unique_keys,
)
from app.api.service import AnalysisService
from app.api.source_ml_contracts import (
    RunSourceMlRecheck,
    SourceMlCapabilities,
    SourceMlRecheck,
    SourceMlSummary,
)
from app.audit.results import capture_result
from app.db.patch_records import PatchConflict
from app.detection.config_model_runtime import (
    ConfigurationModelBusy,
    ConfigurationModelDisabled,
    ConfigurationModelRuntime,
)
from app.detection.config_pair_runtime import ConfigurationPairTooLarge
from app.patching.persistent import PatchNotFound
from app.patching.source_ml import SourceMlConsentRequired, SourceMlWorkflow

router = APIRouter(prefix="/api/v2/patches", tags=["experimental paired source models"])
ModelService = Annotated[AnalysisService, Depends(require_access("configuration_model"))]


@router.get("/ml-capabilities", response_model=SourceMlCapabilities)
def source_ml_capabilities(request: Request, service: Service) -> SourceMlCapabilities:
    settings = cast(ConfigurationModelRuntime, request.app.state.configuration_model).settings
    return capture_result(
        request,
        SourceMlCapabilities(
            inference="configured" if settings.registry_root is not None else "disabled",
            model_sha256=settings.model_sha256,
        ),
    )


@router.post(
    "/{patch_id}/ml-rechecks",
    response_model=SourceMlRecheck,
    status_code=201,
    responses={200: {"model": SourceMlRecheck, "description": "Existing attempt; no inference."}},
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                "application/json": {"schema": _request_schema(RunSourceMlRecheck)},
            },
        }
    },
)
async def run_source_ml_recheck(
    patch_id: UUID, request: Request, response: Response, service: ModelService
) -> SourceMlRecheck:
    body = await _request_body(request, maximum=16 * 1024)
    try:
        options = RunSourceMlRecheck.model_validate(
            json.loads(body.decode(), object_pairs_hook=_unique_keys)
        )
    except (ValueError, RecursionError):
        raise HTTPException(status_code=400, detail="Invalid source ML recheck request.") from None
    runtime = cast(ConfigurationModelRuntime, request.app.state.configuration_model)
    try:
        result, created = await run_in_threadpool(
            SourceMlWorkflow(service.store).run, patch_id, options, runtime
        )
    except PatchNotFound:
        raise HTTPException(status_code=404, detail="Selected draft not found.") from None
    except PatchConflict:
        raise HTTPException(
            status_code=409, detail="Selected source, model or recheck identity conflicts."
        ) from None
    except SourceMlConsentRequired:
        raise HTTPException(
            status_code=403, detail="Explicit local model context consent is required."
        ) from None
    except ConfigurationModelDisabled:
        raise HTTPException(status_code=503, detail="Local paired inference is disabled.") from None
    except ConfigurationModelBusy:
        raise HTTPException(
            status_code=429, detail="Local model worker is busy; no attempt started."
        ) from None
    except ConfigurationPairTooLarge:
        raise HTTPException(
            status_code=413, detail="Source pair or result exceeds its report budget."
        ) from None
    response.status_code = 201 if created else 200
    return capture_result(request, result)


@router.get("/{patch_id}/ml-rechecks", response_model=list[SourceMlSummary])
def list_source_ml_rechecks(
    patch_id: UUID, request: Request, service: Service, limit: Limit = 20, offset: Offset = 0
) -> list[SourceMlSummary]:
    workflow = SourceMlWorkflow(service.store)
    try:
        workflow.drafts.draft(patch_id)
    except PatchNotFound:
        raise HTTPException(status_code=404, detail="Selected draft not found.") from None
    return capture_result(
        request,
        [
            SourceMlSummary.from_recheck(workflow.get(patch_id, key))
            for key in workflow.records.list_ids(patch_id, limit=limit, offset=offset)
        ],
    )


@router.get("/{patch_id}/ml-rechecks/{recheck_id}", response_model=SourceMlRecheck)
def get_source_ml_recheck(
    patch_id: UUID, recheck_id: UUID, request: Request, service: Service
) -> SourceMlRecheck:
    try:
        return capture_result(request, SourceMlWorkflow(service.store).get(patch_id, recheck_id))
    except PatchNotFound:
        raise HTTPException(status_code=404, detail="Selected ML recheck not found.") from None
