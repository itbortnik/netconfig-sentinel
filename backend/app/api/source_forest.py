"""Explicit saved original-Forest selection and immutable ordinary draft rechecks."""

import json
from typing import Annotated
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
from app.api.source_forest_contracts import (
    RunSourceForestRecheck,
    SourceForestRecheck,
    SourceForestSelection,
    SourceForestSummary,
)
from app.audit.results import capture_result
from app.db.patch_records import PatchConflict
from app.patching.persistent import PatchNotFound
from app.patching.source_forest import (
    SourceForestConsentRequired,
    SourceForestTooLarge,
    SourceForestWorkflow,
)

router = APIRouter(prefix="/api/v2/patches", tags=["original statistical source models"])
ModelService = Annotated[AnalysisService, Depends(require_access("configuration_model"))]


@router.get("/{patch_id}/statistical-selection/{analysis_id}", response_model=SourceForestSelection)
def source_forest_selection(
    patch_id: UUID, analysis_id: UUID, request: Request, service: Service
) -> SourceForestSelection:
    try:
        return capture_result(
            request, SourceForestWorkflow(service.store).selection(patch_id, analysis_id)
        )
    except PatchNotFound:
        raise HTTPException(
            status_code=404, detail="Selected draft or analysis not found."
        ) from None
    except PatchConflict:
        raise HTTPException(
            status_code=409, detail="Selected original statistical analysis differs."
        ) from None


@router.post(
    "/{patch_id}/statistical-rechecks",
    response_model=SourceForestRecheck,
    status_code=201,
    responses={
        200: {"model": SourceForestRecheck, "description": "Existing attempt; no evaluation."}
    },
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                "application/json": {"schema": _request_schema(RunSourceForestRecheck)},
            },
        }
    },
)
async def run_source_forest_recheck(
    patch_id: UUID, request: Request, response: Response, service: ModelService
) -> SourceForestRecheck:
    body = await _request_body(request, maximum=16 * 1024)
    try:
        options = RunSourceForestRecheck.model_validate(
            json.loads(body.decode(), object_pairs_hook=_unique_keys)
        )
    except (ValueError, RecursionError):
        raise HTTPException(
            status_code=400, detail="Invalid statistical recheck request."
        ) from None
    try:
        result, created = await run_in_threadpool(
            SourceForestWorkflow(service.store).run, patch_id, options
        )
    except PatchNotFound:
        raise HTTPException(
            status_code=404, detail="Selected draft or analysis not found."
        ) from None
    except PatchConflict:
        raise HTTPException(
            status_code=409,
            detail="Selected source, analysis, model or recheck identity conflicts.",
        ) from None
    except SourceForestConsentRequired:
        raise HTTPException(
            status_code=403, detail="Explicit local model context consent is required."
        ) from None
    except SourceForestTooLarge:
        raise HTTPException(
            status_code=413, detail="Statistical pair exceeds its budget."
        ) from None
    response.status_code = 201 if created else 200
    return capture_result(request, result)


@router.get("/{patch_id}/statistical-rechecks", response_model=list[SourceForestSummary])
def list_source_forest_rechecks(
    patch_id: UUID, request: Request, service: Service, limit: Limit = 20, offset: Offset = 0
) -> list[SourceForestSummary]:
    workflow = SourceForestWorkflow(service.store)
    try:
        workflow.drafts.draft(patch_id)
    except PatchNotFound:
        raise HTTPException(status_code=404, detail="Selected draft not found.") from None
    return capture_result(
        request,
        [
            SourceForestSummary.from_recheck(workflow.get(patch_id, key))
            for key in workflow.records.list_ids(patch_id, limit=limit, offset=offset)
        ],
    )


@router.get("/{patch_id}/statistical-rechecks/{recheck_id}", response_model=SourceForestRecheck)
def get_source_forest_recheck(
    patch_id: UUID, recheck_id: UUID, request: Request, service: Service
) -> SourceForestRecheck:
    try:
        return capture_result(
            request, SourceForestWorkflow(service.store).get(patch_id, recheck_id)
        )
    except PatchNotFound:
        raise HTTPException(
            status_code=404, detail="Selected statistical recheck not found."
        ) from None
