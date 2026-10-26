"""Bounded native candidates with explicit private retention consent and safe inspection."""

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
from app.api.native_patch_contracts import (
    GenerateNativePatch,
    NativePatchCandidate,
    NativePatchSelection,
    NativePatchSummary,
    native_patch_summary,
)
from app.api.service import AnalysisService
from app.audit.results import capture_result
from app.core.permissions import Role
from app.db.native_patch_records import NativePatchInputNotFound, NativePatchTooLarge
from app.db.patch_records import PatchConflict
from app.patching.native_patches import NativePatchWorkflow

router = APIRouter(prefix="/api/v2/configurations/{configuration_id}", tags=["native candidates"])
DraftService = Annotated[AnalysisService, Depends(require_access("draft"))]


@router.get("/native-patch-selection/{analysis_id}", response_model=NativePatchSelection)
def native_patch_selection(
    configuration_id: UUID, analysis_id: UUID, request: Request, service: Service
) -> NativePatchSelection:
    try:
        result = NativePatchWorkflow(service.store).selection(configuration_id, analysis_id)
    except NativePatchInputNotFound:
        raise HTTPException(status_code=404, detail="Selected analysis not found.") from None
    except PatchConflict:
        raise HTTPException(status_code=409, detail="Selected analysis is incompatible.") from None
    return capture_result(request, result)


@router.post(
    "/native-patches",
    response_model=NativePatchCandidate,
    status_code=201,
    responses={
        200: {"model": NativePatchCandidate, "description": "Existing immutable candidate."}
    },
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                "application/json": {
                    "schema": _request_schema(GenerateNativePatch, explicit_version=True)
                }
            },
        }
    },
)
async def generate_native_patch(
    configuration_id: UUID, request: Request, response: Response, service: DraftService
) -> NativePatchCandidate:
    body = await _request_body(request, maximum=16 * 1024)
    try:
        options = GenerateNativePatch.model_validate(
            json.loads(body.decode(), object_pairs_hook=_unique_keys)
        )
    except (ValueError, RecursionError):
        raise HTTPException(status_code=400, detail="Invalid native candidate request.") from None
    try:
        result, created = await run_in_threadpool(
            NativePatchWorkflow(service.store).create,
            configuration_id,
            options,
            cast(Role, request.state.service_role),
        )
    except NativePatchInputNotFound:
        raise HTTPException(status_code=404, detail="Selected input not found.") from None
    except PatchConflict:
        raise HTTPException(
            status_code=409, detail="Selected source, finding or candidate conflicts."
        ) from None
    except NativePatchTooLarge:
        raise HTTPException(
            status_code=413, detail="Native candidate exceeds its budget."
        ) from None
    response.status_code = 201 if created else 200
    return capture_result(request, result)


@router.get("/native-patches", response_model=list[NativePatchSummary])
def list_native_patches(
    configuration_id: UUID,
    request: Request,
    service: Service,
    limit: Limit = 20,
    offset: Offset = 0,
) -> list[NativePatchSummary]:
    workflow = NativePatchWorkflow(service.store)
    if not workflow.records.configuration_exists(configuration_id):
        raise HTTPException(status_code=404, detail="Selected configuration not found.")
    return capture_result(
        request,
        [
            native_patch_summary(workflow.get(configuration_id, key))
            for key in workflow.records.list_ids(configuration_id, limit=limit, offset=offset)
        ],
    )


@router.get("/native-patches/{candidate_id}", response_model=NativePatchCandidate)
def get_native_patch(
    configuration_id: UUID, candidate_id: UUID, request: Request, service: Service
) -> NativePatchCandidate:
    try:
        result = NativePatchWorkflow(service.store).get(configuration_id, candidate_id)
    except NativePatchInputNotFound:
        raise HTTPException(
            status_code=404, detail="Selected native candidate not found."
        ) from None
    return capture_result(request, result)
