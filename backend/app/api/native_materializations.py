"""Explicit native materialization with private source retention consent."""

import json
from typing import Annotated, cast
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from starlette.concurrency import run_in_threadpool

from app.api.access import require_access
from app.api.configurations import Service, _request_body, _request_schema, _unique_keys
from app.api.native_materialization_contracts import (
    CreateNativeMaterialization,
    NativeMaterialization,
)
from app.api.service import AnalysisService
from app.audit.results import capture_result
from app.core.permissions import Role
from app.db.native_materialization_records import NativeMaterializationTooLarge
from app.db.native_patch_records import NativePatchInputNotFound
from app.db.patch_records import PatchConflict
from app.patching.native_materialization import NativeMaterializationWorkflow

router = APIRouter(prefix="/api/v2/configurations", tags=["native materialization"])
DraftService = Annotated[AnalysisService, Depends(require_access("draft"))]


@router.post(
    "/{configuration_id}/native-patches/{candidate_id}/materialization",
    response_model=NativeMaterialization,
    status_code=201,
    responses={200: {"model": NativeMaterialization, "description": "Existing immutable origin."}},
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                "application/json": {
                    "schema": _request_schema(CreateNativeMaterialization, explicit_version=True)
                }
            },
        }
    },
)
async def materialize_native_patch(
    configuration_id: UUID,
    candidate_id: UUID,
    request: Request,
    response: Response,
    service: DraftService,
) -> NativeMaterialization:
    body = await _request_body(request, maximum=16 * 1024)
    try:
        options = CreateNativeMaterialization.model_validate(
            json.loads(body.decode(), object_pairs_hook=_unique_keys)
        )
    except (ValueError, RecursionError):
        raise HTTPException(status_code=400, detail="Invalid materialization request.") from None
    try:
        result, created = await run_in_threadpool(
            NativeMaterializationWorkflow(service.store).create,
            configuration_id,
            candidate_id,
            options,
            cast(Role, request.state.service_role),
        )
    except NativePatchInputNotFound:
        raise HTTPException(status_code=404, detail="Selected native input not found.") from None
    except PatchConflict:
        raise HTTPException(
            status_code=409, detail="Selected native source or materialization conflicts."
        ) from None
    except NativeMaterializationTooLarge:
        raise HTTPException(status_code=413, detail="Materialization exceeds its budget.") from None
    response.status_code = 201 if created else 200
    return capture_result(request, result)


@router.get(
    "/{configuration_id}/native-patches/{candidate_id}/materialization",
    response_model=NativeMaterialization,
)
def get_native_materialization(
    configuration_id: UUID, candidate_id: UUID, request: Request, service: Service
) -> NativeMaterialization:
    try:
        result = NativeMaterializationWorkflow(service.store).get(configuration_id, candidate_id)
    except NativePatchInputNotFound:
        raise HTTPException(status_code=404, detail="Saved materialization not found.") from None
    return capture_result(request, result)


@router.get("/{after_configuration_id}/native-origin", response_model=NativeMaterialization)
def get_native_origin(
    after_configuration_id: UUID, request: Request, service: Service
) -> NativeMaterialization:
    try:
        result = NativeMaterializationWorkflow(service.store).origin(after_configuration_id)
    except NativePatchInputNotFound:
        raise HTTPException(status_code=404, detail="Saved native origin not found.") from None
    return capture_result(request, result)
