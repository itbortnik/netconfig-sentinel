"""Authenticated append-only draft and local review API with idempotent intent IDs."""

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
from app.api.patch_contracts import (
    CreatePatchDraft,
    PatchDraft,
    PatchSummary,
    VerificationRun,
    VerificationSummary,
    VerifyPatch,
)
from app.api.service import AnalysisService
from app.audit.results import capture_result
from app.comparison.snapshots import DiffConflict, DiffLimitExceeded
from app.db.patch_records import PatchConflict
from app.patching.persistent import FormalVerificationUnavailable, PatchNotFound, PatchWorkflow

router = APIRouter(prefix="/api/v1/patches", tags=["draft changes and local review"])
DraftService = Annotated[AnalysisService, Depends(require_access("draft"))]
VerificationService = Annotated[AnalysisService, Depends(require_access("verify"))]


def _error(exception: Exception) -> HTTPException:
    if isinstance(exception, PatchNotFound):
        return HTTPException(status_code=404, detail="Draft or selected snapshot not found.")
    if isinstance(exception, DiffLimitExceeded):
        return HTTPException(status_code=413, detail="Draft or review exceeds size limits.")
    if isinstance(exception, FormalVerificationUnavailable):
        return HTTPException(
            status_code=503, detail="Formal verification is unavailable in this API."
        )
    return HTTPException(status_code=409, detail="Draft identity or selected snapshots conflict.")


@router.post(
    "",
    response_model=PatchDraft,
    status_code=201,
    responses={200: {"model": PatchDraft, "description": "The same draft intent already exists."}},
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                "application/json": {"schema": _request_schema(CreatePatchDraft)},
            },
        }
    },
)
async def create_patch(request: Request, response: Response, service: DraftService) -> PatchDraft:
    body = await _request_body(request, maximum=16 * 1024)
    try:
        options = CreatePatchDraft.model_validate(
            json.loads(body.decode("utf-8"), object_pairs_hook=_unique_keys)
        )
    except (ValueError, RecursionError):
        raise HTTPException(status_code=400, detail="Invalid draft request.") from None
    try:
        result, created = await run_in_threadpool(PatchWorkflow(service.store).create, options)
    except (PatchNotFound, PatchConflict, DiffConflict, DiffLimitExceeded) as exception:
        raise _error(exception) from None
    response.status_code = 201 if created else 200
    return capture_result(request, result)


@router.get("", response_model=list[PatchSummary])
def list_patches(
    after_configuration_id: UUID,
    request: Request,
    service: Service,
    limit: Limit = 20,
    offset: Offset = 0,
) -> list[PatchSummary]:
    if service.store.get_configuration(after_configuration_id) is None:
        raise _error(PatchNotFound())
    return capture_result(
        request,
        [
            PatchSummary.from_draft(item)
            for item in PatchWorkflow(service.store).records.list_drafts(
                after_id=after_configuration_id,
                limit=limit,
                offset=offset,
            )
        ],
    )


@router.get("/{patch_id}", response_model=PatchDraft)
def get_patch(patch_id: UUID, request: Request, service: Service) -> PatchDraft:
    try:
        return capture_result(request, PatchWorkflow(service.store).draft(patch_id))
    except PatchNotFound as exception:
        raise _error(exception) from None


@router.post(
    "/{patch_id}/verify",
    response_model=VerificationRun,
    status_code=201,
    responses={
        200: {"model": VerificationRun, "description": "The same review intent already exists."}
    },
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                "application/json": {"schema": _request_schema(VerifyPatch)},
            },
        }
    },
)
async def verify_patch(
    patch_id: UUID, request: Request, response: Response, service: VerificationService
) -> VerificationRun:
    body = await _request_body(request, maximum=16 * 1024)
    try:
        options = VerifyPatch.model_validate(
            json.loads(body.decode("utf-8"), object_pairs_hook=_unique_keys)
        )
    except (ValueError, RecursionError):
        raise HTTPException(status_code=400, detail="Invalid verification request.") from None
    try:
        result, created = await run_in_threadpool(
            PatchWorkflow(service.store).verify, patch_id, options
        )
    except (
        PatchNotFound,
        PatchConflict,
        DiffConflict,
        DiffLimitExceeded,
        FormalVerificationUnavailable,
    ) as exception:
        raise _error(exception) from None
    response.status_code = 201 if created else 200
    return capture_result(request, result)


@router.get("/{patch_id}/verifications", response_model=list[VerificationSummary])
def list_verifications(
    patch_id: UUID, request: Request, service: Service, limit: Limit = 20, offset: Offset = 0
) -> list[VerificationSummary]:
    workflow = PatchWorkflow(service.store)
    try:
        draft = workflow.draft(patch_id)
    except PatchNotFound as exception:
        raise _error(exception) from None
    return capture_result(
        request,
        [
            VerificationSummary.from_run(run)
            for run in workflow.records.list_reviews(draft, limit=limit, offset=offset)
        ],
    )


@router.get("/{patch_id}/verifications/{verification_id}", response_model=VerificationRun)
def get_verification(
    patch_id: UUID, verification_id: UUID, request: Request, service: Service
) -> VerificationRun:
    workflow = PatchWorkflow(service.store)
    try:
        workflow.draft(patch_id)
    except PatchNotFound as exception:
        raise _error(exception) from None
    run = workflow.records.get_review(verification_id)
    if run is None or run.patch_id != patch_id:
        raise _error(PatchNotFound())
    return capture_result(request, run)
