"""Explicit v2 saved-source network review; v1 local review remains unchanged."""

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
from app.api.source_patch_contracts import (
    SourcePatchCapabilities,
    VerifySourcePatch,
)
from app.api.source_patch_direction_contracts import (
    SourcePatchReview,
    SourcePatchSummary,
    VerifySourcePatchV3,
    parse_source_patch_request,
    source_patch_summary,
)
from app.api.source_patch_sdk_contracts import VerifySourcePatchV2
from app.audit.results import capture_result
from app.db.patch_records import PatchConflict
from app.patching.persistent import PatchNotFound
from app.patching.source_review import (
    SourcePatchConsentRequired,
    SourcePatchReviewTooLarge,
    SourcePatchWorkflow,
)
from app.verification.patch_runtime import (
    PatchVerificationBusy,
    PatchVerificationDisabled,
    PatchVerificationRuntime,
)

router = APIRouter(prefix="/api/v2/patches", tags=["exact saved source network verification"])
VerifyService = Annotated[AnalysisService, Depends(require_access("verify"))]


@router.get("/capabilities", response_model=SourcePatchCapabilities)
def source_patch_capabilities(request: Request, service: Service) -> SourcePatchCapabilities:
    runtime = cast(PatchVerificationRuntime, request.app.state.patch_verification)
    return capture_result(
        request,
        SourcePatchCapabilities(
            network_engine="configured" if runtime.settings.allow_engine_upload else "disabled"
        ),
    )


@router.post(
    "/{patch_id}/verify",
    response_model=SourcePatchReview,
    status_code=201,
    responses={200: {"model": SourcePatchReview, "description": "Existing attempt; no execution."}},
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                "application/json": {
                    "schema": {
                        "anyOf": [
                            _request_schema(VerifySourcePatch),
                            _request_schema(VerifySourcePatchV2),
                            _request_schema(VerifySourcePatchV3),
                        ]
                    }
                }
            },
        }
    },
)
async def verify_source_patch(
    patch_id: UUID, request: Request, response: Response, service: VerifyService
) -> SourcePatchReview:
    body = await _request_body(request, maximum=16 * 1024)
    try:
        options = parse_source_patch_request(
            json.loads(body.decode(), object_pairs_hook=_unique_keys)
        )
    except (ValueError, RecursionError):
        raise HTTPException(
            status_code=400, detail="Invalid source verification request."
        ) from None
    runtime = cast(PatchVerificationRuntime, request.app.state.patch_verification)
    try:
        result, created = await run_in_threadpool(
            SourcePatchWorkflow(service.store).verify, patch_id, options, runtime
        )
    except PatchNotFound:
        raise HTTPException(status_code=404, detail="Selected draft not found.") from None
    except PatchConflict:
        raise HTTPException(
            status_code=409, detail="Selected sources or verification identity conflict."
        ) from None
    except SourcePatchConsentRequired:
        raise HTTPException(
            status_code=403, detail="Explicit local engine upload consent is required."
        ) from None
    except PatchVerificationDisabled:
        raise HTTPException(
            status_code=503, detail="Local network verification is disabled."
        ) from None
    except PatchVerificationBusy:
        raise HTTPException(
            status_code=429, detail="Local verification worker is busy; no attempt started."
        ) from None
    except SourcePatchReviewTooLarge:
        raise HTTPException(
            status_code=413, detail="Source verification exceeds its report budget."
        ) from None
    response.status_code = 201 if created else 200
    return capture_result(request, result)


@router.get("/{patch_id}/verifications", response_model=list[SourcePatchSummary])
def list_source_patch_verifications(
    patch_id: UUID, request: Request, service: Service, limit: Limit = 20, offset: Offset = 0
) -> list[SourcePatchSummary]:
    workflow = SourcePatchWorkflow(service.store)
    try:
        workflow.drafts.draft(patch_id)
    except PatchNotFound:
        raise HTTPException(status_code=404, detail="Selected draft not found.") from None
    return capture_result(
        request,
        [
            source_patch_summary(workflow.get(patch_id, key))
            for key in workflow.records.list_ids(patch_id, limit=limit, offset=offset)
        ],
    )


@router.get("/{patch_id}/verifications/{verification_id}", response_model=SourcePatchReview)
def get_source_patch_verification(
    patch_id: UUID, verification_id: UUID, request: Request, service: Service
) -> SourcePatchReview:
    try:
        return capture_result(
            request, SourcePatchWorkflow(service.store).get(patch_id, verification_id)
        )
    except PatchNotFound:
        raise HTTPException(
            status_code=404, detail="Selected source verification not found."
        ) from None
