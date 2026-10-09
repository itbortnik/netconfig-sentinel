"""Saved exact-candidate verification and service-role decisions, never device execution."""

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
from app.api.model_patch_review_contracts import (
    ReviewSavedModelPatch,
    SavedPatchDecision,
    SavedPatchVerification,
    VerifySavedModelPatch,
)
from app.api.service import AnalysisService
from app.audit.results import capture_result
from app.core.permissions import Role
from app.db.model_patch_records import ModelPatchConflict
from app.patching.saved_model import SavedModelPatchNotFound
from app.patching.saved_review import SavedPatchReviewFailed, SavedPatchReviewWorkflow
from app.verification.patch_runtime import (
    PatchVerificationBusy,
    PatchVerificationDisabled,
    PatchVerificationRuntime,
)

router = APIRouter(prefix="/api/v1/model-patches", tags=["saved model candidate verification"])
VerifyService = Annotated[AnalysisService, Depends(require_access("verify"))]
DecisionService = Annotated[AnalysisService, Depends(require_access("feedback"))]


@router.post(
    "/{patch_id}/verify",
    response_model=SavedPatchVerification,
    status_code=201,
    responses={
        200: {
            "model": SavedPatchVerification,
            "description": "Existing verification; no new execution.",
        }
    },
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {"application/json": {"schema": _request_schema(VerifySavedModelPatch)}},
        }
    },
)
async def verify_model_patch(
    patch_id: UUID, request: Request, response: Response, service: VerifyService
) -> SavedPatchVerification:
    body = await _request_body(request, maximum=16 * 1024)
    try:
        options = VerifySavedModelPatch.model_validate(
            json.loads(body.decode(), object_pairs_hook=_unique_keys)
        )
    except (ValueError, RecursionError):
        raise HTTPException(
            status_code=400, detail="Invalid model patch verification request."
        ) from None
    if (options.mode == "batfish" and not options.allow_local_engine_upload) or (
        options.transformer_sha256 is not None and not options.allow_local_model_context
    ):
        raise HTTPException(
            status_code=403, detail="Explicit selected local worker context permission is required."
        )
    runtime = cast(PatchVerificationRuntime, request.app.state.patch_verification)
    try:
        result, created = await run_in_threadpool(
            SavedPatchReviewWorkflow(service).verify, patch_id, options, runtime
        )
    except SavedModelPatchNotFound:
        raise HTTPException(status_code=404, detail="Selected model patch not found.") from None
    except ModelPatchConflict:
        raise HTTPException(
            status_code=409,
            detail="Selected proposal, retained network or verification identity conflicts.",
        ) from None
    except PatchVerificationDisabled:
        raise HTTPException(
            status_code=503, detail="Selected local verification worker is disabled."
        ) from None
    except PatchVerificationBusy:
        raise HTTPException(
            status_code=429, detail="Local verification worker is busy; no attempt was started."
        ) from None
    except SavedPatchReviewFailed:
        raise HTTPException(
            status_code=503,
            detail="Verification failed; inspect the saved attempt before retrying.",
        ) from None
    response.status_code = 201 if created else 200
    return capture_result(request, result)


@router.get("/{patch_id}/verifications/{verification_id}", response_model=SavedPatchVerification)
def get_model_patch_verification(
    patch_id: UUID, verification_id: UUID, request: Request, service: Service
) -> SavedPatchVerification:
    try:
        return capture_result(
            request, SavedPatchReviewWorkflow(service).get(patch_id, verification_id)
        )
    except SavedModelPatchNotFound:
        raise HTTPException(status_code=404, detail="Selected verification not found.") from None


@router.get("/{patch_id}/verifications", response_model=list[SavedPatchVerification])
def list_model_patch_verifications(
    patch_id: UUID, request: Request, service: Service, limit: Limit = 20, offset: Offset = 0
) -> list[SavedPatchVerification]:
    workflow = SavedPatchReviewWorkflow(service)
    try:
        workflow.generation.get(patch_id)
    except SavedModelPatchNotFound:
        raise HTTPException(status_code=404, detail="Selected model patch not found.") from None
    return capture_result(
        request,
        [
            workflow.get(patch_id, key)
            for key in workflow.records.list_ids(
                patch_id, decisions=False, limit=limit, offset=offset
            )
        ],
    )


@router.post(
    "/{patch_id}/decisions",
    response_model=SavedPatchDecision,
    status_code=201,
    responses={200: {"model": SavedPatchDecision, "description": "Existing immutable decision."}},
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {"application/json": {"schema": _request_schema(ReviewSavedModelPatch)}},
        }
    },
)
async def decide_model_patch(
    patch_id: UUID, request: Request, response: Response, service: DecisionService
) -> SavedPatchDecision:
    body = await _request_body(request, maximum=16 * 1024)
    try:
        options = ReviewSavedModelPatch.model_validate(
            json.loads(body.decode(), object_pairs_hook=_unique_keys)
        )
    except (ValueError, RecursionError):
        raise HTTPException(
            status_code=400, detail="Invalid model patch decision request."
        ) from None
    try:
        result, created = await run_in_threadpool(
            SavedPatchReviewWorkflow(service).decide,
            patch_id,
            options,
            cast(Role, request.state.service_role),
        )
    except SavedModelPatchNotFound:
        raise HTTPException(status_code=404, detail="Selected verification not found.") from None
    except ModelPatchConflict:
        raise HTTPException(
            status_code=409,
            detail="Decision requires matching evidence and explicit approval attestations.",
        ) from None
    response.status_code = 201 if created else 200
    return capture_result(request, result)


@router.get("/{patch_id}/decisions/{decision_id}", response_model=SavedPatchDecision)
def get_model_patch_decision(
    patch_id: UUID, decision_id: UUID, request: Request, service: Service
) -> SavedPatchDecision:
    try:
        return capture_result(
            request, SavedPatchReviewWorkflow(service).get_decision(patch_id, decision_id)
        )
    except SavedModelPatchNotFound:
        raise HTTPException(status_code=404, detail="Selected decision not found.") from None


@router.get("/{patch_id}/decisions", response_model=list[SavedPatchDecision])
def list_model_patch_decisions(
    patch_id: UUID, request: Request, service: Service, limit: Limit = 20, offset: Offset = 0
) -> list[SavedPatchDecision]:
    workflow = SavedPatchReviewWorkflow(service)
    try:
        workflow.generation.get(patch_id)
    except SavedModelPatchNotFound:
        raise HTTPException(status_code=404, detail="Selected model patch not found.") from None
    return capture_result(
        request,
        [
            workflow.get_decision(patch_id, key)
            for key in workflow.records.list_ids(
                patch_id, decisions=True, limit=limit, offset=offset
            )
        ],
    )
