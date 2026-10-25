"""Explicit saved original-Deterministic selection and immutable ordinary draft rechecks."""

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
from app.api.source_deterministic_contracts import (
    RunSourceDeterministicRecheck,
    SourceDeterministicSelection,
)
from app.api.source_partial_contracts import (
    RunSourcePartialDiagnostic,
    SourceDeterministicRecord,
    SourceDeterministicSummaryRecord,
    parse_source_deterministic_request,
    source_deterministic_summary,
)
from app.audit.results import capture_result
from app.db.patch_records import PatchConflict
from app.patching.persistent import PatchNotFound
from app.patching.source_deterministic import (
    SourceDeterministicConsentRequired,
    SourceDeterministicTooLarge,
    SourceDeterministicWorkflow,
)

router = APIRouter(prefix="/api/v2/patches", tags=["original deterministic source models"])
VerificationService = Annotated[AnalysisService, Depends(require_access("verify"))]


@router.get(
    "/{patch_id}/deterministic-selection/{analysis_id}", response_model=SourceDeterministicSelection
)
def source_deterministic_selection(
    patch_id: UUID, analysis_id: UUID, request: Request, service: Service
) -> SourceDeterministicSelection:
    try:
        return capture_result(
            request, SourceDeterministicWorkflow(service.store).selection(patch_id, analysis_id)
        )
    except PatchNotFound:
        raise HTTPException(
            status_code=404, detail="Selected draft or analysis not found."
        ) from None
    except PatchConflict:
        raise HTTPException(
            status_code=409, detail="Selected original deterministic analysis differs."
        ) from None


@router.post(
    "/{patch_id}/deterministic-rechecks",
    response_model=SourceDeterministicRecord,
    status_code=201,
    responses={
        200: {
            "model": SourceDeterministicRecord,
            "description": "Existing attempt; no evaluation.",
        }
    },
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                "application/json": {
                    "schema": {
                        "anyOf": [
                            _request_schema(RunSourceDeterministicRecheck),
                            _request_schema(RunSourcePartialDiagnostic, explicit_version=True),
                        ]
                    }
                },
            },
        }
    },
)
async def run_source_deterministic_recheck(
    patch_id: UUID, request: Request, response: Response, service: VerificationService
) -> SourceDeterministicRecord:
    body = await _request_body(request, maximum=16 * 1024)
    try:
        options = parse_source_deterministic_request(
            json.loads(body.decode(), object_pairs_hook=_unique_keys)
        )
    except (ValueError, RecursionError):
        raise HTTPException(
            status_code=400, detail="Invalid deterministic recheck request."
        ) from None
    try:
        result, created = await run_in_threadpool(
            SourceDeterministicWorkflow(service.store).run, patch_id, options
        )
    except PatchNotFound:
        raise HTTPException(
            status_code=404, detail="Selected draft or analysis not found."
        ) from None
    except PatchConflict:
        raise HTTPException(
            status_code=409,
            detail="Selected source, original analysis, reference or recheck identity conflicts.",
        ) from None
    except SourceDeterministicConsentRequired:
        raise HTTPException(
            status_code=403, detail="Explicit local analysis context consent is required."
        ) from None
    except SourceDeterministicTooLarge:
        raise HTTPException(
            status_code=413, detail="Deterministic pair exceeds its budget."
        ) from None
    response.status_code = 201 if created else 200
    return capture_result(request, result)


@router.get(
    "/{patch_id}/deterministic-rechecks", response_model=list[SourceDeterministicSummaryRecord]
)
def list_source_deterministic_rechecks(
    patch_id: UUID, request: Request, service: Service, limit: Limit = 20, offset: Offset = 0
) -> list[SourceDeterministicSummaryRecord]:
    workflow = SourceDeterministicWorkflow(service.store)
    try:
        workflow.drafts.draft(patch_id)
    except PatchNotFound:
        raise HTTPException(status_code=404, detail="Selected draft not found.") from None
    return capture_result(
        request,
        [
            source_deterministic_summary(workflow.get(patch_id, key))
            for key in workflow.records.list_ids(patch_id, limit=limit, offset=offset)
        ],
    )


@router.get(
    "/{patch_id}/deterministic-rechecks/{recheck_id}", response_model=SourceDeterministicRecord
)
def get_source_deterministic_recheck(
    patch_id: UUID, recheck_id: UUID, request: Request, service: Service
) -> SourceDeterministicRecord:
    try:
        return capture_result(
            request, SourceDeterministicWorkflow(service.store).get(patch_id, recheck_id)
        )
    except PatchNotFound:
        raise HTTPException(
            status_code=404, detail="Selected deterministic recheck not found."
        ) from None
