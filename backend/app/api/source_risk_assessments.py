"""Explicit saved engineering priorities over selected immutable joint evidence."""

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
from app.api.source_risk_contracts import (
    CreateSourceRiskAssessment,
    SourceRiskAssessment,
    SourceRiskSummary,
)
from app.audit.results import capture_result
from app.core.permissions import Role
from app.db.patch_records import PatchConflict
from app.db.source_risk_records import SourceRiskInputNotFound, SourceRiskTooLarge
from app.patching.persistent import PatchNotFound
from app.patching.source_risk import SourceRiskWorkflow

router = APIRouter(
    prefix="/api/v2/patches/{patch_id}/evidence-reports/{report_id}/risk-assessments",
    tags=["source engineering priorities"],
)
VerificationService = Annotated[AnalysisService, Depends(require_access("verify"))]


@router.post(
    "",
    response_model=SourceRiskAssessment,
    status_code=201,
    responses={
        200: {"model": SourceRiskAssessment, "description": "Existing immutable assessment."}
    },
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                "application/json": {"schema": _request_schema(CreateSourceRiskAssessment)}
            },
        }
    },
)
async def create_source_risk_assessment(
    patch_id: UUID,
    report_id: UUID,
    request: Request,
    response: Response,
    service: VerificationService,
) -> SourceRiskAssessment:
    body = await _request_body(request, maximum=16 * 1024)
    try:
        options = CreateSourceRiskAssessment.model_validate(
            json.loads(body.decode(), object_pairs_hook=_unique_keys)
        )
    except (ValueError, RecursionError):
        raise HTTPException(
            status_code=400, detail="Invalid priority assessment request."
        ) from None
    try:
        result, created = await run_in_threadpool(
            SourceRiskWorkflow(service.store).create,
            patch_id,
            report_id,
            options,
            cast(Role, request.state.service_role),
        )
    except (PatchNotFound, SourceRiskInputNotFound):
        raise HTTPException(status_code=404, detail="Selected report not found.") from None
    except PatchConflict:
        raise HTTPException(
            status_code=409, detail="Selected report or assessment conflicts."
        ) from None
    except SourceRiskTooLarge:
        raise HTTPException(
            status_code=413, detail="Priority assessment exceeds its budget."
        ) from None
    response.status_code = 201 if created else 200
    return capture_result(request, result)


@router.get("", response_model=list[SourceRiskSummary])
def list_source_risk_assessments(
    patch_id: UUID,
    report_id: UUID,
    request: Request,
    service: Service,
    limit: Limit = 20,
    offset: Offset = 0,
) -> list[SourceRiskSummary]:
    workflow = SourceRiskWorkflow(service.store)
    try:
        workflow.reports.get(patch_id, report_id)
    except PatchNotFound:
        raise HTTPException(status_code=404, detail="Selected report not found.") from None
    return capture_result(
        request,
        [
            SourceRiskSummary.from_assessment(workflow.get(patch_id, report_id, key))
            for key in workflow.records.list_ids(patch_id, report_id, limit=limit, offset=offset)
        ],
    )


@router.get("/{assessment_id}", response_model=SourceRiskAssessment)
def get_source_risk_assessment(
    patch_id: UUID, report_id: UUID, assessment_id: UUID, request: Request, service: Service
) -> SourceRiskAssessment:
    try:
        return capture_result(
            request, SourceRiskWorkflow(service.store).get(patch_id, report_id, assessment_id)
        )
    except PatchNotFound:
        raise HTTPException(
            status_code=404, detail="Selected priority assessment not found."
        ) from None
