"""Explicit immutable service-role dispositions; approval and device execution are unavailable."""

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
from app.api.source_evidence_decision_contracts import (
    ReviewSourceEvidenceReport,
)
from app.api.source_evidence_decision_direction_contracts import (
    ReviewSourceEvidenceReportV3,
    SourceEvidenceDecisionRecord,
    SourceEvidenceDecisionSummaryRecord,
    parse_source_evidence_decision_request,
    source_evidence_decision_summary,
)
from app.api.source_evidence_decision_sdk_contracts import ReviewSourceEvidenceReportV2
from app.audit.results import capture_result
from app.core.permissions import Role
from app.db.patch_records import PatchConflict
from app.db.source_evidence_decision_records import (
    SourceEvidenceDecisionInputNotFound,
    SourceEvidenceDecisionTooLarge,
)
from app.patching.persistent import PatchNotFound
from app.patching.source_evidence_decision import SourceEvidenceDecisionWorkflow

router = APIRouter(
    prefix="/api/v2/patches/{patch_id}/evidence-reports/{report_id}/decisions",
    tags=["source evidence dispositions"],
)
VerificationService = Annotated[AnalysisService, Depends(require_access("verify"))]


@router.post(
    "",
    response_model=SourceEvidenceDecisionRecord,
    status_code=201,
    responses={
        200: {"model": SourceEvidenceDecisionRecord, "description": "Existing immutable decision."}
    },
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                "application/json": {
                    "schema": {
                        "anyOf": [
                            _request_schema(ReviewSourceEvidenceReport),
                            _request_schema(ReviewSourceEvidenceReportV2),
                            _request_schema(ReviewSourceEvidenceReportV3),
                        ]
                    }
                },
            },
        }
    },
)
async def record_source_evidence_decision(
    patch_id: UUID,
    report_id: UUID,
    request: Request,
    response: Response,
    service: VerificationService,
) -> SourceEvidenceDecisionRecord:
    body = await _request_body(request, maximum=16 * 1024)
    try:
        options = parse_source_evidence_decision_request(
            json.loads(body.decode(), object_pairs_hook=_unique_keys)
        )
    except (ValueError, RecursionError):
        raise HTTPException(status_code=400, detail="Invalid evidence decision request.") from None
    try:
        result, created = await run_in_threadpool(
            SourceEvidenceDecisionWorkflow(service.store).create,
            patch_id,
            report_id,
            options,
            cast(Role, request.state.service_role),
        )
    except (PatchNotFound, SourceEvidenceDecisionInputNotFound):
        raise HTTPException(status_code=404, detail="Selected report not found.") from None
    except PatchConflict:
        raise HTTPException(
            status_code=409, detail="Selected report or decision conflicts."
        ) from None
    except SourceEvidenceDecisionTooLarge:
        raise HTTPException(
            status_code=413, detail="Evidence decision exceeds its budget."
        ) from None
    response.status_code = 201 if created else 200
    return capture_result(request, result)


@router.get("", response_model=list[SourceEvidenceDecisionSummaryRecord])
def list_source_evidence_decisions(
    patch_id: UUID,
    report_id: UUID,
    request: Request,
    service: Service,
    limit: Limit = 20,
    offset: Offset = 0,
) -> list[SourceEvidenceDecisionSummaryRecord]:
    workflow = SourceEvidenceDecisionWorkflow(service.store)
    try:
        workflow.reports.get(patch_id, report_id)
    except PatchNotFound:
        raise HTTPException(status_code=404, detail="Selected report not found.") from None
    return capture_result(
        request,
        [
            source_evidence_decision_summary(workflow.get(patch_id, report_id, key))
            for key in workflow.records.list_ids(patch_id, report_id, limit=limit, offset=offset)
        ],
    )


@router.get("/{decision_id}", response_model=SourceEvidenceDecisionRecord)
def get_source_evidence_decision(
    patch_id: UUID, report_id: UUID, decision_id: UUID, request: Request, service: Service
) -> SourceEvidenceDecisionRecord:
    try:
        return capture_result(
            request,
            SourceEvidenceDecisionWorkflow(service.store).get(patch_id, report_id, decision_id),
        )
    except PatchNotFound:
        raise HTTPException(
            status_code=404, detail="Selected evidence decision not found."
        ) from None
