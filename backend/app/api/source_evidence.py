"""Explicit selected evidence reports; these routes never execute a detector."""

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
from app.api.source_evidence_contracts import (
    CreateSourceEvidenceReport,
)
from app.api.source_evidence_direction_contracts import CreateSourceEvidenceReportV3
from app.api.source_evidence_scope_contracts import (
    CreateSourceEvidenceReportV4,
    SourceEvidenceReportRecord,
    SourceEvidenceSummaryRecord,
    parse_source_evidence_request,
    source_evidence_summary,
)
from app.api.source_evidence_sdk_contracts import CreateSourceEvidenceReportV2
from app.audit.results import capture_result
from app.db.patch_records import PatchConflict
from app.db.source_evidence_records import SourceEvidenceInputNotFound, SourceEvidenceTooLarge
from app.patching.persistent import PatchNotFound
from app.patching.source_evidence import SourceEvidenceWorkflow

router = APIRouter(prefix="/api/v2/patches", tags=["selected source evidence"])
VerificationService = Annotated[AnalysisService, Depends(require_access("verify"))]


@router.post(
    "/{patch_id}/evidence-reports",
    response_model=SourceEvidenceReportRecord,
    status_code=201,
    responses={
        200: {"model": SourceEvidenceReportRecord, "description": "Existing immutable report."}
    },
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                "application/json": {
                    "schema": {
                        "anyOf": [
                            _request_schema(CreateSourceEvidenceReport),
                            _request_schema(CreateSourceEvidenceReportV2),
                            _request_schema(CreateSourceEvidenceReportV3),
                            _request_schema(CreateSourceEvidenceReportV4),
                        ]
                    }
                },
            },
        }
    },
)
async def create_source_evidence_report(
    patch_id: UUID, request: Request, response: Response, service: VerificationService
) -> SourceEvidenceReportRecord:
    body = await _request_body(request, maximum=16 * 1024)
    try:
        options = parse_source_evidence_request(
            json.loads(body.decode(), object_pairs_hook=_unique_keys)
        )
    except (ValueError, RecursionError):
        raise HTTPException(status_code=400, detail="Invalid evidence report request.") from None
    try:
        result, created = await run_in_threadpool(
            SourceEvidenceWorkflow(service.store).create, patch_id, options
        )
    except (PatchNotFound, SourceEvidenceInputNotFound):
        raise HTTPException(status_code=404, detail="Selected draft or result not found.") from None
    except PatchConflict:
        raise HTTPException(
            status_code=409,
            detail="Selected result, source, original analysis or report conflicts.",
        ) from None
    except SourceEvidenceTooLarge:
        raise HTTPException(
            status_code=413, detail="Selected evidence exceeds its budget."
        ) from None
    response.status_code = 201 if created else 200
    return capture_result(request, result)


@router.get("/{patch_id}/evidence-reports", response_model=list[SourceEvidenceSummaryRecord])
def list_source_evidence_reports(
    patch_id: UUID, request: Request, service: Service, limit: Limit = 20, offset: Offset = 0
) -> list[SourceEvidenceSummaryRecord]:
    workflow = SourceEvidenceWorkflow(service.store)
    try:
        workflow.drafts.draft(patch_id)
    except PatchNotFound:
        raise HTTPException(status_code=404, detail="Selected draft not found.") from None
    return capture_result(
        request,
        [
            source_evidence_summary(workflow.get(patch_id, key))
            for key in workflow.records.list_ids(patch_id, limit=limit, offset=offset)
        ],
    )


@router.get("/{patch_id}/evidence-reports/{report_id}", response_model=SourceEvidenceReportRecord)
def get_source_evidence_report(
    patch_id: UUID, report_id: UUID, request: Request, service: Service
) -> SourceEvidenceReportRecord:
    try:
        return capture_result(
            request, SourceEvidenceWorkflow(service.store).get(patch_id, report_id)
        )
    except PatchNotFound:
        raise HTTPException(status_code=404, detail="Selected evidence report not found.") from None
