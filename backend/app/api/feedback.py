"""Authenticated, bounded, immutable and idempotent human assessment endpoints."""

import json
from uuid import UUID

from fastapi import APIRouter, HTTPException, Request, Response
from starlette.concurrency import run_in_threadpool

from app.api.configurations import (
    Limit,
    Offset,
    Service,
    _request_body,
    _request_schema,
    _unique_keys,
)
from app.api.feedback_contracts import FeedbackRecord, SubmitFeedback
from app.api.service import FeedbackTargetNotFound
from app.db.store import FeedbackConflict

router = APIRouter(prefix="/api/v1", tags=["feedback"])


@router.post(
    "/findings/{finding_id}/feedback",
    response_model=FeedbackRecord,
    status_code=201,
    responses={
        200: {"model": FeedbackRecord, "description": "The same submission already exists."}
    },
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                "application/json": {"schema": _request_schema(SubmitFeedback)},
            },
        }
    },
)
async def submit_feedback(
    finding_id: UUID, request: Request, response: Response, service: Service
) -> FeedbackRecord:
    body = await _request_body(request, maximum=16 * 1024)
    try:
        submission = SubmitFeedback.model_validate(
            json.loads(body.decode("utf-8"), object_pairs_hook=_unique_keys)
        )
    except (ValueError, RecursionError):
        raise HTTPException(status_code=400, detail="Invalid feedback submission.") from None
    try:
        record, created = await run_in_threadpool(service.submit_feedback, finding_id, submission)
    except FeedbackTargetNotFound:
        raise HTTPException(status_code=404, detail="Analysis finding not found.") from None
    except FeedbackConflict:
        raise HTTPException(
            status_code=409, detail="Feedback identity or finding binding conflicts."
        ) from None
    response.status_code = 201 if created else 200
    return record


@router.get("/findings/{finding_id}/feedback", response_model=list[FeedbackRecord])
def list_feedback(
    finding_id: UUID, analysis_id: UUID, service: Service, limit: Limit = 20, offset: Offset = 0
) -> list[FeedbackRecord]:
    try:
        analysis, _ = service.feedback_target(analysis_id, finding_id)
    except FeedbackTargetNotFound:
        raise HTTPException(status_code=404, detail="Analysis finding not found.") from None
    return service.store.list_feedback(
        analysis=analysis, finding_id=finding_id, limit=limit, offset=offset
    )
