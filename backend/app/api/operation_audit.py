"""Admin-only, bounded append-only operation history; no update/delete endpoint."""

from typing import Annotated, cast
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app.api.access import require_access
from app.api.service import AnalysisService
from app.audit.contracts import OperationPage, OperationRecord, Receipt
from app.audit.journal import OperationJournal
from app.audit.results import capture_result

router = APIRouter(prefix="/api/v1/operation-audit", tags=["operation history"])
AuditService = Annotated[AnalysisService, Depends(require_access("read_audit"))]


@router.get("", response_model=OperationPage)
def list_operation_audit(
    request: Request,
    service: AuditService,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    before: UUID | None = None,
) -> OperationPage:
    current = cast(Receipt | None, getattr(request.state, "operation_receipt", None))
    try:
        page = OperationJournal(service.store).page(
            limit=limit,
            before=before,
            exclude=current.operation_id if current is not None else None,
        )
    except ValueError:
        raise HTTPException(status_code=400, detail="Unknown operation history cursor.") from None
    return capture_result(request, page)


@router.get("/{operation_id}", response_model=OperationRecord)
def get_operation_audit(
    operation_id: UUID,
    request: Request,
    service: AuditService,
) -> OperationRecord:
    record = OperationJournal(service.store).get(operation_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Operation not found.")
    return capture_result(request, record)
