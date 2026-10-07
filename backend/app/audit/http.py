"""Durable receipt before dispatch; completion describes a response, not client delivery."""

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from time import monotonic
from typing import cast, get_args
from uuid import uuid4

from fastapi import Request
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError
from starlette.concurrency import run_in_threadpool
from starlette.responses import Response
from starlette.routing import Match

from app.audit.contracts import (
    Completion,
    Method,
    Operation,
    PermissionDecision,
    Receipt,
    ResultMetadata,
)
from app.audit.journal import OperationJournal
from app.core.permissions import Permission
from app.core.settings import ApiSettings
from app.db.store import StorageIntegrityError


def _operation(request: Request) -> Operation:
    partial: Operation = "unmatched_api"
    for route in request.app.state.operation_routes:
        match, _ = route.matches(request.scope)
        if match in {Match.FULL, Match.PARTIAL}:
            name = getattr(route, "name", None)
            if name in get_args(Operation.__value__):
                if match == Match.FULL:
                    return cast(Operation, name)
                if partial == "unmatched_api":
                    partial = cast(Operation, name)
    return partial


async def journal_response(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
    journal: OperationJournal | None,
    settings: ApiSettings | None,
) -> Response:
    if (
        journal is None
        or settings is None
        or not (request.url.path == "/api/v1" or request.url.path.startswith("/api/v1/"))
    ):
        return await call_next(request)
    try:
        ready = await run_in_threadpool(journal.ready)
    except (SQLAlchemyError, StorageIntegrityError):
        return JSONResponse({"detail": "Stored data is unavailable."}, status_code=503)
    if not ready:
        # Dependencies authenticate first, then forbid domain access on old schemas.
        # A later successful readiness check must not run an endpoint without a durable receipt.
        request.state.operation_journal_unavailable = True
        return await call_next(request)
    scheme, _, credential = request.headers.get("authorization", "").partition(" ")
    role = (
        settings.role_for_token(credential)
        if (scheme.lower() == "bearer" and credential and len(credential) <= 512)
        else None
    )
    receipt = Receipt(
        operation_id=uuid4(),
        started_at=datetime.now(UTC),
        operation=_operation(request),
        method=cast(
            Method, request.method if request.method in get_args(Method.__value__) else "OTHER"
        ),
        service_role=role,
    )
    request.state.operation_receipt = receipt
    request.state.operation_permissions = {}
    started = monotonic()
    try:
        await run_in_threadpool(journal.start, receipt)
    except Exception:
        return JSONResponse(
            {"detail": "Operation receipt could not be saved; request was not run."},
            status_code=503,
            headers={"X-Operation-Id": str(receipt.operation_id)},
        )
    try:
        response = await call_next(request)
    except Exception:
        # No customer exception text, trace, raw body or assumption of rollback enters the journal.
        response = JSONResponse(
            {"detail": "Operation failed; check saved history before retrying."}, status_code=500
        )
    decisions = cast(dict[Permission, PermissionDecision], request.state.operation_permissions)
    result = cast(ResultMetadata | None, getattr(request.state, "operation_result", None))
    try:
        completion = Completion(
            operation_id=receipt.operation_id,
            receipt_sha256=receipt.sha256,
            completed_at=max(datetime.now(UTC), receipt.started_at),
            status_code=response.status_code,
            duration_ms=max(0, int((monotonic() - started) * 1000)),
            permissions=tuple(decisions[name] for name in sorted(decisions)),
            result=result if response.status_code < 400 else None,
        )
        await run_in_threadpool(journal.complete, receipt, completion)
    except Exception:
        response = JSONResponse(
            {"detail": "Operation outcome is unconfirmed; check saved history before retrying."},
            status_code=503,
        )
    response.headers["X-Operation-Id"] = str(receipt.operation_id)
    return response
