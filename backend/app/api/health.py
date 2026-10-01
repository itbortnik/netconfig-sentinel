"""Liveness and readiness endpoints."""

from typing import Literal

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict

from app.parsers.registry import registered_parsers

router = APIRouter(tags=["service"])


class HealthResponse(BaseModel):
    """Liveness response."""

    model_config = ConfigDict(extra="forbid")

    status: Literal["ok"] = "ok"


class ReadinessChecks(BaseModel):
    """Readiness dependencies checked by the process."""

    model_config = ConfigDict(extra="forbid")

    vendor_parsers: bool
    persistent_api: bool
    database_schema: bool | None


class ReadinessResponse(BaseModel):
    """Readiness response."""

    model_config = ConfigDict(extra="forbid")

    status: Literal["ready", "not_ready"] = "ready"
    checks: ReadinessChecks


@router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    """Report that the API process is alive."""

    return HealthResponse()


@router.get("/ready", response_model=ReadinessResponse)
def ready(request: Request) -> JSONResponse:
    """Report whether the in-process parser registry is initialized."""

    expected_parsers = {"cisco_ios", "juniper_junos"}
    parsers_ready = expected_parsers.issubset(registered_parsers())
    service = request.app.state.analysis_service
    database = service.store.ready() if service is not None else None
    ready_now = parsers_ready and database is not False
    result = ReadinessResponse(
        status="ready" if ready_now else "not_ready",
        checks=ReadinessChecks(
            vendor_parsers=parsers_ready,
            persistent_api=service is not None,
            database_schema=database,
        ),
    )
    return JSONResponse(result.model_dump(), status_code=200 if ready_now else 503)
