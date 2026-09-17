"""Liveness and readiness endpoints."""

from typing import Literal

from fastapi import APIRouter
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


class ReadinessResponse(BaseModel):
    """Readiness response."""

    model_config = ConfigDict(extra="forbid")

    status: Literal["ready"] = "ready"
    checks: ReadinessChecks


@router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    """Report that the API process is alive."""

    return HealthResponse()


@router.get("/ready", response_model=ReadinessResponse)
def ready() -> ReadinessResponse:
    """Report whether the in-process parser registry is initialized."""

    expected_parsers = {"cisco_ios", "juniper_junos"}
    parsers_ready = expected_parsers.issubset(registered_parsers())
    return ReadinessResponse(checks=ReadinessChecks(vendor_parsers=parsers_ready))
