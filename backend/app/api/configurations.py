"""Authenticated bounded configuration uploads and persisted analysis endpoints."""

from __future__ import annotations

import json
import secrets
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel
from starlette.concurrency import run_in_threadpool

from app.api.contracts import (
    AnalysisOptions,
    AnalysisResult,
    AnalysisSummary,
    ConfigurationSnapshot,
    ConfigurationSummary,
    UploadConfiguration,
)
from app.api.service import AnalysisService
from app.db.store import DeviceIdentityConflict
from app.domain import Finding

router = APIRouter(prefix="/api/v1", tags=["analysis"])
MAX_REQUEST_BYTES = 3 * 1024 * 1024
bearer = HTTPBearer(auto_error=False)


def require_service(
    request: Request,
    credential: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
) -> AnalysisService:
    settings = request.app.state.api_settings
    service = request.app.state.analysis_service
    if settings is None or service is None:
        raise HTTPException(status_code=503, detail="Persistent API is not configured.")
    if credential is None or not secrets.compare_digest(
        credential.credentials.encode("utf-8"), settings.api_token.encode("ascii")
    ):
        raise HTTPException(
            status_code=401,
            detail="Authentication required.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not service.store.ready():
        raise HTTPException(status_code=503, detail="Storage schema is unavailable.")
    return service  # type: ignore[no-any-return]


Service = Annotated[AnalysisService, Depends(require_service)]
Limit = Annotated[int, Query(ge=1, le=100)]
Offset = Annotated[int, Query(ge=0, le=10_000)]


def _request_schema(model: type[BaseModel]) -> dict[str, Any]:
    """Inline local definitions because a manual request schema is nested in OpenAPI."""
    schema = model.model_json_schema()
    definitions = schema.pop("$defs", {})

    def expand(value: Any) -> Any:
        if isinstance(value, list):
            return [expand(item) for item in value]
        if isinstance(value, dict):
            reference = value.get("$ref", "")
            if isinstance(reference, str) and reference.startswith("#/$defs/"):
                definition = definitions[reference.removeprefix("#/$defs/")]
                return expand(
                    definition | {key: item for key, item in value.items() if key != "$ref"}
                )
            return {key: expand(item) for key, item in value.items()}
        return value

    result = expand(schema)
    assert isinstance(result, dict)
    return result


def _unique_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate request key")
        result[key] = value
    return result


async def _request_body(request: Request, *, maximum: int, empty_allowed: bool = False) -> bytes:
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type != "application/json" and (content_type or not empty_allowed):
        raise HTTPException(status_code=415, detail="Use application/json.")
    if request.headers.get("content-encoding", "identity") != "identity":
        raise HTTPException(status_code=415, detail="Encoded request bodies are unsupported.")
    if request.headers.get("content-length"):
        try:
            length = int(request.headers["content-length"])
            if length < 0:
                raise ValueError("negative request length")
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid request length.") from None
        if length > maximum:
            raise HTTPException(status_code=413, detail="Upload exceeds request size limit.")
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > maximum:
            raise HTTPException(status_code=413, detail="Upload exceeds request size limit.")
        body.extend(chunk)
    if body and content_type != "application/json":
        raise HTTPException(status_code=415, detail="Use application/json.")
    return bytes(body)


async def _upload_body(request: Request) -> UploadConfiguration:
    body = await _request_body(request, maximum=MAX_REQUEST_BYTES)
    try:
        parsed = json.loads(body.decode("utf-8"), object_pairs_hook=_unique_keys)
        return UploadConfiguration.model_validate(parsed)
    except (ValueError, RecursionError):
        raise HTTPException(status_code=400, detail="Invalid configuration upload.") from None


async def _analysis_body(request: Request) -> AnalysisOptions:
    body = await _request_body(request, maximum=16 * 1024, empty_allowed=True)
    try:
        parsed = json.loads(body.decode("utf-8"), object_pairs_hook=_unique_keys) if body else {}
        return AnalysisOptions.model_validate(parsed)
    except (ValueError, RecursionError):
        raise HTTPException(status_code=400, detail="Invalid analysis options.") from None


@router.post(
    "/configurations",
    response_model=ConfigurationSnapshot,
    status_code=201,
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {"application/json": {"schema": _request_schema(UploadConfiguration)}},
        }
    },
)
async def upload_configuration(request: Request, service: Service) -> ConfigurationSnapshot:
    upload = await _upload_body(request)
    try:
        return await run_in_threadpool(service.upload, upload)
    except DeviceIdentityConflict:
        raise HTTPException(
            status_code=409, detail="Device identity conflicts with stored history."
        ) from None
    except ValueError:
        raise HTTPException(
            status_code=400, detail="Configuration text is invalid or unsupported."
        ) from None


@router.get("/configurations", response_model=list[ConfigurationSummary])
def list_configurations(
    service: Service, device_id: UUID | None = None, limit: Limit = 20, offset: Offset = 0
) -> list[ConfigurationSummary]:
    return [
        ConfigurationSummary(
            configuration_id=item.configuration_id,
            device_id=item.device_id,
            created_at=item.created_at,
            filename=item.canonical.source.filename,
            source_sha256=item.canonical.source.sha256,
            hostname=item.canonical.device.hostname,
            vendor=item.canonical.device.vendor.value,
            platform=item.canonical.device.platform,
            parser_confidence=item.canonical.parser_confidence,
            warning_count=len(item.canonical.parse_warnings),
            unparsed_count=len(item.canonical.unparsed_fragments),
        )
        for item in service.store.list_configurations(
            device_id=device_id, limit=limit, offset=offset
        )
    ]


@router.get("/configurations/{configuration_id}", response_model=ConfigurationSnapshot)
def get_configuration(configuration_id: UUID, service: Service) -> ConfigurationSnapshot:
    item = service.store.get_configuration(configuration_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Configuration not found.")
    return item


@router.post(
    "/configurations/{configuration_id}/analyze",
    response_model=AnalysisResult,
    status_code=201,
    openapi_extra={
        "requestBody": {
            "required": False,
            "content": {"application/json": {"schema": _request_schema(AnalysisOptions)}},
        }
    },
)
async def analyze_configuration(
    configuration_id: UUID, request: Request, service: Service
) -> AnalysisResult:
    options = await _analysis_body(request)
    try:
        result = await run_in_threadpool(service.analyze, configuration_id, options)
    except ValueError:
        raise HTTPException(
            status_code=400, detail="Selected comparisons are unavailable or incompatible."
        ) from None
    if result is None:
        raise HTTPException(status_code=404, detail="Configuration not found.")
    return result


@router.get("/analyses", response_model=list[AnalysisSummary])
def list_analyses(
    service: Service, configuration_id: UUID | None = None, limit: Limit = 20, offset: Offset = 0
) -> list[AnalysisSummary]:
    return [
        AnalysisSummary(
            analysis_id=item.analysis_id,
            configuration_id=item.configuration_id,
            device_id=item.device_id,
            created_at=item.created_at,
            status=item.status,
            finding_count=len(item.findings),
            policy_catalog_version=item.policy_catalog_version,
        )
        for item in service.store.list_analyses(
            configuration_id=configuration_id, limit=limit, offset=offset
        )
    ]


@router.get("/analyses/{analysis_id}", response_model=AnalysisResult)
def get_analysis(analysis_id: UUID, service: Service) -> AnalysisResult:
    item = service.store.get_analysis(analysis_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    return item


@router.get("/analyses/{analysis_id}/findings", response_model=list[Finding])
def get_findings(analysis_id: UUID, service: Service) -> list[Finding]:
    return list(get_analysis(analysis_id, service).findings)
