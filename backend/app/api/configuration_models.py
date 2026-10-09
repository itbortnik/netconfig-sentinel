"""Opt-in experimental inference on exact retained sources of saved analyses."""

import json
from typing import Annotated, cast
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from starlette.concurrency import run_in_threadpool

from app.api.access import require_access
from app.api.configuration_model_contracts import (
    ConfigurationModelCapabilities,
    ConfigurationModelRun,
    RunConfigurationModel,
)
from app.api.configurations import (
    Limit,
    Offset,
    Service,
    _request_body,
    _request_schema,
    _unique_keys,
)
from app.api.service import AnalysisService
from app.audit.results import capture_result
from app.db.configuration_model_records import ConfigurationModelConflict
from app.db.source_records import OriginalSourceUnavailable
from app.detection.config_model_runtime import (
    ConfigurationModelBusy,
    ConfigurationModelDisabled,
    ConfigurationModelRuntime,
)
from app.detection.saved_configuration_model import (
    SavedConfigurationModelFailed,
    SavedConfigurationModelNotFound,
    SavedConfigurationModelWorkflow,
)

router = APIRouter(
    prefix="/api/v1/configuration-model-runs", tags=["experimental configuration models"]
)
ModelService = Annotated[AnalysisService, Depends(require_access("configuration_model"))]


@router.post(
    "",
    response_model=ConfigurationModelRun,
    status_code=201,
    responses={
        200: {"model": ConfigurationModelRun, "description": "Existing attempt; no inference."}
    },
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {"application/json": {"schema": _request_schema(RunConfigurationModel)}},
        }
    },
)
async def run_configuration_model(
    request: Request, response: Response, service: ModelService
) -> ConfigurationModelRun:
    body = await _request_body(request, maximum=16 * 1024)
    try:
        options = RunConfigurationModel.model_validate(
            json.loads(body.decode(), object_pairs_hook=_unique_keys)
        )
    except (ValueError, RecursionError):
        raise HTTPException(
            status_code=400, detail="Invalid configuration model request."
        ) from None
    if options.allow_local_model_context is not True:
        raise HTTPException(
            status_code=403, detail="Explicit local model context permission is required."
        )
    runtime = cast(ConfigurationModelRuntime, request.app.state.configuration_model)
    try:
        result, created = await run_in_threadpool(
            SavedConfigurationModelWorkflow(service).run, options, runtime
        )
    except SavedConfigurationModelNotFound:
        raise HTTPException(status_code=404, detail="Selected analysis not found.") from None
    except (ConfigurationModelConflict, OriginalSourceUnavailable):
        raise HTTPException(
            status_code=409,
            detail="Selected identity, complete parsing or retained original is unavailable.",
        ) from None
    except ConfigurationModelDisabled:
        raise HTTPException(
            status_code=503, detail="Configuration model inference is disabled."
        ) from None
    except ConfigurationModelBusy:
        raise HTTPException(
            status_code=429, detail="Local model is busy; no attempt was started."
        ) from None
    except SavedConfigurationModelFailed:
        raise HTTPException(
            status_code=503,
            detail="Configuration inference failed; inspect the saved attempt before retrying.",
        ) from None
    response.status_code = 201 if created else 200
    return capture_result(request, result)


@router.get("", response_model=list[ConfigurationModelRun])
def list_configuration_model_runs(
    analysis_id: UUID, request: Request, service: Service, limit: Limit = 20, offset: Offset = 0
) -> list[ConfigurationModelRun]:
    if service.store.get_analysis(analysis_id) is None:
        raise HTTPException(status_code=404, detail="Selected analysis not found.")
    workflow = SavedConfigurationModelWorkflow(service)
    return capture_result(
        request,
        [
            workflow.get(key)
            for key in workflow.records.list_ids(
                analysis_id=analysis_id, limit=limit, offset=offset
            )
        ],
    )


@router.get("/capabilities", response_model=ConfigurationModelCapabilities)
def configuration_model_capabilities(
    request: Request, service: Service
) -> ConfigurationModelCapabilities:
    settings = cast(ConfigurationModelRuntime, request.app.state.configuration_model).settings
    return capture_result(
        request,
        ConfigurationModelCapabilities(
            inference="configured" if settings.registry_root is not None else "disabled",
            model_sha256=settings.model_sha256,
        ),
    )


@router.get("/{inference_id}", response_model=ConfigurationModelRun)
def get_configuration_model_run(
    inference_id: UUID, request: Request, service: Service
) -> ConfigurationModelRun:
    try:
        return capture_result(request, SavedConfigurationModelWorkflow(service).get(inference_id))
    except SavedConfigurationModelNotFound:
        raise HTTPException(
            status_code=404, detail="Configuration model attempt not found."
        ) from None
