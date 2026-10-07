"""FastAPI application entry point."""

from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError
from starlette.responses import Response

from app.api.access import router as access_router
from app.api.configurations import router as configuration_router
from app.api.explanations import router as explanation_router
from app.api.feedback import router as feedback_router
from app.api.health import router as health_router
from app.api.patches import router as patch_router
from app.api.service import AnalysisService
from app.api.snapshot_diff import router as snapshot_diff_router
from app.core.document_retrieval import DocumentRetrievalSettings
from app.core.local_model import LocalModelSettings
from app.core.settings import ApiSettings
from app.db.store import StorageIntegrityError, Store
from app.explanation.local_model import LocalModelRuntime
from app.explanation.retrieval_runtime import DocumentRetrievalRuntime
from app.web import UI_CONTENT_SECURITY_POLICY, mount_frontend


def create_app(
    settings: ApiSettings | None = None,
    *,
    frontend_dir: Path | None = None,
    local_model: LocalModelSettings | None = None,
    document_retrieval: DocumentRetrievalSettings | None = None,
) -> FastAPI:
    if (local_model is not None or document_retrieval is not None) and settings is None:
        raise ValueError("local model requires an authenticated persistent API")
    store = Store(settings) if settings is not None else None

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        try:
            yield
        finally:
            if store is not None:
                store.close()

    application = FastAPI(
        title="NetConfig Sentinel",
        version="0.1.0",
        description="Auditable analysis of multi-vendor network configurations.",
        lifespan=lifespan,
    )
    application.state.api_settings = settings
    application.state.analysis_service = AnalysisService(store) if store is not None else None
    application.state.local_model = LocalModelRuntime(local_model) if local_model else None
    application.state.document_retrieval = (
        DocumentRetrievalRuntime(document_retrieval) if document_retrieval else None
    )

    @application.exception_handler(RequestValidationError)
    async def invalid_request(_: Request, __: RequestValidationError) -> JSONResponse:
        return JSONResponse({"detail": "Invalid request parameters."}, status_code=422)

    async def storage_error(_: Request, __: Exception) -> JSONResponse:
        return JSONResponse({"detail": "Stored data is unavailable."}, status_code=503)

    application.add_exception_handler(SQLAlchemyError, storage_error)
    application.add_exception_handler(StorageIntegrityError, storage_error)

    @application.middleware("http")
    async def private_responses(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        if request.url.path == "/ui" or request.url.path.startswith("/ui/"):
            response.headers["Content-Security-Policy"] = UI_CONTENT_SECURITY_POLICY
            response.headers["X-Frame-Options"] = "DENY"
        return response

    application.include_router(health_router)
    application.include_router(access_router)
    application.include_router(configuration_router)
    application.include_router(feedback_router)
    application.include_router(snapshot_diff_router)
    application.include_router(explanation_router)
    application.include_router(patch_router)
    mount_frontend(application, frontend_dir)
    return application


app = create_app(
    ApiSettings.from_environment(),
    local_model=LocalModelSettings.from_environment(),
    document_retrieval=DocumentRetrievalSettings.from_environment(),
)
