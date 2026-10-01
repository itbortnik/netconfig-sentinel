"""FastAPI application entry point."""

from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError
from starlette.responses import Response

from app.api.configurations import router as configuration_router
from app.api.health import router as health_router
from app.api.service import AnalysisService
from app.core.settings import ApiSettings
from app.db.store import StorageIntegrityError, Store


def create_app(settings: ApiSettings | None = None) -> FastAPI:
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
        return response

    application.include_router(health_router)
    application.include_router(configuration_router)
    return application


app = create_app(ApiSettings.from_environment())
