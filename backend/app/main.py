"""FastAPI application entry point."""

from fastapi import FastAPI

from app.api.health import router as health_router

app = FastAPI(
    title="NetConfig Sentinel",
    version="0.1.0",
    description="Auditable analysis of multi-vendor network configurations.",
)
app.include_router(health_router)
