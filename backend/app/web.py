"""Serve only built public UI assets, never project files or configuration history."""

import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

UI_CONTENT_SECURITY_POLICY = (
    "default-src 'none'; script-src 'self'; style-src 'self'; "
    "connect-src 'self'; img-src 'self' data:; font-src 'self'; "
    "base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'"
)


def mount_frontend(application: FastAPI, directory: Path | None = None) -> None:
    if directory is None:
        configured = os.environ.get("NETCONFIG_UI_DIR", "")
        bundled = Path(__file__).parent / "static"
        directory = (
            Path(configured)
            if configured
            else bundled
            if (bundled / "index.html").is_file()
            else Path(__file__).resolve().parents[2] / "frontend" / "dist"
        )

    @application.get("/", include_in_schema=False)
    def index() -> RedirectResponse:
        return RedirectResponse("/ui/")

    if directory.is_dir() and (directory / "index.html").is_file():
        application.mount("/ui", StaticFiles(directory=directory, html=True), name="frontend")
    else:

        @application.get("/ui/", include_in_schema=False)
        def unavailable() -> JSONResponse:
            return JSONResponse(
                {"detail": "Frontend assets are unavailable. Build the frontend first."},
                status_code=503,
            )
