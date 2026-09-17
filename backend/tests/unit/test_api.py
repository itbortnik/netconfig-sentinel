"""Service probe tests."""

import asyncio

import httpx
from app.main import app


async def _get(path: str) -> httpx.Response:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        return await client.get(path)


def test_health() -> None:
    response = asyncio.run(_get("/health"))

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_ready_reports_both_vendor_parsers() -> None:
    response = asyncio.run(_get("/ready"))

    assert response.status_code == 200
    assert response.json() == {
        "status": "ready",
        "checks": {"vendor_parsers": True},
    }
