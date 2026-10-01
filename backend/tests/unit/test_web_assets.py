"""Public UI shell does not make configuration history public or expose project files."""

from pathlib import Path

from app.main import create_app
from fastapi.testclient import TestClient


def test_absent_build_does_not_break_service_probes(tmp_path: Path) -> None:
    with TestClient(create_app(frontend_dir=tmp_path / "missing")) as client:
        assert client.get("/health").status_code == 200
        assert client.get("/").status_code == 503
        assert client.get("/ui/").json() == {
            "detail": "Frontend assets are unavailable. Build the frontend first."
        }
        assert client.get("/ui/assets/missing.js").status_code == 404
        assert client.get("/api/v1/configurations").status_code == 503


def test_built_shell_security_headers_and_path_boundaries(tmp_path: Path) -> None:
    # Fixture file generation is not production serving logic.
    public = tmp_path / "public"
    public.mkdir()
    (public / "index.html").write_text("<html>NetConfig Sentinel</html>", encoding="utf-8")
    (public / "app.js").write_text("export const version = 'test';", encoding="utf-8")
    (tmp_path / "private.cfg").write_text("private-test-secret", encoding="utf-8")
    with TestClient(create_app(frontend_dir=public)) as client:
        response = client.get("/ui/")
        assert response.status_code == 200
        assert response.text == "<html>NetConfig Sentinel</html>"
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["referrer-policy"] == "no-referrer"
        assert response.headers["x-frame-options"] == "DENY"
        assert "script-src 'self'" in response.headers["content-security-policy"]
        assert "form-action 'none'" in response.headers["content-security-policy"]
        assert "unsafe-inline" not in response.headers["content-security-policy"]
        assert client.get("/ui/app.js").status_code == 200
        assert client.get("/ui/%2e%2e/private.cfg").status_code == 404
        assert client.get("/ui/PROJECT_BRIEF.md").status_code == 404
        assert client.get("/ui/backend/app/main.py").status_code == 404
        assert client.get("/ui/.env").status_code == 404
        assert "private-test-secret" not in client.get("/ui/%2e%2e/private.cfg").text
