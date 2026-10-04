"""Local contextual explanations are private, bound, read-only and degrade explicitly."""

from collections.abc import Iterator
from pathlib import Path
from uuid import uuid4

import pytest
from app.core.settings import ApiSettings
from app.db.migrate import upgrade_database
from app.explanation.knowledge import KnowledgeUnavailable
from app.main import create_app
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import text

TOKEN = "explanation-test-shared-service-token-001"
HEADERS = {"Authorization": f"Bearer {TOKEN}"}


@pytest.fixture
def explanation_api(tmp_path: Path) -> Iterator[tuple]:
    settings = ApiSettings(
        f"sqlite:///{tmp_path / 'explanation.sqlite3'}", TOKEN, Fernet.generate_key().decode()
    )
    application = create_app(settings)
    service = application.state.analysis_service
    upgrade_database(service.store.engine)
    with TestClient(application) as client:
        yield client, service, settings


def analyze(client, vendor="cisco", partial=False):
    contents = (
        "hostname explanation-edge\n"
        if vendor == "cisco"
        else "set system host-name explanation-edge\n"
    ) + ("unsupported private raw command\n" if partial else "")
    uploaded = client.post(
        "/api/v1/configurations",
        headers=HEADERS,
        json={
            "device_id": str(uuid4()),
            "filename": "edge.cfg",
            "content": contents,
        },
    )
    assert uploaded.status_code == 201
    response = client.post(
        f"/api/v1/configurations/{uploaded.json()['configuration_id']}/analyze", headers=HEADERS
    )
    assert response.status_code == 201
    return response.json()


def request(client, result, **updates):
    return client.post(
        f"/api/v1/findings/{result['findings'][0]['finding_id']}/explain",
        headers=HEADERS,
        json={
            "analysis_id": result["analysis_id"],
            "finding_sha256": result["explanations"][0]["finding_sha256"],
        }
        | updates,
    )


@pytest.mark.parametrize("vendor", ["cisco", "juniper"])
@pytest.mark.parametrize("partial", [False, True])
def test_sources_are_bound_repeatable_and_do_not_mutate_analysis(explanation_api, vendor, partial):
    client, service, settings = explanation_api
    result = analyze(client, vendor, partial)
    response = request(client, result)
    assert response.status_code == 200, response.text
    bundle = response.json()
    assert bundle["explanation"] == result["explanations"][0]
    for key in ("analysis_id", "configuration_id", "device_id", "source_sha256"):
        assert bundle[key] == result[key]
    assert bundle["provider"] == "deterministic_local"
    assert bundle["llm_status"] == "unavailable"
    assert bundle["documents"][0]["citation"] in result["explanations"][0]["citations"]
    assert "private raw command" not in response.text
    assert request(client, result).json() == bundle
    with TestClient(create_app(settings)) as restarted:
        assert request(restarted, result).json() == bundle
        assert (
            restarted.get(f"/api/v1/analyses/{result['analysis_id']}", headers=HEADERS).json()
            == result
        )
    with service.store.engine.connect() as connection:
        assert connection.execute(text("SELECT count(*) FROM audit_events")).scalar_one() == 2
        assert connection.execute(text("SELECT count(*) FROM analyses")).scalar_one() == 1


def test_llm_selection_does_not_silently_fall_back(explanation_api):
    client, _, _ = explanation_api
    result = analyze(client)
    response = request(client, result, provider="llm")
    assert response.status_code == 503
    assert response.json() == {"detail": "Language model provider is unavailable."}
    assert request(client, result).status_code == 200


def test_binding_and_scope_are_explicit(explanation_api):
    client, _, _ = explanation_api
    result = analyze(client)
    assert request(client, result, finding_sha256="f" * 64).status_code == 409
    assert request(client, result, analysis_id=str(uuid4())).status_code == 404
    response = client.post(
        f"/api/v1/findings/{uuid4()}/explain",
        headers=HEADERS,
        json={"analysis_id": result["analysis_id"], "finding_sha256": "a" * 64},
    )
    assert response.status_code == 404


@pytest.mark.parametrize(
    "updates",
    [{"provider": "external"}, {"prompt": "secret"}, {"risk": 0}, {"finding_sha256": "invalid"}],
)
def test_auth_and_invalid_body_are_sanitized(explanation_api, updates):
    client, _, _ = explanation_api
    result = analyze(client)
    path = f"/api/v1/findings/{result['findings'][0]['finding_id']}/explain"
    assert client.post(path, json=updates).status_code == 401
    response = request(client, result, **updates)
    assert response.status_code == 400
    assert response.json() == {"detail": "Invalid explanation request."}


def test_request_budget_duplicate_keys_and_missing_sources(explanation_api, monkeypatch):
    client, _, _ = explanation_api
    result = analyze(client)
    path = f"/api/v1/findings/{result['findings'][0]['finding_id']}/explain"
    for raw, status in [(b'{"provider":"local","provider":"llm"}', 400), (b"x" * 16385, 413)]:
        assert (
            client.post(
                path, headers=HEADERS | {"Content-Type": "application/json"}, content=raw
            ).status_code
            == status
        )
    assert client.post(path, headers=HEADERS, content="private").status_code == 415

    def missing():
        raise KnowledgeUnavailable("private-file-path")

    monkeypatch.setattr("app.api.explanations.load_knowledge_catalog", missing)
    response = request(client, result)
    assert response.status_code == 503
    assert response.json() == {"detail": "Reviewed knowledge is unavailable."}


def test_openapi_scope_and_unconfigured_service():
    with TestClient(create_app()) as client:
        path = "/api/v1/findings/{finding_id}/explain"
        operation = client.get("/openapi.json").json()["paths"][path]["post"]
        schema = operation["requestBody"]["content"]["application/json"]["schema"]
        assert set(schema["required"]) == {"analysis_id", "finding_sha256"}
        assert schema["additionalProperties"] is False
        assert operation["security"] == [{"HTTPBearer": []}]
        assert client.post(path.replace("{finding_id}", str(uuid4())), json={}).status_code == 503


def test_corrupted_analysis_never_returns_an_explanation(explanation_api):
    client, service, _ = explanation_api
    result = analyze(client)
    with service.store.engine.begin() as connection:
        connection.execute(text("UPDATE analyses SET payload='corrupted-private-data'"))
    response = request(client, result)
    assert response.status_code == 503
    assert response.json() == {"detail": "Stored data is unavailable."}
