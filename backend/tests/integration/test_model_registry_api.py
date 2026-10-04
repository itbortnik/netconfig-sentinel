"""Explicit training, authenticated manifests, restart-safe scoring and leakage guards."""

from collections.abc import Iterator
from copy import deepcopy
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from app.api.contracts import AnalysisResult, TrainModelOptions
from app.core.settings import ApiSettings
from app.db.migrate import upgrade_database
from app.main import create_app
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.exc import OperationalError

TOKEN = "numeric-model-registry-service-token-001"
HEADERS = {"Authorization": f"Bearer {TOKEN}"}
LABELS = {"device_role": "edge", "site_class": "branch", "service_profile": "control"}


@pytest.fixture
def registry_api(tmp_path: Path) -> Iterator[tuple]:
    settings = ApiSettings(
        f"sqlite:///{tmp_path / 'models.sqlite3'}",
        TOKEN,
        Fernet.generate_key().decode(),
    )
    application = create_app(settings)
    service = application.state.analysis_service
    upgrade_database(service.store.engine)
    with TestClient(application) as client:
        yield client, service, settings


def upload(client, index, *, vlans=None, device=None, labels=LABELS, extra=""):
    content = f"hostname forest-{index}\naaa new-model\nip ssh version 2\n"
    for vlan in range(vlans if vlans is not None else index % 7 + 1):
        content += f"vlan {10 + vlan}\n name VLAN-{vlan}\n!\n"
    response = client.post(
        "/api/v1/configurations",
        headers=HEADERS,
        json={
            "device_id": device or str(uuid4()),
            "filename": "forest.cfg",
            "content": content + extra,
            "inventory": labels,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def population(client):
    return [upload(client, index) for index in range(16)]


def train(client, snapshots, **options):
    return client.post(
        "/api/v1/models/isolation-forest",
        headers=HEADERS,
        json={
            "configuration_ids": [item["configuration_id"] for item in snapshots],
            **options,
        },
    )


def analyze(client, snapshot, model_id, **options):
    return client.post(
        f"/api/v1/configurations/{snapshot['configuration_id']}/analyze",
        headers=HEADERS,
        json={"statistical_model_id": model_id, **options},
    )


def test_training_restart_outlier_history_and_encryption(registry_api, monkeypatch) -> None:
    client, service, settings = registry_api
    snapshots = population(client)
    response = train(client, snapshots)
    assert response.status_code == 201, response.text
    model = response.json()
    assert model["status"] == "experimental"
    assert model["metadata"]["sample_count"] == 16
    assert model["metadata"]["estimator_count"] == 200
    assert len(model["training"]) == 16
    assert "trees" not in model
    assert client.get("/api/v1/models", headers=HEADERS).json() == [model]
    target = upload(client, 999, vlans=30)
    monkeypatch.setattr("sklearn.ensemble.IsolationForest.fit", lambda *args: pytest.fail("refit"))
    result = analyze(client, target, model["model_id"])
    assert result.status_code == 201, result.text
    result = result.json()
    assert result["version"] == "analysis-api-0.3.0"
    assert result["statistical"]["model"] == model
    assert result["statistical"]["prediction"] == -1
    findings = [item for item in result["findings"] if item["detector"] == "isolation_forest"]
    assert len(findings) == 1
    explanation = next(
        item for item in result["explanations"] if item["finding_id"] == findings[0]["finding_id"]
    )
    contextual = client.post(
        f"/api/v1/findings/{findings[0]['finding_id']}/explain",
        headers=HEADERS,
        json={
            "analysis_id": result["analysis_id"],
            "finding_sha256": explanation["finding_sha256"],
        },
    )
    assert contextual.status_code == 200, contextual.text
    assert contextual.json()["explanation"] == explanation
    assert all(
        item["document_id"] == "docs/statistical-baseline.md"
        for item in contextual.json()["documents"]
    )
    sources = {item["source"]: item for item in result["risk"]["components"]}
    assert sources["statistical"]["status"] == "completed"
    assert sources["statistical"]["effective_weight"] == pytest.approx(0.1 / 0.45)
    assert sources["verification"]["status"] == "unavailable"
    with TestClient(create_app(settings)) as restarted:
        assert restarted.get(f"/api/v1/models/{model['model_id']}", headers=HEADERS).json() == model
        assert (
            restarted.get(f"/api/v1/analyses/{result['analysis_id']}", headers=HEADERS).json()
            == result
        )
        repeated = analyze(restarted, target, model["model_id"]).json()
        for key in ("statistical", "findings", "explanations", "risk"):
            assert repeated[key] == result[key]
    with service.store.engine.connect() as connection:
        payload = connection.execute(text("SELECT payload FROM models")).scalar_one()
        assert "forest-" not in payload and "thresholds" not in payload
        assert (
            connection.execute(
                text("SELECT count(*) FROM audit_events WHERE action='model.trained'")
            ).scalar_one()
            == 1
        )
        assert connection.execute(text("SELECT count(*) FROM models")).scalar_one() == 1


def test_inlier_is_completed_zero_not_missing(registry_api) -> None:
    client, _, _ = registry_api
    model = train(client, population(client)).json()
    target = upload(client, 100, vlans=4)
    result = analyze(client, target, model["model_id"]).json()
    assert result["statistical"]["prediction"] == 1
    component = next(
        item for item in result["risk"]["components"] if item["source"] == "statistical"
    )
    assert component["status"] == "completed" and component["raw_score"] == 0


def test_model_reference_and_peers_share_only_eligible_risk_signals(registry_api) -> None:
    client, _, _ = registry_api
    snapshots = population(client)
    model = train(client, snapshots).json()
    reference = upload(
        client,
        999,
        vlans=4,
        extra="interface Gi0/1\n switchport mode access\n switchport access vlan 10\n!\n",
    )
    target = upload(
        client,
        999,
        vlans=30,
        device=reference["device_id"],
        extra="interface Gi0/1\n switchport mode access\n switchport access vlan 20\n!\n",
    )
    response = analyze(
        client,
        target,
        model["model_id"],
        reference_configuration_id=reference["configuration_id"],
        peer_configuration_ids=[item["configuration_id"] for item in snapshots[:3]],
    )
    assert response.status_code == 201, response.text
    result = response.json()
    assert result["comparison"]["reference"]["configuration_id"] == reference["configuration_id"]
    assert result["statistical"]["model"]["model_id"] == model["model_id"]
    sources = {item["source"]: item for item in result["risk"]["components"]}
    assert sources["policy"]["effective_weight"] == pytest.approx(0.35 / 0.6)
    assert sources["peer_group"]["effective_weight"] == pytest.approx(0.15 / 0.6)
    assert sources["statistical"]["effective_weight"] == pytest.approx(0.10 / 0.6)
    excluded = {
        item["finding_id"]
        for item in result["findings"]
        if item["detector"] == "expected_configuration"
    }
    assert excluded
    assert excluded.isdisjoint(
        {identity for source in sources.values() for identity in source["finding_ids"]}
    )


def test_training_schema_has_no_unresolved_nested_references(registry_api) -> None:
    client, _, _ = registry_api
    schema = client.get("/openapi.json").json()["paths"]["/api/v1/models/isolation-forest"]["post"]
    assert schema["security"] == [{"HTTPBearer": []}]
    body = schema["requestBody"]["content"]["application/json"]["schema"]
    assert body["properties"]["configuration_ids"]["minItems"] == 8
    assert body["properties"]["configuration_ids"]["maxItems"] == 100
    assert body["additionalProperties"] is False


@pytest.mark.parametrize("bad", ["missing", "partial", "mixed", "same_device", "same_host"])
def test_invalid_population_leaves_no_model_or_audit(registry_api, bad) -> None:
    client, service, _ = registry_api
    snapshots = population(client)[:8]
    if bad == "missing":
        snapshots[-1]["configuration_id"] = str(uuid4())
    elif bad == "partial":
        snapshots[-1] = upload(client, 99, extra="unsupported private input\n")
    elif bad == "mixed":
        snapshots[-1] = upload(client, 99, labels=LABELS | {"site_class": "datacenter"})
    elif bad == "same_device":
        snapshots[-1] = upload(client, 0, device=snapshots[0]["device_id"], vlans=4)
    else:
        snapshots[-1] = upload(client, 0, vlans=4)
    response = train(client, snapshots)
    assert response.status_code == 400
    assert "private" not in response.text
    with service.store.engine.connect() as connection:
        assert connection.execute(text("SELECT count(*) FROM models")).scalar_one() == 0
        assert (
            connection.execute(
                text("SELECT count(*) FROM audit_events WHERE action='model.trained'")
            ).scalar_one()
            == 0
        )


@pytest.mark.parametrize("bad", ["missing", "self", "same_host", "mixed", "partial", "future"])
def test_selected_model_cannot_silently_fall_back_or_leak_training(registry_api, bad) -> None:
    client, _, _ = registry_api
    early = upload(client, 998, vlans=4)
    snapshots = population(client)
    model = train(client, snapshots).json()
    target = upload(client, 999, vlans=4)
    model_id = model["model_id"]
    if bad == "missing":
        model_id = str(uuid4())
    elif bad == "self":
        target = snapshots[0]
    elif bad == "same_host":
        target = upload(client, 0, vlans=4)
    elif bad == "mixed":
        target = upload(client, 997, labels=LABELS | {"device_role": "core"})
    elif bad == "partial":
        target = upload(client, 996, extra="unsupported private input\n")
    else:
        target = early
    response = analyze(client, target, model_id)
    assert response.status_code == 400
    assert client.get("/api/v1/analyses", headers=HEADERS).json() == []


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"configuration_ids": []},
        {"configuration_ids": [str(uuid4())] * 8},
        {"configuration_ids": [str(uuid4()) for _ in range(101)]},
        {"configuration_ids": [str(uuid4()) for _ in range(8)], "contamination": 0},
        {"configuration_ids": [str(uuid4()) for _ in range(8)], "artifact": "no-import"},
    ],
)
def test_training_request_contract_and_auth_first(registry_api, body) -> None:
    client, _, _ = registry_api
    assert client.post("/api/v1/models/isolation-forest", json=body).status_code == 401
    assert (
        client.post("/api/v1/models/isolation-forest", headers=HEADERS, json=body).status_code
        == 400
    )


def test_model_payload_transplant_tamper_and_atomic_audit(registry_api) -> None:
    client, service, _ = registry_api
    snapshots = population(client)
    model = train(client, snapshots).json()
    other = train(client, snapshots, contamination=0.2).json()
    with service.store.engine.begin() as connection:
        ciphertext = connection.execute(
            text("SELECT payload FROM models WHERE id=:id"), {"id": model["model_id"]}
        ).scalar_one()
        connection.execute(
            text("UPDATE models SET payload=:payload WHERE id=:id"),
            {"payload": ciphertext, "id": other["model_id"]},
        )
    assert client.get(f"/api/v1/models/{other['model_id']}", headers=HEADERS).status_code == 503
    with service.store.engine.begin() as connection:
        connection.execute(text("DROP TABLE audit_events"))
    with pytest.raises(OperationalError):
        service.train_model(
            TrainModelOptions(
                configuration_ids=[UUID(item["configuration_id"]) for item in snapshots]
            )
        )
    with service.store.engine.connect() as connection:
        assert connection.execute(text("SELECT count(*) FROM models")).scalar_one() == 2


def test_analysis_contract_rejects_statistical_substitution(registry_api) -> None:
    client, _, _ = registry_api
    model = train(client, population(client)).json()
    target = upload(client, 999, vlans=30)
    result = analyze(client, target, model["model_id"]).json()
    for change in ("version", "prediction", "score", "training", "risk", "model", "offset"):
        modified = deepcopy(result)
        if change == "version":
            modified["version"] = "analysis-api-0.2.0"
        elif change == "prediction":
            modified["statistical"]["prediction"] = 1
        elif change == "score":
            modified["statistical"]["score_samples"] = -0.1
        elif change == "training":
            modified["statistical"]["model"]["training"][0]["device_id"] = target["device_id"]
        elif change == "model":
            modified["statistical"]["model"]["model_id"] = str(uuid4())
        elif change == "offset":
            modified["statistical"]["model"]["decision_offset"] = -0.1
        else:
            modified["risk"]["components"][2]["status"] = "unavailable"
        with pytest.raises(ValueError):
            AnalysisResult.model_validate(modified)


def test_training_slot_limits_requests_and_is_released_after_failure(registry_api) -> None:
    client, service, _ = registry_api
    snapshots = population(client)
    assert service._training_slot.acquire(blocking=False)
    try:
        response = train(client, snapshots)
        assert response.status_code == 429 and response.headers["retry-after"] == "5"
    finally:
        service._training_slot.release()
    bad = deepcopy(snapshots)
    bad[0]["configuration_id"] = str(uuid4())
    assert train(client, bad).status_code == 400
    assert train(client, snapshots).status_code == 201


def test_models_request_bounds_and_missing_records(registry_api) -> None:
    client, _, _ = registry_api
    for path in ("/api/v1/models", f"/api/v1/models/{uuid4()}"):
        assert client.get(path).status_code == 401
    assert client.get(f"/api/v1/models/{uuid4()}", headers=HEADERS).status_code == 404
    for query in ("limit=21", "offset=10001", "limit=0"):
        assert client.get(f"/api/v1/models?{query}", headers=HEADERS).status_code == 422
    response = client.post(
        "/api/v1/models/isolation-forest", headers=HEADERS, content=b"{" + b" " * (16 * 1024)
    )
    assert response.status_code == 415
    response = client.post(
        "/api/v1/models/isolation-forest",
        headers=HEADERS | {"Content-Type": "application/json"},
        content=b"{" + b" " * (16 * 1024),
    )
    assert response.status_code == 413
    response = client.post(
        "/api/v1/models/isolation-forest",
        headers=HEADERS | {"Content-Type": "application/json"},
        content=b'{"configuration_ids": [], "configuration_ids": []}',
    )
    assert response.status_code == 400
