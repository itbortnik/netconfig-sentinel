"""Explicit, bounded, encrypted and restart-safe reference/peer comparisons."""

from collections.abc import Iterator
from copy import deepcopy
from pathlib import Path
from uuid import uuid4

import pytest
from app.api.contracts import AnalysisResult
from app.core.settings import ApiSettings
from app.db.migrate import upgrade_database
from app.db.store import Store
from app.main import create_app
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import text

TOKEN = "comparison-test-token-not-for-deployment-001"
HEADERS = {"Authorization": f"Bearer {TOKEN}"}
LABELS = {"device_role": "edge", "site_class": "branch", "service_profile": "private-test"}


@pytest.fixture
def comparison_api(tmp_path: Path) -> Iterator[tuple[TestClient, Store, ApiSettings]]:
    settings = ApiSettings(
        f"sqlite:///{tmp_path / 'comparison.sqlite3'}", TOKEN, Fernet.generate_key().decode()
    )
    application = create_app(settings)
    store = application.state.analysis_service.store
    upgrade_database(store.engine)
    with TestClient(application) as client:
        yield client, store, settings


def upload(client: TestClient, content: str, *, device: str | None = None, **extra: object) -> dict:
    response = client.post(
        "/api/v1/configurations",
        headers=HEADERS,
        json={"device_id": device or str(uuid4()), "filename": "test.cfg", "content": content}
        | extra,
    )
    assert response.status_code == 201, response.text
    return response.json()


def analyze(client: TestClient, snapshot: dict, options: dict | None = None):
    return client.post(
        f"/api/v1/configurations/{snapshot['configuration_id']}/analyze",
        headers=HEADERS,
        **({"json": options} if options is not None else {}),
    )


def peer_text(host: str, *, telnet: bool = False) -> str:
    return (
        f"hostname {host}\naaa new-model\nip ssh version 2\nline vty 0 4\n"
        f" transport input ssh{' telnet' if telnet else ''}\n!\n"
        "ntp server 192.0.2.1\nlogging host 192.0.2.2\n"
    )


def cohort(client: TestClient) -> tuple[list[dict], dict]:
    peers = [upload(client, peer_text(f"peer-{index}"), inventory=LABELS) for index in range(3)]
    target = upload(client, peer_text("target", telnet=True), inventory=LABELS)
    return peers, target


@pytest.mark.parametrize(
    "labels",
    [
        {"device_role": "edge"},
        LABELS | {"device_role": ""},
        LABELS | {"site_class": " padded"},
        LABELS | {"service_profile": "private\ninput"},
        LABELS | {"service_profile": "private\u0085input"},
        LABELS | {"service_profile": "private\u200binput"},
        LABELS | {"device_role": "x" * 65},
        LABELS | {"unexpected": "private-input"},
    ],
)
def test_inventory_labels_are_complete_bounded_and_never_echoed(comparison_api, labels) -> None:
    client, _, _ = comparison_api
    response = client.post(
        "/api/v1/configurations",
        headers=HEADERS,
        json={
            "device_id": str(uuid4()),
            "filename": "test.cfg",
            "content": "hostname edge\n",
            "inventory": labels,
        },
    )
    assert response.status_code == 400
    assert response.json() == {"detail": "Invalid configuration upload."}


@pytest.mark.parametrize(
    "before",
    [
        "hostname ref-edge\ninterface Gi0/1\n switchport mode access\n"
        " switchport access vlan 10\n!\n",
        "set system host-name ref-edge\n"
        "set interfaces ge-0/0/1 unit 0 family ethernet-switching interface-mode access\n"
        "set interfaces ge-0/0/1 unit 0 family ethernet-switching vlan members 10\n",
    ],
)
def test_reference_provenance_risk_and_restart(comparison_api, before: str) -> None:
    client, store, settings = comparison_api
    reference = upload(client, before)
    current = upload(client, before.replace(" 10", " 20"), device=reference["device_id"])
    policy_only = analyze(client, current).json()
    response = analyze(
        client, current, {"reference_configuration_id": reference["configuration_id"]}
    )
    assert response.status_code == 201, response.text
    result = response.json()
    assert result["version"] == "analysis-api-0.2.0"
    deviations = [
        item for item in result["findings"] if item["detector"] == "expected_configuration"
    ]
    assert len(deviations) == 1
    assert deviations[0]["expected"]["reference_id"] == reference["configuration_id"]
    assert deviations[0]["expected"]["source_sha256"] == reference["canonical"]["source"]["sha256"]
    assert result["risk"] == policy_only["risk"]  # A planned difference is not a risk signal.
    assert result["comparison"]["reference"]["configuration_id"] == reference["configuration_id"]
    deviation = deviations[0]
    explanation = next(
        item for item in result["explanations"] if item["finding_id"] == deviation["finding_id"]
    )
    contextual = client.post(
        f"/api/v1/findings/{deviation['finding_id']}/explain",
        headers=HEADERS,
        json={
            "analysis_id": result["analysis_id"],
            "finding_sha256": explanation["finding_sha256"],
        },
    )
    assert contextual.status_code == 200, contextual.text
    assert contextual.json()["explanation"] == explanation
    assert contextual.json()["documents"][0]["document_id"] == "docs/expected-configuration.md"
    with TestClient(create_app(settings)) as restarted:
        assert (
            restarted.get(f"/api/v1/analyses/{result['analysis_id']}", headers=HEADERS).json()
            == result
        )
    with store.engine.connect() as connection:
        ciphertext = connection.execute(text("SELECT payload FROM analyses")).scalars().all()
        assert all(
            "ref-edge" not in item and "expected_configuration" not in item for item in ciphertext
        )


def test_peer_profile_and_actual_completed_signals(comparison_api) -> None:
    client, store, settings = comparison_api
    peers, target = cohort(client)
    selection = {"peer_configuration_ids": [item["configuration_id"] for item in peers]}
    response = analyze(client, target, selection)
    assert response.status_code == 201, response.text
    result = response.json()
    profile = result["comparison"]["peer_baseline"]
    assert profile["sample_count"] == 3
    assert profile["group"]["device_role"] == LABELS["device_role"]
    assert len(result["comparison"]["peers"]) == 3
    findings = [item for item in result["findings"] if item["detector"] == "peer_baseline"]
    assert [item["category"] for item in findings] == [
        "baseline.management.telnet_enabled_deviation"
    ]
    assert findings[0]["affected_lines"] == [5]
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
    assert len(contextual.json()["documents"]) == 2
    assert all(item["document_id"] == "docs/baseline.md" for item in contextual.json()["documents"])
    sources = {item["source"]: item for item in result["risk"]["components"]}
    assert sources["policy"]["effective_weight"] == pytest.approx(0.7)
    assert sources["peer_group"]["effective_weight"] == pytest.approx(0.3)
    assert sources["peer_group"]["status"] == "completed"
    assert sources["statistical"]["status"] == sources["verification"]["status"] == "unavailable"
    second = analyze(
        client,
        target,
        {"peer_configuration_ids": list(reversed(selection["peer_configuration_ids"]))},
    ).json()
    for key in ("findings", "explanations", "risk", "comparison"):
        assert result[key] == second[key]
    with TestClient(create_app(settings)) as restarted:
        assert (
            restarted.get(f"/api/v1/analyses/{result['analysis_id']}", headers=HEADERS).json()
            == result
        )
    with store.engine.connect() as connection:
        assert connection.execute(text("SELECT count(*) FROM audit_events")).scalar_one() == 6


def test_combined_reference_and_peer_analysis(comparison_api) -> None:
    client, _, _ = comparison_api
    peers, _ = cohort(client)
    before = (
        peer_text("combined")
        + "interface Gi0/1\n switchport mode access\n switchport access vlan 10\n!\n"
    )
    reference = upload(client, before, inventory=LABELS)
    current = upload(
        client,
        before.replace("input ssh\n", "input ssh telnet\n").replace("vlan 10", "vlan 20"),
        device=reference["device_id"],
        inventory=LABELS,
    )
    response = analyze(
        client,
        current,
        {
            "reference_configuration_id": reference["configuration_id"],
            "peer_configuration_ids": [item["configuration_id"] for item in peers],
        },
    )
    assert response.status_code == 201, response.text
    result = response.json()
    assert {item["detector"] for item in result["findings"]} == {
        "policy_engine",
        "peer_baseline",
        "expected_configuration",
    }
    assert AnalysisResult.model_validate(result).comparison is not None
    tampered = deepcopy(result)
    next(item for item in tampered["findings"] if item["detector"] == "expected_configuration")[
        "expected"
    ]["source_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="reference snapshot"):
        AnalysisResult.model_validate(tampered)


def test_reference_deletion_does_not_invent_current_line_anchors(comparison_api) -> None:
    client, _, _ = comparison_api
    before = (
        peer_text("removed")
        + "interface Gi0/1\n switchport mode access\n switchport access vlan 10\n!\n"
    )
    reference = upload(client, before)
    current = upload(client, peer_text("removed"), device=reference["device_id"])
    response = analyze(
        client, current, {"reference_configuration_id": reference["configuration_id"]}
    )
    assert response.status_code == 201, response.text
    result = response.json()
    for finding, explanation in zip(result["findings"], result["explanations"], strict=True):
        if finding["detector"] == "expected_configuration":
            assert finding["affected_lines"] == explanation["anchors"] == []
            assert finding["expected"]["reference_lines"]
            assert finding["observed"]["present"] is False


def test_partial_target_with_peers_keeps_findings_without_risk(comparison_api) -> None:
    client, _, _ = comparison_api
    peers, _ = cohort(client)
    target = upload(client, peer_text("partial") + "unknown private-input\n", inventory=LABELS)
    response = analyze(
        client, target, {"peer_configuration_ids": [item["configuration_id"] for item in peers]}
    )
    assert response.status_code == 201, response.text
    result = response.json()
    assert result["status"] == "partial" and result["risk"] is None
    assert result["comparison"]["peer_baseline"] is not None
    assert any(
        item["category"] == "baseline.parser.unsupported_ratio_high" for item in result["findings"]
    )


@pytest.mark.parametrize(
    "case",
    [
        "missing",
        "current",
        "duplicate",
        "too_few",
        "same_device",
        "mixed_group",
        "partial_peer",
        "newer_peer",
        "no_inventory",
    ],
)
def test_incompatible_peers_fail_without_saving_a_partial_run(comparison_api, case: str) -> None:
    client, store, _ = comparison_api
    peers, target = cohort(client)
    ids = [item["configuration_id"] for item in peers]
    if case == "missing":
        ids[0] = str(uuid4())
    elif case == "current":
        ids[0] = target["configuration_id"]
    elif case == "duplicate":
        ids[1] = ids[0]
    elif case == "too_few":
        ids.pop()
    elif case in {"same_device", "mixed_group", "partial_peer"}:
        original = peers[0]
        content = peer_text("peer-0") + (
            "unknown-command\n" if case == "partial_peer" else "! another version\n"
        )
        labels = LABELS | ({"device_role": "other"} if case == "mixed_group" else {})
        replacement = upload(client, content, device=original["device_id"], inventory=labels)
        target = upload(client, peer_text("new-target", telnet=True), inventory=LABELS)
        if case == "same_device":
            ids[1] = replacement["configuration_id"]
        else:
            ids[0] = replacement["configuration_id"]
    elif case == "newer_peer":
        ids[0] = upload(client, peer_text("future-peer"), inventory=LABELS)["configuration_id"]
    elif case == "no_inventory":
        target = upload(client, peer_text("unlabelled"))
    with store.engine.connect() as connection:
        audits = connection.execute(text("SELECT count(*) FROM audit_events")).scalar_one()
    response = analyze(client, target, {"peer_configuration_ids": ids})
    assert response.status_code == 400
    assert "private-input" not in response.text
    with store.engine.connect() as connection:
        assert connection.execute(text("SELECT count(*) FROM analyses")).scalar_one() == 0
        assert connection.execute(text("SELECT count(*) FROM audit_events")).scalar_one() == audits


@pytest.mark.parametrize("case", ["self", "other_device", "missing", "newer", "partial"])
def test_reference_selection_is_explicit_and_validated(comparison_api, case: str) -> None:
    client, _, _ = comparison_api
    before = upload(client, "hostname edge\n" + ("unknown secret\n" if case == "partial" else ""))
    current = upload(client, "hostname edge\n", device=before["device_id"])
    reference_id = before["configuration_id"]
    if case == "self":
        reference_id = current["configuration_id"]
    elif case == "other_device":
        reference_id = upload(client, "hostname other\n")["configuration_id"]
    elif case == "missing":
        reference_id = str(uuid4())
    elif case == "newer":
        current, before = before, current
        reference_id = before["configuration_id"]
    assert analyze(client, current, {"reference_configuration_id": reference_id}).status_code == 400


def test_optional_body_limits_auth_and_legacy_contract(comparison_api) -> None:
    client, _, _ = comparison_api
    current = upload(client, "hostname edge\n")
    path = f"/api/v1/configurations/{current['configuration_id']}/analyze"
    legacy = analyze(client, current).json()
    assert legacy["version"] == "analysis-api-0.1.0" and legacy["comparison"] is None
    legacy.pop("comparison")  # Existing encrypted rows remain readable without a migration.
    assert AnalysisResult.model_validate(legacy).comparison is None
    for content, status in (
        ("{", 400),
        ('{"peer_configuration_ids":[],"peer_configuration_ids":[]}', 400),
        ("x" * 16385, 413),
    ):
        assert (
            client.post(
                path, content=content, headers=HEADERS | {"Content-Type": "application/json"}
            ).status_code
            == status
        )
    assert client.post(path, headers=HEADERS, json={"secret": "private-input"}).status_code == 400
    assert client.post(path, content="invalid-private-input").status_code == 401
    assert (
        client.post(
            path, content="{}", headers=HEADERS | {"Content-Type": "text/plain"}
        ).status_code
        == 415
    )


def test_openapi_nested_inventory_schema_has_no_unresolved_local_refs(comparison_api) -> None:
    client, _, _ = comparison_api
    document = client.get("/openapi.json").json()
    upload_schema = document["paths"]["/api/v1/configurations"]["post"]["requestBody"]["content"][
        "application/json"
    ]["schema"]
    inventory = upload_schema["properties"]["inventory"]["anyOf"][0]
    assert inventory["additionalProperties"] is False
    assert set(inventory["required"]) == set(LABELS)
    assert "$defs" not in upload_schema and "#/$defs/" not in str(upload_schema)
    analysis_body = document["paths"]["/api/v1/configurations/{configuration_id}/analyze"]["post"][
        "requestBody"
    ]
    assert analysis_body["required"] is False
    schema = analysis_body["content"]["application/json"]["schema"]
    assert schema["properties"]["peer_configuration_ids"]["maxItems"] == 20


@pytest.mark.parametrize("case", ["profile_count", "peer_device", "risk", "version"])
def test_comparison_contract_rejects_rebound_profiles(comparison_api, case: str) -> None:
    client, _, _ = comparison_api
    peers, target = cohort(client)
    result = analyze(
        client, target, {"peer_configuration_ids": [item["configuration_id"] for item in peers]}
    ).json()
    altered = deepcopy(result)
    if case == "profile_count":
        altered["comparison"]["peers"].pop()
    elif case == "peer_device":
        altered["comparison"]["peers"][0]["device_id"] = target["device_id"]
    elif case == "risk":
        altered["risk"]["score"] = 0
    elif case == "version":
        altered["version"] = "analysis-api-0.1.0"
    with pytest.raises(ValueError):
        AnalysisResult.model_validate(altered)
