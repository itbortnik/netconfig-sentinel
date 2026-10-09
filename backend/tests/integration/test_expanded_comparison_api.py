"""Expanded comparisons are explicit, encrypted, replayable and source-bound."""

import os
from collections.abc import Iterator
from copy import deepcopy
from pathlib import Path
from uuid import uuid4

import pytest
from app.api.contracts import AnalysisResult, ExpandedComparisonContext
from app.core.settings import ApiSettings
from app.db.migrate import upgrade_database
from app.db.store import Store, make_engine
from app.main import create_app
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.engine import make_url

TOKEN = "expanded-comparison-owned-service-token-001"
HEADERS = {"Authorization": f"Bearer {TOKEN}"}
LABELS = {"device_role": "edge", "site_class": "branch", "service_profile": "owned"}


@pytest.fixture
def expanded_api(tmp_path: Path) -> Iterator[tuple[TestClient, Store, ApiSettings]]:
    configured = os.environ.get("NETCONFIG_TEST_DATABASE_URL", "")
    if configured:
        # The CI PostgreSQL job opts in explicitly. Never write into a deployment
        # schema or accept a caller-selected database without the test-name gate.
        url = make_url(configured)
        if url.drivername != "postgresql+psycopg" or not (url.database or "").endswith("_test"):
            pytest.fail("expanded comparisons require a postgresql+psycopg *_test database")
        schema_id = uuid4()
        schema = f"sentinel_expanded_test_{schema_id.hex}"
        admin = make_engine(configured)
        store = None
        created = False
        try:
            with admin.begin() as connection:
                connection.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
            created = True
            selected = url.update_query_dict({"options": f"-csearch_path={schema}"})
            settings = ApiSettings(
                selected.render_as_string(hide_password=False),
                TOKEN,
                Fernet.generate_key().decode(),
            )
            application = create_app(settings)
            store = application.state.analysis_service.store
            upgrade_database(store.engine)
            with TestClient(application) as client:
                yield client, store, settings
        finally:
            if store is not None:
                store.close()
            # The exact target is generated here, never read from environment.
            assert schema == f"sentinel_expanded_test_{schema_id.hex}"
            if created:
                with admin.begin() as connection:
                    connection.exec_driver_sql(f'DROP SCHEMA "{schema}" CASCADE')
            admin.dispose()
        return
    settings = ApiSettings(
        f"sqlite:///{tmp_path / 'expanded.sqlite3'}", TOKEN, Fernet.generate_key().decode()
    )
    application = create_app(settings)
    store = application.state.analysis_service.store
    upgrade_database(store.engine)
    with TestClient(application) as client:
        yield client, store, settings


@pytest.mark.parametrize(
    "database",
    [
        "sqlite:///not-a-postgresql-test.sqlite3",
        "postgresql+psycopg://localhost/sentinel",
        "postgresql+psycopg://localhost/sentinel_test_backup",
        "postgresql://localhost/sentinel_test",
    ],
)
def test_expanded_test_database_rejects_non_test_targets(tmp_path, monkeypatch, database):
    monkeypatch.setenv("NETCONFIG_TEST_DATABASE_URL", database)
    fixture = expanded_api.__wrapped__(tmp_path)
    with pytest.raises(pytest.fail.Exception, match=r"postgresql\+psycopg \*_test database"):
        next(fixture)


def source(vendor: str, host: str, address: str = "192.0.2.1") -> str:
    if vendor == "cisco":
        return f"hostname {host}\nntp server {address}\n"
    return f"set system host-name {host}\nset system ntp server {address}\n"


def upload(client, content, device=None):
    response = client.post(
        "/api/v1/configurations",
        headers=HEADERS,
        json={
            "device_id": device or str(uuid4()),
            "filename": "owned.cfg",
            "content": content,
            "inventory": LABELS,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def analyze(client, snapshot, **options):
    return client.post(
        f"/api/v1/configurations/{snapshot['configuration_id']}/analyze",
        headers=HEADERS,
        json=options,
    )


def explain(client, result, finding):
    local = next(
        item for item in result["explanations"] if item["finding_id"] == finding["finding_id"]
    )
    response = client.post(
        f"/api/v1/findings/{finding['finding_id']}/explain",
        headers=HEADERS,
        json={"analysis_id": result["analysis_id"], "finding_sha256": local["finding_sha256"]},
    )
    assert response.status_code == 200, response.text
    bundle = response.json()
    assert bundle["explanation"] == local
    assert bundle["knowledge_version"] == "project-knowledge-0.3.0"
    assert bundle["documents"] and bundle["explanation"]["formal_verification"] == "not_run"
    return bundle


@pytest.mark.parametrize("vendor", ["cisco", "juniper"])
def test_expanded_reference_is_explicit_and_history_unchanged(expanded_api, vendor):
    client, store, settings = expanded_api
    reference = upload(client, source(vendor, "reference"))
    target = upload(client, source(vendor, "reference", "192.0.2.9"), reference["device_id"])
    options = {"reference_configuration_id": reference["configuration_id"]}
    old = analyze(client, target, **options).json()
    assert old["version"] == "analysis-api-0.2.0"
    assert not any(item["detector"] == "expected_configuration" for item in old["findings"])
    response = analyze(client, target, **options, comparison_version="0.2.0")
    assert response.status_code == 201, response.text
    result = response.json()
    assert result["version"] == "analysis-api-0.4.0"
    assert result["comparison"]["version"] == "comparison-context-0.2.0"
    assert result["comparison"]["peer_evaluation"] is None
    assert result["risk"] == old["risk"]
    findings = [item for item in result["findings"] if item["detector"] == "expected_configuration"]
    assert len(findings) == 1 and findings[0]["model_version"] == "expected-config-0.2.0"
    assert findings[0]["affected_lines"] == [2]
    assert findings[0]["expected"]["source_sha256"] == reference["canonical"]["source"]["sha256"]
    bundle = explain(client, result, findings[0])
    assert bundle["documents"][0]["section"] == "expanded-supported-facts"
    with TestClient(create_app(settings)) as restarted:
        for recorded in (old, result):
            assert (
                restarted.get(f"/api/v1/analyses/{recorded['analysis_id']}", headers=HEADERS).json()
                == recorded
            )
        assert explain(restarted, result, findings[0]) == bundle
    with store.engine.connect() as connection:
        encrypted = connection.execute(text("SELECT payload FROM analyses")).scalars().all()
        assert all("192.0.2.9" not in row and "peer_evaluation" not in row for row in encrypted)


@pytest.mark.parametrize("vendor", ["cisco", "juniper"])
@pytest.mark.parametrize("partial", [False, True])
def test_expanded_peer_report_and_saved_explanations(expanded_api, vendor, partial):
    client, _, settings = expanded_api
    peers = [upload(client, source(vendor, f"peer-{index}")) for index in range(3)]
    extra = "unknown PRIVATE_COMMAND\n" if partial else ""
    target = upload(client, source(vendor, "target", "192.0.2.9") + extra)
    response = analyze(
        client,
        target,
        comparison_version="0.2.0",
        peer_configuration_ids=[item["configuration_id"] for item in peers],
    )
    assert response.status_code == 201, response.text
    result = response.json()
    comparison = result["comparison"]
    report = comparison["peer_evaluation"]
    assert len(report["profile_features"]) == 19
    assert report["status"] == result["status"] == ("partial" if partial else "completed")
    assert report["source_sha256"] == result["source_sha256"]
    assert report["findings"] == [
        item for item in result["findings"] if item["detector"] == "peer_baseline"
    ]
    assert bool(report["skipped_features"]) == partial
    assert bool(report["compared_features"]) != partial
    if partial:
        assert result["risk"] is None
        assert not any(
            item["category"] == "baseline.management.ntp_servers_deviation"
            for item in report["findings"]
        )
        assert "PRIVATE_COMMAND" not in response.text
    else:
        assert report["findings"][0]["category"] == "baseline.management.ntp_servers_deviation"
    for finding in report["findings"]:
        bundle = explain(client, result, finding)
        assert bundle["documents"][0]["section"] == "expanded-peer-templates"
    with TestClient(create_app(settings)) as restarted:
        assert (
            restarted.get(f"/api/v1/analyses/{result['analysis_id']}", headers=HEADERS).json()
            == result
        )
    assert isinstance(AnalysisResult.model_validate(result).comparison, ExpandedComparisonContext)


@pytest.mark.parametrize(
    "case",
    [
        "version",
        "profile",
        "report_hash",
        "report_source",
        "report_device",
        "samples",
        "features",
        "findings",
        "status",
    ],
)
def test_expanded_saved_contract_rejects_rebound_context(expanded_api, case):
    client, _, _ = expanded_api
    peers = [upload(client, source("cisco", f"peer-{index}")) for index in range(3)]
    target = upload(client, source("cisco", "target", "192.0.2.9"))
    result = analyze(
        client,
        target,
        comparison_version="0.2.0",
        peer_configuration_ids=[item["configuration_id"] for item in peers],
    ).json()
    altered = deepcopy(result)
    context = altered["comparison"]
    report = context["peer_evaluation"]
    if case == "version":
        altered["version"] = "analysis-api-0.2.0"
    elif case == "profile":
        context["peer_baseline"]["consensus_threshold"] = 0.9
    elif case == "samples":
        context["peers"][0]["source_sha256"] = "f" * 64
    elif case == "features":
        report["profile_features"].pop()
        report["compared_features"].pop()
    elif case == "findings":
        report["findings"] = []
    elif case == "status":
        altered["status"] = "partial"
        altered["risk"] = None
    else:
        field = {
            "report_hash": "baseline_sha256",
            "report_source": "source_sha256",
            "report_device": "device_id",
        }[case]
        report[field] = str(uuid4()) if field == "device_id" else "f" * 64
    with pytest.raises(ValueError):
        AnalysisResult.model_validate(altered)


@pytest.mark.parametrize("version", [None, "0.3.0", 2, "private marker"])
def test_unknown_comparison_versions_are_sanitized_without_saved_run(expanded_api, version):
    client, store, _ = expanded_api
    target = upload(client, source("cisco", "target"))
    response = analyze(client, target, comparison_version=version)
    assert response.status_code == 400 and "private marker" not in response.text
    with store.engine.connect() as connection:
        assert connection.execute(text("SELECT count(*) FROM analyses")).scalar_one() == 0


def test_version_without_selected_inputs_does_not_claim_a_comparison(expanded_api):
    client, _, _ = expanded_api
    target = upload(client, source("cisco", "target"))
    result = analyze(client, target, comparison_version="0.2.0").json()
    assert result["version"] == "analysis-api-0.1.0" and result["comparison"] is None


@pytest.mark.parametrize("vendor", ["cisco", "juniper"])
def test_partial_report_remains_partial_without_a_parser_threshold_finding(expanded_api, vendor):
    client, _, _ = expanded_api
    peers = [upload(client, source(vendor, f"peer-{index}")) for index in range(3)]
    command = "ntp server 192.0.2.1\n" if vendor == "cisco" else "set system ntp server 192.0.2.1\n"
    target = upload(client, source(vendor, "target") + command * 100 + "unknown PRIVATE_COMMAND\n")
    response = analyze(
        client,
        target,
        comparison_version="0.2.0",
        peer_configuration_ids=[item["configuration_id"] for item in peers],
    )
    assert response.status_code == 201, response.text
    result = response.json()
    report = result["comparison"]["peer_evaluation"]
    assert result["status"] == report["status"] == "partial" and result["risk"] is None
    assert report["findings"] == [] and report["compared_features"] == []
    assert len(report["skipped_features"]) == 19
    assert 0 < report["unsupported_ratio"] <= 0.05


@pytest.mark.parametrize("vendor", ["cisco", "juniper"])
def test_nonconsensus_values_are_omitted_not_reported_as_parsing_skips(expanded_api, vendor):
    client, _, _ = expanded_api
    peers = [
        upload(client, source(vendor, f"peer-{index}", f"192.0.2.{index + 1}"))
        for index in range(3)
    ]
    target = upload(client, source(vendor, "target", "192.0.2.9"))
    response = analyze(
        client,
        target,
        comparison_version="0.2.0",
        peer_configuration_ids=[item["configuration_id"] for item in peers],
    )
    assert response.status_code == 201, response.text
    context = response.json()["comparison"]
    assert context["peer_baseline"]["omitted_features"] == ["management.ntp_servers"]
    report = context["peer_evaluation"]
    assert report["status"] == "completed" and not report["skipped_features"]
    assert len(report["compared_features"]) == 18 and not report["findings"]


def test_expanded_reference_peers_and_actual_forest_share_one_saved_run(expanded_api):
    client, _, settings = expanded_api
    training = [
        upload(client, source("cisco", f"train-{index}", f"192.0.2.{index + 20}"))
        for index in range(8)
    ]
    response = client.post(
        "/api/v1/models/isolation-forest",
        headers=HEADERS,
        json={"configuration_ids": [item["configuration_id"] for item in training]},
    )
    assert response.status_code == 201, response.text
    model = response.json()
    peers = [upload(client, source("cisco", f"peer-{index}")) for index in range(3)]
    reference = upload(client, source("cisco", "target"))
    target = upload(client, source("cisco", "target", "192.0.2.9"), reference["device_id"])
    response = analyze(
        client,
        target,
        comparison_version="0.2.0",
        reference_configuration_id=reference["configuration_id"],
        peer_configuration_ids=[item["configuration_id"] for item in peers],
        statistical_model_id=model["model_id"],
    )
    assert response.status_code == 201, response.text
    result = response.json()
    assert result["version"] == "analysis-api-0.4.0"
    assert result["statistical"]["model"] == model
    assert {
        item["source"] for item in result["risk"]["components"] if item["status"] == "completed"
    } == {"policy", "peer_group", "statistical"}
    assert result["comparison"]["peer_evaluation"]["status"] == "completed"
    with TestClient(create_app(settings)) as restarted:
        assert (
            restarted.get(f"/api/v1/analyses/{result['analysis_id']}", headers=HEADERS).json()
            == result
        )


@pytest.mark.parametrize(
    "case", ["newer", "partial", "casefold_host", "same_device", "wrong_group"]
)
def test_expanded_peers_refuse_incompatible_sources_without_persisting(expanded_api, case):
    client, store, _ = expanded_api
    peers = [upload(client, source("cisco", f"peer-{index}")) for index in range(3)]
    if case == "casefold_host":
        peers[1] = upload(client, source("cisco", "PEER-0"))
    elif case == "same_device":
        peers[1] = upload(
            client, source("cisco", "peer-0") + "! a new version\n", peers[0]["device_id"]
        )
    elif case == "partial":
        peers[1] = upload(client, source("cisco", "partial") + "unknown PRIVATE_COMMAND\n")
    elif case == "wrong_group":
        peers[1] = upload(client, source("juniper", "other"))
    target = upload(client, source("cisco", "target"))
    if case == "newer":
        peers[1] = upload(client, source("cisco", "future"))
    response = analyze(
        client,
        target,
        comparison_version="0.2.0",
        peer_configuration_ids=[item["configuration_id"] for item in peers],
    )
    assert response.status_code == 400 and "PRIVATE_COMMAND" not in response.text
    with store.engine.connect() as connection:
        assert connection.execute(text("SELECT count(*) FROM analyses")).scalar_one() == 0
