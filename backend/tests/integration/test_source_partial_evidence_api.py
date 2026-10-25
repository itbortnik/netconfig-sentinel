"""Actual saved partial diagnostic/report/assessment/disposition chains on authored inputs."""

import json
from uuid import uuid4

import pytest
from app.db.source_records import SourceRecords
from app.main import create_app
from fastapi.testclient import TestClient
from sqlalchemy import text
from test_source_partial_diagnostic_api import MARKER, options, post, prepare
from test_source_patch_review_api import ANALYST, ENGINEER, HEADERS, READER
from test_source_patch_review_api import source_api as source_api

ENGINEER_HEADERS = {"Authorization": f"Bearer {ENGINEER}"}


def chain(client, vendor="cisco", partial="after", *, critical=False):
    selected = prepare(client, vendor, partial, critical=critical)
    source_request = options(client, selected)
    response = post(client, selected, source_request, headers=ENGINEER_HEADERS)
    assert response.status_code == 201, response.text
    child = response.json()
    base = f"/api/v2/patches/{selected[0]['patch_id']}/evidence-reports"
    request = {
        "version": "source-evidence-request-0.5.0",
        "mode": "policy_only_partial_diagnostic",
        "report_id": str(uuid4()),
        "draft_sha256": child["draft_sha256"],
        "deterministic": {
            "record_id": child["recheck_id"],
            "review_sha256": child["review_sha256"],
        },
        "forest": None,
        "neural": None,
        "network": None,
    }
    response = client.post(base, headers=ENGINEER_HEADERS, json=request)
    assert response.status_code == 201, response.text
    report = response.json()
    report_base = base + "/" + report["report_id"]
    risk_request = {
        "version": "source-risk-request-0.3.0",
        "assessment_id": str(uuid4()),
        "report_sha256": report["review_sha256"],
        "profile_version": "source-priority-profile-0.1.0",
    }
    response = client.post(
        report_base + "/risk-assessments", headers=ENGINEER_HEADERS, json=risk_request
    )
    assert response.status_code == 201, response.text
    risk = response.json()
    decisions = []
    for verdict in ("rejected", "needs_more_information"):
        decision_request = {
            "version": "source-evidence-decision-request-0.5.0",
            "decision_id": str(uuid4()),
            "report_sha256": report["review_sha256"],
            "verdict": verdict,
            "comment": "Incomplete parsing requires more source context and individual review.",
        }
        response = client.post(
            report_base + "/decisions", headers=ENGINEER_HEADERS, json=decision_request
        )
        assert response.status_code == 201, response.text
        decisions.append((decision_request, response.json()))
    return dict(
        selected=selected,
        child=child,
        source_request=source_request,
        base=base,
        report_base=report_base,
        report_request=request,
        report=report,
        risk_request=risk_request,
        risk=risk,
        decisions=decisions,
    )


def replay(client, saved):
    resources = [
        (saved["base"], saved["report_request"], saved["report"], "report_id"),
        (
            saved["report_base"] + "/risk-assessments",
            saved["risk_request"],
            saved["risk"],
            "assessment_id",
        ),
    ]
    resources += [
        (saved["report_base"] + "/decisions", request, value, "decision_id")
        for request, value in saved["decisions"]
    ]
    for url, request, value, key in resources:
        response = client.post(url, headers=HEADERS, json=request)
        assert response.status_code == 200, response.text
        assert response.json() == value
        response = client.get(url + "/" + value[key], headers=HEADERS)
        assert response.status_code == 200 and response.json() == value
        listing = client.get(url, headers=HEADERS)
        assert listing.status_code == 200, listing.text
        assert any(row[key] == value[key] for row in listing.json())
        assert MARKER not in listing.text


@pytest.mark.parametrize("vendor", ["cisco", "juniper"])
@pytest.mark.parametrize("partial", ["before", "after", "both"])
def test_six_saved_http_chains_survive_source_removal_and_restart(
    source_api, monkeypatch, vendor, partial, tmp_path
):
    client, application, settings, calls = source_api
    saved = chain(client, vendor, partial)
    report, risk = saved["report"], saved["risk"]
    assert report["coverage"] == "partial" and report["formal_qualification"] == "not_proven"
    assert report["deterministic"]["report"] == saved["child"]["outcome"]["report"]
    comp = risk["composition"]
    assert comp["status"] == "unavailable" and comp["coverage"] == "partial"
    assert comp["score"] is comp["band"] is None
    assert comp["availability_mask"] == ["policy"]
    assert all(
        row["effective_weight"] == 0 and row["contribution"] is None for row in comp["components"]
    )
    assert comp["applied_guardrails"] == []
    assert risk["service_role"] == "engineer"
    for _, decision in saved["decisions"]:
        assert decision["service_role"] == "engineer"
        assert (
            decision["individual_identity_verified"]
            is decision["approved"]
            is decision["applied"]
            is False
        )
    assert MARKER not in json.dumps({k: v for k, v in saved.items() if k != "selected"})
    assert calls == []
    replay(client, saved)
    with application.state.analysis_service.store.engine.begin() as connection:
        connection.execute(text("DELETE FROM configuration_sources"))

    def forbidden(*args, **kwargs):
        pytest.fail("history cannot execute parser, policy, source IO, model or engine")

    for name in (
        "app.patching.source_deterministic.prepare_partial_policy",
        "app.patching.source_deterministic.recheck_partial_policy",
        "app.patching.source_deterministic.prepare_original_source",
        "app.parsers.parse_configuration",
        "app.ingestion.source_retention.parse_configuration",
        "app.detection.policy_diagnostic.evaluate_policies",
        "app.detection.policy_engine.evaluate_policies",
    ):
        monkeypatch.setattr(name, forbidden)
    monkeypatch.setattr(SourceRecords, "get", forbidden)
    monkeypatch.setattr("app.detection.policy_engine.POLICY_CATALOGS", {})
    with TestClient(create_app(settings)) as restarted:
        replay(restarted, saved)
    (tmp_path / "saved-chain.json").write_text(
        json.dumps({k: v for k, v in saved.items() if k != "selected"}, sort_keys=True, indent=2),
        encoding="utf-8",
    )


@pytest.mark.parametrize("vendor", ["cisco", "juniper"])
def test_actual_critical_after_policy_remains_visible_without_numeric_aggregate(source_api, vendor):
    saved = chain(source_api[0], vendor, critical=True)
    assert any(
        row["category"] == "routing.default_route_discarded" and row["severity"] == "critical"
        for row in saved["report"]["deterministic"]["report"]["after"]["policy_findings"]
    )
    assert saved["risk"]["composition"]["applicable_guardrails"] == [
        {"kind": "critical_policy", "floor": 0.9}
    ]
    assert saved["risk"]["composition"]["score"] is None


def test_legacy_protocols_refuse_new_partial_dependencies_as_conflicts(source_api):
    client = source_api[0]
    saved = chain(client)
    for version in ("0.1.0", "0.2.0", "0.3.0", "0.4.0"):
        body = saved["report_request"] | {
            "version": "source-evidence-request-" + version,
            "report_id": str(uuid4()),
        }
        body.pop("mode")
        response = client.post(saved["base"], headers=HEADERS, json=body)
        assert response.status_code == 409, response.text
    for version in ("0.1.0", "0.2.0"):
        body = saved["risk_request"] | {
            "version": "source-risk-request-" + version,
            "assessment_id": str(uuid4()),
        }
        response = client.post(
            saved["report_base"] + "/risk-assessments", headers=HEADERS, json=body
        )
        assert response.status_code == 409, response.text
    for version in ("0.1.0", "0.2.0", "0.3.0", "0.4.0"):
        body = saved["decisions"][0][0] | {
            "version": "source-evidence-decision-request-" + version,
            "decision_id": str(uuid4()),
        }
        response = client.post(saved["report_base"] + "/decisions", headers=HEADERS, json=body)
        assert response.status_code == 409, response.text


@pytest.mark.parametrize("route", ["report", "risk", "decision"])
@pytest.mark.parametrize("token", [READER, ANALYST])
def test_new_routes_keep_permissions_before_body_parsing(source_api, route, token):
    client = source_api[0]
    saved = chain(client)
    url = (
        saved["base"]
        if route == "report"
        else saved["report_base"] + ("/risk-assessments" if route == "risk" else "/decisions")
    )
    response = client.post(
        url,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        content=b'{"invalid":',
    )
    assert response.status_code == 403


def test_openapi_new_modes_require_explicit_version(source_api):
    document = source_api[0].get("/openapi.json").json()
    for path, version in (
        ("/api/v2/patches/{patch_id}/deterministic-rechecks", "source-deterministic-request-0.2.0"),
        ("/api/v2/patches/{patch_id}/evidence-reports", "source-evidence-request-0.5.0"),
        (
            "/api/v2/patches/{patch_id}/evidence-reports/{report_id}/risk-assessments",
            "source-risk-request-0.3.0",
        ),
        (
            "/api/v2/patches/{patch_id}/evidence-reports/{report_id}/decisions",
            "source-evidence-decision-request-0.5.0",
        ),
    ):
        branches = document["paths"][path]["post"]["requestBody"]["content"]["application/json"][
            "schema"
        ]["anyOf"]
        selected = next(
            item for item in branches if item["properties"]["version"]["const"] == version
        )
        assert "version" in selected["required"]
