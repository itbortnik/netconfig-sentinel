"""Actual retained-source partial diagnostics; authored controls, not quality evidence."""

import json
from uuid import UUID, uuid4

import app.patching.source_deterministic as workflow_module
import pytest
from app.api.contracts import AnalysisResult
from app.api.source_partial_contracts import (
    RunSourcePartialDiagnostic,
    SourcePartialDiagnostic,
)
from app.db.source_records import SourceRecords
from app.main import create_app
from app.patching.source_deterministic import SourceDeterministicWorkflow
from fastapi.testclient import TestClient
from sqlalchemy import text
from test_source_deterministic_api import content, counts, upload
from test_source_deterministic_api import prepare as prepare_complete
from test_source_patch_review_api import ANALYST, ENGINEER, HEADERS, READER
from test_source_patch_review_api import source_api as source_api

MARKER = "owned-unknown-password-never-a-real-credential"


def authored_text(vendor, telnet, unknown=0, critical=False):
    result = content(vendor, "target", telnet=telnet)
    if critical:
        result += (
            "ip route 0.0.0.0 0.0.0.0 Null0\n"
            if vendor == "cisco"
            else "set routing-options static route 0.0.0.0/0 discard\n"
        )
    prefix = "" if vendor == "cisco" else "set "
    return result + (prefix + "unsupported-owned password " + MARKER + "\n") * unknown


def prepare(client, vendor="cisco", partial="after", *, retain=True, critical=False):
    before = upload(
        client,
        authored_text(vendor, True, int(partial in {"before", "both"})),
        retain=retain,
    )
    after = upload(
        client,
        authored_text(vendor, False, int(partial in {"after", "both"}), critical),
        device=before["device_id"],
        retain=retain,
    )
    response = client.post(
        f"/api/v1/configurations/{before['configuration_id']}/analyze",
        headers=HEADERS,
        json={},
    )
    assert response.status_code == 201, response.text
    analysis = response.json()
    response = client.post(
        "/api/v1/patches",
        headers=HEADERS,
        json={
            "patch_id": str(uuid4()),
            "before_configuration_id": before["configuration_id"],
            "after_configuration_id": after["configuration_id"],
            "before_source_sha256": before["canonical"]["source"]["sha256"],
            "after_source_sha256": after["canonical"]["source"]["sha256"],
        },
    )
    assert response.status_code == 201, response.text
    draft = response.json()
    return draft, before, after, analysis


def options(client, selected, **updates):
    draft, _before, _after, analysis = selected
    response = client.get(
        f"/api/v2/patches/{draft['patch_id']}/deterministic-selection/{analysis['analysis_id']}",
        headers=HEADERS,
    )
    assert response.status_code == 200, response.text
    return {
        "version": "source-deterministic-request-0.2.0",
        "mode": "policy_only_partial_diagnostic",
        "recheck_id": str(uuid4()),
        "draft_sha256": draft["draft_sha256"],
        "before_analysis_id": analysis["analysis_id"],
        "before_analysis_sha256": response.json()["before_analysis_sha256"],
        "reference_canonical_sha256": None,
        "allow_local_analysis_context": True,
    } | updates


def post(client, selected, body, *, headers=HEADERS):
    return client.post(
        f"/api/v2/patches/{selected[0]['patch_id']}/deterministic-rechecks",
        headers=headers,
        json=body,
    )


def get(client, selected, body):
    return client.get(
        f"/api/v2/patches/{selected[0]['patch_id']}/deterministic-rechecks/{body['recheck_id']}",
        headers=HEADERS,
    )


@pytest.mark.parametrize("vendor", ["cisco", "juniper"])
@pytest.mark.parametrize("partial", ["before", "after", "both"])
def test_six_actual_partial_views_restart_without_source_or_detector(
    source_api, monkeypatch, vendor, partial
):
    client, application, settings, calls = source_api
    selected = prepare(client, vendor, partial)
    body = options(client, selected)
    response = post(client, selected, body, headers={"Authorization": f"Bearer {ENGINEER}"})
    assert response.status_code == 201, response.text
    value = SourcePartialDiagnostic.model_validate(response.json())
    assert value.execution_status == "completed" and not calls
    assert value.mode == "policy_only_partial_diagnostic" and value.coverage == "partial"
    assert value.status == "needs_review" and value.formal_verification == "not_run"
    assert not any((value.risk_fused, value.calibrated, value.quality_proven, value.approved))
    assert value.applied is False
    assert value.intent.before_analysis_status == ("completed" if partial == "after" else "partial")
    report = response.json()["outcome"]["report"]
    assert report["before"]["policy_findings"] == selected[3]["findings"]
    assert report["policy_changes"] is None
    assert report["policy_changes_reason"] == "partial_parsing"
    assert report["reference_projection"] is report["peer_profile_sha256"] is None
    assert "partial_comparison_unavailable" in value.validation_blockers
    assert MARKER not in response.text
    operation = client.get(
        f"/api/v1/operation-audit/{response.headers['X-Operation-Id']}", headers=HEADERS
    ).json()
    assert operation["receipt"]["operation"] == "run_source_deterministic_recheck"
    assert body["before_analysis_id"] in operation["completion"]["result"]["resource_ids"]
    assert "source-deterministic-recheck-0.2.0" in (operation["completion"]["result"]["versions"])
    assert MARKER not in json.dumps(operation)
    assert counts(application) == (1, 1)
    with application.state.analysis_service.store.engine.begin() as connection:
        connection.execute(text("DELETE FROM configuration_sources"))

    def forbidden(*args, **kwargs):
        pytest.fail("partial history must not parse, evaluate policies or read retained source")

    for name in ("prepare_partial_policy", "recheck_partial_policy", "prepare_original_source"):
        monkeypatch.setattr(workflow_module, name, forbidden)
    for name in (
        "app.parsers.parse_configuration",
        "app.ingestion.source_retention.parse_configuration",
        "app.detection.policy_diagnostic.evaluate_policies",
        "app.detection.policy_engine.evaluate_policies",
    ):
        monkeypatch.setattr(name, forbidden)
    monkeypatch.setattr("app.detection.policy_engine.POLICY_CATALOGS", {})
    monkeypatch.setattr(SourceRecords, "get", forbidden)
    with TestClient(create_app(settings)) as restarted:
        assert get(restarted, selected, body).json() == response.json()
        replay = post(restarted, selected, body)
        assert replay.status_code == 200 and replay.json() == response.json()
        listing = restarted.get(
            f"/api/v2/patches/{selected[0]['patch_id']}/deterministic-rechecks", headers=HEADERS
        )
        assert listing.status_code == 200, listing.text
        assert listing.json()[0]["version"] == "source-deterministic-summary-0.2.0"
        assert listing.json()[0]["review_sha256"] == value.review_sha256
        assert listing.json()[0]["created_at"] == response.json()["intent"]["created_at"]
        assert MARKER not in listing.text
        assert counts(application) == (1, 1)


@pytest.mark.parametrize("vendor", ["cisco", "juniper"])
def test_critical_after_finding_survives_actual_partial_http(source_api, vendor):
    client, _application, _settings, _calls = source_api
    selected = prepare(client, vendor, critical=True)
    response = post(client, selected, options(client, selected))
    assert response.status_code == 201, response.text
    rows = response.json()["outcome"]["report"]["after"]["policy_findings"]
    assert any(
        row["category"] == "routing.default_route_discarded" and row["severity"] == "critical"
        for row in rows
    )


@pytest.mark.parametrize("partial", ["before", "after", "both"])
def test_old_complete_protocol_still_refuses_partial_without_fallback(source_api, partial):
    client, application, _settings, _calls = source_api
    selected = prepare(client, partial=partial)
    body = options(client, selected)
    body.pop("version")
    body.pop("mode")
    assert post(client, selected, body).status_code == 409
    assert counts(application) == (0, 0)


@pytest.mark.parametrize("role", [READER, ANALYST])
def test_partial_rbac_precedes_body_and_source(source_api, monkeypatch, role):
    client, application, _settings, _calls = source_api
    selected = prepare(client)
    monkeypatch.setattr(SourceRecords, "get", lambda *a, **k: pytest.fail("source read"))
    response = client.post(
        f"/api/v2/patches/{selected[0]['patch_id']}/deterministic-rechecks",
        headers={"Authorization": f"Bearer {role}"},
        content="invalid",
    )
    assert response.status_code == 403 and counts(application) == (0, 0)


@pytest.mark.parametrize(
    "change,remove,code",
    [
        ({}, "version", 400),
        ({}, "mode", 400),
        ({}, "reference_canonical_sha256", 400),
        ({"allow_local_analysis_context": "true"}, None, 400),
        ({"allow_local_analysis_context": False}, None, 403),
        ({"reference_canonical_sha256": "b" * 64}, None, 400),
        ({"draft_sha256": "b" * 64}, None, 409),
        ({"before_analysis_sha256": "b" * 64}, None, 409),
    ],
)
def test_partial_invalid_input_never_reserves(source_api, monkeypatch, change, remove, code):
    client, application, _settings, _calls = source_api
    selected = prepare(client)
    body = options(client, selected, **change)
    if remove:
        body.pop(remove)
    monkeypatch.setattr(
        workflow_module, "recheck_partial_policy", lambda *a: pytest.fail("after executed")
    )
    response = post(client, selected, body)
    assert response.status_code == code, response.text
    assert counts(application) == (0, 0)


@pytest.mark.parametrize("fault", ["finding", "catalog", "status", "comparison"])
def test_exact_original_policy_context_refuses_before_reservation(source_api, monkeypatch, fault):
    client, application, _settings, _calls = source_api
    selected = (
        prepare_complete(client, cohort="reference_only")[:4]
        if fault == "comparison"
        else prepare(client)
    )
    data = selected[3]
    if fault == "finding":
        data["findings"][0]["observed"] = {"owned_changed": True}
    elif fault == "catalog":
        data["policy_catalog_version"] = "owned-unavailable-catalog"
        for finding, explanation in zip(data["findings"], data["explanations"], strict=True):
            finding["model_version"] = data["policy_catalog_version"]
            explanation["detector_version"] = data["policy_catalog_version"]
    elif fault == "status":
        data["status"] = "partial"
        data["risk"] = None
    analysis = AnalysisResult.model_validate(data)
    store = application.state.analysis_service.store
    with store.engine.begin() as connection:
        connection.execute(
            text("UPDATE analyses SET payload=:payload WHERE id=:key"),
            {
                "key": str(analysis.analysis_id),
                "payload": store._encode(
                    analysis.model_dump_json(), kind="analysis", row_id=str(analysis.analysis_id)
                ),
            },
        )
    monkeypatch.setattr(
        workflow_module, "recheck_partial_policy", lambda *a: pytest.fail("after executed")
    )
    response = post(client, selected, options(client, selected))
    assert response.status_code == 409, response.text
    assert counts(application) == (0, 0)


def test_actual_retained_reparse_refuses_changed_canonical_before_reservation(source_api):
    client, application, _settings, _calls = source_api
    selected = prepare(client)
    store = application.state.analysis_service.store
    original = workflow_module.prepare_original_source

    def mismatch(snapshot, content):
        changed = snapshot.model_copy(
            update={
                "canonical": snapshot.canonical.model_copy(
                    update={
                        "management": snapshot.canonical.management.model_copy(
                            update={"ssh_enabled": False}
                        )
                    }
                )
            }
        )
        return original(changed, content)

    # The real preparer freshly parses the retained bytes and rejects a canonical mismatch.
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(workflow_module, "prepare_original_source", mismatch)
        response = post(client, selected, options(client, selected))
    assert response.status_code == 409 and counts(application) == (0, 0)
    assert (
        SourceRecords(store).get(
            UUID(selected[1]["configuration_id"]),
            expected_source_sha256=selected[1]["canonical"]["source"]["sha256"],
            allow_local_read=True,
        )
        is not None
    )


def test_partial_missing_source_and_complete_pair_refuse(source_api):
    client, application, _settings, _calls = source_api
    selected = prepare(client, retain=False)
    assert post(client, selected, options(client, selected)).status_code == 409
    complete = prepare(client, partial="neither")
    assert post(client, complete, options(client, complete)).status_code == 409
    assert counts(application) == (0, 0)


def test_after_failure_is_terminal_and_generic(source_api, monkeypatch):
    client, application, _settings, _calls = source_api
    selected = prepare(client)
    body = options(client, selected)

    def fail(*args):
        raise ValueError(MARKER)

    monkeypatch.setattr(workflow_module, "recheck_partial_policy", fail)
    response = post(client, selected, body)
    assert response.status_code == 201, response.text
    assert response.json()["execution_status"] == "failed"
    assert response.json()["outcome"]["report"] is None
    assert MARKER not in response.text and counts(application) == (1, 1)
    assert post(client, selected, body).json() == response.json()


def test_typed_copy_request_is_revalidated_before_source(source_api, monkeypatch):
    client, application, _settings, _calls = source_api
    selected = prepare(client)
    body = RunSourcePartialDiagnostic.model_validate(options(client, selected))
    forged = body.model_copy(update={"allow_local_analysis_context": "true"})
    monkeypatch.setattr(SourceRecords, "get", lambda *a, **k: pytest.fail("source read"))
    with pytest.raises(ValueError):
        SourceDeterministicWorkflow(application.state.analysis_service.store).run(
            UUID(selected[0]["patch_id"]), forged
        )
    assert counts(application) == (0, 0)


def test_openapi_declares_both_source_versions(source_api):
    client, _application, _settings, _calls = source_api
    response = client.get("/openapi.json")
    assert response.status_code == 200
    schema = response.json()
    operation = schema["paths"]["/api/v2/patches/{patch_id}/deterministic-rechecks"]["post"]
    request = operation["requestBody"]["content"]["application/json"]["schema"]["anyOf"]
    assert len(request) == 2
    assert {row["properties"]["version"]["const"] for row in request} == {
        "source-deterministic-request-0.1.0",
        "source-deterministic-request-0.2.0",
    }
    assert "version" not in request[0]["required"]
    assert {"version", "mode", "reference_canonical_sha256"} <= set(request[1]["required"])
    result = operation["responses"]["201"]["content"]["application/json"]["schema"]
    if "$ref" in result:
        result = schema["components"]["schemas"][result["$ref"].rsplit("/", 1)[-1]]
    assert len(result["anyOf"]) == 2
