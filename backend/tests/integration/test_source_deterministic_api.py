"""Real HTTP deterministic reruns on authored controls, never independent quality evidence."""

import json
from uuid import UUID, uuid4

import app.patching.source_deterministic as workflow_module
import pytest
from app.api.source_deterministic_contracts import (
    RunSourceDeterministicRecheck,
    SourceDeterministicRecheck,
)
from app.db.source_deterministic_records import SourceDeterministicRecords
from app.db.source_records import SourceRecords
from app.main import create_app
from app.patching.source_deterministic import SourceDeterministicWorkflow
from fastapi.testclient import TestClient
from sqlalchemy import text
from test_source_patch_review_api import ANALYST, ENGINEER, HEADERS, READER
from test_source_patch_review_api import source_api as source_api

LABELS = {"device_role": "edge", "site_class": "branch", "service_profile": "owned-control"}


def content(vendor, hostname, address=None, telnet=False):
    if vendor == "cisco":
        return (
            f"hostname {hostname}\nip ssh version 2\nline vty 0 4\n transport input "
            + ("telnet ssh" if telnet else "ssh")
            + "\n!\n"
            + (
                f"interface GigabitEthernet0/1\n ip address 192.0.2.{address} 255.255.255.0\n!\n"
                if address
                else ""
            )
        )
    return (
        f"set system host-name {hostname}\nset system services ssh\n"
        + ("set system services telnet\n" if telnet else "")
        + (
            f"set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.{address}/24\n"
            if address
            else ""
        )
    )


def upload(client, source, *, device=None, retain=False):
    result = client.post(
        "/api/v1/configurations",
        headers=HEADERS,
        json={
            "device_id": device or str(uuid4()),
            "filename": "owned.cfg",
            "content": source,
            "inventory": LABELS,
            "retain_original_source": retain,
        },
    )
    assert result.status_code == 201, result.text
    return result.json()


def prepare(client, vendor="cisco", version="0.3.0", cohort="combined", *, retain=True):
    peers = [upload(client, content(vendor, f"peer-{index}")) for index in range(3)]
    reference = upload(client, content(vendor, "target", 10))
    before = upload(
        client, content(vendor, "target", 12, True), device=reference["device_id"], retain=retain
    )
    after = upload(
        client, content(vendor, "target", 13), device=reference["device_id"], retain=retain
    )
    options = {"comparison_version": version}
    if cohort in {"reference_only", "combined"}:
        options["reference_configuration_id"] = reference["configuration_id"]
    if cohort in {"peers_only", "combined"}:
        options["peer_configuration_ids"] = [peer["configuration_id"] for peer in peers]
    response = client.post(
        f"/api/v1/configurations/{before['configuration_id']}/analyze",
        headers=HEADERS,
        json=options,
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
    response = client.get(
        f"/api/v2/patches/{draft['patch_id']}/deterministic-selection/{analysis['analysis_id']}",
        headers=HEADERS,
    )
    assert response.status_code == 200, response.text
    return draft, before, after, analysis, reference, response.json()


def options(selected, **updates):
    draft, _before, _after, analysis, _reference, selection = selected
    reference = selection["reference"]
    return {
        "recheck_id": str(uuid4()),
        "draft_sha256": draft["draft_sha256"],
        "before_analysis_id": analysis["analysis_id"],
        "before_analysis_sha256": selection["before_analysis_sha256"],
        "reference_canonical_sha256": reference["canonical_sha256"] if reference else None,
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


def counts(application):
    with application.state.analysis_service.store.engine.connect() as connection:
        return tuple(
            connection.execute(text(f"SELECT count(*) FROM {table}")).scalar_one()
            for table in (
                "patch_deterministic_recheck_intents",
                "patch_deterministic_recheck_outcomes",
            )
        )


@pytest.mark.parametrize("vendor", ["cisco", "juniper"])
@pytest.mark.parametrize("version", ["0.1.0", "0.2.0", "0.3.0"])
@pytest.mark.parametrize("cohort", ["reference_only", "peers_only", "combined"])
def test_actual_original_context_http_replay_after_restart(
    source_api, monkeypatch, vendor, version, cohort
):
    client, application, settings, engine_calls = source_api
    selected = prepare(client, vendor, version, cohort)
    body = options(selected)
    response = post(client, selected, body, headers={"Authorization": f"Bearer {ENGINEER}"})
    assert response.status_code == 201, response.text
    view = SourceDeterministicRecheck.model_validate(response.json())
    assert view.execution_status == "completed" and not engine_calls
    assert view.status == "needs_review" and view.formal_verification == "not_run"
    assert not any(
        (view.approved, view.applied, view.quality_proven, view.calibrated, view.risk_fused)
    )
    report = response.json()["outcome"]["report"]
    original = [
        row
        for row in selected[3]["findings"]
        if row["detector"] in {"policy_engine", "expected_configuration", "peer_baseline"}
    ]
    actual = [
        row
        for field in ("policy_findings", "reference_findings", "peer_findings")
        for row in (report["before"][field] or [])
    ]
    assert actual == original
    assert (report["after"]["reference_findings"] is not None) == (cohort != "peers_only")
    assert (report["after"]["peer_findings"] is not None) == (cohort != "reference_only")
    if cohort != "peers_only":
        assert "192.0.2.10" in json.dumps(report["after"]["reference_findings"])
        assert "192.0.2.13" in json.dumps(report["after"]["reference_findings"])
    assert counts(application) == (1, 1)
    operation = client.get(
        f"/api/v1/operation-audit/{response.headers['X-Operation-Id']}", headers=HEADERS
    ).json()
    assert operation["receipt"]["operation"] == "run_source_deterministic_recheck"
    assert operation["authorization"] == "allowed"
    assert body["before_analysis_id"] in operation["completion"]["result"]["resource_ids"]
    assert all(
        value not in json.dumps(operation) for value in ("observed", "expected", "192.0.2.10")
    )
    with application.state.analysis_service.store.engine.begin() as connection:
        connection.execute(text("DELETE FROM configuration_sources"))
        connection.execute(
            text("DELETE FROM configurations WHERE id=:key"),
            {"key": selected[4]["configuration_id"]},
        )

    def forbidden(*args, **kwargs):
        pytest.fail("saved history or identical replay executed a detector or read original text")

    monkeypatch.setattr(workflow_module, "recheck_original_deterministic", forbidden)
    monkeypatch.setattr(SourceRecords, "get", forbidden)
    with TestClient(create_app(settings)) as restarted:
        assert get(restarted, selected, body).json() == response.json()
        replay = post(restarted, selected, body)
        assert replay.status_code == 200 and replay.json() == response.json()
        listing = restarted.get(
            f"/api/v2/patches/{selected[0]['patch_id']}/deterministic-rechecks", headers=HEADERS
        ).json()
        assert len(listing) == 1 and listing[0]["review_sha256"] == view.review_sha256


@pytest.mark.parametrize("vendor", ["cisco", "juniper"])
def test_policy_only_has_no_selected_comparators_or_false_statistical_blocker(source_api, vendor):
    client, _application, _settings, _calls = source_api
    selected = prepare(client, vendor, cohort="policy_only")
    response = post(client, selected, options(selected))
    assert response.status_code == 201, response.text
    result = response.json()
    assert result["execution_status"] == "completed"
    assert "original_statistical_not_rerun" not in result["validation_blockers"]
    for side in ("before", "after"):
        report = result["outcome"]["report"][side]
        assert (
            report["reference_findings"]
            is report["peer_findings"]
            is report["peer_evaluation"]
            is None
        )


@pytest.mark.parametrize("role", [READER, ANALYST])
def test_read_roles_denied_before_body_or_source(source_api, monkeypatch, role):
    client, application, _settings, _calls = source_api
    selected = prepare(client)
    monkeypatch.setattr(SourceRecords, "get", lambda *a, **k: pytest.fail("raw source read"))
    headers = {"Authorization": f"Bearer {role}"}
    response = client.post(
        f"/api/v2/patches/{selected[0]['patch_id']}/deterministic-rechecks",
        headers=headers,
        content="invalid",
    )
    assert response.status_code == 403 and counts(application) == (0, 0)
    assert (
        client.get(
            f"/api/v2/patches/{selected[0]['patch_id']}/deterministic-selection/{selected[3]['analysis_id']}",
            headers=headers,
        ).status_code
        == 200
    )


@pytest.mark.parametrize(
    "update,code",
    [
        ({"allow_local_analysis_context": False}, 403),
        ({"allow_local_analysis_context": "true"}, 400),
        ({"draft_sha256": "b" * 64}, 409),
        ({"before_analysis_sha256": "b" * 64}, 409),
        ({"reference_canonical_sha256": None}, 409),
        ({"reference_canonical_sha256": "b" * 64}, 409),
        ({"before_analysis_id": str(uuid4())}, 404),
    ],
)
def test_invalid_request_never_reserves_or_evaluates(source_api, monkeypatch, update, code):
    client, application, _settings, _calls = source_api
    selected = prepare(client)
    monkeypatch.setattr(
        workflow_module, "recheck_original_deterministic", lambda *a: pytest.fail("detector")
    )
    response = post(client, selected, options(selected, **update))
    assert response.status_code == code, response.text
    assert counts(application) == (0, 0)


def test_missing_retained_pair_refuses_before_reservation(source_api, monkeypatch):
    client, application, _settings, _calls = source_api
    selected = prepare(client, retain=False)
    monkeypatch.setattr(
        workflow_module, "recheck_original_deterministic", lambda *a: pytest.fail("detector")
    )
    assert post(client, selected, options(selected)).status_code == 409
    assert counts(application) == (0, 0)


@pytest.mark.parametrize(
    "budget", ["MAX_DETERMINISTIC_INPUT_BYTES", "MAX_SOURCE_DETERMINISTIC_BYTES"]
)
def test_input_and_proof_budget_admission_before_reservation(source_api, monkeypatch, budget):
    client, application, _settings, _calls = source_api
    selected = prepare(client)
    monkeypatch.setattr(workflow_module, budget, 1)
    monkeypatch.setattr(
        workflow_module, "recheck_original_deterministic", lambda *a: pytest.fail("detector")
    )
    assert post(client, selected, options(selected)).status_code == 413
    assert counts(application) == (0, 0)


def test_detector_failure_is_durable_generic_failure_without_partial_findings(
    source_api, monkeypatch
):
    client, application, _settings, _calls = source_api
    selected = prepare(client)

    def fail(*args):
        raise ValueError("private source diagnostics must not escape")

    monkeypatch.setattr(workflow_module, "recheck_original_deterministic", fail)
    body = options(selected)
    response = post(client, selected, body)
    assert response.status_code == 201, response.text
    result = response.json()
    assert result["execution_status"] == "failed" and result["outcome"]["report"] is None
    assert "private source" not in response.text and counts(application) == (1, 1)
    assert post(client, selected, body).json() == result


def test_completion_audit_failure_keeps_pending_history_without_rerun(source_api, monkeypatch):
    client, application, _settings, _calls = source_api
    selected = prepare(client)
    body = RunSourceDeterministicRecheck.model_validate(options(selected))
    original = SourceDeterministicRecords._audit

    def fail(session, action, key):
        if action == "patch.deterministic_recheck_completed":
            raise RuntimeError("owned injected audit failure")
        original(session, action, key)

    monkeypatch.setattr(SourceDeterministicRecords, "_audit", staticmethod(fail))
    workflow = SourceDeterministicWorkflow(application.state.analysis_service.store)
    with pytest.raises(RuntimeError, match="owned injected"):
        workflow.run(UUID(selected[0]["patch_id"]), body)
    assert counts(application) == (1, 0)
    monkeypatch.setattr(
        workflow_module, "recheck_original_deterministic", lambda *a: pytest.fail("rerun")
    )
    result, created = workflow.run(UUID(selected[0]["patch_id"]), body)
    assert not created and result.execution_status == "pending_unknown" and result.outcome is None


def test_duplicate_keys_or_oversized_body_rejected(source_api):
    client, application, _settings, _calls = source_api
    selected = prepare(client)
    url = f"/api/v2/patches/{selected[0]['patch_id']}/deterministic-rechecks"
    duplicate = json.dumps(options(selected))[:-1] + ',"allow_local_analysis_context":true}'
    assert (
        client.post(
            url, headers=HEADERS | {"Content-Type": "application/json"}, content=duplicate
        ).status_code
        == 400
    )
    assert (
        client.post(
            url,
            headers=HEADERS | {"Content-Type": "application/json"},
            content=" " * (16 * 1024 + 1),
        ).status_code
        == 413
    )
    assert counts(application) == (0, 0)
