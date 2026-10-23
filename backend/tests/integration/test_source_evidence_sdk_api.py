"""SDK-aware report/decision HTTP integration; synthetic worker data is no live evidence."""

from hashlib import sha256
from uuid import UUID, uuid4

import app.patching.source_review as source_workflow
import pytest
from app.api.source_evidence_decision_sdk_contracts import SourceEvidenceDecisionV2
from app.api.source_evidence_sdk_contracts import SourceEvidenceReportV2
from app.api.source_ml_contracts import ml_json
from app.db.source_records import SourceRecords
from app.db.tables import SourceEvidenceReportRow
from app.main import create_app
from app.verification.batfish import BatfishExecution, BatfishResult
from fastapi.testclient import TestClient
from test_source_evidence_api import evidence_api as evidence_api
from test_source_evidence_api import get as get_report
from test_source_evidence_api import options as report_options
from test_source_evidence_api import post as save_report
from test_source_evidence_api import prepare as prepare_inputs
from test_source_evidence_decision_api import get as get_decision
from test_source_evidence_decision_api import options as decision_options
from test_source_evidence_decision_api import post as save_decision
from test_source_ml_recheck_api import source_ml_api as source_ml_api
from test_source_patch_review_api import ENGINEER, HEADERS
from test_source_patch_review_api import get as get_network


@pytest.fixture
def sdk_reports(evidence_api, monkeypatch):
    client, app, settings, neural_calls, network_calls, control = evidence_api
    legacy_worker = source_workflow.check_with_batfish
    sdk = {"observation": "observed", "version": "owned-sdk-control-0.36.0"}

    def worker(before, after, scope, **kwargs):
        if control["status"] in {"unavailable", "error"}:
            network_calls.append(scope)
            result = BatfishResult(
                before_sha256=before.digest,
                after_sha256=after.digest,
                scope=scope,
                status=control["status"],
                reason="sdk_missing" if control["status"] == "unavailable" else "engine_error",
            )
        else:
            result = legacy_worker(before, after, scope, **kwargs)
        return BatfishExecution(
            result=result,
            sdk_version=sdk["version"],
            sdk_observation=sdk["observation"],
        )

    monkeypatch.setattr(source_workflow, "check_with_batfish_evidence", worker)
    return client, app, settings, neural_calls, network_calls, control, sdk


def prepare(sdk_reports, vendor="cisco", *, legacy_network=False):
    client = sdk_reports[0]
    selected = prepare_inputs(client, vendor, include=())
    draft, records, before, _ = selected
    body = {
        "version": "source-patch-request-0.1.0" if legacy_network else "source-patch-request-0.2.0",
        "verification_id": str(uuid4()),
        "draft_sha256": draft["draft_sha256"],
        "scope": {
            "start_node": before["canonical"]["device"]["hostname"],
            "destination": "192.0.2.1/32",
        },
        "companions": [],
        "allow_local_engine_upload": True,
    }
    response = client.post(
        f"/api/v2/patches/{draft['patch_id']}/verify", headers=HEADERS, json=body
    )
    assert response.status_code == 201, response.text
    records["network"] = response.json()
    request = report_options(selected, version="source-evidence-request-0.2.0")
    report = save_report(client, selected, request)
    assert report.status_code == 201, report.text
    return selected, body, request, report.json()


@pytest.mark.parametrize("vendor", ["cisco", "juniper"])
@pytest.mark.parametrize(
    "state", ["observed", "metadata_unavailable", "not_observed", "engine_error"]
)
def test_source_sdk_report_and_decision_replay_are_data_only_after_restart(
    sdk_reports, monkeypatch, vendor, state
):
    client, _, settings, neural_calls, network_calls, control, sdk = sdk_reports
    if state == "metadata_unavailable":
        sdk.update(observation=state, version=None)
    elif state == "not_observed":
        control["status"] = "unavailable"
        sdk.update(observation=state, version=None)
    elif state == "engine_error":
        control["status"] = "error"
    selected, network_request, request, report = prepare(sdk_reports, vendor)
    view = SourceEvidenceReportV2.model_validate(report)
    assert view.network is not None
    assert view.network.sdk_version == sdk["version"]
    assert view.network.sdk_observation == sdk["observation"]
    assert view.network.result.status == control["status"]
    assert view.status == "needs_review" and view.formal_qualification == "not_proven"
    assert view.approved is view.applied is view.quality_proven is False
    assert len(network_calls) == 1 and neural_calls == []

    def forbidden(*args, **kwargs):
        pytest.fail("composition/decision/history accessed raw/model or executed a worker")

    monkeypatch.setattr(SourceRecords, "get", forbidden)
    monkeypatch.setattr("app.db.store.Store.get_model", forbidden)
    monkeypatch.setattr(source_workflow, "check_with_batfish", forbidden)
    monkeypatch.setattr(source_workflow, "check_with_batfish_evidence", forbidden)
    body = decision_options(report, version="source-evidence-decision-request-0.2.0")
    created = save_decision(client, report, body, headers={"Authorization": f"Bearer {ENGINEER}"})
    assert created.status_code == 201, created.text
    decision = SourceEvidenceDecisionV2.model_validate(created.json())
    assert decision.service_role == "engineer"
    assert decision.report_version == report["version"]
    assert decision.approved is decision.applied is decision.individual_identity_verified is False

    with TestClient(create_app(settings)) as restarted:
        assert get_network(restarted, selected[0], network_request).json() == selected[1]["network"]
        assert get_report(restarted, selected, request).json() == report
        replay = save_report(restarted, selected, request)
        assert replay.status_code == 200 and replay.json() == report
        replay_decision = save_decision(restarted, report, body)
        assert replay_decision.status_code == 200 and replay_decision.json() == created.json()
        assert get_decision(restarted, report, body).json() == created.json()


def test_new_report_keeps_legacy_child_sdk_unrecorded_and_protocol_identity(sdk_reports):
    client = sdk_reports[0]
    selected, _, request, report = prepare(sdk_reports, legacy_network=True)
    assert report["network"]["version"] == "source-patch-verification-0.1.0"
    assert report["network"]["sdk_version"] is None
    assert "sdk_observation" not in report["network"]
    assert (
        save_report(
            client, selected, request | {"version": "source-evidence-request-0.1.0"}
        ).status_code
        == 409
    )
    body = decision_options(report)
    assert save_decision(client, report, body).status_code == 409
    body["version"] = "source-evidence-decision-request-0.2.0"
    created = save_decision(client, report, body)
    assert created.status_code == 201
    assert (
        save_decision(
            client, report, body | {"version": "source-evidence-decision-request-0.1.0"}
        ).status_code
        == 409
    )
    old_request = report_options(selected)
    legacy = save_report(client, selected, old_request)
    assert legacy.status_code == 201, legacy.text
    assert (
        save_decision(
            client,
            legacy.json(),
            decision_options(legacy.json(), version="source-evidence-decision-request-0.2.0"),
        ).status_code
        == 409
    )
    assert get_report(client, selected, request).json() == report


def test_resealed_sdk_projection_is_rejected_against_saved_child(sdk_reports):
    client, app, *_ = sdk_reports
    selected, _, request, report = prepare(sdk_reports)
    body = decision_options(report, version="source-evidence-decision-request-0.2.0")
    created = save_decision(client, report, body)
    assert created.status_code == 201
    store = app.state.analysis_service.store
    with store._sessions.begin() as session:
        row = session.get(SourceEvidenceReportRow, str(UUID(report["report_id"])))
        assert row is not None
        content = SourceEvidenceReportV2.model_validate_json(
            store._decode(row.payload, kind="source_evidence_report", row_id=row.id)
        ).model_dump(mode="json")
        content["network"]["sdk_version"] = "different-valid-version-0.99"
        content["review_json"] = ml_json(
            {
                key: value
                for key, value in content.items()
                if key not in {"review_json", "review_sha256"}
            }
        )
        content["review_sha256"] = sha256(content["review_json"].encode()).hexdigest()
        forged = SourceEvidenceReportV2.model_validate(content)
        row.payload = store._encode(
            forged.model_dump_json(), kind="source_evidence_report", row_id=row.id
        )
    report_read = get_report(client, selected, request)
    decision_read = get_decision(client, report, body)
    assert report_read.status_code == decision_read.status_code == 503
    assert "different-valid-version" not in report_read.text + decision_read.text
