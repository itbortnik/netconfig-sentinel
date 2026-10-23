"""HTTP/storage directional controls with synthetic worker data, not actual engine evidence."""

from datetime import timedelta, timezone
from hashlib import sha256
from uuid import UUID, uuid4

import app.patching.source_review as source_workflow
import pytest
from app.api.source_evidence_decision_direction_contracts import SourceEvidenceDecisionV3
from app.api.source_evidence_direction_contracts import SourceEvidenceReportV3
from app.api.source_ml_contracts import ml_json
from app.api.source_patch_direction_contracts import (
    SourcePatchIntentV3,
    SourcePatchVerificationV3,
    parse_source_patch_request,
)
from app.core.patch_verification import PatchVerificationSettings
from app.db.source_patch_records import SourcePatchRecords
from app.db.source_records import SourceRecords
from app.db.tables import SourceEvidenceReportRow, SourcePatchOutcomeRow
from app.main import create_app
from app.verification.batfish import BatfishExecution, BatfishResult
from app.verification.reachability_impact import (
    BatfishDirectionalExecution,
    ReachabilityImpact,
    empty_reachability_impact,
)
from fastapi.testclient import TestClient
from sqlalchemy import text
from test_source_evidence_api import evidence_api as evidence_api
from test_source_evidence_api import get as get_report
from test_source_evidence_api import options as report_options
from test_source_evidence_api import post as save_report
from test_source_evidence_api import prepare as prepare_inputs
from test_source_evidence_decision_api import get as get_decision
from test_source_evidence_decision_api import options as decision_options
from test_source_evidence_decision_api import post as save_decision
from test_source_ml_recheck_api import source_ml_api as source_ml_api
from test_source_patch_review_api import ANALYST, ENGINEER, HEADERS, READER
from test_source_patch_review_api import get as get_network


@pytest.fixture
def directional_api(evidence_api, monkeypatch):
    client, app, settings, neural_calls, network_calls, _ = evidence_api
    control = {"kind": "mixed", "sdk": "observed"}
    legacy_worker = source_workflow.check_with_batfish

    def sdk_worker(*args, **kwargs):
        return BatfishExecution(
            result=legacy_worker(*args, **kwargs),
            sdk_version="owned-older-sdk",
            sdk_observation="observed",
        )

    def worker(before, after, scope, **kwargs):
        network_calls.append(scope)
        kind = control["kind"]
        queried = kind != "not_run"
        result = BatfishResult(
            before_sha256=before.digest,
            after_sha256=after.digest,
            scope=scope,
            status="error"
            if not queried
            else "inconclusive"
            if kind == "empty"
            else "no_differences_in_scope"
            if kind == "none"
            else "differences_found",
            reason="engine_error"
            if not queried
            else "empty_reachable_scope"
            if kind == "empty"
            else "query_completed",
            cleanup_complete=True if queried else None,
            engine_version="owned-direction-fixture" if queried else None,
            difference_count=(2 if kind == "mixed" else 0 if kind in {"none", "empty"} else 1)
            if queried
            else None,
            before_reachable_count=(0 if kind == "empty" else 1) if queried else None,
            after_reachable_count=(0 if kind == "empty" else 1) if queried else None,
        )
        if kind in {"not_run", "empty", "unknown"}:
            state, reason = {
                "not_run": ("not_observed", "not_run"),
                "empty": ("inconclusive", "empty_reachable_scope"),
                "unknown": ("unknown", "incomplete_traces"),
            }[kind]
            impact = empty_reachability_impact(state, reason)
        else:
            witnesses = []
            for index, direction in enumerate(("loss", "gain")):
                if kind not in {direction, "mixed"}:
                    continue
                witnesses.append(
                    {
                        "flow_sha256": str(index + 1) * 64,
                        "before_dispositions": ["ACCEPTED" if direction == "loss" else "NO_ROUTE"],
                        "after_dispositions": ["NO_ROUTE" if direction == "loss" else "ACCEPTED"],
                        "before_trace_count": 1,
                        "after_trace_count": 1,
                        "direction": direction,
                    }
                )
            impact = ReachabilityImpact(
                state="observed",
                reason="query_completed",
                direction={
                    "loss": "loss_found",
                    "gain": "gain_found",
                    "mixed": "loss_and_gain_found",
                    "none": "no_witnesses_returned",
                }[kind],
                lost_witness_count=sum(row["direction"] == "loss" for row in witnesses),
                gained_witness_count=sum(row["direction"] == "gain" for row in witnesses),
                witnesses=witnesses,
            )
        return BatfishDirectionalExecution(
            result=result,
            sdk_version="owned-direction-sdk" if control["sdk"] == "observed" else None,
            sdk_observation=control["sdk"],
            reachability_impact=impact,
        )

    monkeypatch.setattr(source_workflow, "check_with_batfish_directional", worker)
    monkeypatch.setattr(source_workflow, "check_with_batfish_evidence", sdk_worker)
    return client, app, settings, neural_calls, network_calls, control


def prepare(directional_api, vendor="cisco", *, child_version="0.3.0"):
    client = directional_api[0]
    selected = prepare_inputs(client, vendor, include=())
    draft, records, before, _ = selected
    request = {
        "version": "source-patch-request-" + child_version,
        "verification_id": str(uuid4()),
        "draft_sha256": draft["draft_sha256"],
        "scope": {
            "start_node": before["canonical"]["device"]["hostname"],
            "destination": "192.0.2.1/32",
        },
        "companions": [],
        "allow_local_engine_upload": True,
    }
    response = post_network(client, selected, request)
    assert response.status_code == 201, response.text
    records["network"] = response.json()
    return selected, request


def post_network(client, selected, request, *, headers=HEADERS):
    return client.post(
        f"/api/v2/patches/{selected[0]['patch_id']}/verify", headers=headers, json=request
    )


def create_report(client, selected):
    request = report_options(selected, version="source-evidence-request-0.3.0")
    response = save_report(client, selected, request)
    assert response.status_code == 201, response.text
    return request, response.json()


@pytest.mark.parametrize("vendor", ["cisco", "juniper"])
@pytest.mark.parametrize("kind", ["loss", "gain", "mixed", "none", "empty", "unknown", "not_run"])
def test_directional_chain_restart_preserves_all_fields_without_sources_or_execution(
    directional_api, monkeypatch, vendor, kind
):
    client, app, settings, neural_calls, calls, control = directional_api
    control["kind"] = kind
    selected, network_request = prepare(directional_api, vendor)
    source = SourcePatchVerificationV3.model_validate(selected[1]["network"])
    assert source.outcome.network_execution.reachability_impact.state == (
        "observed"
        if kind in {"loss", "gain", "mixed", "none"}
        else "inconclusive"
        if kind == "empty"
        else "unknown"
        if kind == "unknown"
        else "not_observed"
    )

    def forbidden(*args, **kwargs):
        pytest.fail(
            "directional composition/history executed a worker, model, detector or read raw input"
        )

    for target in [
        "app.db.source_records.SourceRecords.get",
        "app.db.store.Store.get_model",
        "app.patching.source_ml.run_configuration_pair_job",
        "app.patching.source_deterministic.recheck_original_deterministic",
        "app.patching.source_forest.recheck_original_forest",
    ]:
        monkeypatch.setattr(target, forbidden)
    for name in [
        "check_with_batfish",
        "check_with_batfish_evidence",
        "check_with_batfish_directional",
    ]:
        monkeypatch.setattr(source_workflow, name, forbidden)
    report_request, report = create_report(client, selected)
    view = SourceEvidenceReportV3.model_validate(report)
    assert view.network.reachability_impact == source.outcome.network_execution.reachability_impact
    assert view.formal_qualification == "not_proven" and view.status == "needs_review"
    assert view.approved is view.applied is view.quality_proven is view.risk_fused is False
    body = decision_options(report, version="source-evidence-decision-request-0.3.0")
    response = save_decision(client, report, body, headers={"Authorization": f"Bearer {ENGINEER}"})
    assert response.status_code == 201, response.text
    decision = SourceEvidenceDecisionV3.model_validate(response.json())
    assert decision.report_version == report["version"] and decision.service_role == "engineer"
    assert decision.individual_identity_verified is decision.approved is decision.applied is False
    with app.state.analysis_service.store.engine.begin() as connection:
        connection.execute(text("DELETE FROM configuration_sources"))
        connection.execute(text("DELETE FROM models"))
    with TestClient(create_app(settings)) as restarted:
        assert get_network(restarted, selected[0], network_request).json() == selected[1]["network"]
        assert post_network(restarted, selected, network_request).json() == selected[1]["network"]
        assert get_report(restarted, selected, report_request).json() == report
        replay = save_report(restarted, selected, report_request)
        assert replay.status_code == 200 and replay.json() == report
        assert get_decision(restarted, report, body).json() == response.json()
        replay = save_decision(restarted, report, body)
        assert replay.status_code == 200 and replay.json() == response.json()
        for path, version in [
            (
                f"/api/v2/patches/{report['patch_id']}/verifications",
                "source-patch-verification-summary-0.3.0",
            ),
            (
                f"/api/v2/patches/{report['patch_id']}/evidence-reports",
                "source-evidence-summary-0.3.0",
            ),
            (
                f"/api/v2/patches/{report['patch_id']}/evidence-reports/{report['report_id']}/decisions",
                "source-evidence-decision-summary-0.3.0",
            ),
        ]:
            listing = restarted.get(path, headers=HEADERS)
            assert listing.status_code == 200 and listing.json()[0]["version"] == version
    assert len(calls) == 1 and neural_calls == []


@pytest.mark.parametrize("child_version", ["0.1.0", "0.2.0", "0.3.0"])
def test_new_parent_may_select_each_explicit_protocol_and_uuid_cannot_change_it(
    directional_api, child_version
):
    client = directional_api[0]
    selected, network_request = prepare(directional_api, child_version=child_version)
    request, report = create_report(client, selected)
    assert report["network"]["version"] == "source-patch-verification-" + child_version
    for version in ["0.1.0", "0.2.0", "0.3.0"]:
        source_response = post_network(
            client, selected, network_request | {"version": "source-patch-request-" + version}
        )
        assert source_response.status_code == (200 if version == child_version else 409)
        if version != "0.3.0":
            assert (
                save_report(
                    client, selected, request | {"version": "source-evidence-request-" + version}
                ).status_code
                == 409
            )
            if child_version == "0.3.0":
                fresh = request | {
                    "report_id": str(uuid4()),
                    "version": "source-evidence-request-" + version,
                }
                assert save_report(client, selected, fresh).status_code == 409
    body = decision_options(report, version="source-evidence-decision-request-0.3.0")
    assert save_decision(client, report, body).status_code == 201
    for version in ["0.1.0", "0.2.0"]:
        assert (
            save_decision(
                client, report, body | {"version": "source-evidence-decision-request-" + version}
            ).status_code
            == 409
        )
    assert get_report(client, selected, request).json() == report


@pytest.mark.parametrize("field", ["flow", "disposition", "sdk"])
def test_valid_resealed_false_direction_projection_fails_saved_child_and_descendant_reads(
    directional_api, field
):
    client, app, *_ = directional_api
    selected, _ = prepare(directional_api)
    request, report = create_report(client, selected)
    body = decision_options(report, version="source-evidence-decision-request-0.3.0")
    assert save_decision(client, report, body).status_code == 201
    content = dict(report)
    if field == "sdk":
        content["network"]["sdk_version"] = "owned-false-sdk"
    else:
        witness = content["network"]["reachability_impact"]["witnesses"][0]
        if field == "flow":
            witness["flow_sha256"] = "0" * 64
        else:
            witness["after_dispositions"] = ["NULL_ROUTED"]
    content["review_json"] = ml_json(
        {
            key: value
            for key, value in content.items()
            if key not in {"review_json", "review_sha256"}
        }
    )
    content["review_sha256"] = sha256(content["review_json"].encode()).hexdigest()
    forged = SourceEvidenceReportV3.model_validate(content)
    store = app.state.analysis_service.store
    with store._sessions.begin() as session:
        row = session.get(SourceEvidenceReportRow, report["report_id"])
        row.payload = store._encode(
            forged.model_dump_json(), kind="source_evidence_report", row_id=row.id
        )
    assert get_report(client, selected, request).status_code == 503
    assert get_decision(client, report, body).status_code == 503


@pytest.mark.parametrize("role", [READER, ANALYST])
def test_new_protocol_requires_verify_permission_and_fresh_explicit_consent(directional_api, role):
    client, _, _, _, calls, _ = directional_api
    selected = prepare_inputs(client, include=())
    draft, _, before, _ = selected
    request = {
        "version": "source-patch-request-0.3.0",
        "verification_id": str(uuid4()),
        "draft_sha256": draft["draft_sha256"],
        "scope": {
            "start_node": before["canonical"]["device"]["hostname"],
            "destination": "192.0.2.1/32",
        },
        "allow_local_engine_upload": True,
    }
    assert (
        post_network(
            client, selected, request, headers={"Authorization": f"Bearer {role}"}
        ).status_code
        == 403
    )
    assert (
        post_network(client, selected, request | {"allow_local_engine_upload": False}).status_code
        == 403
    )
    assert calls == []


@pytest.mark.parametrize("fault", ["exception", "wrong_source", "wrong_type"])
def test_invalid_direction_worker_keeps_preflight_but_no_directional_observation(
    directional_api, monkeypatch, fault
):
    client = directional_api[0]
    original = source_workflow.check_with_batfish_directional

    def invalid(*args, **kwargs):
        if fault == "exception":
            raise RuntimeError("private-direction-error")
        value = original(*args, **kwargs)
        if fault == "wrong_type":
            return value.result
        return value.model_copy(
            update={"result": value.result.model_copy(update={"after_sha256": "f" * 64})}
        )

    monkeypatch.setattr(source_workflow, "check_with_batfish_directional", invalid)
    selected, request = prepare(directional_api)
    execution = selected[1]["network"]["outcome"]["network_execution"]
    assert execution["result"]["reason"] == "worker_failed"
    assert execution["sdk_observation"] == "not_observed" and execution["sdk_version"] is None
    assert execution["reachability_impact"]["state"] == "not_observed"
    assert execution["reachability_impact"]["direction"] is None
    assert "private-direction-error" not in ml_json(selected[1]["network"])
    assert get_network(client, selected[0], request).json() == selected[1]["network"]


def test_lost_completion_replays_pending_attempt_after_restart_without_reexecution(
    directional_api, monkeypatch
):
    client, _, settings, _, calls, _ = directional_api
    selected = prepare_inputs(client, include=())
    draft, _, before, _ = selected
    request = {
        "version": "source-patch-request-0.3.0",
        "verification_id": str(uuid4()),
        "draft_sha256": draft["draft_sha256"],
        "scope": {
            "start_node": before["canonical"]["device"]["hostname"],
            "destination": "192.0.2.1/32",
        },
        "allow_local_engine_upload": True,
    }

    def lost(*args, **kwargs):
        raise RuntimeError("owned completion interruption")

    monkeypatch.setattr(SourcePatchRecords, "complete", lost)
    interrupted = post_network(client, selected, request)
    assert interrupted.status_code == 500
    assert "owned completion interruption" not in interrupted.text
    assert len(calls) == 1
    monkeypatch.setattr(
        source_workflow,
        "check_with_batfish_directional",
        lambda *a, **kw: pytest.fail("pending replay reexecuted"),
    )
    monkeypatch.setattr(
        SourceRecords, "get", lambda *a, **kw: pytest.fail("pending replay read raw")
    )
    with TestClient(
        create_app(
            settings, patch_verification=PatchVerificationSettings(allow_engine_upload=False)
        )
    ) as restarted:
        response = post_network(restarted, selected, request)
        assert response.status_code == 200
        assert (
            response.json()["execution_status"] == "pending_unknown"
            and response.json()["outcome"] is None
        )
        assert get_network(restarted, draft, request).json() == response.json()


@pytest.mark.parametrize("offset", [-3, 3])
def test_source_direction_reservation_preserves_original_offset_in_normative_payload(
    directional_api, offset
):
    client, app, _, _, calls, _ = directional_api
    selected = prepare_inputs(client, include=())
    draft, _, before, _ = selected
    request = parse_source_patch_request(
        {
            "version": "source-patch-request-0.3.0",
            "verification_id": str(uuid4()),
            "draft_sha256": draft["draft_sha256"],
            "scope": {
                "start_node": before["canonical"]["device"]["hostname"],
                "destination": "192.0.2.1/32",
            },
            "allow_local_engine_upload": True,
        }
    )
    workflow = source_workflow.SourcePatchWorkflow(app.state.analysis_service.store)
    _, _, intent = workflow._prepare(UUID(draft["patch_id"]), request)
    intent = SourcePatchIntentV3.model_validate(
        intent.model_dump()
        | {"created_at": intent.created_at.astimezone(timezone(timedelta(hours=offset)))}
    )
    assert workflow.records.reserve(intent)
    saved = workflow.records.get(request.verification_id)
    assert saved[0].model_dump_json() == intent.model_dump_json()
    assert workflow.records.reserve(intent) is False and calls == []


def test_changed_direction_child_invalidates_previously_saved_report_and_decision(
    directional_api,
):
    client, app, *_ = directional_api
    selected, network_request = prepare(directional_api)
    request, report = create_report(client, selected)
    body = decision_options(report, version="source-evidence-decision-request-0.3.0")
    assert save_decision(client, report, body).status_code == 201
    store = app.state.analysis_service.store
    with store._sessions.begin() as session:
        row = session.get(SourcePatchOutcomeRow, network_request["verification_id"])
        value = store._decode(row.payload, kind="source_patch_outcome", row_id=row.verification_id)
        from app.api.source_patch_direction_contracts import SourcePatchOutcomeV3

        content = SourcePatchOutcomeV3.model_validate_json(value).model_dump(mode="json")
        content["network_execution"]["reachability_impact"]["witnesses"][0]["flow_sha256"] = (
            "0" * 64
        )
        changed = SourcePatchOutcomeV3.model_validate(content)
        row.payload = store._encode(
            changed.model_dump_json(), kind="source_patch_outcome", row_id=row.verification_id
        )
    # The modified child remains typed but no longer has the parent's selected proof.
    assert get_network(client, selected[0], network_request).status_code == 200
    assert get_report(client, selected, request).status_code == 503
    assert get_decision(client, report, body).status_code == 503
