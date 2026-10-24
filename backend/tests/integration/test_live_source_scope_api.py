"""Opt-in owned ingress HTTP chains from two authored basepairs, not an independent corpus."""

import json
import os
from importlib.metadata import version as distribution_version
from uuid import uuid4

import app.patching.source_review as workflow_module
import pytest
from app.api.source_evidence_decision_scope_contracts import SourceEvidenceDecisionV4
from app.api.source_evidence_scope_contracts import SourceEvidenceReportV4
from app.api.source_patch_scope_contracts import SourcePatchVerificationV4
from app.api.source_risk_scope_contracts import SourceRiskAssessmentV2
from app.core.patch_verification import PatchVerificationSettings
from app.core.settings import ApiSettings
from app.db.migrate import upgrade_database
from app.db.source_records import SourceRecords
from app.db.tables import ConfigurationSourceRow
from app.main import create_app
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import delete
from test_live_batfish import _snapshot_pair
from test_source_patch_review_api import HEADERS, TOKEN, draft_pair, get, options, post, upload


def _owned_pair(vendor, scenario):
    before, route_loss = _snapshot_pair(vendor)
    edge, core = before.configs
    before_text = edge.text
    candidate = edge.text
    if scenario in {"shutdown_selected", "interface_removed_selected"}:
        extra = (
            "interface Loopback1\n ip address 203.0.113.10 255.255.255.255\n no shutdown\n!\n"
            if vendor == "cisco"
            else "set interfaces lo1 unit 0 family inet address 203.0.113.10/32\n"
        )
        before_text = (
            edge.text.replace("end\n", extra + "end\n") if vendor == "cisco" else edge.text + extra
        )
        candidate = (
            (
                before_text.replace(extra, extra.replace(" no shutdown\n", " shutdown\n"))
                if vendor == "cisco"
                else before_text + "set interfaces lo1 unit 0 disable\n"
            )
            if scenario == "shutdown_selected"
            else before_text.replace(extra, "")
        )
        return before_text, candidate, core.text
    if scenario == "route_loss":
        candidate = route_loss.configs[0].text
    elif scenario in {"reachable_control", "empty_scope"}:
        candidate += (
            "ntp server 192.0.2.254\n"
            if vendor == "cisco"
            else "set system ntp server 192.0.2.254\n"
        )
    elif scenario == "shutdown":
        candidate = (
            candidate.replace(" no shutdown\n", " shutdown\n")
            if vendor == "cisco"
            else candidate + "set interfaces ge-0/0/0 disable\n"
        )
    elif scenario == "interface_removed":
        candidate = (
            candidate.replace(
                "interface GigabitEthernet0/0\n"
                " ip address 192.0.2.1 255.255.255.252\n no shutdown\n!\n",
                "",
            )
            if vendor == "cisco"
            else candidate.replace(
                "set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/30\n", ""
            )
        )
    elif scenario == "source_address_changed":
        candidate = candidate.replace("192.0.2.1", "192.0.2.5")
    else:
        raise ValueError("unknown owned scenario")
    assert candidate != edge.text
    return edge.text, candidate, core.text


def _assert_recorded_scope(ingress, result, vendor, scenario):
    assert ingress["version"] == "ingress-scope-0.1.0"
    for key in ("before_sha256", "after_sha256", "scope", "network_name"):
        assert ingress[key] == result[key]
    assert ingress["semantic_ip_sets_verified"] is False
    assert ingress["complete_flow_coverage"] is False
    assert ingress["source_assignment_context"] == "after"
    if scenario in {"shutdown", "interface_removed"}:
        # Removing the only usable origin prevents the base query from completing.
        # The existing worker intentionally does not acquire ingress in that state.
        assert result["status"] == (
            "incomplete" if (vendor, scenario) == ("cisco", "interface_removed") else "error"
        )
        assert ingress["acquisition_state"] == "not_observed"
        assert ingress["reason"] == "not_run"
        for key in (
            "before",
            "after",
            "eligibility_complete",
            "selected_before_only",
            "selected_after_only",
            "common_eligible",
            "before_eligible_only",
            "after_eligible_only",
            "after_common_assignments",
        ):
            assert ingress[key] is None
        return
    assert ingress["acquisition_state"] == "observed", ingress
    assert ingress["reason"] == "query_completed"
    before = {row["interface"]: row for row in ingress["before"]["interfaces"]}
    after = {row["interface"]: row for row in ingress["after"]["interfaces"]}
    logical = "GigabitEthernet0/0" if vendor == "cisco" else "ge-0/0/0.0"
    assert logical in before and before[logical]["eligible"] is True
    assert logical in after
    assert after[logical]["canonical_id_sha256"] == before[logical]["canonical_id_sha256"]
    selected_variant = scenario in {"shutdown_selected", "interface_removed_selected"}
    target = "Loopback1" if vendor == "cisco" else "lo1.0"
    if selected_variant:
        assert target in before and before[target]["eligible"] is True
        assert before[logical] == after[logical]
        if scenario == "interface_removed_selected":
            assert target not in after
            assert before[target]["canonical_id_sha256"] in ingress["selected_before_only"]
        else:
            assert target in after
            assert after[target]["active"] is after[target]["eligible"] is False
            assert after[target]["eligibility_reason"] == "inactive"
            assert ingress["selected_before_only"] == ingress["selected_after_only"] == []
    else:
        assert ingress["selected_before_only"] == ingress["selected_after_only"] == []
        if scenario == "source_address_changed":
            assert before[logical]["concrete_ipv4_prefixes"] == ["192.0.2.1/30"]
            assert after[logical]["concrete_ipv4_prefixes"] == ["192.0.2.5/30"]
            # Compare captured renderings, without interpreting semantic IP sets.
            assert before[logical]["source_ip_sha256"] != after[logical]["source_ip_sha256"]
        else:
            assert before == after
    # The modeled JunOS physical parent has no concrete IPv4. An observed capture
    # therefore cannot establish complete eligibility, even when its unit is eligible.
    if vendor == "juniper":
        parent = before["ge-0/0/0"]
        assert parent["active"] is True and parent["concrete_ipv4_prefixes"] == []
        assert parent["eligible"] is None and parent["eligibility_reason"] == "no_concrete_ipv4"
        assert ingress["eligibility_complete"] is False
        for key in (
            "common_eligible",
            "before_eligible_only",
            "after_eligible_only",
            "after_common_assignments",
        ):
            assert ingress[key] is None
    else:
        assert ingress["eligibility_complete"] is True
        assert ingress["common_eligible"] == [before[logical]["canonical_id_sha256"]]
        assert (
            ingress["after_common_assignments"][0]["source_ip_sha256"]
            == after[logical]["source_ip_sha256"]
        )
        if selected_variant:
            assert before[target]["canonical_id_sha256"] in ingress["before_eligible_only"]


@pytest.mark.skipif(
    os.environ.get("NETCONFIG_LIVE_BATFISH") != "1",
    reason="requires explicit owned loopback upload and running pinned Batfish",
)
@pytest.mark.parametrize("vendor", ["cisco", "juniper"])
@pytest.mark.parametrize(
    "scenario",
    [
        "route_loss",
        "reachable_control",
        "shutdown",
        "interface_removed",
        "shutdown_selected",
        "interface_removed_selected",
        "source_address_changed",
        "empty_scope",
    ],
)
def test_saved_ingress_chain_with_actual_owned_engine(tmp_path, monkeypatch, vendor, scenario):
    before_text, candidate, companion_text = _owned_pair(vendor, scenario)

    def no_model(*args, **kwargs):
        pytest.fail("owned ingress HTTP chain must not fit or execute models")

    monkeypatch.setattr("sklearn.ensemble.IsolationForest.fit", no_model)
    monkeypatch.setattr("app.patching.source_ml.run_configuration_pair_job", no_model)
    monkeypatch.setattr("app.patching.source_forest.recheck_original_forest", no_model)
    settings = ApiSettings(
        f"sqlite:///{tmp_path / 'owned-live-ingress.sqlite3'}",
        TOKEN,
        Fernet.generate_key().decode(),
    )
    application = create_app(
        settings,
        patch_verification=PatchVerificationSettings(
            allow_engine_upload=True,
            engine_timeout_seconds=120,
        ),
    )
    upgrade_database(application.state.analysis_service.store.engine)
    with TestClient(application) as client:
        draft, before, _after = draft_pair(client, before=before_text, after=candidate)
        companion = upload(client, companion_text)
        body = options(
            draft,
            version="source-patch-request-0.4.0",
            companions=[
                {
                    "configuration_id": companion["configuration_id"],
                    "source_sha256": companion["canonical"]["source"]["sha256"],
                }
            ],
            scope={
                "start_node": "edge",
                "destination": "203.0.113.1/32" if scenario == "empty_scope" else "198.51.100.1/32",
            },
        )
        response = post(client, draft, body)
        assert response.status_code == 201, response.text
        saved = response.json()
        assert SourcePatchVerificationV4.model_validate(saved).model_dump(mode="json") == saved
        execution = saved["outcome"]["network_execution"]
        result, impact, ingress = (
            execution["result"],
            execution["reachability_impact"],
            execution["ingress_scope"],
        )
        assert execution["version"] == "batfish-execution-0.4.0"
        assert execution["sdk_observation"] == "observed"
        assert execution["sdk_version"] == distribution_version("pybatfish")
        assert result["cleanup_complete"] is True
        if result["status"] != "error":
            assert result["engine_version"]
        if scenario not in {"shutdown", "interface_removed"}:
            assert result["status"] in {
                "differences_found",
                "no_differences_in_scope",
                "inconclusive",
            }
        _assert_recorded_scope(ingress, result, vendor, scenario)
        if scenario == "route_loss":
            assert result["status"] == "differences_found"
            assert impact["state"] == "observed" and impact["direction"] == "loss_found"
        elif scenario == "reachable_control":
            assert result["status"] == "no_differences_in_scope"
            assert impact["state"] == "observed" and impact["direction"] == "no_witnesses_returned"
        elif scenario == "empty_scope":
            assert result["status"] == "inconclusive"
            assert impact["state"] == "inconclusive" and impact["direction"] is None
        # Selected extra-interface and source changes have no invented direction expectation.
        assert saved["status"] == "needs_review" and saved["ml_status"] == "not_run"
        assert saved["approved"] is saved["applied"] is False
        analysis = client.post(
            f"/api/v1/configurations/{before['configuration_id']}/analyze", headers=HEADERS, json={}
        )
        assert analysis.status_code == 201, analysis.text
        base = f"/api/v2/patches/{draft['patch_id']}"
        selected = client.get(
            base + "/deterministic-selection/" + analysis.json()["analysis_id"], headers=HEADERS
        )
        assert selected.status_code == 200, selected.text
        deterministic_request = dict(
            recheck_id=str(uuid4()),
            draft_sha256=draft["draft_sha256"],
            before_analysis_id=analysis.json()["analysis_id"],
            before_analysis_sha256=selected.json()["before_analysis_sha256"],
            reference_canonical_sha256=None,
            allow_local_analysis_context=True,
        )
        deterministic = client.post(
            base + "/deterministic-rechecks", headers=HEADERS, json=deterministic_request
        )
        assert deterministic.status_code == 201, deterministic.text
        assert deterministic.json()["execution_status"] == "completed"
        composition = dict(
            version="source-evidence-request-0.4.0",
            report_id=str(uuid4()),
            draft_sha256=draft["draft_sha256"],
            deterministic=dict(
                record_id=deterministic.json()["recheck_id"],
                review_sha256=deterministic.json()["review_sha256"],
            ),
            forest=None,
            neural=None,
            network=dict(record_id=saved["verification_id"], review_sha256=saved["review_sha256"]),
        )
        joint = client.post(base + "/evidence-reports", headers=HEADERS, json=composition)
        assert joint.status_code == 201, joint.text
        report = joint.json()
        assert SourceEvidenceReportV4.model_validate(report).model_dump(mode="json") == report
        assert report["network"]["result"] == result
        for name in ("reachability_impact", "ingress_scope", "sdk_version", "sdk_observation"):
            assert report["network"][name] == execution[name]
        assert report["network"]["execution_version"] == execution["version"]
        assert report["formal_qualification"] == "not_proven"
        assert report["status"] == "needs_review" and report["forest"] is report["neural"] is None
        assert report["approved"] is report["applied"] is report["quality_proven"] is False
        report_url = base + "/evidence-reports/" + report["report_id"]
        decision_url, risk_url = report_url + "/decisions", report_url + "/risk-assessments"
        decision_request = dict(
            version="source-evidence-decision-request-0.4.0",
            decision_id=str(uuid4()),
            report_sha256=report["review_sha256"],
            verdict="needs_more_information",
            comment="Owned service-role diagnostic; no verified individual approval.",
        )
        response = client.post(decision_url, headers=HEADERS, json=decision_request)
        assert response.status_code == 201, response.text
        decision = response.json()
        assert SourceEvidenceDecisionV4.model_validate(decision).model_dump(mode="json") == decision
        assert decision["report_version"] == report["version"]
        assert decision["report_sha256"] == report["review_sha256"]
        assert (
            decision["individual_identity_verified"]
            is decision["approved"]
            is decision["applied"]
            is False
        )
        risk_request = dict(
            version="source-risk-request-0.2.0",
            assessment_id=str(uuid4()),
            report_sha256=report["review_sha256"],
            profile_version="source-priority-profile-0.1.0",
        )
        response = client.post(risk_url, headers=HEADERS, json=risk_request)
        assert response.status_code == 201, response.text
        risk = response.json()
        assert SourceRiskAssessmentV2.model_validate(risk).model_dump(mode="json") == risk
        priority = risk["composition"]
        assert priority["version"] == "source-priority-composition-0.2.0"
        assert priority["formal_qualification"] == "not_proven"
        assert priority["calibrated"] is priority["quality_proven"] is False
        verification = next(
            row for row in priority["components"] if row["source"] == "verification"
        )
        assert verification["observation"]["execution"] == execution
        scoped_loss = impact["state"] == "observed" and impact["direction"] in {
            "loss_found",
            "loss_and_gain_found",
        }
        assert (
            (verification["raw_score"] == 1.0) if scoped_loss else verification["raw_score"] is None
        )
        assert (
            any(row["kind"] == "observed_scoped_loss" for row in priority["applicable_guardrails"])
            == scoped_loss
        )
        if scoped_loss and priority["status"] == "completed":
            assert priority["score"] >= 0.95
        assert risk["individual_identity_verified"] is risk["approved"] is risk["applied"] is False

        def no_replay_execution(*args, **kwargs):
            pytest.fail("saved ingress history must not query an engine or read original sources")

        for name in (
            "check_with_batfish",
            "check_with_batfish_evidence",
            "check_with_batfish_directional",
            "check_with_batfish_scope_evidence",
        ):
            monkeypatch.setattr(workflow_module, name, no_replay_execution)
        monkeypatch.setattr(SourceRecords, "get", no_replay_execution)
        monkeypatch.setattr(
            "app.patching.source_deterministic.recheck_original_deterministic", no_replay_execution
        )
        with application.state.analysis_service.store.engine.begin() as connection:
            connection.execute(delete(ConfigurationSourceRow))
        with TestClient(create_app(settings)) as restarted:
            assert post(restarted, draft, body).status_code == 200
            assert post(restarted, draft, body).json() == saved
            assert get(restarted, draft, body).json() == saved
            for path, request, record in [
                (base + "/deterministic-rechecks", deterministic_request, deterministic.json()),
                (base + "/evidence-reports", composition, report),
                (decision_url, decision_request, decision),
                (risk_url, risk_request, risk),
            ]:
                replay = restarted.post(path, headers=HEADERS, json=request)
                assert replay.status_code == 200 and replay.json() == record
            for path, record in [
                (
                    base + "/deterministic-rechecks/" + deterministic_request["recheck_id"],
                    deterministic.json(),
                ),
                (report_url, report),
                (decision_url + "/" + decision_request["decision_id"], decision),
                (risk_url + "/" + risk_request["assessment_id"], risk),
            ]:
                historical = restarted.get(path, headers=HEADERS)
                assert historical.status_code == 200 and historical.json() == record
            for path, expected in [
                (base + "/verifications", "source-patch-verification-summary-0.4.0"),
                (base + "/evidence-reports", "source-evidence-summary-0.4.0"),
                (decision_url, "source-evidence-decision-summary-0.4.0"),
                (risk_url, "source-risk-summary-0.2.0"),
            ]:
                listing = restarted.get(path, headers=HEADERS)
                assert listing.status_code == 200 and len(listing.json()) == 1
                assert listing.json()[0]["version"] == expected
        print(
            "OWNED_SOURCE_SCOPE_RESULT="
            + json.dumps(
                dict(
                    vendor=vendor,
                    scenario=scenario,
                    basepair_count=2,
                    independent_quality=False,
                    source_version=saved["version"],
                    report_version=report["version"],
                    decision_version=decision["version"],
                    risk_version=risk["version"],
                    composition_version=priority["version"],
                    sdk_version=execution["sdk_version"],
                    sdk_observation=execution["sdk_observation"],
                    engine_version=result["engine_version"],
                    network_status=result["status"],
                    network_reason=result["reason"],
                    cleanup_complete=result["cleanup_complete"],
                    acquisition_state=ingress["acquisition_state"],
                    acquisition_reason=ingress["reason"],
                    ingress_scope=ingress,
                    reachability_impact=impact,
                    source_sha256=saved["review_sha256"],
                    report_sha256=report["review_sha256"],
                    decision_sha256=decision["decision_sha256"],
                    risk_sha256=risk["review_sha256"],
                    priority_score=priority["score"],
                    priority_status=priority["status"],
                    scoped_loss=scoped_loss,
                    raw_network_priority=verification["raw_score"],
                    risk_fused=report["risk_fused"],
                    formal_qualification=report["formal_qualification"],
                    approved=False,
                    applied=False,
                    individual_identity_verified=False,
                    replay_without_originals=True,
                ),
                sort_keys=True,
            )
        )
