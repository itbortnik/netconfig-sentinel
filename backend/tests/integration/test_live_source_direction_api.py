"""Opt-in directional SDK evidence through immutable source, report and decision HTTP records."""

import json
import os
from importlib.metadata import version as distribution_version
from uuid import uuid4

import app.patching.source_review as workflow_module
import pytest
from app.api.source_evidence_decision_direction_contracts import SourceEvidenceDecisionV3
from app.api.source_evidence_direction_contracts import SourceEvidenceReportV3
from app.api.source_patch_direction_contracts import SourcePatchVerificationV3
from app.core.patch_verification import PatchVerificationSettings
from app.core.settings import ApiSettings
from app.db.migrate import upgrade_database
from app.db.tables import ConfigurationSourceRow
from app.main import create_app
from app.verification.snapshots import prepare_snapshot
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import delete
from test_live_batfish import _snapshot_pair
from test_source_patch_review_api import HEADERS, TOKEN, draft_pair, get, options, post, upload


def _directional_snapshot_pair(vendor, scenario):
    before, after = _snapshot_pair(vendor)
    if scenario == "route_gain":
        return after, before
    if scenario != "equal_totals_mixed":
        return before, after
    texts = {c.device_id: c.text for c in before.configs}
    edge_id, core_id = (c.device_id for c in before.configs)
    edge = texts[edge_id]
    if vendor == "cisco":
        texts[core_id] = texts[core_id].replace(
            "end\n", "interface Loopback1\n ip address 198.51.100.129 255.255.255.255\nend\n"
        )
        route = "ip route 198.51.100.0 255.255.255.0 192.0.2.2"
        left = "ip route 198.51.100.0 255.255.255.128 Null0\n" + route
        right = "ip route 198.51.100.128 255.255.255.128 Null0\n" + route
    else:
        texts[core_id] += "set interfaces lo0 unit 0 family inet address 198.51.100.129/32\n"
        route = "set routing-options static route 198.51.100.0/24 next-hop 192.0.2.2"
        left = "set routing-options static route 198.51.100.0/25 discard\n" + route
        right = "set routing-options static route 198.51.100.128/25 discard\n" + route
    return (
        prepare_snapshot({**texts, edge_id: edge.replace(route, left)}),
        prepare_snapshot({**texts, edge_id: edge.replace(route, right)}),
    )


@pytest.mark.skipif(
    os.environ.get("NETCONFIG_LIVE_BATFISH") != "1",
    reason="requires explicit owned loopback upload and running Batfish",
)
@pytest.mark.parametrize("vendor", ["cisco", "juniper"])
@pytest.mark.parametrize(
    "scenario",
    ["route_loss", "route_gain", "equal_totals_mixed", "reachable_control", "empty_scope"],
)
def test_saved_directional_pair_with_actual_owned_engine(tmp_path, monkeypatch, vendor, scenario):
    old, changed = _directional_snapshot_pair(vendor, scenario)
    edge, core = old.configs
    candidate = changed.configs[0].text
    if scenario == "reachable_control":
        candidate = edge.text + (
            "ntp server 192.0.2.254\n"
            if vendor == "cisco"
            else "set system ntp server 192.0.2.254\n"
        )
    settings = ApiSettings(
        f"sqlite:///{tmp_path / 'owned-live-source.sqlite3'}",
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
        draft, before, _after = draft_pair(client, before=edge.text, after=candidate)
        companion = upload(client, core.text)
        body = options(
            draft,
            version="source-patch-request-0.3.0",
            companions=[
                {
                    "configuration_id": companion["configuration_id"],
                    "source_sha256": companion["canonical"]["source"]["sha256"],
                }
            ],
            scope={
                "start_node": "edge",
                "destination": "203.0.113.1/32"
                if scenario == "empty_scope"
                else "198.51.100.0/24"
                if scenario == "equal_totals_mixed"
                else "198.51.100.1/32",
            },
        )
        response = post(client, draft, body)
        assert response.status_code == 201, response.text
        saved = response.json()
        execution = saved["outcome"]["network_execution"]
        result = execution["result"]
        assert saved["version"] == "source-patch-verification-0.3.0"
        assert execution["version"] == "batfish-execution-0.3.0"
        assert execution["sdk_observation"] == "observed"
        # This is an independent comparison, never a parent-side fill of a stored record.
        assert execution["sdk_version"] == distribution_version("pybatfish")
        expected = {
            "route_loss": "differences_found",
            "route_gain": "differences_found",
            "equal_totals_mixed": "differences_found",
            "reachable_control": "no_differences_in_scope",
            "empty_scope": "inconclusive",
        }[scenario]
        print(
            "OWNED_SOURCE_API_RESULT="
            + json.dumps(
                {
                    "vendor": vendor,
                    "scenario": scenario,
                    "status": result["status"],
                    "reason": result["reason"],
                    "engine_version": result["engine_version"],
                    "sdk_version": execution["sdk_version"],
                    "sdk_observation": execution["sdk_observation"],
                    "before_reachable_count": result["before_reachable_count"],
                    "after_reachable_count": result["after_reachable_count"],
                    "difference_count": result["difference_count"],
                    "cleanup_complete": result["cleanup_complete"],
                    "review_sha256": saved["review_sha256"],
                    "ml_status": saved["ml_status"],
                    "overall_status": saved["status"],
                },
                sort_keys=True,
            )
        )
        expected_direction = {
            "route_loss": "loss_found",
            "route_gain": "gain_found",
            "equal_totals_mixed": "loss_and_gain_found",
            "reachable_control": "no_witnesses_returned",
            "empty_scope": None,
        }[scenario]
        impact = execution["reachability_impact"]
        assert impact["direction"] == expected_direction, impact
        assert impact["state"] == ("inconclusive" if scenario == "empty_scope" else "observed")
        assert SourcePatchVerificationV3.model_validate(saved).model_dump(mode="json") == saved
        print(
            "OWNED_SOURCE_DIRECTION_RESULT="
            + json.dumps(
                {
                    "vendor": vendor,
                    "scenario": scenario,
                    "impact": impact,
                    "review_sha256": saved["review_sha256"],
                    "sdk_version": execution["sdk_version"],
                    "sdk_observation": execution["sdk_observation"],
                    "engine_version": result["engine_version"],
                    "status": result["status"],
                    "before_reachable_count": result["before_reachable_count"],
                    "after_reachable_count": result["after_reachable_count"],
                    "difference_count": result["difference_count"],
                    "cleanup_complete": result["cleanup_complete"],
                    "overall_status": saved["status"],
                    "ml_status": saved["ml_status"],
                },
                sort_keys=True,
            )
        )
        assert result["status"] == expected
        assert result["engine_version"] and result["cleanup_complete"] is True
        assert saved["status"] == "needs_review" and saved["ml_status"] == "not_run"
        assert saved["approved"] is saved["applied"] is False
        assert get(client, draft, body).json() == saved
        if scenario == "route_loss":
            assert result["before_reachable_count"] and result["after_reachable_count"] == 0
            assert result["difference_count"]
        elif scenario == "route_gain":
            assert result["before_reachable_count"] == 0 and result["after_reachable_count"]
        elif scenario == "equal_totals_mixed":
            assert result["before_reachable_count"] == result["after_reachable_count"] == 1
            assert result["difference_count"] == 2
            assert impact["lost_witness_count"] == impact["gained_witness_count"] == 1
        elif scenario == "reachable_control":
            assert result["before_reachable_count"] and result["after_reachable_count"]
            assert result["difference_count"] == 0
        else:
            assert result["before_reachable_count"] == result["after_reachable_count"] == 0
        # Compose the actual retained network result with an explicit original policy rerun.
        # No ML runtime is configured in this engine job, and no extra SDK query is needed.
        analysis = client.post(
            f"/api/v1/configurations/{before['configuration_id']}/analyze",
            headers=HEADERS,
            json={},
        )
        assert analysis.status_code == 201, analysis.text
        base = f"/api/v2/patches/{draft['patch_id']}"
        selected = client.get(
            base + "/deterministic-selection/" + analysis.json()["analysis_id"], headers=HEADERS
        )
        assert selected.status_code == 200, selected.text
        deterministic = client.post(
            base + "/deterministic-rechecks",
            headers=HEADERS,
            json={
                "recheck_id": str(uuid4()),
                "draft_sha256": draft["draft_sha256"],
                "before_analysis_id": analysis.json()["analysis_id"],
                "before_analysis_sha256": selected.json()["before_analysis_sha256"],
                "reference_canonical_sha256": None,
                "allow_local_analysis_context": True,
            },
        )
        assert deterministic.status_code == 201, deterministic.text
        assert deterministic.json()["execution_status"] == "completed"
        composition = {
            "version": "source-evidence-request-0.3.0",
            "report_id": str(uuid4()),
            "draft_sha256": draft["draft_sha256"],
            "deterministic": {
                "record_id": deterministic.json()["recheck_id"],
                "review_sha256": deterministic.json()["review_sha256"],
            },
            "forest": None,
            "neural": None,
            "network": {
                "record_id": saved["verification_id"],
                "review_sha256": saved["review_sha256"],
            },
        }
        joint = client.post(base + "/evidence-reports", headers=HEADERS, json=composition)
        assert joint.status_code == 201, joint.text
        report = joint.json()
        assert report["version"] == "source-evidence-report-0.3.0"
        assert report["network"]["result"] == result
        assert report["network"]["reachability_impact"] == impact
        assert SourceEvidenceReportV3.model_validate(report).model_dump(mode="json") == report
        assert report["network"]["execution_version"] == execution["version"]
        assert report["network"]["sdk_version"] == execution["sdk_version"]
        assert report["network"]["sdk_observation"] == "observed"
        assert report["network"]["ml_status"] == "not_run" and report["neural"] is None
        assert report["formal_qualification"] == "not_proven" and report["status"] == "needs_review"
        assert report["approved"] is report["applied"] is False
        assert ("formal_scope_not_passed" in report["validation_blockers"]) == (
            expected != "no_differences_in_scope"
        )
        print(
            "OWNED_SOURCE_EVIDENCE_RESULT="
            + json.dumps(
                {
                    "vendor": vendor,
                    "scenario": scenario,
                    "network_status": report["network"]["result"]["status"],
                    "engine_version": report["network"]["result"]["engine_version"],
                    "sdk_version": report["network"]["sdk_version"],
                    "sdk_observation": report["network"]["sdk_observation"],
                    "overall_status": report["status"],
                    "formal_qualification": report["formal_qualification"],
                    "report_sha256": report["review_sha256"],
                },
                sort_keys=True,
            )
        )
        decision_url = base + "/evidence-reports/" + report["report_id"] + "/decisions"
        decision_request = {
            "version": "source-evidence-decision-request-0.3.0",
            "decision_id": str(uuid4()),
            "report_sha256": report["review_sha256"],
            "verdict": "rejected" if expected == "differences_found" else "needs_more_information",
            "comment": "Authored service-role control; no verified individual approval.",
        }
        response = client.post(decision_url, headers=HEADERS, json=decision_request)
        assert response.status_code == 201, response.text
        decision = response.json()
        assert decision["version"] == "source-evidence-decision-0.3.0"
        assert SourceEvidenceDecisionV3.model_validate(decision).model_dump(mode="json") == decision
        assert decision["report_version"] == report["version"]
        assert decision["request"]["verdict"] == decision_request["verdict"]
        assert decision["report_sha256"] == report["review_sha256"]
        assert decision["service_role"] == "admin"
        assert decision["individual_identity_verified"] is False
        assert decision["approved"] is decision["applied"] is False
        assert (
            client.get(base + "/evidence-reports/" + report["report_id"], headers=HEADERS).json()
            == report
        )
        print(
            "OWNED_SOURCE_EVIDENCE_DECISION_RESULT="
            + json.dumps(
                {
                    "vendor": vendor,
                    "scenario": scenario,
                    "network_status": report["network"]["result"]["status"],
                    "report_sha256": decision["report_sha256"],
                    "decision_sha256": decision["decision_sha256"],
                    "verdict": decision["request"]["verdict"],
                    "recorded_service_role": decision["service_role"],
                    "sdk_version": report["network"]["sdk_version"],
                    "sdk_observation": report["network"]["sdk_observation"],
                    "individual_identity_verified": False,
                    "approved": False,
                },
                sort_keys=True,
            )
        )
        # This new assessment consumes the already-saved actual network evidence;
        # it performs no additional SDK query or model execution.
        from app.api.source_risk_contracts import SourceRiskAssessment

        risk_url = base + "/evidence-reports/" + report["report_id"] + "/risk-assessments"
        risk_request = {
            "version": "source-risk-request-0.1.0",
            "assessment_id": str(uuid4()),
            "report_sha256": report["review_sha256"],
            "profile_version": "source-priority-profile-0.1.0",
        }
        risk_response = client.post(risk_url, headers=HEADERS, json=risk_request)
        assert risk_response.status_code == 201, risk_response.text
        risk = risk_response.json()
        assert SourceRiskAssessment.model_validate(risk).model_dump(mode="json") == risk
        assert risk["report_sha256"] == report["review_sha256"]
        assert risk["service_role"] == "admin"
        assert risk["individual_identity_verified"] is risk["approved"] is risk["applied"] is False
        priority = risk["composition"]
        assert priority["formal_qualification"] == "not_proven"
        assert priority["calibrated"] is priority["quality_proven"] is False
        assert priority["review_status"] == "needs_review"
        verification = next(
            row for row in priority["components"] if row["source"] == "verification"
        )
        scoped_loss = scenario in {"route_loss", "equal_totals_mixed"}
        assert (
            (verification["raw_score"] == 1.0)
            if scoped_loss
            else (
                verification["raw_score"] is None
                and verification["effective_weight"] == 0
                and verification["contribution"] is None
            )
        )
        assert (
            any(row["kind"] == "observed_scoped_loss" for row in priority["applied_guardrails"])
            == scoped_loss
        )
        if scoped_loss:
            assert priority["score"] >= 0.95
        print(
            "OWNED_SOURCE_RISK_RESULT="
            + json.dumps(
                {
                    "vendor": vendor,
                    "scenario": scenario,
                    "assessment_sha256": risk["review_sha256"],
                    "report_sha256": report["review_sha256"],
                    "profile_version": priority["profile_version"],
                    "score": priority["score"],
                    "band": priority["band"],
                    "availability_mask": priority["availability_mask"],
                    "network_component": verification["raw_score"],
                    "scoped_loss_guardrail_applied": scoped_loss,
                    "formal_qualification": priority["formal_qualification"],
                    "quality_proven": False,
                    "individual_identity_verified": False,
                    "approved": False,
                },
                sort_keys=True,
            )
        )
        monkeypatch.setattr(
            workflow_module,
            "check_with_batfish",
            lambda *a, **k: pytest.fail("replay must not query engine"),
        )
        monkeypatch.setattr(
            workflow_module,
            "check_with_batfish_evidence",
            lambda *a, **k: pytest.fail("replay must not query SDK metadata or engine"),
        )
        monkeypatch.setattr(
            workflow_module,
            "check_with_batfish_directional",
            lambda *a, **k: pytest.fail("replay must not query direction or engine"),
        )
        monkeypatch.setattr(
            workflow_module.SourcePatchWorkflow,
            "_source",
            lambda *a, **k: pytest.fail("history must not read original source"),
        )
        with application.state.analysis_service.store.engine.begin() as connection:
            connection.execute(delete(ConfigurationSourceRow))
        with TestClient(create_app(settings)) as restarted:
            assert post(restarted, draft, body).json() == saved
            assert get(restarted, draft, body).json() == saved
            assert (
                restarted.post(base + "/evidence-reports", headers=HEADERS, json=composition).json()
                == report
            )
            assert (
                restarted.get(
                    base + "/evidence-reports/" + composition["report_id"], headers=HEADERS
                ).json()
                == report
            )
            assert (
                restarted.post(decision_url, headers=HEADERS, json=decision_request).json()
                == decision
            )
            assert (
                restarted.get(
                    decision_url + "/" + decision_request["decision_id"], headers=HEADERS
                ).json()
                == decision
            )
            replay = restarted.post(risk_url, headers=HEADERS, json=risk_request)
            assert replay.status_code == 200 and replay.json() == risk
            historical_risk = restarted.get(
                risk_url + "/" + risk_request["assessment_id"], headers=HEADERS
            )
            assert historical_risk.status_code == 200 and historical_risk.json() == risk
            risk_history = restarted.get(risk_url, headers=HEADERS)
            assert risk_history.status_code == 200
            assert len(risk_history.json()) == 1
            assert risk_history.json()[0]["review_sha256"] == risk["review_sha256"]
        # A foreign parent never exposes this result.
        assert (
            client.get(
                f"/api/v2/patches/{uuid4()}/verifications/{body['verification_id']}",
                headers=HEADERS,
            ).status_code
            == 404
        )
