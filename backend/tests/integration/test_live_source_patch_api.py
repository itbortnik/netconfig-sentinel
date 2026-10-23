"""Opt-in authored two-node source pairs through the saved HTTP workflow and real SDK."""

import json
import os
from importlib.metadata import version as distribution_version
from uuid import uuid4

import app.patching.source_review as workflow_module
import pytest
from app.core.patch_verification import PatchVerificationSettings
from app.core.settings import ApiSettings
from app.db.migrate import upgrade_database
from app.main import create_app
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from test_live_batfish import _snapshot_pair
from test_source_patch_review_api import HEADERS, TOKEN, draft_pair, get, options, post, upload


@pytest.mark.skipif(
    os.environ.get("NETCONFIG_LIVE_BATFISH") != "1",
    reason="requires explicit owned loopback upload and running Batfish",
)
@pytest.mark.parametrize("vendor", ["cisco", "juniper"])
@pytest.mark.parametrize("scenario", ["route_loss", "reachable_control", "empty_scope"])
def test_saved_source_pair_with_actual_owned_engine(tmp_path, monkeypatch, vendor, scenario):
    old, changed = _snapshot_pair(vendor)
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
            version="source-patch-request-0.2.0",
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
        execution = saved["outcome"]["network_execution"]
        result = execution["result"]
        assert saved["version"] == "source-patch-verification-0.2.0"
        assert execution["version"] == "batfish-execution-0.2.0"
        assert execution["sdk_observation"] == "observed"
        # This is an independent comparison, never a parent-side fill of a stored record.
        assert execution["sdk_version"] == distribution_version("pybatfish")
        expected = {
            "route_loss": "differences_found",
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
        assert result["status"] == expected
        assert result["engine_version"] and result["cleanup_complete"] is True
        assert saved["status"] == "needs_review" and saved["ml_status"] == "not_run"
        assert saved["approved"] is saved["applied"] is False
        assert get(client, draft, body).json() == saved
        if scenario == "route_loss":
            assert result["before_reachable_count"] and result["after_reachable_count"] == 0
            assert result["difference_count"]
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
            "version": "source-evidence-request-0.2.0",
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
        assert report["version"] == "source-evidence-report-0.2.0"
        assert report["network"]["result"] == result
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
            "version": "source-evidence-decision-request-0.2.0",
            "decision_id": str(uuid4()),
            "report_sha256": report["review_sha256"],
            "verdict": "rejected" if scenario == "route_loss" else "needs_more_information",
            "comment": "Authored service-role control; no verified individual approval.",
        }
        response = client.post(decision_url, headers=HEADERS, json=decision_request)
        assert response.status_code == 201, response.text
        decision = response.json()
        assert decision["version"] == "source-evidence-decision-0.2.0"
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
        # A foreign parent never exposes this result.
        assert (
            client.get(
                f"/api/v2/patches/{uuid4()}/verifications/{body['verification_id']}",
                headers=HEADERS,
            ).status_code
            == 404
        )
