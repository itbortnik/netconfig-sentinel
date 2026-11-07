"""Native lineage regression: real policy/Forest, synthetic neural by default.

Eight authored configurations and one Forest fit per vendor are test setup, not
an independent quality experiment. CPU inference and owned loopback network
execution are separately opt-in; the default does not execute an engine.
"""

import os
from pathlib import Path
from uuid import uuid4

import pytest
from app.api.source_deterministic_contracts import SourceDeterministicRecheck
from app.api.source_evidence_decision_scope_contracts import SourceEvidenceDecisionV4
from app.api.source_evidence_scope_contracts import SourceEvidenceReportV4
from app.api.source_forest_contracts import SourceForestRecheck
from app.api.source_ml_contracts import SourceMlRecheck
from app.api.source_risk_scope_contracts import SourceRiskAssessmentV2
from app.core.configuration_model import ConfigurationModelSettings
from app.core.patch_verification import PatchVerificationSettings
from app.detection.config_pair_runtime import run_configuration_pair_job
from app.main import create_app
from fastapi.testclient import TestClient
from sqlalchemy import text
from test_live_batfish import _snapshot_pair
from test_source_forest_api import upload
from test_source_ml_recheck_api import source_ml_api as source_ml_api
from test_source_patch_review_api import ANALYST, ENGINEER, HEADERS, READER


def _headers(token):
    return {"Authorization": f"Bearer {token}"}


def _prepare(client, vendor):
    """Train only the small existing numeric control, without a manual draft."""
    ids = []
    for index in range(8):
        content = (
            f"hostname owned-training-{index}\nip ssh version 2\n"
            + "".join(f"ntp server 192.0.2.{20 + j}\n" for j in range(index % 4))
            if vendor == "cisco"
            else f"set system host-name owned-training-{index}\nset system services ssh\n"
            + "".join(f"set system ntp server 192.0.2.{20 + j}\n" for j in range(index % 4))
        )
        ids.append(upload(client, content)["configuration_id"])
    response = client.post(
        "/api/v1/models/isolation-forest", headers=HEADERS, json={"configuration_ids": ids}
    )
    assert response.status_code == 201, response.text
    model = response.json()
    topology, _changed_route = _snapshot_pair(vendor)
    edge, core = topology.configs
    original = (
        edge.text.replace(
            "end\n", "ip ssh version 2\nline vty 0 4\n transport input ssh telnet\n!\nend\n"
        )
        if vendor == "cisco"
        else edge.text + "set system services ssh\nset system services telnet\n"
    )
    before = upload(client, original, retain=True)
    companion = upload(client, core.text, retain=True)
    response = client.post(
        f"/api/v1/configurations/{before['configuration_id']}/analyze",
        headers=_headers(ANALYST),
        json={"statistical_model_id": model["model_id"]},
    )
    assert response.status_code == 201, response.text
    analysis = response.json()
    assert analysis["statistical"]["model"] == model
    return before, companion, analysis, model


def _forbidden(*args, **kwargs):
    pytest.fail(
        "native bridge/composition/history executed an unrequested runtime or read raw/model"
    )


def _block_runtime(monkeypatch, *, sources=False):
    for path in (
        "app.api.service.evaluate_policies",
        "app.api.service.evaluate_isolation_forest",
        "app.patching.native_patches.create_vendor_draft",
        "app.patching.native_patches.evaluate_policies",
        "app.patching.vendor_drafts.evaluate_policies",
        "app.patching.source_deterministic.recheck_original_deterministic",
        "app.patching.source_forest.recheck_original_forest",
        "app.patching.source_ml.run_configuration_pair_job",
        "app.patching.source_review.check_with_batfish",
        "app.patching.source_review.check_with_batfish_evidence",
        "app.patching.source_review.check_with_batfish_directional",
        "app.patching.source_review.check_with_batfish_scope_evidence",
    ):
        monkeypatch.setattr(path, _forbidden)
    if sources:
        for path in (
            "app.db.source_records.SourceRecords.get",
            "app.db.store.Store.get_model",
            "app.patching.native_materialization.prepare_native_materialization",
            "app.patching.native_materialization_preparation.prepare_original_source",
            "app.patching.native_materialization_preparation.parse_configuration_with_coverage",
            "app.api.service.parse_configuration_with_coverage",
            "app.parsers.coverage.parse_configuration_with_coverage",
        ):
            monkeypatch.setattr(path, _forbidden)


@pytest.mark.parametrize("vendor", ["cisco", "juniper"])
def test_native_lineage_selected_children_and_runtime_free_history(
    source_ml_api, monkeypatch, vendor
):
    client, application, settings, synthetic_calls = source_ml_api
    registry = os.environ.get("NETCONFIG_NATIVE_CHAIN_REGISTRY", "")
    pin = os.environ.get("NETCONFIG_NATIVE_CHAIN_MODEL_SHA256", "")
    if bool(registry) != bool(pin):
        pytest.fail("native chain CPU registry and independent model pin are required together")
    actual_cpu = bool(registry)
    if actual_cpu:
        application.state.configuration_model.settings = ConfigurationModelSettings(
            registry_root=Path(registry), model_sha256=pin, timeout_seconds=180
        )
        monkeypatch.setattr(
            "app.patching.source_ml.run_configuration_pair_job", run_configuration_pair_job
        )
    else:
        pin = application.state.configuration_model.settings.model_sha256
    live_network = os.environ.get("NETCONFIG_LIVE_BATFISH") == "1"
    application.state.patch_verification.settings = PatchVerificationSettings(
        allow_engine_upload=live_network, engine_timeout_seconds=180
    )
    if not live_network:
        for name in (
            "check_with_batfish",
            "check_with_batfish_evidence",
            "check_with_batfish_directional",
            "check_with_batfish_scope_evidence",
        ):
            monkeypatch.setattr("app.patching.source_review." + name, _forbidden)

    before, companion, analysis, model = _prepare(client, vendor)
    # The single authored Forest fit above is setup; none may occur after original analysis.
    monkeypatch.setattr("sklearn.ensemble.IsolationForest.fit", _forbidden)
    resources = []

    def save(path, request, id_field=None):
        response = client.post(path, headers=_headers(ENGINEER), json=request)
        assert response.status_code == 201, response.text
        value = response.json()
        resources.append(
            dict(
                post_path=path,
                get_path=path + "/" + value[id_field] if id_field else path,
                list_path=path if id_field else None,
                request=request,
                value=value,
                post_wire=response.content,
            )
        )
        return value

    native_base = f"/api/v2/configurations/{before['configuration_id']}/native-patches"
    selected = client.get(
        f"/api/v2/configurations/{before['configuration_id']}/native-patch-selection/{analysis['analysis_id']}",
        headers=_headers(READER),
    )
    assert selected.status_code == 200, selected.text
    selection = selected.json()
    assert len(selection["finding_pins"]) == 1
    finding = selection["finding_pins"][0]
    native = save(
        native_base,
        dict(
            version="native-patch-request-0.1.0",
            candidate_id=str(uuid4()),
            analysis_id=analysis["analysis_id"],
            analysis_sha256=selection["analysis_sha256"],
            finding_id=finding["finding_id"],
            finding_sha256=finding["finding_sha256"],
            source_sha256=selection["source"]["source_sha256"],
            canonical_sha256=selection["canonical_sha256"],
            policy_catalog_version=selection["policy_catalog_version"],
            allow_local_native_generation=True,
            allow_private_candidate_retention=True,
        ),
        "candidate_id",
    )
    with monkeypatch.context() as bridge_guard:
        _block_runtime(bridge_guard)
        materialization = save(
            native_base + "/" + native["candidate_id"] + "/materialization",
            dict(
                version="native-materialization-request-0.1.0",
                after_configuration_id=str(uuid4()),
                patch_id=str(uuid4()),
                native_review_sha256=native["review_sha256"],
                allow_local_source_materialization=True,
                allow_private_candidate_source_retention=True,
            ),
        )
    assert all(
        materialization[name] is False
        for name in (
            "fresh_policy_recheck_performed",
            "model_recheck_performed",
            "network_verification_performed",
            "individual_identity_verified",
            "approved",
            "applied",
        )
    )
    assert not synthetic_calls
    patch_id = materialization["patch_id"]
    base = f"/api/v2/patches/{patch_id}"
    selected = client.get(
        base + "/deterministic-selection/" + analysis["analysis_id"], headers=HEADERS
    )
    assert selected.status_code == 200, selected.text
    analysis_pin = selected.json()["before_analysis_sha256"]
    assert analysis_pin == selection["analysis_sha256"]
    deterministic = save(
        base + "/deterministic-rechecks",
        dict(
            recheck_id=str(uuid4()),
            draft_sha256=materialization["draft_sha256"],
            before_analysis_id=analysis["analysis_id"],
            before_analysis_sha256=analysis_pin,
            reference_canonical_sha256=None,
            allow_local_analysis_context=True,
        ),
        "recheck_id",
    )
    SourceDeterministicRecheck.model_validate(deterministic)
    forest = save(
        base + "/statistical-rechecks",
        dict(
            recheck_id=str(uuid4()),
            draft_sha256=materialization["draft_sha256"],
            before_analysis_id=analysis["analysis_id"],
            before_analysis_sha256=analysis_pin,
            model_id=model["model_id"],
            artifact_sha256=model["artifact_sha256"],
            allow_local_model_context=True,
        ),
        "recheck_id",
    )
    SourceForestRecheck.model_validate(forest)
    neural = save(
        base + "/ml-rechecks",
        dict(
            recheck_id=str(uuid4()),
            draft_sha256=materialization["draft_sha256"],
            model_sha256=pin,
            allow_local_model_context=True,
        ),
        "recheck_id",
    )
    SourceMlRecheck.model_validate(neural)
    assert len(synthetic_calls) == (0 if actual_cpu else 1)
    for child in (deterministic, forest, neural):
        assert child["execution_status"] == "completed"
        assert child["patch_id"] == patch_id
        assert child["draft_sha256"] == materialization["draft_sha256"]
        for side in ("before", "after"):
            for field in ("configuration_id", "device_id", "source_sha256"):
                assert child["intent"][side][field] == materialization[side][field]
        assert child["intent"]["before"]["canonical_sha256"] == selection["canonical_sha256"]
        assert (
            child["intent"]["after"]["canonical_sha256"]
            == materialization["after_canonical_sha256"]
        )
    for child in (deterministic, forest):
        assert child["before_analysis_id"] == analysis["analysis_id"]
        assert child["before_analysis_sha256"] == analysis_pin
    assert forest["outcome"]["report"]["model"] == model
    assert (
        forest["outcome"]["report"]["scores"]["before_score_samples"]
        == analysis["statistical"]["score_samples"]
    )
    policy = deterministic["outcome"]["report"]
    assert any(
        row["category"] == "management.telnet_enabled"
        for row in policy["policy_changes"]["resolved"]
    )
    assert not any(
        row["category"] == "management.telnet_enabled" for row in policy["after"]["policy_findings"]
    )

    network = None
    if live_network:
        network = save(
            base + "/verify",
            dict(
                version="source-patch-request-0.4.0",
                verification_id=str(uuid4()),
                draft_sha256=materialization["draft_sha256"],
                companions=[
                    dict(
                        configuration_id=companion["configuration_id"],
                        source_sha256=companion["canonical"]["source"]["sha256"],
                    )
                ],
                scope=dict(start_node="edge", destination="198.51.100.1/32"),
                allow_local_engine_upload=True,
            ),
        )
        resources[-1]["get_path"] = base + "/verifications/" + network["verification_id"]
        resources[-1]["list_path"] = base + "/verifications"
        assert network["execution_status"] == "completed"
        execution = network["outcome"]["network_execution"]
        assert execution["sdk_observation"] == "observed" and execution["sdk_version"]
        assert execution["result"]["status"] == "no_differences_in_scope"
        assert execution["result"]["before_reachable_count"] > 0
        assert execution["result"]["after_reachable_count"] > 0
        assert execution["result"]["cleanup_complete"] is True
    children = dict(deterministic=deterministic, forest=forest, neural=neural, network=network)
    report_request = dict(
        version="source-evidence-request-0.4.0",
        report_id=str(uuid4()),
        draft_sha256=materialization["draft_sha256"],
        **{
            kind: dict(
                record_id=row.get("recheck_id", row.get("verification_id")),
                review_sha256=row["review_sha256"],
            )
            if row
            else None
            for kind, row in children.items()
        },
    )
    with monkeypatch.context() as pure_guard:
        _block_runtime(pure_guard, sources=True)
        stale = report_request | {
            "report_id": str(uuid4()),
            "forest": report_request["forest"] | {"review_sha256": "0" * 64},
        }
        refused = client.post(base + "/evidence-reports", headers=_headers(ENGINEER), json=stale)
        assert refused.status_code == 409, refused.text
        report = save(base + "/evidence-reports", report_request, "report_id")
        SourceEvidenceReportV4.model_validate(report)
        assert report["before_analysis_id"] == analysis["analysis_id"]
        assert report["before_analysis_sha256"] == analysis_pin
        for kind, child in children.items():
            if child is None:
                assert report[kind] is None
            else:
                assert report[kind]["review_sha256"] == child["review_sha256"]
                assert report[kind]["record_id"] == child.get(
                    "recheck_id", child.get("verification_id")
                )
        assert report["formal_qualification"] == "not_proven"
        report_base = base + "/evidence-reports/" + report["report_id"]
        risk = save(
            report_base + "/risk-assessments",
            dict(
                version="source-risk-request-0.2.0",
                assessment_id=str(uuid4()),
                report_sha256=report["review_sha256"],
                profile_version="source-priority-profile-0.1.0",
            ),
            "assessment_id",
        )
        SourceRiskAssessmentV2.model_validate(risk)
        verification_component = next(
            row for row in risk["composition"]["components"] if row["source"] == "verification"
        )
        assert verification_component["raw_score"] is None
        assert verification_component["status"] == "unavailable"
        assert verification_component["effective_weight"] == 0
        assert verification_component["contribution"] is None
        if network is None:
            assert "network_not_selected" in report["validation_blockers"]
            assert verification_component["reason"] == "not_selected"
        decision = save(
            report_base + "/decisions",
            dict(
                version="source-evidence-decision-request-0.4.0",
                decision_id=str(uuid4()),
                report_sha256=report["review_sha256"],
                verdict="needs_more_information",
                comment=(
                    "Authored service-role control; vendor syntax and individual approval "
                    "remain unverified."
                ),
            ),
            "decision_id",
        )
        SourceEvidenceDecisionV4.model_validate(decision)
    assert decision["service_role"] == "engineer"
    for value in (report, risk, decision):
        assert value["approved"] is value["applied"] is False
    assert risk["individual_identity_verified"] is decision["individual_identity_verified"] is False
    assert len(synthetic_calls) == (0 if actual_cpu else 1)
    origin_path = (
        f"/api/v2/configurations/{materialization['after']['configuration_id']}/native-origin"
    )
    origin = client.get(origin_path, headers=_headers(READER))
    assert origin.status_code == 200 and origin.json() == materialization
    for resource in resources:
        loaded = client.get(resource["get_path"], headers=_headers(READER))
        assert loaded.status_code == 200 and loaded.json() == resource["value"]
        resource["get_wire"] = loaded.content
        if resource["list_path"]:
            listing = client.get(resource["list_path"], headers=_headers(READER))
            assert listing.status_code == 200
            resource["list_wire"] = listing.content
    with application.state.analysis_service.store.engine.begin() as connection:
        connection.execute(text("DELETE FROM configuration_sources"))
        connection.execute(text("DELETE FROM models"))
    _block_runtime(monkeypatch, sources=True)
    with TestClient(create_app(settings)) as restarted:
        assert restarted.get(origin_path, headers=_headers(READER)).content == origin.content
        for resource in resources:
            loaded = restarted.get(resource["get_path"], headers=_headers(READER))
            assert loaded.status_code == 200 and loaded.content == resource["get_wire"]
            if resource["list_path"]:
                listing = restarted.get(resource["list_path"], headers=_headers(READER))
                assert listing.status_code == 200 and listing.content == resource["list_wire"]
            replay = restarted.post(
                resource["post_path"], headers=HEADERS, json=resource["request"]
            )
            assert replay.status_code == 200 and replay.content == resource["post_wire"]
            assert replay.json() == resource["value"]
    assert len(synthetic_calls) == (0 if actual_cpu else 1)
