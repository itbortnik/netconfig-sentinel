"""Synthetic ingress HTTP/storage controls; real engines, inference and model fits are forbidden."""

from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
from uuid import UUID, uuid4

import app.patching.source_review as network_module
import pytest
from app.api.source_ml_contracts import ml_json
from app.api.source_risk_scope_contracts import CreateSourceRiskAssessmentV2
from app.db.source_risk_records import SourceRiskRecords
from app.db.tables import SourceEvidenceReportRow, SourceRiskAssessmentRow
from app.main import create_app
from app.patching.source_risk import SourceRiskWorkflow
from app.verification.batfish import BatfishResult
from app.verification.ingress_scope import (
    BatfishScopeExecution,
    IngressScopeObservation,
    empty_ingress_scope,
)
from app.verification.ingress_scope_worker import canonical_id, derived_fields, location_rendering
from fastapi.testclient import TestClient
from sqlalchemy import text
from test_source_direction_api import directional_api as directional_api
from test_source_evidence_api import evidence_api as evidence_api
from test_source_ml_recheck_api import source_ml_api as source_ml_api
from test_source_patch_review_api import ANALYST, ENGINEER, HEADERS, READER
from test_source_risk_api import block_execution, counts, options, post, prepare, url
from test_source_risk_api import risk_api as risk_api


@pytest.fixture
def scope_api(risk_api, monkeypatch):
    control = risk_api[-1]
    control["scope"] = "observed"
    directional = network_module.check_with_batfish_directional

    def worker(before, after, scope, **kwargs):
        execution = directional(before, after, scope, **kwargs)
        result = BatfishResult.model_validate(
            execution.result.model_dump()
            | {
                "network_name": "sentinel-" + "a" * 32,
            }
        )
        if control["scope"] == "unknown":
            ingress = empty_ingress_scope(
                before.digest,
                after.digest,
                scope,
                result.network_name,
                state="unknown",
                reason="query_failed",
            )
        else:
            node, interface, opaque = (
                scope.start_node,
                "GigabitEthernet0/0",
                "owned-opaque-IP-space",
            )
            row = dict(
                node=node,
                interface=interface,
                canonical_id_sha256=canonical_id(node, interface),
                location_rendering=location_rendering(node, interface),
                active=True,
                switchport=False,
                interface_type="PHYSICAL",
                concrete_ipv4_prefixes=["192.0.2.1/24"],
                eligible=True,
                eligibility_reason="active_concrete_ipv4",
                source_ip_rendering=opaque,
                source_ip_sha256=sha256(opaque.encode()).hexdigest(),
            )
            old, new = {"interfaces": [row]}, {"interfaces": [row]}
            ingress = IngressScopeObservation.model_validate(
                dict(
                    before_sha256=before.digest,
                    after_sha256=after.digest,
                    scope=scope.model_dump(mode="json"),
                    network_name=result.network_name,
                    acquisition_state="observed",
                    reason="query_completed",
                    before=old,
                    after=new,
                )
                | derived_fields(old, new)
            )
        return BatfishScopeExecution(
            result=result,
            sdk_version=execution.sdk_version,
            sdk_observation=execution.sdk_observation,
            reachability_impact=execution.reachability_impact,
            ingress_scope=ingress,
        )

    monkeypatch.setattr(network_module, "check_with_batfish_scope_evidence", worker)
    return risk_api


def new_report(scope_api, vendor="cisco"):
    return prepare(scope_api, vendor, version="0.4.0", network="0.4.0")


def new_options(report):
    return options(report, version="source-risk-request-0.2.0")


def report_url(report):
    return url(report).removesuffix("/risk-assessments")


def decision_body(report):
    return dict(
        version="source-evidence-decision-request-0.4.0",
        decision_id=str(uuid4()),
        report_sha256=report["review_sha256"],
        verdict="needs_more_information",
        comment="Owned synthetic scope evidence; individual review required.",
    )


def reseal(body):
    proof = ml_json({k: v for k, v in body.items() if k not in {"review_json", "review_sha256"}})
    return body | {"review_json": proof, "review_sha256": sha256(proof.encode()).hexdigest()}


@pytest.mark.parametrize("vendor", ["cisco", "juniper"])
@pytest.mark.parametrize("scope_state", ["observed", "unknown"])
def test_complete_saved_chain_restarts_without_sources_models_reference_or_worker(
    scope_api, monkeypatch, vendor, scope_state
):
    client, app, settings, neural_calls, calls, control = scope_api
    control["scope"] = scope_state
    report, reference, children = new_report(scope_api, vendor)
    network = children["network"]
    ingress = network["outcome"]["network_execution"]["ingress_scope"]
    assert report["network"]["ingress_scope"] == ingress
    assert len(calls) == 1 and not neural_calls
    body = new_options(report)
    engineer = {"Authorization": f"Bearer {ENGINEER}"}
    saved = post(client, report, body, headers=engineer)
    assert saved.status_code == 201, saved.text
    risk = saved.json()
    assert risk["composition"]["score"] == 0.95
    assert (
        risk["composition"]["components"][-1]["observation"]["execution"]["ingress_scope"]
        == ingress
    )
    decision_request = decision_body(report)
    decision = client.post(
        report_url(report) + "/decisions", headers=engineer, json=decision_request
    )
    assert decision.status_code == 201, decision.text
    block_execution(monkeypatch)
    monkeypatch.setattr(
        network_module,
        "check_with_batfish_scope_evidence",
        lambda *a, **k: pytest.fail("scope rerun"),
    )
    with app.state.analysis_service.store.engine.begin() as connection:
        connection.execute(text("DELETE FROM configuration_sources"))
        connection.execute(text("DELETE FROM models"))
        connection.execute(
            text("DELETE FROM configurations WHERE id=:id"), {"id": reference["configuration_id"]}
        )
    with TestClient(create_app(settings)) as restarted:
        base = f"/api/v2/patches/{report['patch_id']}"
        assert (
            restarted.get(
                base + "/verifications/" + network["verification_id"], headers=HEADERS
            ).json()
            == network
        )
        assert (
            restarted.post(
                base + "/verify", headers=HEADERS, json=network["intent"]["request"]
            ).json()
            == network
        )
        assert restarted.get(report_url(report), headers=HEADERS).json() == report
        assert (
            restarted.post(
                base + "/evidence-reports", headers=HEADERS, json=report["request"]
            ).json()
            == report
        )
        assert post(restarted, report, body).json() == risk
        assert post(restarted, report, body).status_code == 200
        assert (
            restarted.get(url(report) + "/" + body["assessment_id"], headers=HEADERS).json() == risk
        )
        assert (
            restarted.post(
                report_url(report) + "/decisions", headers=HEADERS, json=decision_request
            ).json()
            == decision.json()
        )
        for path, version in [
            (base + "/verifications", "source-patch-verification-summary-0.4.0"),
            (base + "/evidence-reports", "source-evidence-summary-0.4.0"),
            (report_url(report) + "/decisions", "source-evidence-decision-summary-0.4.0"),
            (url(report), "source-risk-summary-0.2.0"),
        ]:
            response = restarted.get(path, headers=HEADERS)
            assert response.status_code == 200, response.text
            assert response.json()[0]["version"] == version
    assert counts(app) == (1, 1) and len(calls) == 1 and not neural_calls


@pytest.mark.parametrize("role", [READER, ANALYST])
def test_read_roles_denied_before_new_body_parsing(scope_api, role):
    client = scope_api[0]
    report, _, _ = new_report(scope_api)
    base = f"/api/v2/patches/{report['patch_id']}"
    headers = {"Authorization": f"Bearer {role}"}
    for path in [
        base + "/verify",
        base + "/evidence-reports",
        report_url(report) + "/decisions",
        url(report),
    ]:
        assert client.post(path, headers=headers, content=b"x" * 20000).status_code == 403


def test_mixed_protocols_conflict_without_new_records(scope_api):
    client, app, *_ = scope_api
    report, _, _ = new_report(scope_api)
    base = f"/api/v2/patches/{report['patch_id']}"
    for version in ["0.1.0", "0.2.0", "0.3.0"]:
        request = report["request"] | {
            "report_id": str(uuid4()),
            "version": "source-evidence-request-" + version,
        }
        assert (
            client.post(base + "/evidence-reports", headers=HEADERS, json=request).status_code
            == 409
        )
        request = decision_body(report) | {"version": "source-evidence-decision-request-" + version}
        assert (
            client.post(
                report_url(report) + "/decisions", headers=HEADERS, json=request
            ).status_code
            == 409
        )
    assert post(client, report, options(report)).status_code == 409
    old, _, _ = prepare(scope_api, network="", version="0.3.0")
    assert post(client, old, new_options(old)).status_code == 409
    assert counts(app) == (0, 0)


@pytest.mark.parametrize("target", ["report", "risk"])
def test_resealed_valid_false_scope_fails_against_full_chain(scope_api, target):
    client, app, *_ = scope_api
    report, _, _ = new_report(scope_api)
    body = new_options(report)
    response = post(client, report, body)
    assert response.status_code == 201
    risk = response.json()
    record = report if target == "report" else risk
    scope = (
        record["network"]["ingress_scope"]
        if target == "report"
        else record["composition"]["components"][-1]["observation"]["execution"]["ingress_scope"]
    )
    row = scope["after"]["interfaces"][0]
    row["active"], row["eligible"], row["eligibility_reason"] = False, False, "inactive"
    scope.update(derived_fields(scope["before"], scope["after"]))
    kind, cls, key = (
        ("source_evidence_report", SourceEvidenceReportRow, report["report_id"])
        if target == "report"
        else ("source_risk_assessment", SourceRiskAssessmentRow, body["assessment_id"])
    )
    store = app.state.analysis_service.store
    with store._sessions.begin() as session:
        row = session.get(cls, key)
        row.payload = store._encode(ml_json(reseal(record)), kind=kind, row_id=key)
    assert client.get(url(report) + "/" + body["assessment_id"], headers=HEADERS).status_code == 503
    if target == "report":
        assert client.get(report_url(report), headers=HEADERS).status_code == 503
    else:
        assert client.get(report_url(report), headers=HEADERS).status_code == 200


def test_v2_atomic_audit_and_same_id_race_preserve_winner(scope_api, monkeypatch):
    client, app, *_ = scope_api
    report, _, _ = new_report(scope_api)
    body = new_options(report)
    original = SourceRiskRecords._audit
    monkeypatch.setattr(
        SourceRiskRecords,
        "_audit",
        staticmethod(lambda *a: (_ for _ in ()).throw(RuntimeError("private-failure"))),
    )
    assert post(client, report, body).status_code == 500
    assert counts(app) == (0, 0)
    monkeypatch.setattr(SourceRiskRecords, "_audit", staticmethod(original))
    workflow = SourceRiskWorkflow(app.state.analysis_service.store)
    request = CreateSourceRiskAssessmentV2.model_validate(body)
    with ThreadPoolExecutor(max_workers=2) as pool:
        records = list(
            pool.map(
                lambda role: workflow.create(
                    UUID(report["patch_id"]), UUID(report["report_id"]), request, role
                ),
                ("engineer", "admin"),
            )
        )
    assert sorted(created for _, created in records) == [False, True]
    assert records[0][0] == records[1][0] and counts(app) == (1, 1)
