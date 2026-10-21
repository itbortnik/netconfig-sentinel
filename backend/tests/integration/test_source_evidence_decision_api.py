"""Actual disposition HTTP/storage flow; authored fixtures do not verify human identity."""

import json
from concurrent.futures import ThreadPoolExecutor
from uuid import UUID, uuid4

import pytest
from app.api.source_evidence_decision_contracts import (
    ReviewSourceEvidenceReport,
    SourceEvidenceDecision,
)
from app.db.source_evidence_decision_records import SourceEvidenceDecisionRecords
from app.db.source_records import SourceRecords
from app.main import create_app
from app.patching.source_evidence_decision import SourceEvidenceDecisionWorkflow
from fastapi.testclient import TestClient
from sqlalchemy import text
from test_source_evidence_api import evidence_api as evidence_api
from test_source_evidence_api import options as report_options
from test_source_evidence_api import post as save_report
from test_source_evidence_api import prepare as prepare_inputs
from test_source_ml_recheck_api import source_ml_api as source_ml_api
from test_source_patch_review_api import ANALYST, ENGINEER, HEADERS, READER

COMMENT = "Authored role disposition: request the missing scoped evidence and individual review."


def prepare(client, vendor="cisco", *, include=()):
    inputs = prepare_inputs(client, vendor, include=include)
    response = save_report(client, inputs, report_options(inputs))
    assert response.status_code == 201, response.text
    return response.json()


def options(report, **updates):
    return {
        "decision_id": str(uuid4()),
        "report_sha256": report["review_sha256"],
        "verdict": "needs_more_information",
        "comment": COMMENT,
    } | updates


def url(report):
    return f"/api/v2/patches/{report['patch_id']}/evidence-reports/{report['report_id']}/decisions"


def post(client, report, body, *, headers=HEADERS):
    return client.post(url(report), headers=headers, json=body)


def get(client, report, body, *, headers=HEADERS):
    return client.get(url(report) + "/" + body["decision_id"], headers=headers)


def counts(app):
    with app.state.analysis_service.store.engine.connect() as connection:
        return (
            connection.execute(text("SELECT count(*) FROM patch_evidence_decisions")).scalar_one(),
            connection.execute(
                text(
                    "SELECT count(*) FROM audit_events "
                    "WHERE action='patch.evidence_decision_recorded'"
                )
            ).scalar_one(),
        )


@pytest.mark.parametrize("vendor", ["cisco", "juniper"])
@pytest.mark.parametrize("verdict", ["rejected", "needs_more_information"])
def test_actual_saved_disposition_is_pure_and_replays_original_role_after_restart(
    evidence_api, monkeypatch, vendor, verdict
):
    client, app, settings, neural_calls, network_calls, _control = evidence_api
    report = prepare(client, vendor, include=("forest", "neural", "network"))
    assert len(neural_calls) == len(network_calls) == 1

    def forbidden(*args, **kwargs):
        pytest.fail("disposition or history executed a model/engine/detector or read raw/model")

    monkeypatch.setattr(SourceRecords, "get", forbidden)
    monkeypatch.setattr("app.db.store.Store.get_model", forbidden)
    monkeypatch.setattr(
        "app.patching.source_deterministic.recheck_original_deterministic", forbidden
    )
    monkeypatch.setattr("app.patching.source_forest.recheck_original_forest", forbidden)
    monkeypatch.setattr("app.patching.source_ml.run_configuration_pair_job", forbidden)
    monkeypatch.setattr("app.patching.source_review.check_with_batfish", forbidden)
    body = options(report, verdict=verdict)
    response = post(client, report, body, headers={"Authorization": f"Bearer {ENGINEER}"})
    assert response.status_code == 201, response.text
    view = SourceEvidenceDecision.model_validate(response.json())
    assert view.service_role == "engineer" and view.request.verdict == verdict
    assert not any((view.approved, view.applied, view.individual_identity_verified))
    assert view.report_sha256 == report["review_sha256"]
    assert view.before.model_dump(mode="json") == report["before"]
    assert view.after.model_dump(mode="json") == report["after"]
    audit = client.get(
        "/api/v1/operation-audit/" + response.headers["X-Operation-Id"], headers=HEADERS
    )
    assert audit.status_code == 200, audit.text
    operation = audit.json()
    assert operation["receipt"]["operation"] == "record_source_evidence_decision"
    assert body["decision_id"] in operation["completion"]["result"]["resource_ids"]
    assert all(value not in audit.text for value in (COMMENT, "comment", "anomaly_score", "scores"))
    assert counts(app) == (1, 1)
    with app.state.analysis_service.store.engine.begin() as connection:
        connection.execute(text("DELETE FROM configuration_sources"))
        connection.execute(text("DELETE FROM models"))
    with TestClient(create_app(settings)) as restarted:
        replay = post(restarted, report, body)
        assert replay.status_code == 200 and replay.json() == response.json()
        read = get(restarted, report, body, headers={"Authorization": f"Bearer {READER}"})
        assert read.status_code == 200 and read.json() == response.json()
        listing = restarted.get(url(report), headers={"Authorization": f"Bearer {ANALYST}"})
        assert listing.status_code == 200 and len(listing.json()) == 1
        summary = listing.json()[0]
        assert (
            summary["service_role"] == "engineer"
            and summary["decision_sha256"] == view.decision_sha256
        )
        assert "comment" not in listing.text and "decision_json" not in summary
        parent = restarted.get(url(report).removesuffix("/decisions"), headers=HEADERS)
        assert parent.status_code == 200 and parent.json() == report
    assert counts(app) == (1, 1) and len(neural_calls) == len(network_calls) == 1


@pytest.mark.parametrize("role", [READER, ANALYST])
def test_read_roles_cannot_post_even_invalid_body_but_can_read_decisions(evidence_api, role):
    client, app, *_ = evidence_api
    report = prepare(client)
    body = options(report)
    saved = post(client, report, body)
    assert saved.status_code == 201, saved.text
    headers = {"Authorization": f"Bearer {role}"}
    denied = client.post(url(report), headers=headers, content=b"{" + b"x" * 20_000)
    assert denied.status_code == 403 and counts(app) == (1, 1)
    assert get(client, report, body, headers=headers).status_code == 200
    assert client.get(url(report), headers=headers).status_code == 200
    assert post(client, report, body, headers=headers).status_code == 403


@pytest.mark.parametrize(
    "updates",
    [
        {"verdict": "approved"},
        {"comment": ""},
        {"comment": " \n\t"},
        {"comment": "x" * 1201},
        {"comment": "x\x00"},
        {"service_role": "engineer"},
        {"individual_identity_verified": True},
        {"applied": False},
        {"report_sha256": "F" * 64},
    ],
)
def test_invalid_disposition_body_never_creates_a_domain_record(evidence_api, updates):
    client, app, *_ = evidence_api
    report = prepare(client)
    response = post(client, report, options(report, **updates))
    assert response.status_code == 400 and counts(app) == (0, 0)


def test_unicode_comment_uses_python_codepoints_and_remains_literal_text(evidence_api):
    client, app, *_ = evidence_api
    report = prepare(client)
    comment = "😀" * 1200
    response = post(client, report, options(report, comment=comment))
    assert response.status_code == 201, response.text
    assert response.json()["request"]["comment"] == comment
    literal = '<img src=x onerror="alert(1)">'
    body = options(report, verdict="rejected", comment=literal)
    response = post(client, report, body)
    assert (
        response.status_code == 201
        and get(client, report, body).json()["request"]["comment"] == literal
    )
    assert counts(app) == (2, 2)


def test_report_hash_and_foreign_route_parent_cannot_be_substituted(evidence_api):
    client, app, *_ = evidence_api
    report = prepare(client)
    other = prepare(client, "juniper")
    assert post(client, report, options(other)).status_code == 409
    assert post(client, report | {"patch_id": str(uuid4())}, options(report)).status_code == 409
    assert post(client, report | {"report_id": str(uuid4())}, options(report)).status_code == 404
    assert counts(app) == (0, 0)


@pytest.mark.parametrize(
    "change",
    [{"comment": "Different intent"}, {"verdict": "rejected"}, {"report_sha256": "f" * 64}],
)
def test_changed_same_uuid_conflicts_without_replacing_original(evidence_api, change):
    client, app, *_ = evidence_api
    report = prepare(client)
    body = options(report)
    original = post(client, report, body)
    assert original.status_code == 201, original.text
    assert post(client, report, body | change).status_code == 409
    assert get(client, report, body).json() == original.json() and counts(app) == (1, 1)


def test_append_only_history_paginates_without_promoting_latest_verdict(evidence_api):
    client, app, *_ = evidence_api
    report = prepare(client)
    ids = []
    for index in range(21):
        body = options(report, verdict="rejected" if index % 2 else "needs_more_information")
        response = post(client, report, body)
        assert response.status_code == 201, response.text
        ids.append(body["decision_id"])
    first = client.get(url(report), headers=HEADERS).json()
    last = client.get(url(report) + "?offset=20", headers=HEADERS).json()
    assert [row["decision_id"] for row in first + last] == list(reversed(ids))
    assert len(first) == 20 and len(last) == 1 and counts(app) == (21, 21)
    assert client.get(url(report).removesuffix("/decisions"), headers=HEADERS).json() == report


def test_duplicate_keys_request_and_proof_budgets_refuse_before_domain_write(
    evidence_api, monkeypatch
):
    client, app, *_ = evidence_api
    report = prepare(client)
    body = options(report)
    headers = HEADERS | {"Content-Type": "application/json"}
    duplicate = json.dumps(body)[:-1] + ',"verdict":"rejected"}'
    assert client.post(url(report), headers=headers, content=duplicate).status_code == 400
    assert client.post(url(report), headers=headers, content=b" " * 16385).status_code == 413
    monkeypatch.setattr(
        "app.api.source_evidence_decision_contracts.MAX_SOURCE_EVIDENCE_DECISION_BYTES", 16
    )
    assert post(client, report, body).status_code == 413 and counts(app) == (0, 0)


def test_domain_audit_failure_rolls_back_decision_atomically(evidence_api, monkeypatch):
    client, app, *_ = evidence_api
    report = prepare(client)

    def fail(*args):
        raise RuntimeError("owned audit failure")

    monkeypatch.setattr(SourceEvidenceDecisionRecords, "_audit", staticmethod(fail))
    response = post(client, report, options(report))
    assert response.status_code == 500 and counts(app) == (0, 0)
    assert "owned audit failure" not in response.text


def test_lost_operation_completion_recovers_committed_decision_by_get(evidence_api, monkeypatch):
    client, app, *_ = evidence_api
    report = prepare(client)
    body = options(report)
    journal = app.state.operation_journal
    original = journal.complete

    def fail(receipt, completion):
        if receipt.operation == "record_source_evidence_decision":
            raise RuntimeError("owned response failure")
        return original(receipt, completion)

    monkeypatch.setattr(journal, "complete", fail)
    assert post(client, report, body).status_code == 503 and counts(app) == (1, 1)
    response = get(client, report, body)
    assert response.status_code == 200 and response.json()["decision_id"] == body["decision_id"]


def test_concurrent_same_intent_has_one_immutable_winner(evidence_api):
    client, app, *_ = evidence_api
    report = prepare(client)
    body = ReviewSourceEvidenceReport.model_validate(options(report))
    workflow = SourceEvidenceDecisionWorkflow(app.state.analysis_service.store)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(
            pool.map(
                lambda _: workflow.create(
                    UUID(report["patch_id"]), UUID(report["report_id"]), body, "engineer"
                ),
                range(2),
            )
        )
    assert sorted(created for _view, created in results) == [False, True]
    assert results[0][0] == results[1][0] and counts(app) == (1, 1)


def test_foreign_decision_route_is_not_exposed_and_missing_parent_has_no_history(evidence_api):
    client, app, *_ = evidence_api
    report = prepare(client)
    other = prepare(client, "juniper")
    body = options(report)
    assert post(client, report, body).status_code == 201
    assert get(client, other, body).status_code == 404
    assert post(client, other, body).status_code == 409
    assert client.get(url(report | {"patch_id": str(uuid4())}), headers=HEADERS).status_code == 404
    assert get(client, report, body | {"decision_id": str(uuid4())}).status_code == 404
    assert counts(app) == (1, 1)


def test_corrupt_parent_or_decision_is_unavailable_without_leaking_contents(evidence_api):
    client, app, *_ = evidence_api
    report = prepare(client)
    body = options(report)
    assert post(client, report, body).status_code == 201
    with app.state.analysis_service.store.engine.begin() as connection:
        connection.execute(
            text("UPDATE patch_evidence_decisions SET payload='invalid-private-value'")
        )
    for response in (
        get(client, report, body),
        client.get(url(report), headers=HEADERS),
        post(client, report, body),
    ):
        assert response.status_code == 503
        assert "invalid-private-value" not in response.text and COMMENT not in response.text
    assert counts(app) == (1, 1)
