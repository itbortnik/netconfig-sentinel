"""Saved priority HTTP controls; synthetic workers never perform model or SDK execution."""

import json
from concurrent.futures import ThreadPoolExecutor
from uuid import UUID, uuid4

import pytest
from app.api.source_risk_contracts import CreateSourceRiskAssessment, SourceRiskAssessment
from app.db.source_records import SourceRecords
from app.db.source_risk_records import SourceRiskRecords
from app.main import create_app
from app.patching.source_risk import SourceRiskWorkflow
from fastapi.testclient import TestClient
from sqlalchemy import text
from test_source_deterministic_api import options as deterministic_options
from test_source_deterministic_api import post as save_deterministic
from test_source_deterministic_api import prepare as prepare_deterministic
from test_source_direction_api import directional_api as directional_api
from test_source_evidence_api import evidence_api as evidence_api
from test_source_ml_recheck_api import PIN
from test_source_ml_recheck_api import source_ml_api as source_ml_api
from test_source_patch_review_api import ANALYST, ENGINEER, HEADERS, READER


@pytest.fixture
def risk_api(directional_api, monkeypatch):
    # The imported fixtures configure only synthetic workers and isolated SQLite/PG schemas.
    # Unlike the original joint-report preparation helper, this fixture never trains Forest.
    monkeypatch.setattr(
        "sklearn.ensemble.IsolationForest.fit", lambda *a, **k: pytest.fail("unexpected model fit")
    )
    return directional_api


def prepare(risk_api, vendor="cisco", *, version="0.3.0", network="0.3.0", neural=False):
    client = risk_api[0]
    selected = prepare_deterministic(client, vendor)
    draft, before, _after, _analysis, reference, _selection = selected
    response = save_deterministic(client, selected, deterministic_options(selected))
    assert response.status_code == 201, response.text
    children = {"deterministic": response.json(), "forest": None, "neural": None, "network": None}
    base = f"/api/v2/patches/{draft['patch_id']}"
    if neural:
        response = client.post(
            base + "/ml-rechecks",
            headers=HEADERS,
            json={
                "recheck_id": str(uuid4()),
                "draft_sha256": draft["draft_sha256"],
                "model_sha256": PIN,
                "allow_local_model_context": True,
            },
        )
        assert response.status_code == 201, response.text
        children["neural"] = response.json()
    if network:
        response = client.post(
            base + "/verify",
            headers=HEADERS,
            json={
                "version": "source-patch-request-" + network,
                "verification_id": str(uuid4()),
                "draft_sha256": draft["draft_sha256"],
                "scope": {
                    "start_node": before["canonical"]["device"]["hostname"],
                    "destination": "192.0.2.1/32",
                },
                "companions": [],
                "allow_local_engine_upload": True,
            },
        )
        assert response.status_code == 201, response.text
        children["network"] = response.json()
    request = {
        "version": "source-evidence-request-" + version,
        "report_id": str(uuid4()),
        "draft_sha256": draft["draft_sha256"],
        **{
            kind: {
                "record_id": value.get("recheck_id", value.get("verification_id")),
                "review_sha256": value["review_sha256"],
            }
            if value
            else None
            for kind, value in children.items()
        },
    }
    response = client.post(base + "/evidence-reports", headers=HEADERS, json=request)
    assert response.status_code == 201, response.text
    return response.json(), reference, children


def options(report, **updates):
    return {
        "assessment_id": str(uuid4()),
        "report_sha256": report["review_sha256"],
        "profile_version": "source-priority-profile-0.1.0",
    } | updates


def url(report):
    return (
        f"/api/v2/patches/{report['patch_id']}/evidence-reports/"
        f"{report['report_id']}/risk-assessments"
    )


def post(client, report, body, *, headers=HEADERS):
    return client.post(url(report), headers=headers, json=body)


def get(client, report, body, *, headers=HEADERS):
    return client.get(url(report) + "/" + body["assessment_id"], headers=headers)


def counts(app):
    with app.state.analysis_service.store.engine.connect() as connection:
        return (
            connection.execute(text("SELECT count(*) FROM patch_risk_assessments")).scalar_one(),
            connection.execute(
                text(
                    "SELECT count(*) FROM audit_events WHERE action='patch.risk_assessment_created'"
                )
            ).scalar_one(),
        )


def block_execution(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("priority history read source/model/reference or executed a detector/worker")

    for path in (
        "app.db.store.Store.get_model",
        "app.db.store.Store.get_configuration",
        "app.detection.policy_engine.evaluate_policies",
        "app.patching.source_deterministic.recheck_original_deterministic",
        "app.patching.source_forest.recheck_original_forest",
        "app.patching.source_ml.run_configuration_pair_job",
        "app.patching.source_review.check_with_batfish",
        "app.patching.source_review.check_with_batfish_evidence",
        "app.patching.source_review.check_with_batfish_directional",
    ):
        monkeypatch.setattr(path, forbidden)
    monkeypatch.setattr(SourceRecords, "get", forbidden)


@pytest.mark.parametrize("vendor", ["cisco", "juniper"])
def test_full_history_without_originals_models_or_reference_preserves_first_role_and_report(
    risk_api, monkeypatch, vendor
):
    client, app, settings, neural_calls, network_calls, _ = risk_api
    report, reference, _ = prepare(risk_api, vendor, neural=True)
    assert len(neural_calls) == len(network_calls) == 1
    block_execution(monkeypatch)
    body = options(report)
    with app.state.analysis_service.store.engine.begin() as connection:
        connection.execute(text("DELETE FROM configuration_sources"))
        connection.execute(text("DELETE FROM models"))
        connection.execute(
            text("DELETE FROM configurations WHERE id=:id"), {"id": reference["configuration_id"]}
        )
    response = post(client, report, body, headers={"Authorization": f"Bearer {ENGINEER}"})
    assert response.status_code == 201, response.text
    record = SourceRiskAssessment.model_validate(response.json())
    assert record.service_role == "engineer" and record.composition.score == 0.95
    assert record.composition.components[-1].raw_score == 1
    assert not any((record.approved, record.applied, record.individual_identity_verified))
    operation = client.get(
        "/api/v1/operation-audit/" + response.headers["X-Operation-Id"], headers=HEADERS
    )
    assert operation.status_code == 200, operation.text
    audit = operation.json()
    assert audit["receipt"]["operation"] == "create_source_risk_assessment"
    assert body["assessment_id"] in audit["completion"]["result"]["resource_ids"]
    assert all(
        value not in operation.text
        for value in ("observation", "witnesses", "score_samples", "review_json", "confidence")
    )
    with TestClient(create_app(settings)) as restarted:
        assert post(restarted, report, body).json() == response.json()
        assert post(restarted, report, body).status_code == 200
        assert get(
            restarted, report, body, headers={"Authorization": f"Bearer {READER}"}
        ).json() == (response.json())
        listing = restarted.get(url(report), headers={"Authorization": f"Bearer {ANALYST}"})
        assert listing.status_code == 200, listing.text
        summary = listing.json()[0]
        assert summary["review_sha256"] == record.review_sha256
        assert summary["applicable_guardrails"] == ["observed_scoped_loss"]
        assert "composition" not in summary and "witnesses" not in listing.text
        original = restarted.get(url(report).removesuffix("/risk-assessments"), headers=HEADERS)
        assert original.status_code == 200 and original.json() == report
    assert counts(app) == (1, 1) and len(neural_calls) == len(network_calls) == 1


@pytest.mark.parametrize("kind", ["loss", "gain", "mixed", "none", "empty", "unknown", "not_run"])
def test_network_states_do_not_convert_missing_nonloss_evidence_into_zero_or_safety(risk_api, kind):
    client, app, *_rest, control = risk_api
    control["kind"] = kind
    report, _, _ = prepare(risk_api)
    response = post(client, report, options(report))
    assert response.status_code == 201, response.text
    component = response.json()["composition"]["components"][-1]
    assert (component["status"] == "completed") == (kind in {"loss", "mixed"})
    assert component["raw_score"] == (1 if kind in {"loss", "mixed"} else None)
    assert response.json()["composition"]["formal_qualification"] == "not_proven"
    assert counts(app) == (1, 1)


@pytest.mark.parametrize("version", ["0.1.0", "0.2.0", "0.3.0"])
def test_historical_parent_versions_are_accepted_without_rewriting_them(risk_api, version):
    client, app, *_ = risk_api
    report, _, _ = prepare(risk_api, version=version, network="")
    response = post(client, report, options(report))
    assert response.status_code == 201, response.text
    assert response.json()["report_version"] == "source-evidence-report-" + version
    assert response.json()["composition"]["components"][-1]["raw_score"] is None
    assert (
        client.get(url(report).removesuffix("/risk-assessments"), headers=HEADERS).json() == report
    )
    assert counts(app) == (1, 1)


@pytest.mark.parametrize("role", [READER, ANALYST])
def test_read_roles_cannot_create_even_malformed_body(risk_api, role):
    client, app, *_ = risk_api
    report, _, _ = prepare(risk_api, network="")
    body = options(report)
    assert post(client, report, body).status_code == 201
    headers = {"Authorization": f"Bearer {role}"}
    assert client.post(url(report), headers=headers, content=b"x" * 20_000).status_code == 403
    assert get(client, report, body, headers=headers).status_code == 200
    assert client.get(url(report), headers=headers).status_code == 200
    assert counts(app) == (1, 1)


@pytest.mark.parametrize(
    "change",
    [
        {"profile_version": "client-choice"},
        {"version": "source-risk-request-0.2.0"},
        {"weights": {"policy": 1}},
        {"service_role": "admin"},
        {"approved": False},
        {"report_sha256": "F" * 64},
    ],
)
def test_invalid_or_client_owned_fields_never_write(risk_api, change):
    client, app, *_ = risk_api
    report, _, _ = prepare(risk_api, network="")
    assert post(client, report, options(report, **change)).status_code == 400
    body = options(report)
    body.pop("profile_version")
    assert post(client, report, body).status_code == 400
    assert counts(app) == (0, 0)


def test_wrong_pin_route_uuid_and_missing_parent_have_distinct_results(risk_api):
    client, app, *_ = risk_api
    report, _, _ = prepare(risk_api, network="")
    body = options(report)
    assert post(client, report, body | {"report_sha256": "f" * 64}).status_code == 409
    assert post(client, report | {"patch_id": str(uuid4())}, body).status_code == 409
    assert post(client, report | {"report_id": str(uuid4())}, body).status_code == 404
    assert counts(app) == (0, 0)
    response = post(client, report, body)
    assert response.status_code == 201
    assert post(client, report, body | {"report_sha256": "f" * 64}).status_code == 409
    assert post(client, report | {"report_id": str(uuid4())}, body).status_code == 409
    assert get(client, report | {"patch_id": str(uuid4())}, body).status_code == 404
    assert get(client, report, body | {"assessment_id": str(uuid4())}).status_code == 404
    assert get(client, report, body).json() == response.json() and counts(app) == (1, 1)


def test_duplicate_keys_and_input_and_projection_budgets_are_bounded(risk_api, monkeypatch):
    client, app, *_ = risk_api
    report, _, _ = prepare(risk_api, network="")
    body = options(report)
    duplicate = json.dumps(body)[:-1] + ',"profile_version":"source-priority-profile-0.1.0"}'
    headers = HEADERS | {"Content-Type": "application/json"}
    assert client.post(url(report), headers=headers, content=duplicate).status_code == 400
    assert client.post(url(report), headers=headers, content=b" " * 16385).status_code == 413
    monkeypatch.setattr("app.api.source_risk_contracts.MAX_SOURCE_RISK_PROOF_BYTES", 16)
    assert post(client, report, body).status_code == 413
    assert counts(app) == (0, 0)


def test_domain_audit_failure_rolls_back_assessment(risk_api, monkeypatch):
    client, app, *_ = risk_api
    report, _, _ = prepare(risk_api, network="")

    def fail(*args):
        raise RuntimeError("owned-private-failure")

    monkeypatch.setattr(SourceRiskRecords, "_audit", staticmethod(fail))
    response = post(client, report, options(report))
    assert response.status_code == 500 and "owned-private-failure" not in response.text
    assert counts(app) == (0, 0)


def test_lost_operation_completion_recovers_committed_assessment_without_new_uuid(
    risk_api, monkeypatch
):
    client, app, *_ = risk_api
    report, _, _ = prepare(risk_api, network="")
    body = options(report)
    journal = app.state.operation_journal
    original = journal.complete

    def fail(receipt, completion):
        if receipt.operation == "create_source_risk_assessment":
            raise RuntimeError("owned-response-failure")
        return original(receipt, completion)

    monkeypatch.setattr(journal, "complete", fail)
    assert post(client, report, body).status_code == 503 and counts(app) == (1, 1)
    assert get(client, report, body).status_code == 200
    assert post(client, report, body).status_code == 503 and counts(app) == (1, 1)


def test_concurrent_same_uuid_has_one_audited_winner(risk_api):
    _client, app, *_ = risk_api
    report, _, _ = prepare(risk_api, network="")
    body = CreateSourceRiskAssessment.model_validate(options(report))
    workflow = SourceRiskWorkflow(app.state.analysis_service.store)
    with ThreadPoolExecutor(max_workers=2) as pool:
        records = list(
            pool.map(
                lambda role: workflow.create(
                    UUID(report["patch_id"]), UUID(report["report_id"]), body, role
                ),
                ("engineer", "admin"),
            )
        )
    assert sorted(created for _, created in records) == [False, True]
    assert records[0][0] == records[1][0] and counts(app) == (1, 1)


def test_append_only_collection_paginates_stably_and_bounds_parameters(risk_api):
    client, app, *_ = risk_api
    report, _, _ = prepare(risk_api, network="")
    ids = []
    for _ in range(3):
        body = options(report)
        assert post(client, report, body).status_code == 201
        ids.append(body["assessment_id"])
    first = client.get(url(report) + "?limit=2", headers=HEADERS)
    last = client.get(url(report) + "?limit=2&offset=2", headers=HEADERS)
    assert [row["assessment_id"] for row in first.json() + last.json()] == list(reversed(ids))
    assert client.get(url(report) + "?limit=101", headers=HEADERS).status_code == 422
    assert client.get(url(report) + "?offset=-1", headers=HEADERS).status_code == 422
    assert client.get(url(report | {"patch_id": str(uuid4())}), headers=HEADERS).status_code == 404
    assert counts(app) == (3, 3)
