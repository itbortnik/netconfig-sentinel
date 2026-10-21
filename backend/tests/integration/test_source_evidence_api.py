"""Actual report HTTP flow; neural/network fixtures are explicitly synthetic controls."""

import json
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from uuid import UUID, uuid4

import app.patching.source_deterministic as deterministic_module
import app.patching.source_review as network_module
import pytest
from app.api.source_deterministic_contracts import SourceDeterministicIntent
from app.api.source_evidence_contracts import CreateSourceEvidenceReport, SourceEvidenceReport
from app.core.patch_verification import PatchVerificationSettings
from app.db.source_deterministic_records import SourceDeterministicRecords
from app.db.source_evidence_records import SourceEvidenceRecords
from app.db.source_records import SourceRecords
from app.main import create_app
from app.patching.source_evidence import SourceEvidenceWorkflow
from app.verification.batfish import BatfishResult
from fastapi.testclient import TestClient
from sqlalchemy import text
from test_source_forest_api import prepare as prepare_forest
from test_source_ml_recheck_api import PIN
from test_source_ml_recheck_api import source_ml_api as source_ml_api
from test_source_patch_review_api import ANALYST, ENGINEER, HEADERS, READER


@pytest.fixture
def evidence_api(source_ml_api, monkeypatch):
    client, application, settings, neural_calls = source_ml_api
    application.state.patch_verification.settings = PatchVerificationSettings(
        allow_engine_upload=True
    )
    network_calls = []
    control = {"status": "no_differences_in_scope"}

    def worker(before, after, scope, **kwargs):
        network_calls.append(scope)
        status = control["status"]
        queried = status in {"no_differences_in_scope", "differences_found", "inconclusive"}
        return BatfishResult(
            before_sha256=before.digest,
            after_sha256=after.digest,
            scope=scope,
            status=status,
            reason=(
                "empty_reachable_scope"
                if status == "inconclusive"
                else "query_completed"
                if queried
                else "timeout"
            ),
            engine_version="owned-evidence-fixture" if queried else None,
            cleanup_complete=True if queried else None,
            difference_count=(1 if status == "differences_found" else 0) if queried else None,
            before_reachable_count=(0 if status == "inconclusive" else 1) if queried else None,
            after_reachable_count=(1 if status == "no_differences_in_scope" else 0)
            if queried
            else None,
        )

    monkeypatch.setattr(network_module, "check_with_batfish", worker)
    yield client, application, settings, neural_calls, network_calls, control


def prepare(client, vendor="cisco", *, include=("forest", "neural", "network")):
    selected = prepare_forest(client, vendor)
    draft, before, after, analysis, model, _selection = selected
    base = f"/api/v2/patches/{draft['patch_id']}"
    response = client.get(
        base + "/deterministic-selection/" + analysis["analysis_id"], headers=HEADERS
    )
    assert response.status_code == 200, response.text
    original = response.json()
    response = client.post(
        base + "/deterministic-rechecks",
        headers=HEADERS,
        json={
            "recheck_id": str(uuid4()),
            "draft_sha256": draft["draft_sha256"],
            "before_analysis_id": analysis["analysis_id"],
            "before_analysis_sha256": original["before_analysis_sha256"],
            "reference_canonical_sha256": None,
            "allow_local_analysis_context": True,
        },
    )
    assert response.status_code == 201, response.text
    results = {"deterministic": response.json(), "forest": None, "neural": None, "network": None}
    requests = {
        "forest": (
            "statistical-rechecks",
            {
                "recheck_id": str(uuid4()),
                "draft_sha256": draft["draft_sha256"],
                "before_analysis_id": analysis["analysis_id"],
                "before_analysis_sha256": original["before_analysis_sha256"],
                "model_id": model["model_id"],
                "artifact_sha256": model["artifact_sha256"],
                "allow_local_model_context": True,
            },
        ),
        "neural": (
            "ml-rechecks",
            {
                "recheck_id": str(uuid4()),
                "draft_sha256": draft["draft_sha256"],
                "model_sha256": PIN,
                "allow_local_model_context": True,
            },
        ),
        "network": (
            "verify",
            {
                "verification_id": str(uuid4()),
                "draft_sha256": draft["draft_sha256"],
                "scope": {
                    "start_node": before["canonical"]["device"]["hostname"],
                    "destination": "192.0.2.1/32",
                },
                "companions": [],
                "allow_local_engine_upload": True,
            },
        ),
    }
    for kind in include:
        path, body = requests[kind]
        response = client.post(base + "/" + path, headers=HEADERS, json=body)
        assert response.status_code == 201, response.text
        results[kind] = response.json()
        assert results[kind]["execution_status"] == "completed"
    return draft, results, before, after


def options(selected, **updates):
    draft, records, *_ = selected
    return {
        "report_id": str(uuid4()),
        "draft_sha256": draft["draft_sha256"],
        **{
            kind: {
                "record_id": row.get("recheck_id", row.get("verification_id")),
                "review_sha256": row["review_sha256"],
            }
            if row
            else None
            for kind, row in records.items()
        },
    } | updates


def post(client, selected, body, *, headers=HEADERS):
    return client.post(
        f"/api/v2/patches/{selected[0]['patch_id']}/evidence-reports", headers=headers, json=body
    )


def get(client, selected, body, *, headers=HEADERS):
    return client.get(
        f"/api/v2/patches/{selected[0]['patch_id']}/evidence-reports/{body['report_id']}",
        headers=headers,
    )


def counts(application):
    with application.state.analysis_service.store.engine.connect() as connection:
        return connection.execute(text("SELECT count(*) FROM patch_evidence_reports")).scalar_one()


@pytest.mark.parametrize("vendor", ["cisco", "juniper"])
def test_actual_http_saved_composition_and_disabled_restart_never_execute(
    evidence_api, monkeypatch, vendor
):
    client, application, settings, neural_calls, network_calls, _control = evidence_api
    selected = prepare(client, vendor)
    assert len(neural_calls) == len(network_calls) == 1

    def forbidden(*args, **kwargs):
        pytest.fail(
            "report composition or history executed a detector/model/engine or read original"
        )

    monkeypatch.setattr(SourceRecords, "get", forbidden)
    monkeypatch.setattr(application.state.analysis_service.store, "get_model", forbidden)
    monkeypatch.setattr("app.detection.policy_engine.evaluate_policies", forbidden)
    monkeypatch.setattr(deterministic_module, "recheck_original_deterministic", forbidden)
    monkeypatch.setattr(network_module, "check_with_batfish", forbidden)
    monkeypatch.setattr("app.patching.source_ml.run_configuration_pair_job", forbidden)
    monkeypatch.setattr("app.patching.source_forest.recheck_original_forest", forbidden)
    body = options(selected)
    response = post(client, selected, body, headers={"Authorization": f"Bearer {ENGINEER}"})
    assert response.status_code == 201, response.text
    view = SourceEvidenceReport.model_validate(response.json())
    assert view.status == "needs_review" and view.formal_qualification == "not_proven"
    assert not any(
        (view.approved, view.applied, view.quality_proven, view.calibrated, view.risk_fused)
    )
    assert view.network.ml_status == "not_run" and view.network.sdk_version is None
    assert (
        view.forest.scores.before_score_samples
        == selected[1]["forest"]["outcome"]["report"]["scores"]["before_score_samples"]
    )
    assert (
        view.neural.before.anomaly_score
        == selected[1]["neural"]["outcome"]["report"]["before"]["prediction"]["anomaly_score"]
    )
    assert counts(application) == 1 and len(neural_calls) == len(network_calls) == 1
    audit = client.get(
        f"/api/v1/operation-audit/{response.headers['X-Operation-Id']}", headers=HEADERS
    )
    assert audit.status_code == 200, audit.text
    operation = audit.json()
    assert operation["receipt"]["operation"] == "create_source_evidence_report"
    assert body["report_id"] in operation["completion"]["result"]["resource_ids"]
    assert all(
        value not in audit.text
        for value in (
            "anomaly_score",
            "score_samples",
            "owned-target",
            "observed",
            "category_scores",
        )
    )
    with application.state.analysis_service.store.engine.begin() as connection:
        connection.execute(text("DELETE FROM configuration_sources"))
        connection.execute(text("DELETE FROM models"))
    with TestClient(create_app(settings)) as restarted:
        assert (
            get(restarted, selected, body, headers={"Authorization": f"Bearer {READER}"}).json()
            == response.json()
        )
        replay = post(restarted, selected, body)
        assert replay.status_code == 200 and replay.json() == response.json()
        listing = restarted.get(
            f"/api/v2/patches/{selected[0]['patch_id']}/evidence-reports", headers=HEADERS
        ).json()
        assert len(listing) == 1 and listing[0]["review_sha256"] == view.review_sha256
    assert counts(application) == 1


@pytest.mark.parametrize(
    "status", ["error", "differences_found", "inconclusive", "no_differences_in_scope"]
)
def test_completed_network_result_keeps_its_actual_meaning(evidence_api, status):
    client, _app, _settings, _neural, _network, control = evidence_api
    control["status"] = status
    selected = prepare(client, include=("network",))
    response = post(client, selected, options(selected))
    assert response.status_code == 201, response.text
    view = response.json()
    assert view["network"]["result"]["status"] == status
    assert view["formal_qualification"] == "not_proven" and view["status"] == "needs_review"
    assert ("formal_scope_not_passed" in view["validation_blockers"]) == (
        status != "no_differences_in_scope"
    )
    assert "original_statistical_not_selected" in view["validation_blockers"]
    assert "neural_not_selected" in view["validation_blockers"]
    assert view["forest"] is view["neural"] is None


@pytest.mark.parametrize("role", [READER, ANALYST])
def test_read_roles_cannot_save_even_invalid_body_but_can_read_reports(evidence_api, role):
    client, app, _settings, *_ = evidence_api
    selected = prepare(client, include=())
    body = options(selected)
    saved = post(client, selected, body)
    assert saved.status_code == 201, saved.text
    headers = {"Authorization": f"Bearer {role}"}
    response = client.post(
        f"/api/v2/patches/{selected[0]['patch_id']}/evidence-reports",
        headers=headers,
        content="invalid",
    )
    assert response.status_code == 403 and counts(app) == 1
    assert get(client, selected, body, headers=headers).json() == saved.json()


@pytest.mark.parametrize("kind", ["deterministic", "forest", "neural", "network"])
def test_changed_selected_proof_refused_before_insert(evidence_api, kind):
    client, app, _settings, *_ = evidence_api
    selected = prepare(client)
    body = options(selected)
    body[kind]["review_sha256"] = "b" * 64
    assert post(client, selected, body).status_code == 409
    assert counts(app) == 0


@pytest.mark.parametrize(
    "fault", ["missing", "draft", "null_required", "extra", "omitted_nullable"]
)
def test_invalid_request_or_missing_result_has_no_report(evidence_api, fault):
    client, app, _settings, *_ = evidence_api
    selected = prepare(client, include=())
    body = options(selected)
    expected = 400
    if fault == "missing":
        body["deterministic"]["record_id"] = str(uuid4())
        expected = 404
    elif fault == "draft":
        body["draft_sha256"] = "b" * 64
        expected = 409
    elif fault == "null_required":
        body["deterministic"] = None
    elif fault == "extra":
        body["approved"] = True
    else:
        del body["network"]
    response = post(client, selected, body)
    assert response.status_code == expected, response.text
    assert counts(app) == 0


@pytest.mark.parametrize("state", ["failed", "pending_unknown"])
def test_unconfirmed_or_failed_deterministic_attempt_not_composed(evidence_api, monkeypatch, state):
    client, app, _settings, *_ = evidence_api
    selected = prepare(client, include=())
    previous = selected[1]["deterministic"]
    request = previous["intent"]["request"] | {"recheck_id": str(uuid4())}
    if state == "failed":

        def fail(*args):
            raise ValueError("owned failure")

        monkeypatch.setattr(deterministic_module, "recheck_original_deterministic", fail)
        response = client.post(
            f"/api/v2/patches/{selected[0]['patch_id']}/deterministic-rechecks",
            headers=HEADERS,
            json=request,
        )
        assert response.status_code == 201, response.text
        result = response.json()
    else:
        intent = SourceDeterministicIntent.model_validate(
            previous["intent"] | {"request": request, "created_at": datetime.now(UTC).isoformat()}
        )
        assert SourceDeterministicRecords(app.state.analysis_service.store).reserve(intent)
        result = deterministic_module.SourceDeterministicRecheck.from_records(
            intent, None
        ).model_dump(mode="json")
    selected[1]["deterministic"] = result
    assert post(client, selected, options(selected)).status_code == 409
    assert counts(app) == 0


def test_mixed_parent_records_do_not_form_a_common_report(evidence_api):
    client, app, _settings, *_ = evidence_api
    selected = prepare(client, include=("neural",))
    other = prepare(client, "juniper", include=("neural",))
    body = options(selected, neural=options(other)["neural"])
    assert post(client, selected, body).status_code == 409 and counts(app) == 0


def test_same_targets_with_another_original_analysis_are_not_combined(evidence_api):
    client, app, _settings, *_ = evidence_api
    selected = prepare(client, include=("forest",))
    old = selected[1]["forest"]
    model = old["intent"]["selection"]["original"]["model"]
    analysis = client.post(
        f"/api/v1/configurations/{selected[2]['configuration_id']}/analyze",
        headers=HEADERS,
        json={"statistical_model_id": model["model_id"]},
    )
    assert analysis.status_code == 201, analysis.text
    base = f"/api/v2/patches/{selected[0]['patch_id']}"
    original = client.get(
        base + "/statistical-selection/" + analysis.json()["analysis_id"], headers=HEADERS
    )
    assert original.status_code == 200, original.text
    request = old["intent"]["request"] | {
        "recheck_id": str(uuid4()),
        "before_analysis_id": analysis.json()["analysis_id"],
        "before_analysis_sha256": original.json()["before_analysis_sha256"],
    }
    forest = client.post(base + "/statistical-rechecks", headers=HEADERS, json=request)
    assert forest.status_code == 201, forest.text
    assert forest.json()["execution_status"] == "completed"
    selected[1]["forest"] = forest.json()
    assert post(client, selected, options(selected)).status_code == 409 and counts(app) == 0


def test_report_history_paginates_without_losing_the_last_record(evidence_api):
    client, app, _settings, *_ = evidence_api
    selected = prepare(client, include=())
    ids = []
    for _ in range(21):
        response = post(client, selected, options(selected))
        assert response.status_code == 201, response.text
        ids.append(response.json()["report_id"])
    base = f"/api/v2/patches/{selected[0]['patch_id']}/evidence-reports"
    first = client.get(base, headers=HEADERS).json()
    last = client.get(base + "?offset=20", headers=HEADERS).json()
    assert [row["report_id"] for row in first + last] == list(reversed(ids))
    assert len(first) == 20 and len(last) == 1 and counts(app) == 21


def test_duplicate_keys_body_budget_and_input_budget(evidence_api, monkeypatch):
    client, app, _settings, *_ = evidence_api
    selected = prepare(client, include=())
    url = f"/api/v2/patches/{selected[0]['patch_id']}/evidence-reports"
    headers = HEADERS | {"Content-Type": "application/json"}
    duplicate = json.dumps(options(selected))[:-1] + ',"network":null}'
    assert client.post(url, headers=headers, content=duplicate).status_code == 400
    assert client.post(url, headers=headers, content=" " * (16 * 1024 + 1)).status_code == 413
    monkeypatch.setattr("app.db.source_evidence_records.MAX_SOURCE_EVIDENCE_INPUT_BYTES", 1)
    assert post(client, selected, options(selected)).status_code == 413
    assert counts(app) == 0


def test_domain_audit_failure_rolls_back_single_atomic_report(evidence_api, monkeypatch):
    client, app, _settings, *_ = evidence_api
    selected = prepare(client, include=())

    def fail(*args):
        raise RuntimeError("owned audit failure")

    monkeypatch.setattr(SourceEvidenceRecords, "_audit", staticmethod(fail))
    response = post(client, selected, options(selected))
    assert response.status_code == 500 and counts(app) == 0
    assert "owned audit failure" not in response.text


def test_two_requests_save_one_immutable_report_and_audit(evidence_api):
    client, app, _settings, *_ = evidence_api
    selected = prepare(client, include=())
    body = CreateSourceEvidenceReport.model_validate(options(selected))
    workflow = SourceEvidenceWorkflow(app.state.analysis_service.store)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(
            pool.map(lambda _: workflow.create(UUID(selected[0]["patch_id"]), body), range(2))
        )
    assert sorted(created for _view, created in results) == [False, True]
    assert results[0][0] == results[1][0] and counts(app) == 1


def test_changed_same_id_is_conflict_and_foreign_parent_is_not_exposed(evidence_api):
    client, app, _settings, *_ = evidence_api
    selected = prepare(client, include=("neural",))
    body = options(selected)
    response = post(client, selected, body)
    assert response.status_code == 201, response.text
    assert post(client, selected, body | {"neural": None}).status_code == 409
    assert (
        client.get(
            f"/api/v2/patches/{uuid4()}/evidence-reports/{body['report_id']}", headers=HEADERS
        ).status_code
        == 404
    )
    assert counts(app) == 1


def test_lost_operation_completion_reads_the_committed_domain_report(evidence_api, monkeypatch):
    client, app, _settings, *_ = evidence_api
    selected = prepare(client, include=())
    body = options(selected)
    journal = app.state.operation_journal
    original = journal.complete

    def fail(receipt, completion):
        if receipt.operation == "create_source_evidence_report":
            raise RuntimeError("owned response journal failure")
        return original(receipt, completion)

    monkeypatch.setattr(journal, "complete", fail)
    assert post(client, selected, body).status_code == 503 and counts(app) == 1
    response = get(client, selected, body)
    assert response.status_code == 200 and response.json()["report_id"] == body["report_id"]
