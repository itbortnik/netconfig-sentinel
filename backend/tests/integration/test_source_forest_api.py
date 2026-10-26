"""Real numeric Forest HTTP attempts on authored controls, never quality measurements."""

import json
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from uuid import UUID, uuid4

import app.patching.source_forest as workflow_module
import pytest
from app.api.source_forest_contracts import RunSourceForestRecheck, SourceForestRecheck
from app.audit.results import _selected
from app.core.configuration_model import ConfigurationModelSettings
from app.db.migrate import upgrade_database
from app.db.source_forest_records import SourceForestRecords
from app.db.source_records import SourceRecords
from app.main import create_app
from app.patching.source_forest import SourceForestWorkflow
from fastapi.testclient import TestClient
from sqlalchemy import inspect, text
from test_source_ml_recheck_api import source_ml_api as source_ml_api
from test_source_patch_review_api import ANALYST, ENGINEER, HEADERS, READER

LABELS = {"device_role": "edge", "site_class": "branch", "service_profile": "owned-control"}


def upload(client, content, *, device=None, retain=False, labels=LABELS):
    result = client.post(
        "/api/v1/configurations",
        headers=HEADERS,
        json={
            "device_id": device or str(uuid4()),
            "filename": "owned.cfg",
            "content": content,
            "inventory": labels,
            "retain_original_source": retain,
        },
    )
    assert result.status_code == 201, result.text
    return result.json()


def prepare(client, vendor="cisco", *, retain=True):
    ids = []
    for index in range(8):
        content = (
            (
                f"hostname owned-training-{index}\nip ssh version 2\n"
                + "".join(f"ntp server 192.0.2.{20 + j}\n" for j in range(index % 4))
            )
            if vendor == "cisco"
            else (
                f"set system host-name owned-training-{index}\nset system services ssh\n"
                + "".join(f"set system ntp server 192.0.2.{20 + j}\n" for j in range(index % 4))
            )
        )
        ids.append(upload(client, content)["configuration_id"])
    response = client.post(
        "/api/v1/models/isolation-forest", headers=HEADERS, json={"configuration_ids": ids}
    )
    assert response.status_code == 201, response.text
    model = response.json()
    contents = (
        (
            "hostname owned-target\nline vty 0 4\n transport input telnet ssh\n!\n",
            "hostname owned-target\nline vty 0 4\n transport input ssh\n!\n",
        )
        if vendor == "cisco"
        else (
            "set system host-name owned-target\nset system services telnet\n",
            "set system host-name owned-target\nset system services ssh\n",
        )
    )
    before = upload(client, contents[0], retain=retain)
    after = upload(client, contents[1], device=before["device_id"], retain=retain)
    response = client.post(
        f"/api/v1/configurations/{before['configuration_id']}/analyze",
        headers=HEADERS,
        json={"statistical_model_id": model["model_id"]},
    )
    assert response.status_code == 201, response.text
    analysis = response.json()
    response = client.post(
        "/api/v1/patches",
        headers=HEADERS,
        json={
            "patch_id": str(uuid4()),
            "before_configuration_id": before["configuration_id"],
            "after_configuration_id": after["configuration_id"],
            "before_source_sha256": before["canonical"]["source"]["sha256"],
            "after_source_sha256": after["canonical"]["source"]["sha256"],
        },
    )
    assert response.status_code == 201, response.text
    draft = response.json()
    response = client.get(
        f"/api/v2/patches/{draft['patch_id']}/statistical-selection/{analysis['analysis_id']}",
        headers=HEADERS,
    )
    assert response.status_code == 200, response.text
    return draft, before, after, analysis, model, response.json()


def options(selected, **updates):
    draft, _before, _after, analysis, model, selection = selected
    return {
        "recheck_id": str(uuid4()),
        "draft_sha256": draft["draft_sha256"],
        "before_analysis_id": analysis["analysis_id"],
        "before_analysis_sha256": selection["before_analysis_sha256"],
        "model_id": model["model_id"],
        "artifact_sha256": model["artifact_sha256"],
        "allow_local_model_context": True,
    } | updates


def post(client, selected, body, *, headers=HEADERS):
    return client.post(
        f"/api/v2/patches/{selected[0]['patch_id']}/statistical-rechecks",
        headers=headers,
        json=body,
    )


def get(client, selected, body, *, headers=HEADERS):
    return client.get(
        f"/api/v2/patches/{selected[0]['patch_id']}/statistical-rechecks/{body['recheck_id']}",
        headers=headers,
    )


def counts(app):
    with app.state.analysis_service.store.engine.connect() as connection:
        return tuple(
            connection.execute(text(f"SELECT count(*) FROM {table}")).scalar_one()
            for table in ("patch_statistical_recheck_intents", "patch_statistical_recheck_outcomes")
        )


@pytest.fixture
def forest_api(source_ml_api):
    client, application, settings, calls = source_ml_api
    application.state.configuration_model.settings = ConfigurationModelSettings()
    yield client, application, settings, calls


@pytest.mark.parametrize("vendor", ["cisco", "juniper"])
def test_actual_frozen_http_pair_restart_pure_replay_without_neural_runtime(
    forest_api, monkeypatch, vendor
):
    client, application, settings, neural_calls = forest_api
    selected = prepare(client, vendor)
    draft, before, after, analysis, _model, _selection = selected
    monkeypatch.setattr(
        "sklearn.ensemble.IsolationForest.fit", lambda *a, **k: pytest.fail("refit")
    )
    body = options(selected)
    response = post(client, selected, body, headers={"Authorization": f"Bearer {ENGINEER}"})
    assert response.status_code == 201, response.text
    view = SourceForestRecheck.model_validate(response.json())
    assert view.execution_status == "completed" and not neural_calls
    assert (
        view.outcome.report.scores.before_score_samples == analysis["statistical"]["score_samples"]
    )
    assert view.status == "needs_review" and view.formal_verification == "not_run"
    assert not any(
        (view.approved, view.applied, view.quality_proven, view.calibrated, view.risk_fused)
    )
    assert counts(application) == (1, 1)
    audit = client.get(
        f"/api/v1/operation-audit/{response.headers['X-Operation-Id']}", headers=HEADERS
    )
    assert audit.status_code == 200, audit.text
    operation = audit.json()
    assert operation["receipt"]["operation"] == "run_source_forest_recheck"
    assert operation["authorization"] == "allowed"
    assert body["before_analysis_id"] in operation["completion"]["result"]["resource_ids"]
    assert all(
        value not in audit.text
        for value in ("score_samples", "owned-training", "trees", "review_json")
    )
    listing = client.get(
        f"/api/v2/patches/{draft['patch_id']}/statistical-rechecks", headers=HEADERS
    ).json()
    assert len(listing) == 1 and listing[0]["review_sha256"] == view.review_sha256
    with application.state.analysis_service.store.engine.begin() as connection:
        connection.execute(text("DELETE FROM models WHERE id=:key"), {"key": str(view.model_id)})
    monkeypatch.setattr(
        workflow_module, "recheck_original_forest", lambda *a: pytest.fail("recheck")
    )
    monkeypatch.setattr(SourceRecords, "get", lambda *a, **k: pytest.fail("original"))
    with TestClient(create_app(settings)) as restarted:
        assert post(restarted, selected, body).status_code == 200
        assert get(restarted, selected, body).json() == response.json()
        assert post(restarted, selected, body).json() == response.json()
    for snapshot in (before, after):
        assert (
            client.get(
                f"/api/v1/configurations/{snapshot['configuration_id']}", headers=HEADERS
            ).json()
            == snapshot
        )


@pytest.mark.parametrize("role", [READER, ANALYST])
def test_read_role_denied_before_body_or_original_but_can_read_selection(
    forest_api, monkeypatch, role
):
    client, app, _settings, _calls = forest_api
    selected = prepare(client)
    monkeypatch.setattr(SourceRecords, "get", lambda *a, **k: pytest.fail("original"))
    headers = {"Authorization": f"Bearer {role}"}
    response = client.post(
        f"/api/v2/patches/{selected[0]['patch_id']}/statistical-rechecks",
        headers=headers,
        content="invalid",
    )
    assert response.status_code == 403 and counts(app) == (0, 0)
    assert (
        client.get(
            f"/api/v2/patches/{selected[0]['patch_id']}/statistical-selection/{selected[3]['analysis_id']}",
            headers=headers,
        ).status_code
        == 200
    )


@pytest.mark.parametrize(
    "update,code",
    [
        ({"allow_local_model_context": False}, 403),
        ({"allow_local_model_context": 1}, 400),
        ({"allow_local_model_context": "true"}, 400),
        ({"model_id": str(uuid4())}, 409),
        ({"artifact_sha256": "b" * 64}, 409),
        ({"before_analysis_sha256": "b" * 64}, 409),
        ({"draft_sha256": "b" * 64}, 409),
        ({"endpoint": "http://127.0.0.1"}, 400),
    ],
)
def test_invalid_selection_does_not_reserve_or_score(forest_api, monkeypatch, update, code):
    client, app, _settings, _calls = forest_api
    selected = prepare(client)
    monkeypatch.setattr(
        workflow_module, "recheck_original_forest", lambda *a: pytest.fail("scorer")
    )
    assert post(client, selected, options(selected, **update)).status_code == code
    assert counts(app) == (0, 0)


def test_no_retained_source_and_missing_original_model_refuse(forest_api):
    client, app, _settings, _calls = forest_api
    selected = prepare(client, retain=False)
    assert post(client, selected, options(selected)).status_code == 409
    with app.state.analysis_service.store.engine.begin() as connection:
        connection.execute(text("DELETE FROM models WHERE id=:id"), {"id": selected[4]["model_id"]})
    assert post(client, selected, options(selected)).status_code == 409
    assert counts(app) == (0, 0)


def test_unavailable_result_generic_failure_and_audit_metadata_only(forest_api, monkeypatch):
    client, app, _settings, _calls = forest_api
    selected = prepare(client)

    def fail(*args):
        raise ValueError("private diagnostics must not escape")

    monkeypatch.setattr(workflow_module, "recheck_original_forest", fail)
    body = options(selected)
    response = post(client, selected, body)
    assert response.status_code == 201 and response.json()["outcome"]["report"] is None
    assert (
        response.json()["execution_status"] == "failed"
        and "private diagnostics" not in response.text
    )
    view = SourceForestRecheck.model_validate(response.json())
    metadata = json.dumps(_selected(view))
    assert body["before_analysis_id"] in metadata and view.review_sha256 in metadata
    assert all(
        value not in metadata for value in ("score_samples", "owned-target", "review_json", "trees")
    )
    selection_metadata = json.dumps(
        _selected(workflow_module.SourceForestSelection.model_validate(selected[5]))
    )
    assert "owned-training" not in selection_metadata and "score_samples" not in selection_metadata
    assert post(client, selected, body).json() == response.json() and counts(app) == (1, 1)
    with app.state.analysis_service.store.engine.connect() as connection:
        actions = (
            connection.execute(
                text(
                    "SELECT action FROM audit_events "
                    "WHERE action LIKE 'patch.statistical_recheck_%'"
                )
            )
            .scalars()
            .all()
        )
    assert sorted(actions) == [
        "patch.statistical_recheck_completed",
        "patch.statistical_recheck_requested",
    ]


def test_two_sessions_reserve_one_numeric_evaluation(forest_api, monkeypatch):
    client, app, _settings, _calls = forest_api
    selected = prepare(client)
    body = RunSourceForestRecheck.model_validate(options(selected))
    store = app.state.analysis_service.store
    original, numeric = SourceForestRecords.reserve, workflow_module.recheck_original_forest
    barrier, calls = Barrier(2), []

    def reserve(records, intent):
        barrier.wait(timeout=20)
        return original(records, intent)

    def evaluate(*args):
        calls.append(True)
        return numeric(*args)

    monkeypatch.setattr(SourceForestRecords, "reserve", reserve)
    monkeypatch.setattr(workflow_module, "recheck_original_forest", evaluate)

    def run(_):
        return SourceForestWorkflow(store).run(UUID(selected[0]["patch_id"]), body)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(run, range(2)))
    assert sorted(created for _view, created in results) == [False, True]
    assert len(calls) == 1 and counts(app) == (1, 1)
    assert (
        SourceForestWorkflow(store)
        .get(UUID(selected[0]["patch_id"]), body.recheck_id)
        .execution_status
        == "completed"
    )


@pytest.mark.parametrize("phase", ["requested", "completed"])
def test_real_atomic_domain_audit_failure_rolls_back_its_sibling(forest_api, monkeypatch, phase):
    client, app, _settings, _calls = forest_api
    selected = prepare(client)
    body = RunSourceForestRecheck.model_validate(options(selected))
    workflow = SourceForestWorkflow(app.state.analysis_service.store)
    original = SourceForestRecords._audit

    def audit(session, action, key):
        if action == f"patch.statistical_recheck_{phase}":
            raise RuntimeError("owned injected audit failure")
        original(session, action, key)

    monkeypatch.setattr(SourceForestRecords, "_audit", staticmethod(audit))
    with pytest.raises(RuntimeError, match="owned injected audit failure"):
        workflow.run(UUID(selected[0]["patch_id"]), body)
    assert counts(app) == ((0, 0) if phase == "requested" else (1, 0))
    if phase == "completed":
        monkeypatch.setattr(
            workflow_module, "recheck_original_forest", lambda *a: pytest.fail("rerun")
        )
        view, created = workflow.run(UUID(selected[0]["patch_id"]), body)
        assert not created and view.execution_status == "pending_unknown"


def test_populated_12_to_13_preserves_actual_legacy_history(forest_api):
    client, app, _settings, _calls = forest_api
    selected = prepare(client)
    store = app.state.analysis_service.store
    with store.engine.begin() as connection:
        connection.exec_driver_sql("DROP TABLE native_patch_candidates")
        connection.exec_driver_sql("DROP TABLE patch_risk_assessments")
        connection.exec_driver_sql("DROP TABLE patch_evidence_decisions")
        connection.exec_driver_sql("DROP TABLE patch_evidence_reports")
        connection.exec_driver_sql("DROP TABLE patch_deterministic_recheck_outcomes")
        connection.exec_driver_sql("DROP TABLE patch_deterministic_recheck_intents")
        connection.exec_driver_sql("DROP TABLE patch_statistical_recheck_outcomes")
        connection.exec_driver_sql("DROP TABLE patch_statistical_recheck_intents")
        connection.execute(text("UPDATE alembic_version SET version_num='0012_source_ml_rechecks'"))
    names = set(inspect(store.engine).get_table_names()) - {"alembic_version"}

    def physical():
        with store.engine.connect() as connection:
            return {
                name: sorted(map(repr, connection.execute(text(f'SELECT * FROM "{name}"')).all()))
                for name in names
            }

    old = physical()
    assert not store.ready()
    upgrade_database(store.engine)
    upgrade_database(store.engine)
    assert store.ready() and physical() == old
    assert post(client, selected, options(selected)).status_code == 201


def test_four_new_operation_receipts_capture_permissions_and_safe_bindings(forest_api):
    client, _app, _settings, _calls = forest_api
    selected = prepare(client)
    patch, analysis = selected[0]["patch_id"], selected[3]["analysis_id"]
    body = options(selected)
    requests = [
        (
            client.get(
                f"/api/v2/patches/{patch}/statistical-selection/{analysis}", headers=HEADERS
            ),
            "source_forest_selection",
        ),
        (post(client, selected, body), "run_source_forest_recheck"),
        (get(client, selected, body), "get_source_forest_recheck"),
        (
            client.get(f"/api/v2/patches/{patch}/statistical-rechecks", headers=HEADERS),
            "list_source_forest_rechecks",
        ),
    ]
    for response, name in requests:
        assert response.status_code in (200, 201), response.text
        record = client.get(
            f"/api/v1/operation-audit/{response.headers['X-Operation-Id']}", headers=HEADERS
        ).json()
        assert record["receipt"]["operation"] == name
        assert record["authorization"] == "allowed"
        assert record["completion"]["permissions"][0]["granted"] is True
        assert analysis in record["completion"]["result"]["resource_ids"]
        assert all(
            value not in json.dumps(record)
            for value in ("score_samples", "owned-training", "review_json", "trees")
        )
