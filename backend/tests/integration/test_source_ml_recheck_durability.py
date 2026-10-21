"""Atomic pair reservations, historical binding and additive schema compatibility."""

import json
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from uuid import UUID, uuid4

import app.patching.source_ml as workflow_module
import pytest
from app.api.source_ml_contracts import RunSourceMlRecheck
from app.core.configuration_model import ConfigurationModelSettings
from app.db.migrate import upgrade_database
from app.db.source_ml_records import SourceMlRecords
from app.db.store import StorageIntegrityError
from app.detection.config_model_runtime import ConfigurationModelRuntime
from app.patching.source_ml import SourceMlWorkflow
from sqlalchemy import inspect, text
from test_source_ml_recheck_api import HEADERS, counts, get, options, pair, post
from test_source_ml_recheck_api import source_ml_api as source_ml_api


def test_separate_runtime_race_reserves_one_worker_and_one_outcome(source_ml_api, monkeypatch):
    client, application, _settings, calls = source_ml_api
    draft, *_ = pair(client)
    body = RunSourceMlRecheck.model_validate(options(draft))
    store = application.state.analysis_service.store
    selected = application.state.configuration_model.settings
    barrier, original = Barrier(2), SourceMlRecords.reserve

    def reserve(records, intent):
        barrier.wait(timeout=20)
        return original(records, intent)

    monkeypatch.setattr(SourceMlRecords, "reserve", reserve)

    def run(_):
        return SourceMlWorkflow(store).run(
            UUID(draft["patch_id"]), body, ConfigurationModelRuntime(selected)
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(run, range(2)))
    assert sorted(created for _view, created in results) == [False, True]
    assert len(calls) == 1 and counts(application) == (1, 1)
    assert (
        SourceMlWorkflow(store).get(UUID(draft["patch_id"]), body.recheck_id).execution_status
        == "completed"
    )


@pytest.mark.parametrize("phase", ["requested", "completed"])
def test_atomic_audit_failure_preserves_unknown_without_reexecution(
    source_ml_api, monkeypatch, phase
):
    client, application, _settings, calls = source_ml_api
    draft, *_ = pair(client)
    body = RunSourceMlRecheck.model_validate(options(draft))
    store = application.state.analysis_service.store
    original = SourceMlRecords._audit

    def fail(session, action, key):
        if action == f"patch.ml_recheck_{phase}":
            raise RuntimeError("owned injected audit failure")
        original(session, action, key)

    monkeypatch.setattr(SourceMlRecords, "_audit", staticmethod(fail))
    workflow = SourceMlWorkflow(store)
    with pytest.raises(RuntimeError, match="owned injected audit failure"):
        workflow.run(UUID(draft["patch_id"]), body, application.state.configuration_model)
    assert counts(application) == ((0, 0) if phase == "requested" else (1, 0))
    assert len(calls) == (0 if phase == "requested" else 1)
    if phase == "completed":
        old = workflow.get(UUID(draft["patch_id"]), body.recheck_id)
        assert old.execution_status == "pending_unknown" and old.outcome is None
        monkeypatch.setattr(
            workflow_module, "run_configuration_pair_job", lambda *a: pytest.fail("worker")
        )
        view, created = workflow.run(
            UUID(draft["patch_id"]), body, ConfigurationModelRuntime(ConfigurationModelSettings())
        )
        assert not created and view == old


@pytest.mark.parametrize(
    "fault",
    [
        "canonical",
        "source",
        "draft",
        "parent",
        "outcome_intent",
        "outcome_source",
        "outcome_model",
        "ciphertext",
    ],
)
def test_authenticated_drift_and_ciphertext_relocation_fail_closed(source_ml_api, fault):
    client, application, _settings, _calls = source_ml_api
    draft, *_ = pair(client)
    body = options(draft)
    assert post(client, draft, body).status_code == 201
    store = application.state.analysis_service.store
    outcome = fault.startswith("outcome")
    table = "patch_ml_recheck_outcomes" if outcome else "patch_ml_recheck_intents"
    column, kind = ("recheck_id", "source_ml_outcome") if outcome else ("id", "source_ml_intent")
    key = body["recheck_id"]
    with store.engine.connect() as connection:
        cipher = connection.execute(
            text(f"SELECT payload FROM {table} WHERE {column}=:id"), {"id": key}
        ).scalar_one()
    raw = json.loads(store._decode(cipher, kind=kind, row_id=key))
    if fault in ("canonical", "source"):
        raw["before"][f"{fault}_sha256"] = "b" * 64
    elif fault == "draft":
        raw["request"]["draft_sha256"] = "b" * 64
    elif fault == "parent":
        raw["patch_id"] = str(uuid4())
    elif fault == "outcome_intent":
        raw["intent_sha256"] = "b" * 64
    elif fault == "outcome_source":
        raw["report"]["after"]["prediction"]["raw_source_sha256"] = "b" * 64
    elif fault == "outcome_model":
        raw["report"]["after"]["model"]["tokenizer_sha256"] = "b" * 64
    encoded = store._encode(
        json.dumps(raw), kind=kind, row_id=str(uuid4()) if fault == "ciphertext" else key
    )
    with store.engine.begin() as connection:
        connection.execute(
            text(f"UPDATE {table} SET payload=:value WHERE {column}=:id"),
            {"id": key, "value": encoded},
        )
    with pytest.raises(StorageIntegrityError, match="Stored data is unavailable"):
        SourceMlWorkflow(store).get(UUID(draft["patch_id"]), UUID(key))
    response = get(client, draft, body)
    assert response.status_code == 503 and "transport input" not in response.text


@pytest.mark.parametrize("phase", ["job", "proof"])
def test_both_envelope_and_proof_headroom_are_admitted_before_reservation(
    source_ml_api, monkeypatch, phase
):
    import app.detection.config_pair_runtime as runtime

    client, application, _settings, calls = source_ml_api
    draft, *_ = pair(client)
    if phase == "job":
        monkeypatch.setattr(runtime, "MAX_PAIR_JOB_BYTES", 1)
    else:
        monkeypatch.setattr(workflow_module, "MAX_SOURCE_ML_BYTES", 1)
    assert post(client, draft, options(draft)).status_code == 413
    assert counts(application) == (0, 0) and not calls


def test_real_upgrade_11_to_12_preserves_populated_legacy_rows_byte_for_byte(source_ml_api):
    client, application, _settings, _calls = source_ml_api
    draft, *_ = pair(client)
    assert (
        client.post(
            f"/api/v1/patches/{draft['patch_id']}/verify",
            headers=HEADERS,
            json={"verification_id": str(uuid4()), "draft_sha256": draft["draft_sha256"]},
        ).status_code
        == 201
    )
    store = application.state.analysis_service.store
    with store.engine.begin() as connection:
        connection.exec_driver_sql("DROP TABLE patch_ml_recheck_outcomes")
        connection.exec_driver_sql("DROP TABLE patch_deterministic_recheck_outcomes")
        connection.exec_driver_sql("DROP TABLE patch_deterministic_recheck_intents")
        connection.exec_driver_sql("DROP TABLE patch_statistical_recheck_outcomes")
        connection.exec_driver_sql("DROP TABLE patch_statistical_recheck_intents")
        connection.exec_driver_sql("DROP TABLE patch_ml_recheck_intents")
        connection.execute(
            text("UPDATE alembic_version SET version_num='0011_source_patch_reviews'")
        )
    names = sorted(set(inspect(store.engine).get_table_names()) - {"alembic_version"})

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
    assert post(client, draft, options(draft)).status_code == 201
