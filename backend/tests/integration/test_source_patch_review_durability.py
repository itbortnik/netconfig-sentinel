"""Real encrypted persistence with an explicitly mocked network SDK boundary."""

import json
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from uuid import UUID, uuid4

import app.patching.source_review as workflow_module
import pytest
from app.api.source_patch_contracts import VerifySourcePatch
from app.audit.results import _selected
from app.core.patch_verification import PatchVerificationSettings
from app.db.migrate import upgrade_database
from app.db.source_patch_records import SourcePatchRecords
from app.db.store import StorageIntegrityError
from app.patching.source_review import SourcePatchWorkflow
from app.verification.patch_runtime import PatchVerificationRuntime
from sqlalchemy import inspect, text
from test_source_patch_review_api import (
    HEADERS,
    counts,
    draft_pair,
    get,
    options,
    post,
)
from test_source_patch_review_api import (
    source_api as source_api,
)


def test_separate_runtime_same_id_race_runs_one_worker_and_one_atomic_outcome(
    source_api, monkeypatch
):
    client, application, _settings, calls = source_api
    draft, *_ = draft_pair(client)
    body = VerifySourcePatch.model_validate(options(draft))
    store = application.state.analysis_service.store
    barrier = Barrier(2)
    original = SourcePatchRecords.reserve

    def reserve(records, intent):
        barrier.wait(timeout=20)
        return original(records, intent)

    monkeypatch.setattr(SourcePatchRecords, "reserve", reserve)

    def run(_):
        runtime = PatchVerificationRuntime(PatchVerificationSettings(allow_engine_upload=True))
        return SourcePatchWorkflow(store).verify(UUID(draft["patch_id"]), body, runtime)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(run, range(2)))
    assert sorted(created for _view, created in results) == [False, True]
    assert len(calls) == 1 and counts(application) == (1, 1)
    final = SourcePatchWorkflow(store).get(UUID(draft["patch_id"]), body.verification_id)
    assert final.execution_status == "completed"
    with store.engine.connect() as connection:
        assert (
            connection.execute(
                text(
                    "SELECT count(*) FROM audit_events "
                    "WHERE action LIKE 'patch.network_verification_%'"
                )
            ).scalar_one()
            == 2
        )


@pytest.mark.parametrize("phase", ["requested", "completed"])
def test_audit_failure_rolls_back_sibling_record_and_pending_replay_never_executes(
    source_api, monkeypatch, phase
):
    client, application, _settings, calls = source_api
    draft, *_ = draft_pair(client)
    request = VerifySourcePatch.model_validate(options(draft))
    store = application.state.analysis_service.store
    original = SourcePatchRecords._audit

    def fail(session, action, key):
        if action == f"patch.network_verification_{phase}":
            raise RuntimeError("owned injected audit failure")
        original(session, action, key)

    monkeypatch.setattr(SourcePatchRecords, "_audit", staticmethod(fail))
    workflow = SourcePatchWorkflow(store)
    with pytest.raises(RuntimeError, match="owned injected audit failure"):
        workflow.verify(UUID(draft["patch_id"]), request, application.state.patch_verification)
    assert counts(application) == ((0, 0) if phase == "requested" else (1, 0))
    assert len(calls) == (0 if phase == "requested" else 1)
    if phase == "completed":
        saved = workflow.get(UUID(draft["patch_id"]), request.verification_id)
        assert saved.execution_status == "pending_unknown" and saved.outcome is None
        assert saved.intent.preflight.formal_verification == "not_run"
        monkeypatch.setattr(
            workflow_module, "check_with_batfish", lambda *a, **k: pytest.fail("SDK")
        )
        result, created = workflow.verify(
            UUID(draft["patch_id"]), request, PatchVerificationRuntime(PatchVerificationSettings())
        )
        assert not created and result == saved


@pytest.mark.parametrize(
    "fault",
    [
        "network_hash",
        "canonical_hash",
        "draft_hash",
        "preflight_hash",
        "intent_scope",
        "outcome_intent",
        "outcome_network",
        "outcome_scope",
        "ciphertext_row",
    ],
)
def test_authenticated_record_drift_and_ciphertext_relocation_fail_closed(source_api, fault):
    client, application, _settings, _calls = source_api
    draft, *_ = draft_pair(client)
    body = options(draft)
    saved = post(client, draft, body)
    assert saved.status_code == 201
    store = application.state.analysis_service.store
    outcome = fault.startswith("outcome")
    table = "patch_network_review_outcomes" if outcome else "patch_network_review_intents"
    column = "verification_id" if outcome else "id"
    kind = "source_patch_outcome" if outcome else "source_patch_intent"
    key = body["verification_id"]
    with store.engine.connect() as connection:
        original = connection.execute(
            text(f"SELECT payload FROM {table} WHERE {column}=:id"), {"id": key}
        ).scalar_one()
    raw = json.loads(store._decode(original, kind=kind, row_id=key))
    digest = "a" * 64
    if fault == "network_hash":
        raw["before_network_sha256"] = digest
    elif fault == "canonical_hash":
        raw["before"]["canonical_sha256"] = digest
    elif fault == "draft_hash":
        raw["request"]["draft_sha256"] = digest
    elif fault == "preflight_hash":
        raw["preflight"]["before"]["source_sha256"] = digest
    elif fault == "intent_scope":
        raw["request"]["scope"]["destination"] = "198.51.100.0/24"
    elif fault == "outcome_intent":
        raw["intent_sha256"] = digest
    elif fault == "outcome_network":
        raw["network_result"]["before_sha256"] = digest
    elif fault == "outcome_scope":
        raw["network_result"]["scope"]["destination"] = "198.51.100.0/24"
    encoded = store._encode(
        json.dumps(raw), kind=kind, row_id=str(uuid4()) if fault == "ciphertext_row" else key
    )
    with store.engine.begin() as connection:
        connection.execute(
            text(f"UPDATE {table} SET payload=:value WHERE {column}=:id"),
            {"id": key, "value": encoded},
        )
    with pytest.raises(StorageIntegrityError, match="Stored data is unavailable"):
        SourcePatchWorkflow(store).get(UUID(draft["patch_id"]), UUID(key))
    response = get(client, draft, body)
    assert response.status_code == 503 and "203.0.113" not in response.text


def test_additive_upgrade_10_to_11_preserves_real_legacy_snapshots_reviews_and_ciphertexts(
    source_api,
):
    client, application, _settings, calls = source_api
    draft, before, after = draft_pair(client)
    body = options(draft)
    legacy_path = f"/api/v1/patches/{draft['patch_id']}/verify"
    legacy = client.post(
        legacy_path,
        headers=HEADERS,
        json={"verification_id": body["verification_id"], "draft_sha256": draft["draft_sha256"]},
    )
    assert legacy.status_code == 201
    store = application.state.analysis_service.store
    # The only 0011 additions are the two empty tables. Restore the actual populated
    # 0010 layout and revision, then execute the real additive Alembic upgrade.
    with store.engine.begin() as connection:
        connection.exec_driver_sql("DROP TABLE patch_network_review_outcomes")
        connection.exec_driver_sql("DROP TABLE patch_ml_recheck_outcomes")
        connection.exec_driver_sql("DROP TABLE patch_ml_recheck_intents")
        connection.exec_driver_sql("DROP TABLE patch_network_review_intents")
        connection.execute(
            text("UPDATE alembic_version SET version_num='0010_model_patch_protocols'")
        )
    assert not store.ready()
    names = sorted(set(inspect(store.engine).get_table_names()) - {"alembic_version"})

    def physical_history():
        with store.engine.connect() as connection:
            return {
                name: sorted(map(repr, connection.execute(text(f'SELECT * FROM "{name}"')).all()))
                for name in names
            }

    frozen = physical_history()
    assert client.get("/ready").status_code == 503
    upgrade_database(store.engine)
    upgrade_database(store.engine)
    assert store.ready() and physical_history() == frozen
    assert post(client, draft, body).status_code == 201
    assert len(calls) == 1
    # The namespaces may share a UUID but retain separate records and contracts.
    assert (
        client.post(
            legacy_path,
            headers=HEADERS,
            json={
                "verification_id": body["verification_id"],
                "draft_sha256": draft["draft_sha256"],
            },
        ).json()
        == legacy.json()
    )
    refusal = client.post(
        legacy_path,
        headers=HEADERS,
        json={
            "verification_id": str(uuid4()),
            "draft_sha256": draft["draft_sha256"],
            "mode": "batfish",
        },
    )
    assert refusal.status_code == 503 and len(calls) == 1
    for snapshot in (before, after):
        assert (
            client.get(
                f"/api/v1/configurations/{snapshot['configuration_id']}", headers=HEADERS
            ).json()
            == snapshot
        )


@pytest.mark.parametrize(
    "missing", ["patch_network_review_intents", "patch_network_review_outcomes"]
)
def test_readiness_requires_both_new_tables(source_api, missing):
    client, application, _settings, calls = source_api
    with application.state.analysis_service.store.engine.begin() as connection:
        if missing == "patch_network_review_intents":
            connection.exec_driver_sql("DROP TABLE patch_network_review_outcomes")
        connection.exec_driver_sql(f"DROP TABLE {missing}")
    assert not application.state.analysis_service.store.ready()
    assert client.get("/ready").status_code == 503
    assert client.get("/api/v2/patches/capabilities", headers=HEADERS).status_code == 503
    assert calls == []


def test_capabilities_do_not_probe_engine_and_audit_projection_has_no_private_scope_or_prose(
    source_api,
):
    client, application, _settings, calls = source_api
    capabilities = client.get("/api/v2/patches/capabilities", headers=HEADERS)
    assert capabilities.status_code == 200
    assert capabilities.json()["network_engine"] == "configured"
    assert capabilities.json()["health_checked"] is False and calls == []
    draft, *_ = draft_pair(client)
    body = options(draft)
    assert post(client, draft, body).status_code == 201
    view = SourcePatchWorkflow(application.state.analysis_service.store).get(
        UUID(draft["patch_id"]), UUID(body["verification_id"])
    )
    selected = json.dumps(_selected(view))
    assert view.review_sha256 in selected
    assert view.outcome.intent_sha256 in selected
    assert all(value not in selected for value in ("edge", "203.0.113", "review_json", "preflight"))
    other, *_ = draft_pair(client)
    assert get(client, other, body).status_code == 404
