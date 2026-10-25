"""Encrypted .2 history, transactional audit and immutable replay on authored inputs."""

import json
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, timedelta, timezone
from uuid import UUID, uuid4

import app.patching.source_deterministic as workflow_module
import pytest
from app.api.source_ml_contracts import ml_json, source_ml_fingerprint
from app.api.source_partial_contracts import (
    SourcePartialIntent,
    SourcePartialOutcome,
    source_deterministic_view,
)
from app.db.patch_records import PatchConflict
from app.db.source_deterministic_records import SourceDeterministicRecords
from app.db.source_records import SourceRecords
from app.db.store import StorageIntegrityError
from app.patching.source_deterministic import SourceDeterministicWorkflow
from sqlalchemy import text
from test_source_partial_diagnostic_api import MARKER, get, options, post, prepare
from test_source_patch_review_api import source_api as source_api


@pytest.fixture
def partial_saved(source_api):
    client, application, _settings, _calls = source_api
    selected = prepare(client, partial="both")
    response = post(client, selected, options(client, selected))
    assert response.status_code == 201, response.text
    store = application.state.analysis_service.store
    saved = SourceDeterministicRecords(store).get(UUID(response.json()["recheck_id"]))
    assert saved is not None
    intent, outcome = saved
    assert isinstance(intent, SourcePartialIntent) and isinstance(outcome, SourcePartialOutcome)
    # An independent ID allows storage tests to reserve a new record while using the
    # same actual saved draft, analysis, source members and completed policy report.
    request = intent.request.model_copy(update={"recheck_id": uuid4()})
    intent = intent.model_copy(update={"request": request})
    outcome = outcome.model_copy(
        update={"recheck_id": request.recheck_id, "intent_sha256": source_ml_fingerprint(intent)}
    )
    source_deterministic_view(intent, outcome)
    return store, intent, outcome


def counts(store, key):
    with store.engine.connect() as connection:
        return tuple(
            connection.execute(
                text(f"SELECT count(*) FROM {table} WHERE {column}=:key"), {"key": str(key)}
            ).scalar_one()
            for table, column in (
                ("patch_deterministic_recheck_intents", "id"),
                ("patch_deterministic_recheck_outcomes", "recheck_id"),
            )
        )


def audit_counts(store, key):
    with store.engine.connect() as connection:
        return {
            action: count
            for action, count in connection.execute(
                text(
                    "SELECT action, count(*) FROM audit_events WHERE resource_id=:key "
                    "GROUP BY action"
                ),
                {"key": str(key)},
            )
        }


def encoded_update(store, intent, *, terminal, change):
    table, column, kind = (
        ("patch_deterministic_recheck_outcomes", "recheck_id", "source_deterministic_outcome")
        if terminal
        else ("patch_deterministic_recheck_intents", "id", "source_deterministic_intent")
    )
    key = str(intent.request.recheck_id)
    with store.engine.connect() as connection:
        payload = connection.execute(
            text(f"SELECT payload FROM {table} WHERE {column}=:key"), {"key": key}
        ).scalar_one()
    data = json.loads(store._decode(payload, kind=kind, row_id=key))
    change(data)
    with store.engine.begin() as connection:
        connection.execute(
            text(f"UPDATE {table} SET payload=:payload WHERE {column}=:key"),
            {"key": key, "payload": store._encode(json.dumps(data), kind=kind, row_id=key)},
        )


def test_saved_projection_history_needs_no_source_parser_policy_catalog(partial_saved, monkeypatch):
    store, intent, outcome = partial_saved
    database = SourceDeterministicRecords(store)
    assert database.reserve(intent)
    database.complete(outcome)
    original_view = source_deterministic_view(intent, outcome).model_dump_json()
    with store.engine.begin() as connection:
        connection.execute(text("DELETE FROM configuration_sources"))

    def forbidden(*args, **kwargs):
        pytest.fail("saved partial projection must not execute source or detector code")

    for name in (
        "get_configuration",
        "get_analysis",
        "get_model",
    ):
        monkeypatch.setattr(store, name, forbidden)
    monkeypatch.setattr(SourceRecords, "get", forbidden)
    for name in (
        "app.parsers.parse_configuration",
        "app.ingestion.source_retention.parse_configuration",
        "app.detection.policy_diagnostic.prepare_partial_policy",
        "app.detection.policy_diagnostic.recheck_partial_policy",
        "app.detection.policy_diagnostic.evaluate_policies",
        "app.detection.policy_engine.evaluate_policies",
        "app.patching.source_deterministic.prepare_original_source",
    ):
        monkeypatch.setattr(name, forbidden)
    monkeypatch.setattr("app.detection.policy_engine.POLICY_CATALOGS", {})
    assert database.get(intent.request.recheck_id) == (intent, outcome)
    assert not database.reserve(intent)
    database.complete(outcome)
    saved = database.get(intent.request.recheck_id)
    assert saved is not None
    assert source_deterministic_view(*saved).model_dump_json() == original_view
    assert MARKER not in original_view
    assert counts(store, intent.request.recheck_id) == (1, 1)
    assert audit_counts(store, intent.request.recheck_id) == {
        "patch.deterministic_recheck_requested": 1,
        "patch.deterministic_recheck_completed": 1,
    }


@pytest.mark.parametrize("offset", [3, -3])
def test_sql_timestamp_normalizes_utc_without_rewriting_payload_or_proof(partial_saved, offset):
    store, intent, outcome = partial_saved
    zone = timezone(timedelta(hours=offset))
    intent = intent.model_copy(update={"created_at": intent.created_at.astimezone(zone)})
    outcome = outcome.model_copy(
        update={
            "intent_sha256": source_ml_fingerprint(intent),
            "completed_at": outcome.completed_at.astimezone(zone),
        }
    )
    original = source_deterministic_view(intent, outcome)
    database = SourceDeterministicRecords(store)
    assert database.reserve(intent)
    database.complete(outcome)
    saved = database.get(intent.request.recheck_id)
    assert saved is not None
    assert source_deterministic_view(*saved).model_dump_json() == original.model_dump_json()
    with store.engine.connect() as connection:
        stamp, payload = connection.execute(
            text(
                "SELECT created_at,payload FROM patch_deterministic_recheck_intents WHERE id=:key"
            ),
            {"key": str(intent.request.recheck_id)},
        ).one()
    assert str(stamp) == intent.created_at.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S.%f")
    assert (
        store._decode(
            payload, kind="source_deterministic_intent", row_id=str(intent.request.recheck_id)
        )
        == intent.model_dump_json()
    )


@pytest.mark.parametrize("phase", ["requested", "completed"])
def test_atomic_domain_audit_rollback_and_pending_replay(partial_saved, monkeypatch, phase):
    store, intent, outcome = partial_saved
    database = SourceDeterministicRecords(store)
    original = database._audit

    def fail(session, action, key):
        if action == f"patch.deterministic_recheck_{phase}":
            raise RuntimeError("owned partial audit rollback control")
        original(session, action, key)

    monkeypatch.setattr(SourceDeterministicRecords, "_audit", staticmethod(fail))
    with pytest.raises(RuntimeError, match="owned partial"):
        assert database.reserve(intent)
        database.complete(outcome)
    assert counts(store, intent.request.recheck_id) == ((0, 0) if phase == "requested" else (1, 0))
    if phase == "completed":
        monkeypatch.setattr(
            workflow_module, "recheck_partial_policy", lambda *a: pytest.fail("pending rerun")
        )
        view, created = SourceDeterministicWorkflow(store).run(intent.patch_id, intent.request)
        assert not created and view.execution_status == "pending_unknown"


def test_racing_reservations_and_terminal_writes_keep_single_audits(partial_saved, monkeypatch):
    from threading import Barrier, local

    store, intent, outcome = partial_saved
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(
            pool.map(lambda _: SourceDeterministicRecords(store).reserve(intent), range(2))
        )
    assert sorted(results) == [False, True]
    original = SourceDeterministicRecords._get
    barrier, state = Barrier(2), local()

    def synchronized(self, session, key):
        result = original(self, session, key)
        if not getattr(state, "seen", False):
            state.seen = True
            barrier.wait(timeout=10)
        return result

    monkeypatch.setattr(SourceDeterministicRecords, "_get", synchronized)
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(lambda _: SourceDeterministicRecords(store).complete(outcome), range(2)))
    monkeypatch.setattr(SourceDeterministicRecords, "_get", original)
    assert SourceDeterministicRecords(store).get(intent.request.recheck_id) == (intent, outcome)
    assert counts(store, intent.request.recheck_id) == (1, 1)
    assert audit_counts(store, intent.request.recheck_id) == {
        "patch.deterministic_recheck_requested": 1,
        "patch.deterministic_recheck_completed": 1,
    }


def test_terminal_commit_survives_uncertain_response_without_execution(source_api, monkeypatch):
    client, application, _settings, _calls = source_api
    selected = prepare(client)
    body = options(client, selected)
    original = SourceDeterministicRecords.complete

    def lost_response(self, outcome):
        original(self, outcome)
        raise RuntimeError("owned uncertain response after durable completion")

    monkeypatch.setattr(SourceDeterministicRecords, "complete", lost_response)
    with pytest.raises(RuntimeError, match="owned uncertain response"):
        SourceDeterministicWorkflow(application.state.analysis_service.store).run(
            UUID(selected[0]["patch_id"]),
            workflow_module.parse_source_deterministic_request(body),
        )
    monkeypatch.setattr(
        workflow_module, "recheck_partial_policy", lambda *a: pytest.fail("durable rerun")
    )
    response = post(client, selected, body)
    assert response.status_code == 200, response.text
    assert response.json()["execution_status"] == "completed"
    assert get(client, selected, body).json() == response.json()


@pytest.mark.parametrize(
    "fault",
    ["parse_summary", "unknown_location", "canonical", "before_status", "ciphertext", "row_time"],
)
def test_intent_corruption_is_503_without_parser_or_catalog(source_api, monkeypatch, fault):
    client, application, _settings, _calls = source_api
    selected = prepare(client, partial="both")
    body = options(client, selected)
    assert post(client, selected, body).status_code == 201
    store = application.state.analysis_service.store
    database = SourceDeterministicRecords(store)
    intent, _outcome = database.get(UUID(body["recheck_id"]))

    def change(data):
        if fault == "parse_summary":
            data["after_parse"]["summary"]["confidence"] = 0.25
        elif fault == "unknown_location":
            data["after_parse"]["unknown_locations"][0]["source_lines"] = [1]
        elif fault == "canonical":
            data["after"]["canonical_sha256"] = "b" * 64
        elif fault == "before_status":
            data["before_analysis_status"] = "completed"

    encoded_update(store, intent, terminal=False, change=change)
    with store.engine.begin() as connection:
        if fault == "row_time":
            connection.execute(
                text(
                    "UPDATE patch_deterministic_recheck_intents SET created_at='2000-01-01' "
                    "WHERE id=:key"
                ),
                {"key": body["recheck_id"]},
            )
        elif fault == "ciphertext":
            connection.execute(
                text("UPDATE patch_deterministic_recheck_intents SET payload=:bad WHERE id=:key"),
                {"key": body["recheck_id"], "bad": "invalid-owned-ciphertext"},
            )
    monkeypatch.setattr(
        workflow_module, "recheck_partial_policy", lambda *a: pytest.fail("corrupt rerun")
    )
    response = get(client, selected, body)
    assert response.status_code == 503, response.text
    assert MARKER not in response.text


@pytest.mark.parametrize("fault", ["protocol", "intent", "finding", "parse", "source"])
def test_outcome_corruption_is_unavailable(partial_saved, fault):
    store, intent, outcome = partial_saved
    database = SourceDeterministicRecords(store)
    assert database.reserve(intent)
    database.complete(outcome)

    def change(data):
        if fault == "protocol":
            data["version"] = "source-deterministic-outcome-0.1.0"
            data["execution_status"] = "failed"
            data["report"] = None
            data["failure_reason"] = "original_context_or_deterministic_result_unavailable"
        elif fault == "intent":
            data["intent_sha256"] = "b" * 64
        elif fault == "finding":
            data["report"]["before"]["policy_findings"][0]["observed"] = {"changed": True}
        elif fault == "parse":
            data["report"]["after"]["parse"]["summary"]["confidence"] = 0.25
        elif fault == "source":
            data["report"]["after"]["source_sha256"] = "b" * 64

    encoded_update(store, intent, terminal=True, change=change)
    with pytest.raises(StorageIntegrityError):
        database.get(intent.request.recheck_id)


def test_request_mismatch_is_conflict_and_retains_first_terminal_result(partial_saved):
    store, intent, outcome = partial_saved
    database = SourceDeterministicRecords(store)
    assert database.reserve(intent)
    database.complete(outcome)
    changed = intent.model_copy(
        update={
            "request": intent.request.model_copy(update={"draft_sha256": "b" * 64}),
            "selection": intent.selection.model_copy(update={"draft_sha256": "b" * 64}),
        }
    )
    with pytest.raises(PatchConflict):
        database.reserve(changed)
    failed = SourcePartialOutcome(
        recheck_id=outcome.recheck_id,
        intent_sha256=outcome.intent_sha256,
        completed_at=outcome.completed_at,
        execution_status="failed",
        failure_reason="original_context_or_deterministic_result_unavailable",
    )
    with pytest.raises(PatchConflict):
        database.complete(failed)
    saved = database.get(intent.request.recheck_id)
    assert saved is not None
    assert ml_json([row.model_dump(mode="json") for row in saved]) == (
        ml_json([intent.model_dump(mode="json"), outcome.model_dump(mode="json")])
    )


def test_same_id_http_request_mismatch_is_409(source_api):
    client, application, _settings, _calls = source_api
    selected = prepare(client)
    body = options(client, selected)
    first = post(client, selected, body)
    assert first.status_code == 201
    second = post(client, selected, body | {"allow_local_analysis_context": False})
    assert second.status_code == 409, second.text
    assert get(client, selected, body).json() == first.json()
    assert counts(application.state.analysis_service.store, UUID(body["recheck_id"])) == (1, 1)
