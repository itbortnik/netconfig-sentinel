"""Encrypted deterministic history and additive schema; authored controls, not quality."""

import json
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from app.api.contracts import SnapshotBinding
from app.api.model_patch_contracts import fingerprint
from app.api.patch_contracts import CreatePatchDraft
from app.api.source_deterministic_contracts import (
    OriginalDeterministicContext,
    RunSourceDeterministicRecheck,
    SourceDeterministicIntent,
    SourceDeterministicMember,
    SourceDeterministicOutcome,
    SourceDeterministicReport,
    SourceDeterministicSelection,
)
from app.api.source_ml_contracts import ml_json, source_ml_fingerprint
from app.core.settings import ApiSettings
from app.db.migrate import upgrade_database
from app.db.patch_records import PatchConflict
from app.db.source_deterministic_records import SourceDeterministicRecords
from app.db.store import StorageIntegrityError, Store
from app.detection.baseline.pair import prepare_original_reference, recheck_original_deterministic
from app.ingestion.source_retention import canonical_fingerprint
from app.patching.persistent import PatchWorkflow
from cryptography.fernet import Fernet
from sqlalchemy import inspect, text
from test_original_deterministic_pair import prepared as prepared
from test_original_deterministic_pair import text as authored_text


def member(snapshot):
    return SourceDeterministicMember.model_validate(
        SnapshotBinding.from_snapshot(snapshot).model_dump()
        | {"canonical_sha256": canonical_fingerprint(snapshot)}
    )


@pytest.fixture
def saved_pair(tmp_path, prepared):
    before, after, analysis, reference = prepared()
    store = Store(
        ApiSettings(
            f"sqlite:///{tmp_path / 'durable.sqlite3'}",
            "owned-deterministic-records-token-00001",
            Fernet.generate_key().decode(),
        )
    )
    upgrade_database(store.engine)
    store.add_configuration(reference)
    for snapshot, content in (
        (before, authored_text("cisco", "target", 12, True)),
        (after, authored_text("cisco", "target", 13, False)),
    ):
        store.add_configuration(snapshot, retain_original_source=True, original_source=content)
    store.add_analysis(analysis)
    draft, _created = PatchWorkflow(store).create(
        CreatePatchDraft(
            patch_id=uuid4(),
            before_configuration_id=before.configuration_id,
            after_configuration_id=after.configuration_id,
            before_source_sha256=before.canonical.source.sha256,
            after_source_sha256=after.canonical.source.sha256,
        )
    )
    request = RunSourceDeterministicRecheck(
        recheck_id=uuid4(),
        draft_sha256=draft.draft_sha256,
        before_analysis_id=analysis.analysis_id,
        before_analysis_sha256=fingerprint(analysis),
        reference_canonical_sha256=canonical_fingerprint(reference),
        allow_local_analysis_context=True,
    )
    selection = SourceDeterministicSelection(
        patch_id=draft.patch_id,
        draft_sha256=draft.draft_sha256,
        before=SnapshotBinding.from_snapshot(before),
        before_analysis_id=analysis.analysis_id,
        before_analysis_sha256=request.before_analysis_sha256,
        before_analysis_created_at=analysis.created_at,
        original=OriginalDeterministicContext.from_analysis(analysis),
        reference=member(reference),
    )
    intent = SourceDeterministicIntent(
        patch_id=draft.patch_id,
        request=request,
        before=member(before),
        after=member(after),
        selection=selection,
        reference_projection=prepare_original_reference(before, analysis, reference),
        created_at=datetime.now(UTC),
    )
    report = SourceDeterministicReport.from_pair(
        intent, recheck_original_deterministic(before, after, analysis, reference)
    )
    outcome = SourceDeterministicOutcome(
        recheck_id=request.recheck_id,
        intent_sha256=source_ml_fingerprint(intent),
        completed_at=datetime.now(UTC),
        execution_status="completed",
        report=report,
    )
    try:
        yield store, intent, outcome
    finally:
        store.close()


def counts(store):
    with store.engine.connect() as connection:
        return tuple(
            connection.execute(text(f"SELECT count(*) FROM {name}")).scalar_one()
            for name in (
                "patch_deterministic_recheck_intents",
                "patch_deterministic_recheck_outcomes",
            )
        )


def assert_records(actual, intent, outcome):
    assert actual is not None
    assert ml_json([row.model_dump(mode="json") if row else None for row in actual]) == ml_json(
        [row.model_dump(mode="json") if row else None for row in (intent, outcome)]
    )


def test_replay_and_history_survive_reference_and_raw_source_removal(saved_pair, monkeypatch):
    store, intent, outcome = saved_pair
    database = SourceDeterministicRecords(store)
    assert database.reserve(intent)
    assert database.get(intent.request.recheck_id) == (intent, None)
    database.complete(outcome)
    with store.engine.begin() as connection:
        connection.execute(text("DELETE FROM configuration_sources"))
        connection.execute(
            text("DELETE FROM configurations WHERE id=:key"),
            {"key": str(intent.selection.reference.configuration_id)},
        )

    def forbidden(*args, **kwargs):
        pytest.fail("history read source/model/reference or executed a detector")

    for name in ("get_model", "get_configuration"):
        monkeypatch.setattr(store, name, forbidden)
    for name in (
        "app.db.source_records.SourceRecords.get",
        "app.ingestion.source_retention.prepare_original_source",
        "app.detection.baseline.pair.recheck_original_deterministic",
        "app.detection.baseline.pair.prepare_original_reference",
        "app.detection.baseline.pair.require_original_deterministic_context",
        "app.detection.policy_engine.evaluate_policies",
    ):
        monkeypatch.setattr(name, forbidden)
    assert not database.reserve(intent)
    assert_records(database.get(intent.request.recheck_id), intent, outcome)
    database.complete(outcome)
    assert database.list_ids(intent.patch_id, limit=20, offset=0) == [intent.request.recheck_id]
    assert counts(store) == (1, 1)


@pytest.mark.parametrize("phase", ["requested", "completed"])
def test_domain_audit_failure_rolls_back_only_its_atomic_sibling(saved_pair, monkeypatch, phase):
    store, intent, outcome = saved_pair
    database = SourceDeterministicRecords(store)
    original = SourceDeterministicRecords._audit

    def fail(session, action, key):
        if action == f"patch.deterministic_recheck_{phase}":
            raise RuntimeError("owned injected audit failure")
        original(session, action, key)

    monkeypatch.setattr(SourceDeterministicRecords, "_audit", staticmethod(fail))
    with pytest.raises(RuntimeError, match="owned injected audit failure"):
        assert database.reserve(intent)
        database.complete(outcome)
    assert counts(store) == ((0, 0) if phase == "requested" else (1, 0))
    if phase == "completed":
        assert database.get(intent.request.recheck_id) == (intent, None)


@pytest.mark.parametrize(
    "fault",
    [
        "canonical",
        "analysis",
        "original_observation",
        "reference_projection",
        "outcome_intent",
        "outcome_source",
        "ciphertext",
        "row_time",
    ],
)
def test_authenticated_tamper_and_ciphertext_relocation_refuse(saved_pair, fault):
    store, intent, outcome = saved_pair
    database = SourceDeterministicRecords(store)
    assert database.reserve(intent)
    database.complete(outcome)
    terminal = fault.startswith("outcome")
    table = (
        "patch_deterministic_recheck_outcomes"
        if terminal
        else "patch_deterministic_recheck_intents"
    )
    column, kind = (
        ("recheck_id", "source_deterministic_outcome")
        if terminal
        else ("id", "source_deterministic_intent")
    )
    key = str(intent.request.recheck_id)
    with store.engine.connect() as connection:
        payload = connection.execute(
            text(f"SELECT payload FROM {table} WHERE {column}=:key"), {"key": key}
        ).scalar_one()
    data = json.loads(store._decode(payload, kind=kind, row_id=key))
    if fault == "canonical":
        data["after"]["canonical_sha256"] = "b" * 64
    elif fault == "analysis":
        data["request"]["before_analysis_sha256"] = "b" * 64
        data["selection"]["before_analysis_sha256"] = "b" * 64
    elif fault == "original_observation":
        data["selection"]["original"]["findings"][0]["observed"] = {"changed": "owned"}
    elif fault == "reference_projection":
        data["reference_projection"]["source_sha256"] = "b" * 64
    elif fault == "outcome_intent":
        data["intent_sha256"] = "b" * 64
    elif fault == "outcome_source":
        data["report"]["after"]["source_sha256"] = "b" * 64
    encoded = store._encode(
        json.dumps(data), kind=kind, row_id=str(uuid4()) if fault == "ciphertext" else key
    )
    with store.engine.begin() as connection:
        connection.execute(
            text(f"UPDATE {table} SET payload=:payload WHERE {column}=:key"),
            {"key": key, "payload": encoded},
        )
        if fault == "row_time":
            connection.execute(
                text(f"UPDATE {table} SET created_at='2000-01-01 00:00:00' WHERE {column}=:key"),
                {"key": key},
            )
    with pytest.raises(StorageIntegrityError, match="Stored data is unavailable"):
        database.get(intent.request.recheck_id)


def test_one_reservation_winner_under_two_sessions(saved_pair):
    store, intent, _outcome = saved_pair
    with ThreadPoolExecutor(max_workers=2) as pool:
        wins = list(pool.map(lambda _: SourceDeterministicRecords(store).reserve(intent), range(2)))
    assert sorted(wins) == [False, True] and counts(store) == (1, 0)


def test_immutable_request_identity_and_terminal_outcome(saved_pair):
    store, intent, outcome = saved_pair
    database = SourceDeterministicRecords(store)
    assert database.reserve(intent)
    altered = intent.model_copy(
        update={
            "request": intent.request.model_copy(
                update={"recheck_id": intent.request.recheck_id, "before_analysis_sha256": "b" * 64}
            ),
            "selection": intent.selection.model_copy(update={"before_analysis_sha256": "b" * 64}),
        }
    )
    with pytest.raises(PatchConflict):
        database.reserve(altered)
    database.complete(outcome)
    failed = SourceDeterministicOutcome(
        recheck_id=outcome.recheck_id,
        intent_sha256=outcome.intent_sha256,
        completed_at=outcome.completed_at,
        execution_status="failed",
        failure_reason="original_context_or_deterministic_result_unavailable",
    )
    with pytest.raises(PatchConflict):
        database.complete(failed)
    assert_records(database.get(intent.request.recheck_id), intent, outcome)


def test_populated_13_to_14_upgrade_is_additive_and_repeatable(saved_pair):
    store, intent, outcome = saved_pair
    with store.engine.begin() as connection:
        connection.exec_driver_sql("DROP TABLE patch_risk_assessments")
        connection.exec_driver_sql("DROP TABLE patch_evidence_decisions")
        connection.exec_driver_sql("DROP TABLE patch_evidence_reports")
        connection.exec_driver_sql("DROP TABLE patch_deterministic_recheck_outcomes")
        connection.exec_driver_sql("DROP TABLE patch_deterministic_recheck_intents")
        connection.execute(
            text("UPDATE alembic_version SET version_num='0013_source_forest_rechecks'")
        )
    names = set(inspect(store.engine).get_table_names()) - {"alembic_version"}

    def physical():
        with store.engine.connect() as connection:
            return {
                name: sorted(map(repr, connection.execute(text(f'SELECT * FROM "{name}"')).all()))
                for name in names
            }

    before = physical()
    assert not store.ready()
    upgrade_database(store.engine)
    upgrade_database(store.engine)
    assert store.ready() and physical() == before
    assert SourceDeterministicRecords(store).reserve(intent)
    SourceDeterministicRecords(store).complete(outcome)


@pytest.mark.parametrize("phase", ["reserve", "complete", "read"])
def test_record_budget_refusal_is_atomic(saved_pair, monkeypatch, phase):
    import app.db.source_deterministic_records as records_module

    store, intent, outcome = saved_pair
    database = SourceDeterministicRecords(store)
    if phase != "reserve":
        assert database.reserve(intent)
    monkeypatch.setattr(records_module, "MAX_SOURCE_DETERMINISTIC_BYTES", 1)
    with pytest.raises(StorageIntegrityError):
        if phase == "reserve":
            database.reserve(intent)
        elif phase == "complete":
            database.complete(outcome)
        else:
            database.get(intent.request.recheck_id)
    assert counts(store) == ((0, 0) if phase == "reserve" else (1, 0))


def test_two_terminal_writers_keep_one_outcome_and_one_audit(saved_pair, monkeypatch):
    from threading import Barrier, local

    store, intent, outcome = saved_pair
    database = SourceDeterministicRecords(store)
    assert database.reserve(intent)
    original = SourceDeterministicRecords._get
    barrier, state = Barrier(2), local()

    def synchronized(self, session, key):
        value = original(self, session, key)
        if not getattr(state, "seen", False):
            state.seen = True
            barrier.wait(timeout=10)
        return value

    monkeypatch.setattr(SourceDeterministicRecords, "_get", synchronized)
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(lambda _: SourceDeterministicRecords(store).complete(outcome), range(2)))
    monkeypatch.setattr(SourceDeterministicRecords, "_get", original)
    assert_records(database.get(intent.request.recheck_id), intent, outcome)
    assert counts(store) == (1, 1)
    with store.engine.connect() as connection:
        assert (
            connection.execute(
                text(
                    "SELECT count(*) FROM audit_events "
                    "WHERE action='patch.deterministic_recheck_completed'"
                )
            ).scalar_one()
            == 1
        )
