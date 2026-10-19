"""Real SQLite encrypted records; no ordinary HTTP workflow or source admission claim."""

import json
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from app.api.model_patch_contracts import fingerprint
from app.api.patch_contracts import CreatePatchDraft
from app.api.source_forest_contracts import SourceForestIntent, SourceForestOutcome
from app.api.source_ml_contracts import source_ml_fingerprint
from app.core.settings import ApiSettings
from app.db.migrate import upgrade_database
from app.db.source_forest_records import SourceForestRecords
from app.db.store import StorageIntegrityError, Store
from app.detection.statistical.artifact import ForestArtifact
from app.patching.persistent import PatchWorkflow
from cryptography.fernet import Fernet
from sqlalchemy import inspect, text
from test_original_forest_pair import authored_target_sources
from test_original_forest_pair import selected_forest_pair as selected_forest_pair
from test_source_forest_contracts import records


@pytest.fixture
def saved_pair(tmp_path, selected_forest_pair):
    before, after, analysis, model = selected_forest_pair
    store = Store(
        ApiSettings(
            f"sqlite:///{tmp_path / 'history.sqlite3'}",
            "owned-source-forest-records-token-00001",
            Fernet.generate_key().decode(),
        )
    )
    upgrade_database(store.engine)
    for snapshot, original in zip(
        (before, after), authored_target_sources(str(before.canonical.device.vendor)), strict=True
    ):
        store.add_configuration(snapshot, retain_original_source=True, original_source=original)
    store.add_model(model)
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
    old, old_outcome = records(selected_forest_pair)
    data = old.model_dump(mode="json")
    data.update(patch_id=str(draft.patch_id), created_at=datetime.now(UTC).isoformat())
    for field in (data["request"], data["selection"]):
        field.update(draft_sha256=draft.draft_sha256, before_analysis_sha256=fingerprint(analysis))
    data["selection"]["patch_id"] = str(draft.patch_id)
    intent = SourceForestIntent.model_validate(data)
    outcome = SourceForestOutcome.model_validate(
        old_outcome.model_dump(mode="json")
        | {
            "intent_sha256": source_ml_fingerprint(intent),
            "completed_at": datetime.now(UTC).isoformat(),
        }
    )
    try:
        yield store, intent, outcome
    finally:
        store.close()


def counts(store):
    with store.engine.connect() as connection:
        return tuple(
            connection.execute(text(f"SELECT count(*) FROM {name}")).scalar_one()
            for name in ("patch_statistical_recheck_intents", "patch_statistical_recheck_outcomes")
        )


def test_exact_replay_and_history_do_not_load_original_model_or_evaluate(saved_pair, monkeypatch):
    store, intent, outcome = saved_pair
    database = SourceForestRecords(store)
    assert database.reserve(intent)
    assert database.get(intent.request.recheck_id) == (intent, None)
    database.complete(outcome)

    def forbidden(*args, **kwargs):
        pytest.fail("history loaded model/original or evaluated")

    monkeypatch.setattr(store, "get_model", forbidden)
    monkeypatch.setattr(ForestArtifact, "score_samples", forbidden)
    monkeypatch.setattr("app.db.source_records.SourceRecords.get", forbidden)
    monkeypatch.setattr("app.ingestion.source_retention.prepare_original_source", forbidden)
    assert not database.reserve(intent)
    assert database.get(intent.request.recheck_id) == (intent, outcome)
    database.complete(outcome)
    assert database.list_ids(intent.patch_id, limit=20, offset=0) == [intent.request.recheck_id]
    assert counts(store) == (1, 1)


@pytest.mark.parametrize("phase", ["requested", "completed"])
def test_domain_audit_failure_rolls_back_only_its_atomic_sibling(saved_pair, monkeypatch, phase):
    store, intent, outcome = saved_pair
    database = SourceForestRecords(store)
    original = SourceForestRecords._audit

    def fail(session, action, key):
        if action == f"patch.statistical_recheck_{phase}":
            raise RuntimeError("owned injected audit failure")
        original(session, action, key)

    monkeypatch.setattr(SourceForestRecords, "_audit", staticmethod(fail))
    with pytest.raises(RuntimeError, match="owned injected audit failure"):
        assert database.reserve(intent)
        database.complete(outcome)
    assert counts(store) == ((0, 0) if phase == "requested" else (1, 0))
    if phase == "completed":
        assert database.get(intent.request.recheck_id) == (intent, None)


@pytest.mark.parametrize(
    "fault",
    ["canonical", "analysis", "original_tuple", "outcome_intent", "outcome_number", "ciphertext"],
)
def test_authenticated_tamper_or_ciphertext_relocation_refuses(saved_pair, fault):
    store, intent, outcome = saved_pair
    database = SourceForestRecords(store)
    assert database.reserve(intent)
    database.complete(outcome)
    terminal = fault.startswith("outcome")
    table = (
        "patch_statistical_recheck_outcomes" if terminal else "patch_statistical_recheck_intents"
    )
    column, kind = (
        ("recheck_id", "source_forest_outcome") if terminal else ("id", "source_forest_intent")
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
    elif fault == "original_tuple":
        data["selection"]["original"]["score_samples"] += 1e-6
        data["selection"]["original"]["decision_function"] += 1e-6
        data["selection"]["original"]["prediction"] = (
            -1 if data["selection"]["original"]["decision_function"] < 0 else 1
        )
    elif fault == "outcome_intent":
        data["intent_sha256"] = "b" * 64
    elif fault == "outcome_number":
        data["report"]["scores"]["after_decision_function"] += 1e-6
    encoded = store._encode(
        json.dumps(data), kind=kind, row_id=str(uuid4()) if fault == "ciphertext" else key
    )
    with store.engine.begin() as connection:
        connection.execute(
            text(f"UPDATE {table} SET payload=:payload WHERE {column}=:key"),
            {"key": key, "payload": encoded},
        )
    with pytest.raises(StorageIntegrityError, match="Stored data is unavailable"):
        database.get(intent.request.recheck_id)


def test_one_reservation_winner_under_two_sessions(saved_pair):
    store, intent, _outcome = saved_pair
    with ThreadPoolExecutor(max_workers=2) as pool:
        wins = list(pool.map(lambda _: SourceForestRecords(store).reserve(intent), range(2)))
    assert sorted(wins) == [False, True] and counts(store) == (1, 0)


def test_populated_12_to_13_upgrade_is_additive_and_repeatable(saved_pair):
    store, intent, outcome = saved_pair
    with store.engine.begin() as connection:
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

    before = physical()
    assert not store.ready()
    upgrade_database(store.engine)
    upgrade_database(store.engine)
    assert store.ready() and physical() == before
    assert SourceForestRecords(store).reserve(intent)
    SourceForestRecords(store).complete(outcome)
