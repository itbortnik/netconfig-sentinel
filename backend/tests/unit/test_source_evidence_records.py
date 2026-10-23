"""Real encrypted SQLite composition, immutable replay and additive migration controls."""

import json
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from threading import Barrier, local
from uuid import uuid4

import pytest
from app.api.source_deterministic_contracts import (
    SourceDeterministicOutcome,
    SourceDeterministicRecheck,
)
from app.api.source_evidence_contracts import CreateSourceEvidenceReport, SelectedEvidenceRef
from app.api.source_ml_contracts import ml_json, source_ml_fingerprint
from app.core.settings import ApiSettings
from app.db.migrate import SCHEMA_REVISION, upgrade_database
from app.db.patch_records import PatchConflict, PatchRecords
from app.db.source_deterministic_records import SourceDeterministicRecords
from app.db.source_evidence_records import (
    SourceEvidenceInputNotFound,
    SourceEvidenceRecords,
    SourceEvidenceTooLarge,
)
from app.db.source_forest_records import SourceForestRecords
from app.db.source_ml_records import SourceMlRecords
from app.db.source_patch_records import SourcePatchRecords
from app.db.store import StorageIntegrityError, Store
from app.detection.fusion import RiskSource, fuse_risk
from cryptography.fernet import Fernet
from sqlalchemy import inspect, text
from test_original_deterministic_pair import prepared as prepared
from test_source_deterministic_records import saved_pair as saved_pair
from test_source_evidence_contracts import joint_fixture


@pytest.fixture
def saved_inputs(saved_pair):
    store, intent, outcome = saved_pair
    children = SourceDeterministicRecords(store)
    assert children.reserve(intent)
    children.complete(outcome)
    child = SourceDeterministicRecheck.from_records(intent, outcome)
    request = CreateSourceEvidenceReport(
        report_id=uuid4(),
        draft_sha256=intent.request.draft_sha256,
        deterministic=SelectedEvidenceRef(
            record_id=child.recheck_id, review_sha256=child.review_sha256
        ),
        forest=None,
        neural=None,
        network=None,
    )
    return store, intent, outcome, request


@pytest.fixture
def all_selected(tmp_path, prepared):
    captured = []

    def prepare(**kwargs):
        value = prepared(**kwargs)
        captured.append(value)
        return value

    draft, request, deterministic, forest, neural, network = joint_fixture(
        prepare, statistical=True, neural=True, network_status="error"
    )
    before, after, analysis, reference = captured[0]
    # Match the contract fixture's authored statistical context exactly; no model is trained,
    # loaded or executed in this database fixture.
    sources = [RiskSource.POLICY, RiskSource.STATISTICAL, RiskSource.PEER_GROUP]
    analysis = analysis.model_copy(
        update={
            "statistical": forest.intent.selection.original,
            "risk": fuse_risk(
                [
                    finding
                    for finding in analysis.findings
                    if finding.detector != "expected_configuration"
                ],
                device_id=before.device_id,
                completed_detectors=sources,
            ),
        }
    )
    assert source_ml_fingerprint(analysis) == deterministic.before_analysis_sha256
    store = Store(
        ApiSettings(
            f"sqlite:///{tmp_path / 'all-selected.sqlite3'}",
            "owned-joint-evidence-records-token-00001",
            Fernet.generate_key().decode(),
        )
    )
    upgrade_database(store.engine)
    for snapshot in (before, after, reference):
        store.add_configuration(snapshot)
    store.add_analysis(analysis)
    PatchRecords(store).add_draft(draft)
    for repository, child in (
        (SourceDeterministicRecords(store), deterministic),
        (SourceForestRecords(store), forest),
        (SourceMlRecords(store), neural),
        (SourcePatchRecords(store), network),
    ):
        assert repository.reserve(child.intent)
        repository.complete(child.outcome)
    try:
        yield store, draft, request, deterministic, forest, neural, network
    finally:
        store.close()


def rows(store):
    with store.engine.connect() as connection:
        return (
            connection.execute(text("SELECT count(*) FROM patch_evidence_reports")).scalar_one(),
            connection.execute(
                text(
                    "SELECT count(*) FROM audit_events WHERE action='patch.evidence_report_created'"
                )
            ).scalar_one(),
        )


def test_encrypted_exact_replay_keeps_original_time_and_one_audit(saved_inputs):
    store, intent, _outcome, request = saved_inputs
    database = SourceEvidenceRecords(store)
    first = database.prepare(intent.patch_id, request)
    assert database.add(first) == (first, True)
    later = database.prepare(intent.patch_id, request)
    assert later.created_at > first.created_at
    assert database.add(later) == (first, False)
    assert database.get(request.report_id) == first
    assert database.get(uuid4()) is None
    assert database.list_ids(intent.patch_id, limit=10, offset=0) == [request.report_id]
    assert database.list_ids(intent.patch_id, limit=10, offset=1) == []
    assert database.list_ids(uuid4(), limit=10, offset=0) == []
    assert rows(store) == (1, 1)
    with store.engine.connect() as connection:
        payload = connection.execute(
            text("SELECT payload FROM patch_evidence_reports")
        ).scalar_one()
        audit = connection.execute(
            text("SELECT action,resource_id FROM audit_events WHERE action=:action"),
            {"action": "patch.evidence_report_created"},
        ).one()
    assert str(request.report_id) not in payload
    assert intent.before.source_sha256 not in payload
    assert first.review_json not in payload
    assert audit == ("patch.evidence_report_created", str(request.report_id))
    assert first.formal_qualification == "not_proven" and first.quality_proven is False


def test_selected_optional_records_are_integrity_checked_and_keep_actual_results(
    all_selected, monkeypatch
):
    store, draft, request, _deterministic, forest, neural, network = all_selected
    database = SourceEvidenceRecords(store)

    def forbidden(*args, **kwargs):
        pytest.fail("selected composition executed a model, engine or raw source lookup")

    for name in ("get_model", "get_configuration"):
        monkeypatch.setattr(store, name, forbidden)
    for name in (
        "app.db.source_records.SourceRecords.get",
        "app.detection.statistical.pair.recheck_original_forest",
        "app.verification.batfish.check_with_batfish",
        "app.patching.source_ml.run_configuration_pair_job",
    ):
        monkeypatch.setattr(name, forbidden)
    report = database.prepare(draft.patch_id, request)
    assert report.forest.scores == forest.outcome.report.scores
    assert (
        report.neural.before.anomaly_score == neural.outcome.report.before.prediction.anomaly_score
    )
    assert report.network.result == network.outcome.network_result
    assert report.network.result.status == "error"
    assert report.formal_qualification == "not_proven"
    assert "formal_scope_not_passed" in report.validation_blockers
    assert database.add(report) == (report, True)
    assert database.get(request.report_id) == report
    assert rows(store) == (1, 1)


@pytest.mark.parametrize("kind", ["forest", "neural", "network"])
def test_optional_selected_dependency_removal_is_404_before_creation_and_503_after(
    all_selected, kind
):
    store, draft, request, *_ = all_selected
    database = SourceEvidenceRecords(store)
    report = database.prepare(draft.patch_id, request)
    assert database.add(report) == (report, True)
    table, outcome, column = {
        "forest": (
            "patch_statistical_recheck_intents",
            "patch_statistical_recheck_outcomes",
            "recheck_id",
        ),
        "neural": ("patch_ml_recheck_intents", "patch_ml_recheck_outcomes", "recheck_id"),
        "network": (
            "patch_network_review_intents",
            "patch_network_review_outcomes",
            "verification_id",
        ),
    }[kind]
    key = str(getattr(request, kind).record_id)
    with store.engine.begin() as connection:
        connection.execute(text(f"DELETE FROM {outcome} WHERE {column}=:key"), {"key": key})
        connection.execute(text(f"DELETE FROM {table} WHERE id=:key"), {"key": key})
    with pytest.raises(SourceEvidenceInputNotFound):
        database.prepare(draft.patch_id, request.model_copy(update={"report_id": uuid4()}))
    with pytest.raises(StorageIntegrityError):
        database.get(request.report_id)
    assert rows(store) == (1, 1)


def test_history_and_creation_need_no_raw_reference_model_or_execution(saved_inputs, monkeypatch):
    store, intent, _outcome, request = saved_inputs
    database = SourceEvidenceRecords(store)
    report = database.prepare(intent.patch_id, request)
    assert database.add(report) == (report, True)
    with store.engine.begin() as connection:
        connection.execute(text("DELETE FROM configuration_sources"))
        connection.execute(text("DELETE FROM models"))
        connection.execute(
            text("DELETE FROM configurations WHERE id=:key"),
            {"key": str(intent.selection.reference.configuration_id)},
        )

    def forbidden(*args, **kwargs):
        pytest.fail("composition loaded raw/model/reference or executed a detector/engine")

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
    assert database.get(request.report_id) == report
    assert database.add(database.prepare(intent.patch_id, request)) == (report, False)
    assert rows(store) == (1, 1)


def test_missing_inputs_and_request_binding_conflicts_are_distinct(saved_inputs):
    store, intent, _outcome, request = saved_inputs
    database = SourceEvidenceRecords(store)
    with pytest.raises(SourceEvidenceInputNotFound):
        database.prepare(uuid4(), request)
    missing = request.model_copy(
        update={"deterministic": request.deterministic.model_copy(update={"record_id": uuid4()})}
    )
    with pytest.raises(SourceEvidenceInputNotFound):
        database.prepare(intent.patch_id, missing)
    changed = request.model_copy(update={"draft_sha256": "b" * 64})
    with pytest.raises(PatchConflict):
        database.prepare(intent.patch_id, changed)
    changed = request.model_copy(
        update={
            "deterministic": request.deterministic.model_copy(update={"review_sha256": "b" * 64})
        }
    )
    with pytest.raises(PatchConflict):
        database.prepare(intent.patch_id, changed)
    assert rows(store) == (0, 0)


def test_incomplete_existing_child_cannot_be_composed(saved_inputs):
    store, intent, _outcome, request = saved_inputs
    with store.engine.begin() as connection:
        connection.execute(text("DELETE FROM patch_deterministic_recheck_outcomes"))
    with pytest.raises(PatchConflict):
        SourceEvidenceRecords(store).prepare(intent.patch_id, request)
    assert rows(store) == (0, 0)


def test_changed_request_uuid_conflicts_with_original_report(saved_inputs):
    store, intent, outcome, request = saved_inputs
    database = SourceEvidenceRecords(store)
    report = database.prepare(intent.patch_id, request)
    assert database.add(report) == (report, True)
    new_intent = intent.model_copy(
        update={"request": intent.request.model_copy(update={"recheck_id": uuid4()})}
    )
    new_outcome = SourceDeterministicOutcome.model_validate(
        outcome.model_dump()
        | {
            "recheck_id": new_intent.request.recheck_id,
            "intent_sha256": source_ml_fingerprint(new_intent),
        }
    )
    children = SourceDeterministicRecords(store)
    assert children.reserve(new_intent)
    children.complete(new_outcome)
    child = SourceDeterministicRecheck.from_records(new_intent, new_outcome)
    different = request.model_copy(
        update={
            "deterministic": SelectedEvidenceRef(
                record_id=child.recheck_id, review_sha256=child.review_sha256
            )
        }
    )
    with pytest.raises(PatchConflict):
        database.add(database.prepare(intent.patch_id, different))
    assert database.get(request.report_id) == report
    assert rows(store) == (1, 1)


def test_add_rechecks_the_exact_projection_after_prepare(saved_inputs):
    store, intent, _outcome, request = saved_inputs
    database = SourceEvidenceRecords(store)
    report = database.prepare(intent.patch_id, request)
    data = report.model_dump(mode="json")
    data["deterministic"]["policy_catalog_version"] = "forged-projection"
    proof = ml_json(
        {
            name: value
            for name, value in data.items()
            if name not in {"review_json", "review_sha256"}
        }
    )
    data.update(review_json=proof, review_sha256=sha256(proof.encode()).hexdigest())
    forged = type(report).model_validate(data)
    with pytest.raises(PatchConflict):
        database.add(forged)
    assert rows(store) == (0, 0)


def test_list_ids_orders_saved_report_time_and_keeps_distinct_report_ids(saved_inputs):
    store, intent, _outcome, request = saved_inputs
    database = SourceEvidenceRecords(store)
    first = database.prepare(intent.patch_id, request)
    second = database.prepare(intent.patch_id, request.model_copy(update={"report_id": uuid4()}))
    assert database.add(first)[1]
    assert database.add(second)[1]
    assert database.list_ids(intent.patch_id, limit=10, offset=0) == [
        second.report_id,
        first.report_id,
    ]
    assert database.list_ids(intent.patch_id, limit=1, offset=1) == [first.report_id]
    assert rows(store) == (2, 2)


def test_audit_failure_rolls_back_report_atomically(saved_inputs, monkeypatch):
    store, intent, _outcome, request = saved_inputs
    database = SourceEvidenceRecords(store)
    report = database.prepare(intent.patch_id, request)

    def fail(session, key):
        raise RuntimeError("owned injected report audit failure")

    monkeypatch.setattr(SourceEvidenceRecords, "_audit", staticmethod(fail))
    with pytest.raises(RuntimeError, match="owned injected report audit failure"):
        database.add(report)
    assert rows(store) == (0, 0)
    assert database.get(request.report_id) is None


@pytest.mark.parametrize(
    "fault", ["metadata", "relocated", "projection", "proof", "child", "missing"]
)
def test_authenticated_report_and_selected_dependency_tamper_refuse(saved_inputs, fault):
    store, intent, _outcome, request = saved_inputs
    database = SourceEvidenceRecords(store)
    report = database.prepare(intent.patch_id, request)
    assert database.add(report) == (report, True)
    key = str(request.report_id)
    with store.engine.begin() as connection:
        if fault == "metadata":
            connection.execute(
                text("UPDATE patch_evidence_reports SET created_at='2000-01-01 00:00:00'")
            )
        elif fault in {"child", "missing"}:
            if fault == "missing":
                connection.execute(text("DELETE FROM patch_deterministic_recheck_outcomes"))
            else:
                child_key = str(request.deterministic.record_id)
                payload = connection.execute(
                    text("SELECT payload FROM patch_deterministic_recheck_outcomes")
                ).scalar_one()
                data = json.loads(
                    store._decode(payload, kind="source_deterministic_outcome", row_id=child_key)
                )
                data["completed_at"] = (datetime.now(UTC) + timedelta(seconds=1)).isoformat()
                connection.execute(
                    text("UPDATE patch_deterministic_recheck_outcomes SET payload=:payload"),
                    {
                        "payload": store._encode(
                            json.dumps(data), kind="source_deterministic_outcome", row_id=child_key
                        )
                    },
                )
        else:
            data = report.model_dump(mode="json")
            if fault == "projection":
                data["deterministic"]["policy_catalog_version"] = "another-saved-catalog"
                proof = ml_json(
                    {
                        name: value
                        for name, value in data.items()
                        if name not in {"review_json", "review_sha256"}
                    }
                )
                data.update(review_json=proof, review_sha256=sha256(proof.encode()).hexdigest())
            elif fault == "proof":
                data["review_sha256"] = "b" * 64
            connection.execute(
                text("UPDATE patch_evidence_reports SET payload=:payload"),
                {
                    "payload": store._encode(
                        json.dumps(data),
                        kind="source_evidence_report",
                        row_id=str(uuid4()) if fault == "relocated" else key,
                    )
                },
            )
    with pytest.raises(StorageIntegrityError, match="Stored data is unavailable"):
        database.get(request.report_id)


@pytest.mark.parametrize("budget", ["input", "plain", "cipher", "proof"])
def test_creation_budget_refusal_is_atomic(saved_inputs, monkeypatch, budget):
    import app.api.source_evidence_contracts as contracts
    import app.db.source_evidence_records as records

    store, intent, _outcome, request = saved_inputs
    database = SourceEvidenceRecords(store)
    report = database.prepare(intent.patch_id, request)
    if budget == "input":
        monkeypatch.setattr(records, "MAX_SOURCE_EVIDENCE_INPUT_BYTES", 1)
    elif budget == "plain":
        monkeypatch.setattr(records, "MAX_SOURCE_EVIDENCE_BYTES", 1)
    elif budget == "proof":
        monkeypatch.setattr(contracts, "MAX_SOURCE_EVIDENCE_BYTES", 1)
    else:
        monkeypatch.setattr(records, "MAX_SOURCE_EVIDENCE_CIPHERTEXT_BYTES", 1)
    with pytest.raises(SourceEvidenceTooLarge):
        if budget == "cipher":
            database.add(report)
        else:
            database.prepare(intent.patch_id, request)
    with pytest.raises(SourceEvidenceTooLarge):
        database.add(report)
    assert rows(store) == (0, 0)


@pytest.mark.parametrize("budget", ["input", "plain", "cipher", "proof"])
def test_stored_oversize_refuses_as_integrity_error(saved_inputs, monkeypatch, budget):
    import app.api.source_evidence_contracts as contracts
    import app.db.source_evidence_records as records

    store, intent, _outcome, request = saved_inputs
    database = SourceEvidenceRecords(store)
    report = database.prepare(intent.patch_id, request)
    assert database.add(report) == (report, True)
    target, constant = {
        "input": (records, "MAX_SOURCE_EVIDENCE_INPUT_BYTES"),
        "plain": (records, "MAX_SOURCE_EVIDENCE_BYTES"),
        "cipher": (records, "MAX_SOURCE_EVIDENCE_CIPHERTEXT_BYTES"),
        "proof": (contracts, "MAX_SOURCE_EVIDENCE_BYTES"),
    }[budget]
    monkeypatch.setattr(target, constant, 1)
    with pytest.raises(StorageIntegrityError):
        database.get(request.report_id)
    assert rows(store) == (1, 1)


def test_two_insertion_writers_return_one_saved_winner(saved_inputs, monkeypatch):
    store, intent, _outcome, request = saved_inputs
    database = SourceEvidenceRecords(store)
    reports = [database.prepare(intent.patch_id, request) for _ in range(2)]
    original = SourceEvidenceRecords._get
    barrier, state = Barrier(2), local()

    def synchronized(self, session, report_id):
        value = original(self, session, report_id)
        if not getattr(state, "seen", False):
            state.seen = True
            barrier.wait(timeout=10)
        return value

    monkeypatch.setattr(SourceEvidenceRecords, "_get", synchronized)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(database.add, reports))
    monkeypatch.setattr(SourceEvidenceRecords, "_get", original)
    assert sorted(created for _report, created in results) == [False, True]
    assert results[0][0] == results[1][0] == database.get(request.report_id)
    assert rows(store) == (1, 1)


def test_populated_14_to_15_upgrade_is_additive_and_repeatable(saved_inputs):
    store, intent, _outcome, request = saved_inputs
    with store.engine.begin() as connection:
        connection.exec_driver_sql("DROP TABLE patch_risk_assessments")
        connection.exec_driver_sql("DROP TABLE patch_evidence_decisions")
        connection.exec_driver_sql("DROP TABLE patch_evidence_reports")
        connection.execute(
            text("UPDATE alembic_version SET version_num='0014_deterministic_rechecks'")
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
    assert SCHEMA_REVISION == "0017_source_risk_assessments"
    assert store.ready() and physical() == before
    database = SourceEvidenceRecords(store)
    assert database.add(database.prepare(intent.patch_id, request))[1]
    assert rows(store) == (1, 1)
