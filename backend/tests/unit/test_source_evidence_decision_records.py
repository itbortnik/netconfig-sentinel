"""Encrypted SQLite disposition controls over actual integrity-checked saved reports."""

import json
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, timedelta, timezone
from hashlib import sha256
from threading import Barrier, local
from uuid import uuid4

import pytest
from app.api.source_evidence_decision_contracts import SourceEvidenceDecision
from app.api.source_ml_contracts import ml_json
from app.core.settings import ApiSettings
from app.db.migrate import SCHEMA_REVISION, upgrade_database
from app.db.patch_records import PatchConflict, PatchRecords
from app.db.source_deterministic_records import SourceDeterministicRecords
from app.db.source_evidence_decision_records import (
    SourceEvidenceDecisionInputNotFound,
    SourceEvidenceDecisionRecords,
    SourceEvidenceDecisionTooLarge,
)
from app.db.source_evidence_records import SourceEvidenceRecords
from app.db.source_patch_records import SourcePatchRecords
from app.db.store import StorageIntegrityError, Store
from app.db.tables import SourceEvidenceDecisionRow
from cryptography.fernet import Fernet
from sqlalchemy import inspect, text
from test_original_deterministic_pair import prepared as prepared
from test_original_deterministic_pair import text as authored_text
from test_source_evidence_contracts import joint_fixture
from test_source_evidence_decision_contracts import request as decision_request
from test_source_evidence_decision_contracts import reseal


@pytest.fixture
def saved_report(tmp_path, prepared):
    captured = []

    def prepare(**kwargs):
        value = prepared(**kwargs)
        captured.append(value)
        return value

    draft, request, deterministic, _forest, _neural, network = joint_fixture(
        prepare, network_status="error"
    )
    before, after, analysis, reference = captured[0]
    settings = ApiSettings(
        f"sqlite:///{tmp_path / 'dispositions.sqlite3'}",
        "owned-evidence-decision-records-token-00001",
        Fernet.generate_key().decode(),
    )
    store = Store(settings)
    upgrade_database(store.engine)
    store.add_configuration(reference)
    for snapshot, content in (
        (before, authored_text("cisco", "target", 12, True)),
        (after, authored_text("cisco", "target", 13, False)),
    ):
        store.add_configuration(snapshot, retain_original_source=True, original_source=content)
    store.add_analysis(analysis)
    assert PatchRecords(store).add_draft(draft)[1]
    for records, child in (
        (SourceDeterministicRecords(store), deterministic),
        (SourcePatchRecords(store), network),
    ):
        assert records.reserve(child.intent)
        records.complete(child.outcome)
    reports = SourceEvidenceRecords(store)
    report, created = reports.add(reports.prepare(draft.patch_id, request))
    assert created
    try:
        yield store, settings, report, deterministic
    finally:
        store.close()


def counts(store):
    with store.engine.connect() as connection:
        return (
            connection.execute(text("SELECT count(*) FROM patch_evidence_decisions")).scalar_one(),
            connection.execute(
                text(
                    "SELECT count(*) FROM audit_events "
                    "WHERE action='patch.evidence_decision_recorded'"
                )
            ).scalar_one(),
        )


def prepare(database, report, request=None, role="engineer"):
    return database.prepare(
        report.patch_id,
        report.report_id,
        request or decision_request(report),
        service_role=role,
    )


def test_encrypted_append_only_disposition_preserves_report_and_service_role(saved_report):
    store, _settings, report, _deterministic = saved_report
    database = SourceEvidenceDecisionRecords(store)
    request = decision_request(report, comment="Owned private disposition text.")
    before = SourceEvidenceRecords(store).get(report.report_id)
    first = prepare(database, report, request)
    assert database.add(first) == (first, True)
    later = prepare(database, report, request, role="admin")
    assert later.created_at > first.created_at and later.service_role == "admin"
    assert database.add(later) == (first, False)
    assert database.get(first.decision_id) == first
    assert database.get(uuid4()) is None
    assert counts(store) == (1, 1)
    assert first.service_role == "engineer"
    assert first.individual_identity_verified is first.approved is first.applied is False
    assert SourceEvidenceRecords(store).get(report.report_id) == before == report
    with store.engine.connect() as connection:
        row = connection.execute(text("SELECT * FROM patch_evidence_decisions")).one()
        audit = connection.execute(
            text("SELECT * FROM audit_events WHERE action='patch.evidence_decision_recorded'")
        ).one()
    assert request.comment not in repr(row) and request.comment not in repr(audit)
    assert first.decision_json not in repr(row)
    assert report.review_sha256 not in row.payload
    assert audit.action == "patch.evidence_decision_recorded"
    assert audit.resource_id == str(first.decision_id)


@pytest.mark.parametrize("offset_hours", [-3, 3])
def test_non_utc_row_timestamp_preserves_offset_proof_replay_and_instant_order(
    saved_report, offset_hours
):
    store, _settings, report, _deterministic = saved_report
    records = SourceEvidenceDecisionRecords(store)
    instant = report.created_at + timedelta(seconds=1)
    decision = SourceEvidenceDecision.from_report(
        report,
        decision_request(report),
        service_role="engineer",
        created_at=instant.astimezone(timezone(timedelta(hours=offset_hours))),
    )
    original_json, original_proof = decision.model_dump_json(), decision.decision_json
    assert records.add(decision) == (decision, True)
    saved = records.get(decision.decision_id)
    assert saved == decision and saved.model_dump_json() == original_json
    assert saved.created_at.utcoffset() == timedelta(hours=offset_hours)
    assert saved.decision_json == original_proof
    assert saved.decision_sha256 == decision.decision_sha256
    with store._sessions() as session:
        row = session.get(SourceEvidenceDecisionRow, str(decision.decision_id))
        assert row is not None
        assert row.created_at.replace(tzinfo=UTC) == instant
        assert (
            store._decode(row.payload, kind="source_evidence_decision", row_id=row.id)
            == original_json
        )
    replay = prepare(records, report, decision.request, role="admin")
    assert records.add(replay) == (decision, False)
    later = SourceEvidenceDecision.from_report(
        report,
        decision_request(report),
        service_role="admin",
        created_at=instant + timedelta(seconds=1),
    )
    assert records.add(later) == (later, True)
    assert records.list_ids(report.patch_id, report.report_id, limit=10, offset=0) == [
        later.decision_id,
        decision.decision_id,
    ]
    assert counts(store) == (2, 2)


def test_restart_and_history_after_raw_model_reference_removal_need_no_execution(
    saved_report, monkeypatch
):
    store, settings, report, deterministic = saved_report
    database = SourceEvidenceDecisionRecords(store)
    first = prepare(database, report)
    assert database.add(first) == (first, True)
    with store.engine.begin() as connection:
        connection.execute(text("DELETE FROM configuration_sources"))
        connection.execute(text("DELETE FROM models"))
        connection.execute(
            text("DELETE FROM configurations WHERE id=:key"),
            {"key": str(deterministic.intent.selection.reference.configuration_id)},
        )
    store.close()
    reopened = Store(settings)

    def forbidden(*args, **kwargs):
        pytest.fail("disposition loaded raw/model/reference or ran a detector/engine")

    for name in ("get_model", "get_configuration"):
        monkeypatch.setattr(reopened, name, forbidden)
    for name in (
        "app.db.source_records.SourceRecords.get",
        "app.ingestion.source_retention.prepare_original_source",
        "app.detection.baseline.pair.recheck_original_deterministic",
        "app.detection.baseline.pair.prepare_original_reference",
        "app.detection.baseline.pair.require_original_deterministic_context",
        "app.detection.policy_engine.evaluate_policies",
        "app.verification.batfish.check_with_batfish",
        "app.patching.source_ml.run_configuration_pair_job",
    ):
        monkeypatch.setattr(name, forbidden)
    try:
        records = SourceEvidenceDecisionRecords(reopened)
        assert records.get(first.decision_id) == first
        assert records.add(prepare(records, report, first.request, role="admin")) == (first, False)
        second = prepare(records, report)
        assert records.add(second) == (second, True)
        assert counts(reopened) == (2, 2)
    finally:
        reopened.close()


def test_missing_parent_route_and_hash_conflicts_are_distinct(saved_report):
    store, _settings, report, _deterministic = saved_report
    records = SourceEvidenceDecisionRecords(store)
    request = decision_request(report)
    with pytest.raises(SourceEvidenceDecisionInputNotFound):
        records.prepare(report.patch_id, uuid4(), request, "engineer")
    with pytest.raises(PatchConflict):
        records.prepare(uuid4(), report.report_id, request, "engineer")
    with pytest.raises(PatchConflict):
        records.prepare(
            report.patch_id,
            report.report_id,
            request.model_copy(update={"report_sha256": "0" * 64}),
            "engineer",
        )
    assert counts(store) == (0, 0)


@pytest.mark.parametrize("field", ["comment", "verdict", "report"])
def test_same_uuid_changed_intent_or_parent_conflicts(saved_report, field):
    store, _settings, report, _deterministic = saved_report
    records = SourceEvidenceDecisionRecords(store)
    first = prepare(records, report)
    assert records.add(first) == (first, True)
    if field == "report":
        reports = SourceEvidenceRecords(store)
        report = reports.add(
            reports.prepare(
                report.patch_id, report.request.model_copy(update={"report_id": uuid4()})
            )
        )[0]
        request = first.request.model_copy(update={"report_sha256": report.review_sha256})
    else:
        request = first.request.model_copy(
            update={field: "changed private comment" if field == "comment" else "rejected"}
        )
    with pytest.raises(PatchConflict):
        records.add(prepare(records, report, request))
    assert records.get(first.decision_id) == first
    assert counts(store) == (1, 1)


@pytest.mark.parametrize("field", ["canonical", "source", "analysis", "draft", "report"])
def test_bypassing_prepare_with_coherently_resealed_projection_is_refused(saved_report, field):
    store, _settings, report, _deterministic = saved_report
    records = SourceEvidenceDecisionRecords(store)
    decision = prepare(records, report)
    data = decision.model_dump(mode="json")
    if field == "canonical":
        data["after"]["canonical_sha256"] = "1" * 64
    elif field == "source":
        data["after"]["configuration_id"] = str(uuid4())
        data["after"]["source_sha256"] = "1" * 64
    elif field == "analysis":
        data["before_analysis_id"] = str(uuid4())
        data["before_analysis_sha256"] = "1" * 64
    elif field == "draft":
        data["draft_sha256"] = "1" * 64
    else:
        data["request"]["report_sha256"] = "1" * 64
        data["report_sha256"] = "1" * 64
    forged = SourceEvidenceDecision.model_validate(reseal(data))
    with pytest.raises(PatchConflict):
        records.add(forged)
    assert counts(store) == (0, 0)


def test_atomic_domain_audit_failure_leaves_no_decision(saved_report, monkeypatch):
    store, _settings, report, _deterministic = saved_report
    records = SourceEvidenceDecisionRecords(store)
    decision = prepare(records, report)

    def fail(session, key):
        raise RuntimeError("owned injected disposition audit failure")

    monkeypatch.setattr(SourceEvidenceDecisionRecords, "_audit", staticmethod(fail))
    with pytest.raises(RuntimeError, match="owned injected disposition audit failure"):
        records.add(decision)
    assert counts(store) == (0, 0)
    assert records.get(decision.decision_id) is None
    assert SourceEvidenceRecords(store).get(report.report_id) == report


@pytest.mark.parametrize(
    "fault", ["timestamp", "relocated", "proof", "projection", "report", "child"]
)
def test_stored_decision_and_parent_dependency_tamper_refuses(saved_report, fault):
    store, _settings, report, deterministic = saved_report
    records = SourceEvidenceDecisionRecords(store)
    decision = prepare(records, report)
    assert records.add(decision) == (decision, True)
    with store.engine.begin() as connection:
        if fault == "timestamp":
            connection.execute(
                text("UPDATE patch_evidence_decisions SET created_at='2000-01-01 00:00:00'")
            )
        elif fault == "child":
            connection.execute(
                text("DELETE FROM patch_deterministic_recheck_outcomes WHERE recheck_id=:key"),
                {"key": str(deterministic.recheck_id)},
            )
        elif fault == "report":
            data = report.model_dump(mode="json")
            data["deterministic"]["policy_catalog_version"] = "coherently-forged-parent"
            proof = ml_json(
                {
                    name: value
                    for name, value in data.items()
                    if name not in {"review_json", "review_sha256"}
                }
            )
            data.update(review_json=proof, review_sha256=sha256(proof.encode()).hexdigest())
            connection.execute(
                text("UPDATE patch_evidence_reports SET payload=:payload WHERE id=:key"),
                {
                    "key": str(report.report_id),
                    "payload": store._encode(
                        json.dumps(data),
                        kind="source_evidence_report",
                        row_id=str(report.report_id),
                    ),
                },
            )
        else:
            data = decision.model_dump(mode="json")
            if fault == "proof":
                data["decision_sha256"] = "0" * 64
            elif fault == "projection":
                data["after"]["canonical_sha256"] = "0" * 64
                data = reseal(data)
            connection.execute(
                text("UPDATE patch_evidence_decisions SET payload=:payload WHERE id=:key"),
                {
                    "key": str(decision.decision_id),
                    "payload": store._encode(
                        json.dumps(data),
                        kind="source_evidence_decision",
                        row_id=str(uuid4()) if fault == "relocated" else str(decision.decision_id),
                    ),
                },
            )
    with pytest.raises(StorageIntegrityError, match="Stored data is unavailable"):
        records.get(decision.decision_id)
    if fault in {"child", "report"}:
        with pytest.raises(StorageIntegrityError):
            prepare(records, report)


def test_parent_reader_uses_the_same_session_and_all_checks(saved_report, monkeypatch):
    store, _settings, report, _deterministic = saved_report
    records = SourceEvidenceDecisionRecords(store)
    called = []
    original = SourceEvidenceRecords._get

    def observe(self, session, report_id):
        called.append(session)
        return original(self, session, report_id)

    def no_public_get(*args, **kwargs):
        pytest.fail("nested parent get opened a separate session")

    monkeypatch.setattr(SourceEvidenceRecords, "_get", observe)
    monkeypatch.setattr(SourceEvidenceRecords, "get", no_public_get)
    decision = prepare(records, report)
    assert records.add(decision) == (decision, True)
    assert records.get(decision.decision_id) == decision
    assert len(called) == 3


def test_removed_parent_refuses_historical_decision_as_integrity_error(saved_report):
    store, _settings, report, _deterministic = saved_report
    records = SourceEvidenceDecisionRecords(store)
    decision = prepare(records, report)
    assert records.add(decision) == (decision, True)
    # Simulate out-of-band database corruption. Ordinary application writes never disable
    # foreign keys or delete an immutable report that a decision references.
    with store.engine.connect() as connection:
        connection.exec_driver_sql("PRAGMA foreign_keys=OFF")
        connection.commit()
        try:
            connection.execute(
                text("DELETE FROM patch_evidence_reports WHERE id=:key"),
                {"key": str(report.report_id)},
            )
            connection.commit()
        finally:
            connection.exec_driver_sql("PRAGMA foreign_keys=ON")
            connection.commit()
    with pytest.raises(StorageIntegrityError):
        records.get(decision.decision_id)
    with pytest.raises(SourceEvidenceDecisionInputNotFound):
        prepare(records, report)
    assert counts(store) == (1, 1)


def test_plaintext_budget_counts_utf8_bytes_without_truncating_comments(saved_report, monkeypatch):
    import app.db.source_evidence_decision_records as module

    store, _settings, report, _deterministic = saved_report
    records = SourceEvidenceDecisionRecords(store)
    decision = prepare(records, report, decision_request(report, comment="Ж" * 1200))
    raw = decision.model_dump_json()
    assert len(raw.encode("utf-8")) > len(raw)
    monkeypatch.setattr(module, "MAX_SOURCE_EVIDENCE_DECISION_BYTES", len(raw.encode("utf-8")) - 1)
    with pytest.raises(SourceEvidenceDecisionTooLarge):
        records.add(decision)
    assert counts(store) == (0, 0)


@pytest.mark.parametrize("budget", ["plain", "cipher", "proof"])
def test_creation_budget_refusal_is_atomic(saved_report, monkeypatch, budget):
    import app.api.source_evidence_decision_contracts as contracts
    import app.db.source_evidence_decision_records as module

    store, _settings, report, _deterministic = saved_report
    records = SourceEvidenceDecisionRecords(store)
    decision = prepare(records, report)
    if budget == "plain":
        monkeypatch.setattr(module, "MAX_SOURCE_EVIDENCE_DECISION_BYTES", 1)
    elif budget == "cipher":
        monkeypatch.setattr(module, "MAX_SOURCE_EVIDENCE_DECISION_CIPHERTEXT_BYTES", 1)
    else:
        monkeypatch.setattr(contracts, "MAX_SOURCE_EVIDENCE_DECISION_BYTES", 1)
    with pytest.raises(SourceEvidenceDecisionTooLarge):
        records.add(decision)
    if budget != "cipher":
        with pytest.raises(SourceEvidenceDecisionTooLarge):
            prepare(records, report)
    assert counts(store) == (0, 0)


@pytest.mark.parametrize("budget", ["plain", "cipher", "proof"])
def test_stored_oversize_is_an_integrity_failure(saved_report, monkeypatch, budget):
    import app.api.source_evidence_decision_contracts as contracts
    import app.db.source_evidence_decision_records as module

    store, _settings, report, _deterministic = saved_report
    records = SourceEvidenceDecisionRecords(store)
    decision = prepare(records, report)
    assert records.add(decision) == (decision, True)
    target, key = {
        "plain": (module, "MAX_SOURCE_EVIDENCE_DECISION_BYTES"),
        "cipher": (module, "MAX_SOURCE_EVIDENCE_DECISION_CIPHERTEXT_BYTES"),
        "proof": (contracts, "MAX_SOURCE_EVIDENCE_DECISION_BYTES"),
    }[budget]
    monkeypatch.setattr(target, key, 1)
    with pytest.raises(StorageIntegrityError):
        records.get(decision.decision_id)
    assert counts(store) == (1, 1)


def test_concurrent_writers_keep_one_role_timestamp_proof_and_audit(saved_report, monkeypatch):
    store, _settings, report, _deterministic = saved_report
    records = SourceEvidenceDecisionRecords(store)
    request = decision_request(report)
    decisions = [prepare(records, report, request, role) for role in ("engineer", "admin")]
    original = SourceEvidenceDecisionRecords._get
    barrier, state = Barrier(2), local()

    def synchronize(self, session, decision_id):
        value = original(self, session, decision_id)
        if not getattr(state, "seen", False):
            state.seen = True
            barrier.wait(timeout=10)
        return value

    monkeypatch.setattr(SourceEvidenceDecisionRecords, "_get", synchronize)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(records.add, decisions))
    monkeypatch.setattr(SourceEvidenceDecisionRecords, "_get", original)
    assert sorted(created for _decision, created in results) == [False, True]
    assert results[0][0] == results[1][0] == records.get(request.decision_id)
    assert results[0][0] in decisions
    assert counts(store) == (1, 1)


def test_paginated_history_scopes_both_parent_ids_and_has_a_stable_tie_order(saved_report):
    store, _settings, report, _deterministic = saved_report
    records = SourceEvidenceDecisionRecords(store)
    first = prepare(records, report)
    second = SourceEvidenceDecision.from_report(
        report,
        decision_request(report, verdict="rejected"),
        service_role="admin",
        created_at=first.created_at,
    )
    third = SourceEvidenceDecision.from_report(
        report,
        decision_request(report),
        service_role="engineer",
        created_at=first.created_at + timedelta(seconds=1),
    )
    for decision in (first, second, third):
        assert records.add(decision)[1]
    expected = [third.decision_id, *sorted([first.decision_id, second.decision_id], reverse=True)]
    assert records.list_ids(report.patch_id, report.report_id, limit=10, offset=0) == expected
    assert records.list_ids(report.patch_id, report.report_id, limit=1, offset=1) == expected[1:2]
    assert records.list_ids(uuid4(), report.report_id, limit=10, offset=0) == []
    assert records.list_ids(report.patch_id, uuid4(), limit=10, offset=0) == []
    assert counts(store) == (3, 3)


def test_populated_15_to_16_upgrade_is_additive_and_repeatable(saved_report):
    store, _settings, report, _deterministic = saved_report
    with store.engine.begin() as connection:
        connection.exec_driver_sql("DROP TABLE patch_risk_assessments")
        connection.exec_driver_sql("DROP TABLE patch_evidence_decisions")
        connection.execute(
            text("UPDATE alembic_version SET version_num='0015_source_evidence_reports'")
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
    records = SourceEvidenceDecisionRecords(store)
    assert records.add(prepare(records, report))[1]
    assert counts(store) == (1, 1)
