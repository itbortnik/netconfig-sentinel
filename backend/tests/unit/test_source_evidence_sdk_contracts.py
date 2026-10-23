"""SDK-aware projection controls; authored envelopes are not actual SDK observations."""

from datetime import UTC, datetime, timedelta, timezone
from hashlib import sha256
from uuid import uuid4

import pytest
from app.api import source_evidence_decision_sdk_contracts, source_evidence_sdk_contracts
from app.api.source_evidence_contracts import SourceEvidenceReport
from app.api.source_evidence_decision_contracts import (
    ReviewSourceEvidenceReport,
    SourceEvidenceDecision,
)
from app.api.source_evidence_decision_sdk_contracts import (
    ReviewSourceEvidenceReportV2,
    SourceEvidenceDecisionV2,
    parse_source_evidence_decision_json,
    parse_source_evidence_decision_request,
    source_evidence_decision,
    source_evidence_decision_summary,
    validate_source_evidence_decision,
)
from app.api.source_evidence_sdk_contracts import (
    CreateSourceEvidenceReportV2,
    SourceEvidenceReportV2,
    SourceNetworkEvidenceV2,
    parse_source_evidence_report_json,
    parse_source_evidence_request,
    source_evidence_report,
    source_evidence_summary,
    validate_source_evidence_report,
)
from app.api.source_ml_contracts import ml_json
from app.api.source_patch_contracts import source_review_fingerprint
from app.api.source_patch_sdk_contracts import (
    SourcePatchIntentV2,
    SourcePatchOutcomeV2,
    SourcePatchVerificationV2,
    VerifySourcePatchV2,
)
from app.audit.results import result_metadata
from app.db.patch_records import PatchConflict
from app.db.source_evidence_decision_records import SourceEvidenceDecisionRecords
from app.db.source_evidence_records import SourceEvidenceRecords
from app.db.source_patch_records import SourcePatchRecords
from app.db.store import StorageIntegrityError
from app.db.tables import SourceEvidenceDecisionRow, SourceEvidenceReportRow
from app.patching.source_evidence import SourceEvidenceWorkflow
from app.patching.source_evidence_decision import SourceEvidenceDecisionWorkflow
from app.verification.batfish import BatfishExecution
from sqlalchemy import text
from test_original_deterministic_pair import prepared as prepared
from test_source_evidence_contracts import compose, joint_fixture
from test_source_evidence_records import all_selected as all_selected


def sdk_network(network, *, state="observed", new_identity=False):
    source_request = VerifySourcePatchV2.model_validate(
        network.intent.request.model_dump()
        | {"version": "source-patch-request-0.2.0"}
        | ({"verification_id": uuid4()} if new_identity else {})
    )
    intent = SourcePatchIntentV2.model_validate(
        network.intent.model_dump()
        | {"version": "source-patch-intent-0.2.0", "request": source_request.model_dump()}
    )
    outcome = SourcePatchOutcomeV2(
        verification_id=source_request.verification_id,
        intent_sha256=source_review_fingerprint(intent),
        completed_at=network.outcome.completed_at,
        network_execution=BatfishExecution(
            result=network.outcome.network_result,
            sdk_version="0.36.0" if state == "observed" else None,
            sdk_observation=state,
        ),
    )
    return SourcePatchVerificationV2.from_records(intent, outcome)


def sdk_fixture(prepared, *, state="observed", network_status=None, legacy_network=False):
    if network_status is None:
        network_status = "unavailable" if state == "not_observed" else "no_differences_in_scope"
    draft, request, deterministic, forest, neural, network = joint_fixture(
        prepared, statistical=True, neural=True, network_status=network_status
    )
    assert network is not None and network.outcome is not None
    if not legacy_network:
        network = sdk_network(network, state=state)
    body = request.model_dump() | {"version": "source-evidence-request-0.2.0"}
    body["network"] = {"record_id": network.verification_id, "review_sha256": network.review_sha256}
    request = CreateSourceEvidenceReportV2.model_validate(body)
    return draft, request, deterministic, forest, neural, network


def sdk_report(fixture):
    draft, request, deterministic, forest, neural, network = fixture
    return source_evidence_report(
        draft,
        request,
        deterministic,
        forest=forest,
        neural=neural,
        network=network,
        created_at=datetime.now(UTC),
    )


def validate_report(report, fixture):
    draft, _, deterministic, forest, neural, network = fixture
    return validate_source_evidence_report(
        report, draft, deterministic, forest=forest, neural=neural, network=network
    )


def sdk_decision(report):
    request = ReviewSourceEvidenceReportV2(
        decision_id=uuid4(),
        report_sha256=report.review_sha256,
        verdict="needs_more_information",
        comment="Authored control; identity and quality unavailable.",
    )
    return source_evidence_decision(
        report, request, service_role="engineer", created_at=datetime.now(UTC)
    )


def reseal(value, *, decision=False):
    prefix = "decision" if decision else "review"
    proof = ml_json(
        {k: v for k, v in value.items() if k not in {prefix + "_json", prefix + "_sha256"}}
    )
    return value | {prefix + "_json": proof, prefix + "_sha256": sha256(proof.encode()).hexdigest()}


@pytest.mark.parametrize(
    "state,status",
    [
        ("observed", "no_differences_in_scope"),
        ("observed", "error"),
        ("metadata_unavailable", "no_differences_in_scope"),
        ("metadata_unavailable", "error"),
        ("not_observed", "unavailable"),
        ("not_observed", "error"),
    ],
)
def test_report_projects_exact_saved_execution_without_promotion(prepared, state, status):
    fixture = sdk_fixture(prepared, state=state, network_status=status)
    report = sdk_report(fixture)
    execution = fixture[-1].outcome.network_execution
    assert isinstance(report, SourceEvidenceReportV2)
    assert report.network.result == execution.result
    assert report.network.sdk_version == execution.sdk_version
    assert report.network.sdk_observation == execution.sdk_observation
    assert report.network.execution_version == execution.version
    assert report.request.network.review_sha256 == fixture[-1].review_sha256
    assert not any(
        (
            report.risk_fused,
            report.quality_proven,
            report.calibrated,
            report.approved,
            report.applied,
        )
    )
    assert report.status == "needs_review" and report.formal_qualification == "not_proven"
    assert source_evidence_summary(report).version == "source-evidence-summary-0.2.0"
    assert (
        parse_source_evidence_report_json(report.model_dump_json()).model_dump_json()
        == report.model_dump_json()
    )
    validate_report(report, fixture)


def test_legacy_replay_and_new_report_with_legacy_child_are_data_only(prepared, monkeypatch):
    import importlib.metadata

    monkeypatch.setattr(importlib.metadata, "version", lambda *a: pytest.fail("SDK lookup on read"))
    old_fixture = joint_fixture(prepared, network_status="no_differences_in_scope")
    old = compose(old_fixture)
    old_dump = old.model_dump_json()
    parsed = parse_source_evidence_report_json(old_dump)
    assert type(parsed) is SourceEvidenceReport
    assert parsed.model_dump_json() == old_dump and parsed.review_sha256 == old.review_sha256
    assert parse_source_evidence_request(old.request.model_dump(exclude={"version"})) == old.request
    new_fixture = sdk_fixture(prepared, legacy_network=True)
    report = sdk_report(new_fixture)
    assert report.network.version == "source-patch-verification-0.1.0"
    assert report.network.sdk_version is None
    assert "sdk_observation" not in report.network.model_dump()
    validate_report(report, new_fixture)
    decision = sdk_decision(report)
    validate_source_evidence_decision(decision, report)
    assert decision.report_version == "source-evidence-report-0.2.0"
    old_request = ReviewSourceEvidenceReport(
        decision_id=uuid4(),
        report_sha256=old.review_sha256,
        verdict="rejected",
        comment="Authored historical control.",
    )
    old_decision = source_evidence_decision(
        old, old_request, service_role="admin", created_at=datetime.now(UTC)
    )
    assert type(old_decision) is SourceEvidenceDecision
    assert (
        parse_source_evidence_decision_json(old_decision.model_dump_json()).model_dump_json()
        == old_decision.model_dump_json()
    )
    assert (
        parse_source_evidence_decision_request(old_request.model_dump(exclude={"version"}))
        == old_request
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("sdk_version", None),
        ("sdk_version", "0.36.1"),
        ("sdk_observation", "metadata_unavailable"),
        ("record_id", None),
        ("review_sha256", "f" * 64),
        ("network_device_count", 2),
    ],
)
def test_resealed_false_projection_cannot_replace_selected_child(prepared, field, value):
    fixture = sdk_fixture(prepared)
    report = sdk_report(fixture)
    body = report.model_dump(mode="json")
    body["network"][field] = str(uuid4()) if field == "record_id" else value
    if field == "sdk_version" and value is None:
        body["network"]["sdk_observation"] = "metadata_unavailable"
    if field == "sdk_observation":
        body["network"]["sdk_version"] = None
    if field in {"record_id", "review_sha256"}:
        body["request"]["network"][field] = body["network"][field]
    forged = SourceEvidenceReportV2.model_validate(reseal(body))
    with pytest.raises(ValueError):
        validate_report(forged, fixture)


@pytest.mark.parametrize(
    "change",
    [
        {"sdk_version": ""},
        {"sdk_version": "not a version"},
        {"sdk_version": "é"},
        {"sdk_version": "x" * 129},
        {"sdk_version": None},
        {"sdk_observation": "metadata_unavailable"},
        {"sdk_observation": "not_observed"},
        {"execution_version": "batfish-execution-9.0.0"},
        {"network_device_count": True},
        {"network_device_count": 33},
        {"ml_status": "completed"},
    ],
)
def test_projection_rejects_invalid_execution_state(prepared, change):
    report = sdk_report(sdk_fixture(prepared))
    with pytest.raises(ValueError):
        SourceNetworkEvidenceV2.model_validate(report.network.model_dump() | change)


@pytest.mark.parametrize(
    "flag", ["risk_fused", "calibrated", "quality_proven", "approved", "applied"]
)
@pytest.mark.parametrize("value", [True, 0, "false"])
def test_report_requires_exact_false_even_when_resealed(prepared, flag, value):
    report = sdk_report(sdk_fixture(prepared))
    with pytest.raises(ValueError):
        SourceEvidenceReportV2.model_validate(
            reseal(report.model_dump(mode="json") | {flag: value})
        )


def test_full_child_validation_rejects_bypassed_inner_proof(prepared):
    fixture = sdk_fixture(prepared)
    network = fixture[-1]
    bypassed = network.model_copy(update={"review_sha256": "f" * 64})
    with pytest.raises(ValueError):
        sdk_report((*fixture[:-1], bypassed))
    with pytest.raises(ValueError):
        sdk_report((*fixture[:-1], network.model_copy(update={"outcome": None})))


def test_report_and_decision_protocols_do_not_silently_cross(prepared):
    fixture = sdk_fixture(prepared)
    report = sdk_report(fixture)
    legacy_request = parse_source_evidence_request(fixture[1].model_dump(exclude={"version"}))
    with pytest.raises(ValueError):
        sdk_report((fixture[0], legacy_request, *fixture[2:]))
    legacy_report = compose(joint_fixture(prepared))
    request = sdk_decision(report).request
    with pytest.raises(ValueError):
        source_evidence_decision(
            legacy_report, request, service_role="engineer", created_at=datetime.now(UTC)
        )
    old_request = ReviewSourceEvidenceReport.model_validate(request.model_dump(exclude={"version"}))
    with pytest.raises(ValueError):
        source_evidence_decision(
            report, old_request, service_role="engineer", created_at=datetime.now(UTC)
        )


@pytest.mark.parametrize("kind", ["report", "decision"])
def test_unknown_and_missing_stored_versions_fail_strict_dispatch(prepared, kind):
    report = sdk_report(sdk_fixture(prepared))
    value = report if kind == "report" else sdk_decision(report)
    parser = (
        parse_source_evidence_report_json
        if kind == "report"
        else parse_source_evidence_decision_json
    )
    body = value.model_dump(mode="json")
    for version in [None, "unexpected-9.0.0"]:
        with pytest.raises(ValueError):
            parser(ml_json(reseal(body | {"version": version}, decision=kind == "decision")))
    body.pop("version")
    with pytest.raises(ValueError):
        parser(ml_json(reseal(body, decision=kind == "decision")))


def test_decision_exact_binding_role_time_and_audit_metadata(prepared):
    fixture = sdk_fixture(prepared)
    report = sdk_report(fixture)
    decision = sdk_decision(report)
    validate_source_evidence_decision(decision, report)
    assert isinstance(decision, SourceEvidenceDecisionV2)
    assert decision.report_version == report.version
    assert decision.report_sha256 == report.review_sha256
    assert decision.service_role == "engineer"
    assert not any((decision.individual_identity_verified, decision.approved, decision.applied))
    assert (
        source_evidence_decision_summary(decision).version
        == "source-evidence-decision-summary-0.2.0"
    )
    assert report.version in result_metadata(report).versions
    assert decision.version in result_metadata(decision).versions
    assert decision.decision_id in result_metadata(decision).resource_ids
    for role, time in [
        ("reader", datetime.now(UTC)),
        ("engineer", report.created_at - timedelta(seconds=1)),
    ]:
        with pytest.raises(ValueError):
            source_evidence_decision(report, decision.request, service_role=role, created_at=time)
    body = decision.model_dump(mode="json") | {"before_analysis_sha256": "f" * 64}
    forged = SourceEvidenceDecisionV2.model_validate(reseal(body, decision=True))
    with pytest.raises(ValueError):
        validate_source_evidence_decision(forged, report)


@pytest.mark.parametrize("flag", ["individual_identity_verified", "approved", "applied"])
@pytest.mark.parametrize("value", [True, 0, "false"])
def test_decision_requires_exact_false_even_when_resealed(prepared, flag, value):
    decision = sdk_decision(sdk_report(sdk_fixture(prepared)))
    with pytest.raises(ValueError):
        SourceEvidenceDecisionV2.model_validate(
            reseal(decision.model_dump(mode="json") | {flag: value}, decision=True)
        )


@pytest.fixture
def saved_sdk_inputs(all_selected):
    store, draft, request, deterministic, forest, neural, legacy_network = all_selected
    network = sdk_network(legacy_network, new_identity=True)
    records = SourcePatchRecords(store)
    assert records.reserve(network.intent)
    records.complete(network.outcome)
    sdk_request = CreateSourceEvidenceReportV2.model_validate(
        request.model_dump()
        | {
            "version": "source-evidence-request-0.2.0",
            "report_id": uuid4(),
            "network": {
                "record_id": network.verification_id,
                "review_sha256": network.review_sha256,
            },
        }
    )
    return store, (draft, sdk_request, deterministic, forest, neural, network), request


def saved_reports(saved_sdk_inputs):
    store, fixture, legacy_request = saved_sdk_inputs
    records = SourceEvidenceRecords(store)
    current, created = records.add(records.prepare(fixture[0].patch_id, fixture[1]))
    assert created
    legacy, created = records.add(records.prepare(fixture[0].patch_id, legacy_request))
    assert created
    return store, current, legacy


def test_sdk_storage_replay_keeps_saved_role_time_proof_and_needs_no_execution(
    saved_sdk_inputs, monkeypatch
):
    import importlib.metadata

    store, report, legacy_report = saved_reports(saved_sdk_inputs)
    reports, decisions = SourceEvidenceRecords(store), SourceEvidenceDecisionRecords(store)
    decision = sdk_decision(report)
    assert decisions.add(decision) == (decision, True)

    def forbidden(*args, **kwargs):
        pytest.fail("SDK-aware history ran an SDK lookup, detector, model or raw source lookup")

    monkeypatch.setattr(importlib.metadata, "version", forbidden)
    for name in ("get_model", "get_configuration"):
        monkeypatch.setattr(store, name, forbidden)
    for name in (
        "app.db.source_records.SourceRecords.get",
        "app.detection.statistical.pair.recheck_original_forest",
        "app.verification.batfish.check_with_batfish",
        "app.verification.batfish.check_with_batfish_evidence",
        "app.patching.source_ml.run_configuration_pair_job",
    ):
        monkeypatch.setattr(name, forbidden)
    with store.engine.begin() as connection:
        connection.execute(text("DELETE FROM configuration_sources"))
        connection.execute(text("DELETE FROM models"))
        connection.execute(
            text("DELETE FROM configurations WHERE id=:key"),
            {"key": str(saved_sdk_inputs[1][2].intent.selection.reference.configuration_id)},
        )
    assert reports.get(report.report_id).model_dump_json() == report.model_dump_json()
    assert reports.get(legacy_report.report_id).model_dump_json() == legacy_report.model_dump_json()
    assert reports.add(reports.prepare(report.patch_id, report.request)) == (report, False)
    later = decisions.prepare(report.patch_id, report.report_id, decision.request, "admin")
    assert later.service_role == "admin" and later.created_at > decision.created_at
    assert decisions.add(later) == (decision, False)
    assert decisions.get(decision.decision_id).model_dump_json() == decision.model_dump_json()
    assert decisions.list_ids(report.patch_id, report.report_id, limit=1, offset=0) == [
        decision.decision_id
    ]
    assert decisions.list_ids(report.patch_id, report.report_id, limit=1, offset=1) == []
    with store.engine.connect() as connection:
        assert connection.execute(
            text("SELECT count(*) FROM audit_events WHERE action='patch.evidence_report_created'")
        ).scalar_one() == 2
        assert connection.execute(
            text(
                "SELECT count(*) FROM audit_events WHERE action='patch.evidence_decision_recorded'"
            )
        ).scalar_one() == 1


def test_legacy_request_cannot_select_sdk_child_and_same_uuid_cannot_change_protocol(
    saved_sdk_inputs,
):
    store, fixture, legacy_request = saved_sdk_inputs
    draft, request, *_ = fixture
    reports = SourceEvidenceRecords(store)
    mixed_request = parse_source_evidence_request(
        request.model_dump() | {"version": legacy_request.version, "report_id": uuid4()}
    )
    with pytest.raises(PatchConflict):
        reports.prepare(draft.patch_id, mixed_request)
    report, created = SourceEvidenceWorkflow(store).create(draft.patch_id, request)
    assert created
    conflicting = parse_source_evidence_request(
        legacy_request.model_dump() | {"report_id": report.report_id}
    )
    with pytest.raises(PatchConflict):
        SourceEvidenceWorkflow(store).create(draft.patch_id, conflicting)
    assert reports.list_ids(draft.patch_id, limit=20, offset=0) == [report.report_id]


def test_corrupt_historical_legacy_reference_to_sdk_child_is_storage_failure(saved_sdk_inputs):
    store, report, legacy = saved_reports(saved_sdk_inputs)
    body = legacy.model_dump(mode="json")
    reference = report.request.network.model_dump(mode="json")
    body["request"]["network"] = reference
    body["network"] |= reference
    forged = SourceEvidenceReport.model_validate(reseal(body))
    with store._sessions.begin() as session:
        row = session.get(SourceEvidenceReportRow, str(legacy.report_id))
        row.payload = store._encode(
            forged.model_dump_json(), kind="source_evidence_report", row_id=row.id
        )
    with pytest.raises(StorageIntegrityError):
        SourceEvidenceRecords(store).get(legacy.report_id)


def test_decision_storage_rejects_mixed_protocol_and_corrupted_historical_binding(
    saved_sdk_inputs,
):
    store, report, legacy_report = saved_reports(saved_sdk_inputs)
    records = SourceEvidenceDecisionRecords(store)
    old_request = ReviewSourceEvidenceReport(
        decision_id=uuid4(),
        report_sha256=report.review_sha256,
        verdict="rejected",
        comment="Authored protocol control.",
    )
    with pytest.raises(PatchConflict):
        records.prepare(report.patch_id, report.report_id, old_request, "engineer")
    new_request = ReviewSourceEvidenceReportV2(
        decision_id=uuid4(),
        report_sha256=legacy_report.review_sha256,
        verdict="rejected",
        comment="Authored protocol control.",
    )
    with pytest.raises(PatchConflict):
        records.prepare(legacy_report.patch_id, legacy_report.report_id, new_request, "engineer")
    decision = sdk_decision(report)
    assert records.add(decision) == (decision, True)
    old_request = ReviewSourceEvidenceReport.model_validate(
        decision.request.model_dump(exclude={"version"})
    )
    with pytest.raises(PatchConflict):
        SourceEvidenceDecisionWorkflow(store).create(
            report.patch_id, report.report_id, old_request, "admin"
        )
    body = decision.model_dump(mode="json")
    body["version"] = "source-evidence-decision-0.1.0"
    body["request"]["version"] = "source-evidence-decision-request-0.1.0"
    body["report_version"] = "source-evidence-report-0.1.0"
    forged = SourceEvidenceDecision.model_validate(reseal(body, decision=True))
    with store._sessions.begin() as session:
        row = session.get(SourceEvidenceDecisionRow, str(decision.decision_id))
        row.payload = store._encode(
            forged.model_dump_json(), kind="source_evidence_decision", row_id=row.id
        )
    with pytest.raises(StorageIntegrityError):
        records.get(decision.decision_id)


@pytest.mark.parametrize("offset", [-3, 3])
def test_sdk_storage_preserves_non_utc_normative_proofs(saved_sdk_inputs, offset):
    store, fixture, _ = saved_sdk_inputs
    draft, request, deterministic, forest, neural, network = fixture
    stamp = datetime.now(UTC).astimezone(timezone(timedelta(hours=offset)))
    report = source_evidence_report(
        draft,
        request,
        deterministic,
        forest=forest,
        neural=neural,
        network=network,
        created_at=stamp,
    )
    reports, decisions = SourceEvidenceRecords(store), SourceEvidenceDecisionRecords(store)
    assert reports.add(report) == (report, True)
    decision = source_evidence_decision(
        report,
        sdk_decision(report).request,
        service_role="engineer",
        created_at=stamp + timedelta(seconds=1),
    )
    assert decisions.add(decision) == (decision, True)
    assert reports.get(report.report_id).model_dump_json() == report.model_dump_json()
    assert decisions.get(decision.decision_id).model_dump_json() == decision.model_dump_json()


def test_sdk_projection_budgets_do_not_truncate_or_promote(prepared, monkeypatch):
    fixture = sdk_fixture(prepared)
    report = sdk_report(fixture)
    with monkeypatch.context() as bounded:
        bounded.setattr(source_evidence_sdk_contracts, "MAX_SOURCE_EVIDENCE_BYTES", 1)
        with pytest.raises(source_evidence_sdk_contracts.SourceEvidenceProjectionTooLarge):
            sdk_report(fixture)
    monkeypatch.setattr(
        source_evidence_decision_sdk_contracts, "MAX_SOURCE_EVIDENCE_DECISION_BYTES", 1
    )
    with pytest.raises(
        source_evidence_decision_sdk_contracts.SourceEvidenceDecisionProjectionTooLarge
    ):
        sdk_decision(report)


def test_sdk_report_can_explicitly_select_no_network(prepared):
    draft, request, deterministic, forest, neural, _ = sdk_fixture(prepared)
    request = CreateSourceEvidenceReportV2.model_validate(request.model_dump() | {"network": None})
    fixture = draft, request, deterministic, forest, neural, None
    report = sdk_report(fixture)
    assert report.network is None
    assert "network_not_selected" in report.validation_blockers
    assert "network" not in source_evidence_summary(report).selected_kinds
    validate_report(report, fixture)
    validate_source_evidence_decision(sdk_decision(report), report)
