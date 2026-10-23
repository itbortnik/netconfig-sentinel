"""Directional protocol integrity controls using authored witnesses, not live evidence."""

from datetime import UTC, datetime, timedelta, timezone
from uuid import uuid4

import pytest
from app.api.source_evidence_decision_direction_contracts import (
    ReviewSourceEvidenceReportV3,
    parse_source_evidence_decision_json,
    source_evidence_decision,
    source_evidence_decision_summary,
    validate_source_evidence_decision,
)
from app.api.source_evidence_direction_contracts import (
    CreateSourceEvidenceReportV3,
    SourceEvidenceReportV3,
    parse_source_evidence_report_json,
    parse_source_evidence_request,
    source_evidence_report,
    source_evidence_summary,
    validate_source_evidence_report,
)
from app.api.source_patch_contracts import source_review_fingerprint
from app.api.source_patch_direction_contracts import (
    SourcePatchIntentV3,
    SourcePatchOutcomeV3,
    SourcePatchVerificationV3,
    VerifySourcePatchV3,
    parse_source_patch_intent_json,
    parse_source_patch_outcome_json,
    parse_source_patch_request,
    parse_source_patch_review,
    source_patch_summary,
    source_patch_view,
)
from app.audit.results import result_metadata
from app.db.patch_records import PatchConflict
from app.db.source_evidence_decision_records import SourceEvidenceDecisionRecords
from app.db.source_evidence_records import SourceEvidenceRecords
from app.db.source_patch_records import SourcePatchRecords
from app.db.store import StorageIntegrityError
from app.db.tables import SourceEvidenceReportRow
from app.verification.batfish import BatfishResult
from app.verification.reachability_impact import (
    BatfishDirectionalExecution,
    ReachabilityImpact,
    empty_reachability_impact,
)
from sqlalchemy import text
from test_original_deterministic_pair import prepared as prepared
from test_source_evidence_contracts import compose, joint_fixture
from test_source_evidence_records import all_selected as all_selected
from test_source_evidence_sdk_contracts import reseal, sdk_network


def authored_impact(kind="mixed"):
    """Existence witnesses with equal aggregate counts still expose two directions."""
    if kind == "unknown":
        return empty_reachability_impact("unknown", "incomplete_traces")
    if kind == "empty":
        return empty_reachability_impact("inconclusive", "empty_reachable_scope")
    if kind == "not_run":
        return empty_reachability_impact("not_observed", "not_run")
    rows = []
    for ordinal, direction in enumerate(("loss", "gain")):
        if kind not in {direction, "mixed"}:
            continue
        rows.append(
            {
                "flow_sha256": str(ordinal + 1) * 64,
                "before_dispositions": ["ACCEPTED" if direction == "loss" else "NO_ROUTE"],
                "after_dispositions": ["NO_ROUTE" if direction == "loss" else "ACCEPTED"],
                "before_trace_count": 1,
                "after_trace_count": 1,
                "direction": direction,
            }
        )
    return ReachabilityImpact(
        state="observed",
        reason="query_completed",
        direction={
            "loss": "loss_found",
            "gain": "gain_found",
            "mixed": "loss_and_gain_found",
            "none": "no_witnesses_returned",
        }[kind],
        lost_witness_count=sum(row["direction"] == "loss" for row in rows),
        gained_witness_count=sum(row["direction"] == "gain" for row in rows),
        witnesses=rows,
    )


def direction_network(network, *, kind="mixed", new_identity=False):
    request = VerifySourcePatchV3.model_validate(
        network.intent.request.model_dump()
        | {"version": "source-patch-request-0.3.0"}
        | ({"verification_id": uuid4()} if new_identity else {})
    )
    intent = SourcePatchIntentV3.model_validate(
        network.intent.model_dump()
        | {"version": "source-patch-intent-0.3.0", "request": request.model_dump()}
    )
    result = network.outcome.network_result.model_dump()
    queried = kind != "not_run"
    result.update(
        status="error"
        if not queried
        else "inconclusive"
        if kind == "empty"
        else "no_differences_in_scope"
        if kind == "none"
        else "differences_found",
        reason="engine_error"
        if not queried
        else "empty_reachable_scope"
        if kind == "empty"
        else "query_completed",
        cleanup_complete=True if queried else None,
        engine_version="owned-direction-fixture" if queried else None,
        difference_count=(2 if kind == "mixed" else 0 if kind in {"none", "empty"} else 1)
        if queried
        else None,
        before_reachable_count=(0 if kind == "empty" else 1) if queried else None,
        after_reachable_count=(0 if kind == "empty" else 1) if queried else None,
    )
    outcome = SourcePatchOutcomeV3(
        verification_id=request.verification_id,
        intent_sha256=source_review_fingerprint(intent),
        completed_at=network.outcome.completed_at,
        network_execution=BatfishDirectionalExecution(
            result=BatfishResult.model_validate(result),
            sdk_version="owned-direction-control-0.36.0",
            sdk_observation="observed",
            reachability_impact=authored_impact(kind),
        ),
    )
    return SourcePatchVerificationV3.from_records(intent, outcome)


def directional_fixture(prepared, *, kind="mixed", child="direction"):
    draft, request, deterministic, forest, neural, network = joint_fixture(
        prepared, statistical=True, neural=True, network_status="no_differences_in_scope"
    )
    if child == "direction":
        network = direction_network(network, kind=kind)
    elif child == "sdk":
        network = sdk_network(network)
    elif child == "none":
        network = None
    request = CreateSourceEvidenceReportV3.model_validate(
        request.model_dump()
        | {
            "version": "source-evidence-request-0.3.0",
            "network": {
                "record_id": network.verification_id,
                "review_sha256": network.review_sha256,
            }
            if network
            else None,
        }
    )
    return draft, request, deterministic, forest, neural, network


def report_for(fixture, *, created_at=None):
    draft, request, deterministic, forest, neural, network = fixture
    return source_evidence_report(
        draft,
        request,
        deterministic,
        forest=forest,
        neural=neural,
        network=network,
        created_at=created_at or datetime.now(UTC),
    )


def validate_report(report, fixture):
    draft, _, deterministic, forest, neural, network = fixture
    validate_source_evidence_report(
        report, draft, deterministic, forest=forest, neural=neural, network=network
    )


def decision_for(report, *, created_at=None):
    request = ReviewSourceEvidenceReportV3(
        decision_id=uuid4(),
        report_sha256=report.review_sha256,
        verdict="needs_more_information",
        comment="Authored directional control; individual review remains required.",
    )
    return source_evidence_decision(
        report, request, service_role="engineer", created_at=created_at or datetime.now(UTC)
    )


@pytest.mark.parametrize("kind", ["loss", "gain", "mixed", "none", "empty", "unknown", "not_run"])
def test_direction_is_exactly_projected_with_no_status_promotion(prepared, kind):
    fixture = directional_fixture(prepared, kind=kind)
    report = report_for(fixture)
    network = fixture[-1]
    assert isinstance(report, SourceEvidenceReportV3)
    assert (
        report.network.reachability_impact == network.outcome.network_execution.reachability_impact
    )
    assert report.network.result == network.outcome.network_result
    assert report.network.execution_version == "batfish-execution-0.3.0"
    assert report.formal_qualification == "not_proven" and report.status == "needs_review"
    assert not any(
        (
            report.risk_fused,
            report.calibrated,
            report.quality_proven,
            report.approved,
            report.applied,
        )
    )
    validate_report(report, fixture)
    assert (
        parse_source_evidence_report_json(report.model_dump_json()).model_dump_json()
        == report.model_dump_json()
    )
    assert source_evidence_summary(report).version == "source-evidence-summary-0.3.0"
    assert source_patch_summary(network).version == "source-patch-verification-summary-0.3.0"
    assert parse_source_patch_request(network.intent.request.model_dump()) == network.intent.request
    assert parse_source_patch_review(network).model_dump_json() == network.model_dump_json()
    assert (
        source_patch_view(
            parse_source_patch_intent_json(network.intent.model_dump_json()),
            parse_source_patch_outcome_json(network.outcome.model_dump_json()),
        )
        == network
    )
    decision = decision_for(report)
    validate_source_evidence_decision(decision, report)
    assert decision.report_version == report.version
    assert decision.individual_identity_verified is decision.approved is decision.applied is False
    assert (
        source_evidence_decision_summary(decision).version
        == "source-evidence-decision-summary-0.3.0"
    )
    assert parse_source_evidence_decision_json(decision.model_dump_json()) == decision
    assert report.version in result_metadata(report).versions
    assert decision.version in result_metadata(decision).versions
    assert network.version in result_metadata(network).versions


@pytest.mark.parametrize("child", ["legacy", "sdk", "none"])
def test_new_report_explicitly_selects_historical_or_absent_network(prepared, monkeypatch, child):
    import importlib.metadata

    monkeypatch.setattr(importlib.metadata, "version", lambda *a: pytest.fail("history SDK lookup"))
    fixture = directional_fixture(prepared, child=child)
    report = report_for(fixture)
    validate_report(report, fixture)
    if child == "none":
        assert report.network is None and "network_not_selected" in report.validation_blockers
    else:
        assert report.network.version == fixture[-1].version
        assert "reachability_impact" not in report.network.model_dump()
    old = compose(joint_fixture(prepared))
    assert (
        parse_source_evidence_report_json(old.model_dump_json()).model_dump_json()
        == old.model_dump_json()
    )
    assert parse_source_evidence_request(old.request.model_dump(exclude={"version"})) == old.request


@pytest.mark.parametrize("field", ["flow", "disposition", "sdk", "limits"])
def test_resealed_direction_projection_is_checked_against_full_selected_child(prepared, field):
    fixture = directional_fixture(prepared)
    report = report_for(fixture)
    body = report.model_dump(mode="json")
    impact = body["network"]["reachability_impact"]
    if field == "flow":
        impact["witnesses"][0]["flow_sha256"] = "0" * 64
    elif field == "disposition":
        impact["witnesses"][0]["after_dispositions"] = ["NULL_ROUTED"]
    elif field == "sdk":
        body["network"]["sdk_version"] = "owned-different-sdk"
    else:
        impact["limitations"] = []
        with pytest.raises(ValueError):
            SourceEvidenceReportV3.model_validate(reseal(body))
        return
    forged = SourceEvidenceReportV3.model_validate(reseal(body))
    with pytest.raises(ValueError):
        validate_report(forged, fixture)


@pytest.mark.parametrize("version", ["0.1.0", "0.2.0"])
def test_direction_child_and_parent_cannot_be_resealed_into_older_protocol(prepared, version):
    fixture = directional_fixture(prepared)
    request = parse_source_evidence_request(
        fixture[1].model_dump() | {"version": "source-evidence-request-" + version}
    )
    with pytest.raises(ValueError):
        report_for((fixture[0], request, *fixture[2:]))
    report = report_for(fixture)
    decision = decision_for(report)
    from app.api.source_evidence_decision_direction_contracts import (
        parse_source_evidence_decision_request,
    )

    old = parse_source_evidence_decision_request(
        decision.request.model_dump() | {"version": "source-evidence-decision-request-" + version}
    )
    with pytest.raises(ValueError):
        source_evidence_decision(report, old, service_role="engineer", created_at=datetime.now(UTC))


@pytest.mark.parametrize("offset", [-3, 3])
def test_directional_storage_preserves_proof_offsets_and_reads_without_raw_or_model(
    all_selected, monkeypatch, offset
):
    store, draft, old_request, deterministic, forest, neural, old_network = all_selected
    network = direction_network(old_network, new_identity=True)
    records = SourcePatchRecords(store)
    assert records.reserve(network.intent)
    records.complete(network.outcome)
    request = CreateSourceEvidenceReportV3.model_validate(
        old_request.model_dump()
        | {
            "version": "source-evidence-request-0.3.0",
            "report_id": uuid4(),
            "network": {
                "record_id": network.verification_id,
                "review_sha256": network.review_sha256,
            },
        }
    )
    fixture = draft, request, deterministic, forest, neural, network
    stamp = datetime.now(UTC).astimezone(timezone(timedelta(hours=offset)))
    report = report_for(fixture, created_at=stamp)
    reports, decisions = SourceEvidenceRecords(store), SourceEvidenceDecisionRecords(store)
    assert reports.add(report) == (report, True)
    decision = decision_for(report, created_at=stamp + timedelta(seconds=1))
    assert decisions.add(decision) == (decision, True)

    def forbidden(*args, **kwargs):
        pytest.fail("historical directional data executed or accessed unavailable inputs")

    for target in [
        "app.db.source_records.SourceRecords.get",
        "app.db.store.Store.get_model",
        "app.verification.batfish.check_with_batfish_directional",
        "app.patching.source_ml.run_configuration_pair_job",
    ]:
        monkeypatch.setattr(target, forbidden)
    with store.engine.begin() as connection:
        connection.execute(text("DELETE FROM configuration_sources"))
        connection.execute(text("DELETE FROM models"))
    assert reports.get(report.report_id).model_dump_json() == report.model_dump_json()
    assert decisions.get(decision.decision_id).model_dump_json() == decision.model_dump_json()
    assert (
        records.get(network.verification_id)[0].model_dump_json()
        == network.intent.model_dump_json()
    )
    older = parse_source_evidence_request(
        request.model_dump() | {"version": "source-evidence-request-0.2.0"}
    )
    with pytest.raises(PatchConflict):
        reports.prepare(draft.patch_id, older)
    # A fresh sealed proof with a valid but false witness is still refused against its child.
    body = report.model_dump(mode="json")
    body["network"]["reachability_impact"]["witnesses"][0]["flow_sha256"] = "0" * 64
    forged = SourceEvidenceReportV3.model_validate(reseal(body))
    with store._sessions.begin() as session:
        row = session.get(SourceEvidenceReportRow, str(report.report_id))
        row.payload = store._encode(
            forged.model_dump_json(), kind="source_evidence_report", row_id=row.id
        )
    with pytest.raises(StorageIntegrityError):
        reports.get(report.report_id)
    with pytest.raises(StorageIntegrityError):
        decisions.get(decision.decision_id)
