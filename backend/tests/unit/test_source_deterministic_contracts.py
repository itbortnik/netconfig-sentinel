"""Typed frozen replay boundaries; authored toy cases do not establish real quality."""

import json
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from uuid import uuid4

import pytest
from app.api.contracts import SnapshotBinding
from app.api.model_patch_contracts import fingerprint
from app.api.source_deterministic_contracts import (
    OriginalDeterministicContext,
    RunSourceDeterministicRecheck,
    SourceDeterministicIntent,
    SourceDeterministicMember,
    SourceDeterministicOutcome,
    SourceDeterministicRecheck,
    SourceDeterministicReport,
    SourceDeterministicSelection,
    SourceDeterministicSummary,
)
from app.api.source_ml_contracts import ml_json, source_ml_fingerprint
from app.detection.baseline.pair import recheck_original_deterministic
from app.ingestion.source_retention import canonical_fingerprint
from test_original_deterministic_pair import prepared as prepared


def records(selected):
    before, after, analysis, reference = selected
    pair = recheck_original_deterministic(before, after, analysis, reference)

    def member(snapshot):
        return SourceDeterministicMember.model_validate(
            SnapshotBinding.from_snapshot(snapshot).model_dump()
            | {"canonical_sha256": canonical_fingerprint(snapshot)}
        )

    patch = uuid4()
    request = RunSourceDeterministicRecheck(
        recheck_id=uuid4(),
        draft_sha256="a" * 64,
        before_analysis_id=analysis.analysis_id,
        before_analysis_sha256=fingerprint(analysis),
        reference_canonical_sha256=canonical_fingerprint(reference) if reference else None,
        allow_local_analysis_context=True,
    )
    selection = SourceDeterministicSelection(
        patch_id=patch,
        draft_sha256=request.draft_sha256,
        before=SnapshotBinding.from_snapshot(before),
        before_analysis_id=request.before_analysis_id,
        before_analysis_sha256=request.before_analysis_sha256,
        before_analysis_created_at=analysis.created_at,
        original=OriginalDeterministicContext.from_analysis(analysis),
        reference=member(reference) if reference else None,
    )
    intent = SourceDeterministicIntent(
        patch_id=patch,
        request=request,
        before=member(before),
        after=member(after),
        selection=selection,
        reference_projection=pair.reference,
        created_at=datetime.now(UTC),
    )
    report = SourceDeterministicReport.from_pair(intent, pair)
    outcome = SourceDeterministicOutcome(
        recheck_id=request.recheck_id,
        intent_sha256=source_ml_fingerprint(intent),
        completed_at=datetime.now(UTC),
        execution_status="completed",
        report=report,
    )
    return intent, outcome


def rehash(body):
    body["review_json"] = ml_json(
        {key: value for key, value in body.items() if key not in {"review_json", "review_sha256"}}
    )
    body["review_sha256"] = sha256(body["review_json"].encode()).hexdigest()
    return body


@pytest.mark.parametrize("vendor", ["cisco", "juniper"])
@pytest.mark.parametrize("version", ["0.1.0", "0.2.0", "0.3.0"])
@pytest.mark.parametrize("cohort", ["policy_only", "reference_only", "peers_only", "combined"])
def test_frozen_original_scope_and_exact_json_roundtrip(prepared, vendor, version, cohort):
    intent, outcome = records(prepared(vendor, version, cohort))
    view = SourceDeterministicRecheck.from_records(intent, outcome)
    assert SourceDeterministicRecheck.model_validate_json(view.model_dump_json()) == view
    assert json.loads(view.review_json) == view.model_dump(
        mode="json", exclude={"review_json", "review_sha256"}
    )
    assert view.review_sha256 == sha256(view.review_json.encode()).hexdigest()
    assert SourceDeterministicSummary.from_recheck(view).review_sha256 == view.review_sha256
    assert outcome.report.comparison_version == (
        "not_selected" if cohort == "policy_only" else version
    )
    assert (outcome.report.before.reference_findings is not None) == (
        cohort in {"reference_only", "combined"}
    )
    assert (outcome.report.after.peer_findings is not None) == (
        cohort in {"peers_only", "combined"}
    )
    assert (outcome.report.after.peer_evaluation is not None) == (
        cohort in {"peers_only", "combined"} and version != "0.1.0"
    )
    context = intent.selection.original.comparison
    assert outcome.report.peer_profile_sha256 == (
        fingerprint(context.peer_baseline) if context and context.peer_baseline else None
    )
    assert view.formal_verification == "not_run" and view.status == "needs_review"
    assert "all_original_detectors_not_rerun" not in view.validation_blockers
    assert "original_statistical_not_rerun" not in view.validation_blockers


def test_pending_failed_and_statistical_not_rerun_are_explicit(prepared):
    intent, _outcome = records(prepared(cohort="policy_only"))
    original = intent.selection.original.model_copy(update={"statistical_present": True})
    intent = intent.model_copy(
        update={"selection": intent.selection.model_copy(update={"original": original})}
    )
    pending = SourceDeterministicRecheck.from_records(intent, None)
    failed = SourceDeterministicRecheck.from_records(
        intent,
        SourceDeterministicOutcome(
            recheck_id=intent.request.recheck_id,
            intent_sha256=source_ml_fingerprint(intent),
            completed_at=datetime.now(UTC),
            execution_status="failed",
            failure_reason="original_context_or_deterministic_result_unavailable",
        ),
    )
    assert pending.execution_status == "pending_unknown"
    assert failed.execution_status == "failed" and failed.outcome.report is None
    assert "original_statistical_not_rerun" in pending.validation_blockers
    assert "deterministic_execution_unknown" in pending.validation_blockers
    assert "original_deterministic_unavailable" in failed.validation_blockers


def test_selected_completed_zero_is_not_unselected(prepared):
    before, after, analysis, reference = prepared(cohort="reference_only")
    after = after.model_copy(
        update={"canonical": reference.canonical, "parser_coverage": reference.parser_coverage}
    )
    intent, outcome = records((before, after, analysis, reference))
    assert outcome.report.after.reference_findings == ()
    assert outcome.report.after.peer_findings is None
    body = SourceDeterministicRecheck.from_records(intent, outcome).model_dump(mode="json")
    body["outcome"]["report"]["after"]["reference_findings"] = None
    with pytest.raises(ValueError):
        SourceDeterministicRecheck.model_validate(rehash(body))


@pytest.mark.parametrize("value", [0, 1, "true"])
def test_request_requires_nullable_reference_pin_and_exact_consent(prepared, value):
    intent, _ = records(prepared(cohort="policy_only"))
    body = intent.request.model_dump(mode="json")
    body["allow_local_analysis_context"] = value
    with pytest.raises(ValueError):
        RunSourceDeterministicRecheck.model_validate(body)
    body = intent.request.model_dump(mode="json")
    del body["reference_canonical_sha256"]
    with pytest.raises(ValueError):
        RunSourceDeterministicRecheck.model_validate(body)


@pytest.mark.parametrize(
    "fault",
    [
        "consent",
        "draft",
        "analysis",
        "canonical",
        "device",
        "source",
        "time",
        "timezone",
        "ref_id",
        "ref_version",
    ],
)
def test_intent_binds_source_context_reference_and_time(prepared, fault):
    intent, _ = records(prepared())
    body = intent.model_dump(mode="json")
    if fault == "consent":
        body["request"]["allow_local_analysis_context"] = False
    elif fault in {"draft", "analysis", "canonical"}:
        body["request"][
            {
                "draft": "draft_sha256",
                "analysis": "before_analysis_sha256",
                "canonical": "reference_canonical_sha256",
            }[fault]
        ] = "b" * 64
    elif fault == "device":
        body["after"]["device_id"] = str(uuid4())
    elif fault == "source":
        body["after"]["source_sha256"] = body["before"]["source_sha256"]
    elif fault == "time":
        body["selection"]["before_analysis_created_at"] = (
            intent.created_at + timedelta(seconds=1)
        ).isoformat()
    elif fault == "timezone":
        body["created_at"] = intent.created_at.replace(tzinfo=None).isoformat()
    elif fault == "ref_id":
        body["reference_projection"]["reference_id"] = str(uuid4())
    else:
        body["reference_projection"]["version"] = "expected-config-0.1.0"
    with pytest.raises(ValueError):
        SourceDeterministicIntent.model_validate(body)


@pytest.mark.parametrize(
    "flag", ["risk_fused", "calibrated", "quality_proven", "approved", "applied"]
)
@pytest.mark.parametrize("value", [True, 0, "false"])
def test_recheck_cannot_promote_false_flags(prepared, flag, value):
    intent, outcome = records(prepared())
    body = SourceDeterministicRecheck.from_records(intent, outcome).model_dump(mode="json")
    body[flag] = value
    with pytest.raises(ValueError):
        SourceDeterministicRecheck.model_validate(rehash(body))


@pytest.mark.parametrize(
    "fault",
    [
        "proof",
        "hash",
        "intent_pin",
        "original_before",
        "catalog",
        "profile",
        "source",
        "ref_source",
        "ref_observed",
        "own_coverage",
        "own_count",
        "before_report",
    ],
)
def test_rehash_cannot_hide_frozen_result_drift(prepared, fault):
    intent, outcome = records(prepared())
    body = SourceDeterministicRecheck.from_records(intent, outcome).model_dump(mode="json")
    report = body["outcome"]["report"]
    if fault == "proof":
        body["review_json"] += " "
        body["review_sha256"] = sha256(body["review_json"].encode()).hexdigest()
    elif fault == "hash":
        body["review_sha256"] = "b" * 64
    else:
        if fault == "intent_pin":
            body["outcome"]["intent_sha256"] = "b" * 64
        elif fault == "original_before":
            finding = report["before"]["policy_findings"][0]
            original_id = finding["finding_id"]
            finding["title"] += " altered"
            for row in report["policy_changes"]["resolved"]:
                if row["finding_id"] == original_id:
                    row["title"] = finding["title"]
            for pair in report["policy_changes"]["persistent"]:
                if pair["before"]["finding_id"] == original_id:
                    pair["before"]["title"] = finding["title"]
        elif fault == "catalog":
            report["policy_catalog_version"] = "policy-rules-unknown"
        elif fault == "profile":
            report["peer_profile_sha256"] = "b" * 64
        elif fault == "source":
            report["after"]["configuration_id"] = str(uuid4())
        elif fault == "ref_source":
            report["reference_projection"]["source_sha256"] = "b" * 64
        elif fault == "ref_observed":
            report["after"]["reference_findings"][0]["observed"]["source_sha256"] = "b" * 64
        elif fault == "own_coverage":
            report["after"]["peer_evaluation"]["coverage"]["source_sha256"] = "b" * 64
        elif fault == "own_count":
            report["after"]["peer_evaluation"]["coverage"]["command_units"] += 1
        else:
            report["before"]["peer_evaluation"]["limitations"].append("altered report")
        rehash(body)
    with pytest.raises(ValueError):
        SourceDeterministicRecheck.model_validate(body)


@pytest.mark.parametrize(
    "fault", ["drop", "duplicate", "evidence", "relabel_persistent", "semantic"]
)
def test_policy_partition_keeps_full_fields_multiplicity_and_semantics(prepared, fault):
    _intent, outcome = records(prepared(cohort="policy_only"))
    report = outcome.report.model_dump(mode="json")
    changes = report["policy_changes"]
    assert changes["resolved"] and changes["persistent"]
    if fault == "drop":
        changes["resolved"].pop()
    elif fault == "duplicate":
        changes["resolved"].append(changes["resolved"][0])
    elif fault == "evidence":
        changes["resolved"][0]["evidence"] = []
    elif fault == "relabel_persistent":
        pair = changes["persistent"].pop()
        changes["resolved"].append(pair["before"])
        changes["introduced"].append(pair["after"])
    else:
        pair = changes["persistent"][0]
        pair["after"]["observed"] = {"changed": True}
        for row in report["after"]["policy_findings"]:
            if row["finding_id"] == pair["after"]["finding_id"]:
                row["observed"] = pair["after"]["observed"]
    with pytest.raises(ValueError):
        SourceDeterministicReport.model_validate(report)


def test_history_reads_no_raw_snapshots_catalog_or_comparator(prepared, monkeypatch):
    intent, outcome = records(prepared())
    serialized = SourceDeterministicRecheck.from_records(intent, outcome).model_dump_json()

    def unavailable(*args, **kwargs):
        raise AssertionError("historical read must not evaluate or load live inputs")

    for name in (
        "evaluate_policies",
        "compare_expanded_reference",
        "compare_expected_configuration",
        "evaluate_peer_baseline",
        "evaluate_expanded_peer_baseline",
        "evaluate_measured_peer_baseline",
        "compare_policy_findings",
    ):
        monkeypatch.setattr("app.detection.baseline.pair." + name, unavailable)
    monkeypatch.setattr("app.db.store.Store.get_configuration", unavailable)
    monkeypatch.setattr("app.policies.POLICY_CATALOGS", {})
    assert SourceDeterministicRecheck.model_validate_json(serialized).review_sha256


def test_original_projection_filters_statistical_without_recomputing(prepared, monkeypatch):
    _before, _after, analysis, _reference = prepared(cohort="policy_only")
    statistical = analysis.findings[0].model_copy(
        update={"detector": "isolation_forest", "finding_id": uuid4()}
    )
    analysis = analysis.model_copy(
        update={"findings": (*analysis.findings, statistical), "statistical": object()}
    )

    def unavailable(*args, **kwargs):
        raise AssertionError("context projection cannot evaluate original detectors")

    monkeypatch.setattr("app.detection.policy_engine.evaluate_policies", unavailable)
    context = OriginalDeterministicContext.from_analysis(analysis)
    assert context.statistical_present is True
    assert context.findings == analysis.findings[:-1]


def test_legacy_after_findings_remain_bound_to_frozen_consensus(prepared):
    intent, outcome = records(prepared(version="0.1.0", cohort="combined"))
    body = SourceDeterministicRecheck.from_records(intent, outcome).model_dump(mode="json")
    # Before contains Telnet deviation; retain a fabricated copy on the after side with
    # a changed expected consensus. Source/device/version alone must not accept it.
    finding = body["outcome"]["report"]["before"]["peer_findings"][0]
    finding["expected"]["peer_support_count"] = 1
    body["outcome"]["report"]["after"]["peer_findings"] = [finding]
    with pytest.raises(ValueError):
        SourceDeterministicRecheck.model_validate(rehash(body))


def test_unknown_historical_catalog_is_preserved_without_live_membership(prepared):
    intent, outcome = records(prepared(cohort="policy_only"))
    body = SourceDeterministicRecheck.from_records(intent, outcome).model_dump(mode="json")
    catalog = "historical-external-catalog-unknown"
    body["intent"]["selection"]["original"]["policy_catalog_version"] = catalog
    body["outcome"]["report"]["policy_catalog_version"] = catalog

    def change_versions(value):
        if isinstance(value, dict):
            if value.get("detector") == "policy_engine":
                value["model_version"] = catalog
            for item in value.values():
                change_versions(item)
        elif isinstance(value, list):
            for item in value:
                change_versions(item)

    change_versions(body["intent"])
    change_versions(body["outcome"]["report"])
    body["outcome"]["intent_sha256"] = sha256(ml_json(body["intent"]).encode()).hexdigest()
    assert (
        SourceDeterministicRecheck.model_validate(
            rehash(body)
        ).outcome.report.policy_catalog_version
        == catalog
    )
