"""Typed/proof boundary only; no saved ordinary statistical workflow exists here."""

import json
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from uuid import uuid4

import pytest
from app.api.contracts import SnapshotBinding
from app.api.source_forest_contracts import (
    RunSourceForestRecheck,
    SourceForestIntent,
    SourceForestMember,
    SourceForestOutcome,
    SourceForestRecheck,
    SourceForestReport,
    SourceForestSelection,
    SourceForestSummary,
)
from app.api.source_ml_contracts import ml_json, source_ml_fingerprint
from app.detection.statistical.pair import recheck_original_forest
from app.ingestion.source_retention import canonical_fingerprint
from test_original_forest_pair import selected_forest_pair as selected_forest_pair


def records(selected):
    before, after, analysis, model = selected
    patch = uuid4()
    request = RunSourceForestRecheck(
        recheck_id=uuid4(),
        draft_sha256="a" * 64,
        before_analysis_id=analysis.analysis_id,
        before_analysis_sha256="b" * 64,
        model_id=model.summary.model_id,
        artifact_sha256=model.summary.artifact_sha256,
        allow_local_model_context=True,
    )
    selection = SourceForestSelection(
        patch_id=patch,
        draft_sha256=request.draft_sha256,
        before=SnapshotBinding.from_snapshot(before),
        before_analysis_id=analysis.analysis_id,
        before_analysis_sha256=request.before_analysis_sha256,
        before_analysis_created_at=analysis.created_at,
        original=analysis.statistical,
    )

    def member(snapshot):
        return SourceForestMember.model_validate(
            SnapshotBinding.from_snapshot(snapshot).model_dump()
            | {"canonical_sha256": canonical_fingerprint(snapshot)}
        )

    intent = SourceForestIntent(
        patch_id=patch,
        request=request,
        before=member(before),
        after=member(after),
        selection=selection,
        created_at=datetime.now(UTC),
    )
    report = SourceForestReport(
        model=model.summary, scores=recheck_original_forest(before, after, analysis, model)
    )
    outcome = SourceForestOutcome(
        recheck_id=request.recheck_id,
        intent_sha256=source_ml_fingerprint(intent),
        completed_at=datetime.now(UTC),
        execution_status="completed",
        report=report,
    )
    return intent, outcome


def test_complete_pending_failed_and_normative_proof_do_not_promote(selected_forest_pair):
    intent, outcome = records(selected_forest_pair)
    pending = SourceForestRecheck.from_records(intent, None)
    completed = SourceForestRecheck.from_records(intent, outcome)
    failed = SourceForestRecheck.from_records(
        intent,
        SourceForestOutcome(
            recheck_id=intent.request.recheck_id,
            intent_sha256=source_ml_fingerprint(intent),
            completed_at=datetime.now(UTC),
            execution_status="failed",
            failure_reason="original_baseline_or_numeric_result_unavailable",
        ),
    )
    assert [row.execution_status for row in (pending, completed, failed)] == [
        "pending_unknown",
        "completed",
        "failed",
    ]
    assert failed.outcome.report is None
    for view in (pending, completed, failed):
        assert view.status == "needs_review" and view.formal_verification == "not_run"
        assert not any(
            (view.quality_proven, view.calibrated, view.risk_fused, view.approved, view.applied)
        )
        assert view.review_sha256 == sha256(view.review_json.encode()).hexdigest()
        assert json.loads(view.review_json) == view.model_dump(
            mode="json", exclude={"review_json", "review_sha256"}
        )
        assert SourceForestRecheck.model_validate_json(view.model_dump_json()) == view
        assert SourceForestSummary.from_recheck(view).review_sha256 == view.review_sha256


@pytest.mark.parametrize("fault", ["range", "decision", "prediction", "nan", "model"])
def test_new_numeric_wrapper_closes_legacy_tuple_gaps(selected_forest_pair, fault):
    _intent, outcome = records(selected_forest_pair)
    body = outcome.report.model_dump(mode="json")
    if fault == "range":
        body["scores"]["after_score_samples"] = 0.1
    elif fault == "decision":
        body["scores"]["after_decision_function"] += 1e-9
    elif fault == "prediction":
        body["scores"]["after_prediction"] *= -1
    elif fault == "nan":
        body["scores"]["after_score_samples"] = float("nan")
    else:
        body["scores"]["model_id"] = str(uuid4())
    with pytest.raises(ValueError):
        SourceForestReport.model_validate(body)


@pytest.mark.parametrize(
    "fault", ["model", "analysis", "consent", "snapshot", "future", "timezone"]
)
def test_intent_selection_and_chronology_refuse_drift(selected_forest_pair, fault):
    intent, _outcome = records(selected_forest_pair)
    body = intent.model_dump(mode="json")
    if fault in {"model", "analysis"}:
        body["request"]["model_id" if fault == "model" else "before_analysis_id"] = str(uuid4())
    elif fault == "consent":
        body["request"]["allow_local_model_context"] = False
    elif fault == "snapshot":
        body["before"]["configuration_id"] = str(uuid4())
    elif fault == "future":
        body["selection"]["before_analysis_created_at"] = (
            intent.created_at + timedelta(seconds=1)
        ).isoformat()
    else:
        body["created_at"] = intent.created_at.replace(tzinfo=None).isoformat()
    with pytest.raises(ValueError):
        SourceForestIntent.model_validate(body)


@pytest.mark.parametrize(
    "flag", ["risk_fused", "calibrated", "quality_proven", "approved", "applied"]
)
@pytest.mark.parametrize("value", [True, 0])
def test_projection_flags_are_exact_false(selected_forest_pair, flag, value):
    intent, outcome = records(selected_forest_pair)
    body = SourceForestRecheck.from_records(intent, outcome).model_dump(mode="json")
    body[flag] = value
    with pytest.raises(ValueError):
        SourceForestRecheck.model_validate(body)


@pytest.mark.parametrize(
    "fault", ["outer_hash", "raw_proof", "nested_intent", "before_tuple", "model_summary"]
)
def test_rehashed_projection_cannot_hide_inner_binding_drift(selected_forest_pair, fault):
    intent, outcome = records(selected_forest_pair)
    body = SourceForestRecheck.from_records(intent, outcome).model_dump(mode="json")
    if fault == "outer_hash":
        body["review_sha256"] = "b" * 64
    elif fault == "raw_proof":
        body["review_json"] += " "
        body["review_sha256"] = sha256(body["review_json"].encode()).hexdigest()
    else:
        if fault == "nested_intent":
            body["outcome"]["intent_sha256"] = "b" * 64
        elif fault == "before_tuple":
            report = body["outcome"]["report"]
            scores = report["scores"]
            scores["before_score_samples"] += 1e-6
            scores["before_decision_function"] = (
                scores["before_score_samples"] - report["model"]["decision_offset"]
            )
            scores["before_prediction"] = -1 if scores["before_decision_function"] < 0 else 1
        else:
            body["outcome"]["report"]["model"]["training_hostnames"][0] = "different-training-host"
        body["review_json"] = ml_json(
            {
                key: value
                for key, value in body.items()
                if key not in {"review_json", "review_sha256"}
            }
        )
        body["review_sha256"] = sha256(body["review_json"].encode()).hexdigest()
    with pytest.raises(ValueError):
        SourceForestRecheck.model_validate(body)
