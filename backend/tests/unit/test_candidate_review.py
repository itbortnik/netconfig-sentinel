"""Declared unit inputs test bindings, not actual model/engine execution."""

import json
from dataclasses import replace

import pytest
from app.domain.fingerprints import finding_fingerprint
from app.explanation.patch_provider import validate_patch_answer
from app.patching.candidate_review import (
    CandidateReviewReport,
    CandidateReviewUnavailable,
    build_candidate_review,
)
from app.verification.batfish import BatfishResult, ReachabilityScope
from app.verification.model_patch import ModelPatchBatfishReport, prepare_model_patch_snapshots
from pydantic import ValidationError

from ml.inference.change_contracts import MLChangeReview, SidePrediction, TransformerSupplement
from ml.instruct.network_cases import authored_network_patch_cases


def inputs():
    case = authored_network_patch_cases()[0]
    prepared = case.patch.prepared
    generated = validate_patch_answer(
        json.dumps(
            {
                "summary": "Declared unit candidate, not actual inference.",
                "technical_explanation": "Replace the selected explicit SSH version line.",
                "possible_impact": [],
                "recommendation": "Engineer review is required.",
                "patch_draft": {"edits": [{"source_line": 3, "replacement": "ip ssh version 2"}]},
                "assumptions": [],
                "missing_information": ["Access is unverified."],
                "citations": [prepared.chunks[0].citation],
                "requires_human_review": True,
            }
        ).encode(),
        prepared,
    )
    scope = ReachabilityScope(start_node="edge", destination="198.51.100.1/32")
    pair = prepare_model_patch_snapshots(generated, prepared=prepared, before=case.before)
    network = ModelPatchBatfishReport(
        device_id=pair.device_id,
        source_sha256=prepared.source_sha256,
        candidate_sha256=generated.metadata.review.proposal.after_sha256,
        finding_sha256=finding_fingerprint(prepared.finding),
        context_sha256=prepared.prompt.context_sha256,
        batfish=BatfishResult(
            before_sha256=pair.before.digest,
            after_sha256=pair.after.digest,
            scope=scope,
            status="no_differences_in_scope",
            reason="query_completed",
            engine_version="declared-unit-version",
            difference_count=0,
            before_reachable_count=1,
            after_reachable_count=1,
            cleanup_complete=True,
        ),
    )
    return case, generated, scope, network


def selected_ml(generated, *, category="telnet_enabled"):
    proposal = generated.metadata.review.proposal

    def side(source, lines):
        return SidePrediction(
            raw_source_sha256=source,
            sanitized_source_sha256="3" * 64,
            model_sha256="1" * 64,
            total_lines=lines,
            anomaly_score=0.3,
            category_scores={category: 0.2},
            severity_scores=None,
            line_scores=(0.1,) * lines,
            block_attention=(1.0,),
            embedding_sha256=None,
            embedding_dimensions=0,
            replacement_counts={},
        )

    return MLChangeReview(
        local_review=generated.metadata.review,
        transformer=TransformerSupplement(
            status="completed",
            reason=None,
            model_sha256="1" * 64,
            tokenizer_sha256="2" * 64,
            training_report_sha256="3" * 64,
            training_format="multitask-training-0.2.0",
            runtime_torch_version="declared-unit",
            sanitization_version="config-sanitizer-0.1.0",
            before=side(proposal.before_sha256, proposal.before_line_count),
            after=side(proposal.after_sha256, proposal.after_line_count),
        ),
    )


def test_absent_checks_are_missing_not_passed_and_no_engine_or_model_runs(monkeypatch):
    case, generated, scope, _ = inputs()
    monkeypatch.setattr(
        "app.verification.model_patch.check_with_batfish",
        lambda *args, **kwargs: pytest.fail("implicit engine query"),
    )
    report = build_candidate_review(
        generated, prepared=case.patch.prepared, before=case.before, scope=scope
    )
    assert report.network_result is None and report.ml_reviews == ()
    assert "formal_report_not_supplied" in report.missing_checks
    assert "ml_model_not_selected" in report.missing_checks
    assert report.status == "needs_review" and report.approved is False
    assert report.local_review == generated.metadata.review


def test_scoped_success_and_completed_ml_remain_unqualified():
    case, generated, scope, network = inputs()
    report = build_candidate_review(
        generated,
        prepared=case.patch.prepared,
        before=case.before,
        scope=scope,
        network_result=network,
        ml_reviews=(selected_ml(generated),),
        expected_model_sha256s=("1" * 64,),
    )
    assert report.network_result == network and len(report.ml_reviews) == 1
    assert "formal_report_not_supplied" not in report.missing_checks
    assert "ml_selected_category_not_supported" in report.missing_checks
    assert "ml_quality_not_qualified" in report.missing_checks
    assert "human_review_required" in report.missing_checks
    assert "device_syntax_not_verified" in report.missing_checks
    assert report.applied is report.approved is False
    assert generated.metadata.review.preflight.formal_verification == "not_run"


@pytest.mark.parametrize(
    "field",
    [
        "device_id",
        "source_sha256",
        "candidate_sha256",
        "finding_sha256",
        "context_sha256",
        "before_sha256",
        "after_sha256",
        "scope",
        "approved",
    ],
)
def test_foreign_formal_report_is_rejected(field):
    case, generated, scope, network = inputs()
    if field in {"before_sha256", "after_sha256", "scope"}:
        value = (
            ReachabilityScope(start_node="core", destination="198.51.100.1/32")
            if field == "scope"
            else "f" * 64
        )
        network = network.model_copy(
            update={"batfish": network.batfish.model_copy(update={field: value})}
        )
    else:
        from uuid import UUID

        value = UUID(int=99) if field == "device_id" else True if field == "approved" else "f" * 64
        network = network.model_copy(update={field: value})
    with pytest.raises(CandidateReviewUnavailable, match=r"^Candidate review is unavailable\.$"):
        build_candidate_review(
            generated,
            prepared=case.patch.prepared,
            before=case.before,
            scope=scope,
            network_result=network,
        )


@pytest.mark.parametrize("mutation", ["pin", "missing_pin", "duplicate", "source", "local_review"])
def test_foreign_unpinned_or_duplicate_ml_is_rejected(mutation):
    case, generated, scope, _ = inputs()
    ml = selected_ml(generated)
    pins = ("1" * 64,)
    rows = (ml,)
    if mutation == "pin":
        pins = ("f" * 64,)
    elif mutation == "missing_pin":
        pins = ()
    elif mutation == "duplicate":
        rows, pins = (ml, ml), ("1" * 64, "1" * 64)
    elif mutation == "source":
        ml = ml.model_copy(
            update={
                "transformer": ml.transformer.model_copy(
                    update={
                        "before": ml.transformer.before.model_copy(
                            update={"raw_source_sha256": "f" * 64}
                        )
                    }
                )
            }
        )
        rows = (ml,)
    else:
        ml = ml.model_copy(
            update={"local_review": ml.local_review.model_copy(update={"status": "approved"})}
        )
        rows = (ml,)
    with pytest.raises(CandidateReviewUnavailable):
        build_candidate_review(
            generated,
            prepared=case.patch.prepared,
            before=case.before,
            scope=scope,
            ml_reviews=rows,
            expected_model_sha256s=pins,
        )


def test_tampered_generated_candidate_is_rejected():
    case, generated, scope, _ = inputs()
    with pytest.raises(CandidateReviewUnavailable):
        build_candidate_review(
            replace(generated, candidate_text="private-invalid"),
            prepared=case.patch.prepared,
            before=case.before,
            scope=scope,
        )


@pytest.mark.parametrize(
    "status,reason,counts,missing",
    [
        ("unavailable", "upload_not_authorized", None, "formal_query_not_completed"),
        ("error", "engine_error", None, "formal_query_not_completed"),
        ("incomplete", "initialization_issues", None, "formal_query_not_completed"),
        ("inconclusive", "empty_reachable_scope", (0, 0, 0), "empty_formal_scope"),
        ("differences_found", "query_completed", (1, 1, 0), "reachability_differences_unreviewed"),
        ("no_differences_in_scope", "query_completed", (0, 1, 1), None),
    ],
)
def test_all_declared_formal_outcomes_remain_separate_from_approval(
    status, reason, counts, missing
):
    case, generated, scope, network = inputs()
    changes = {"status": status, "reason": reason, "cleanup_complete": None}
    for key, value in zip(
        ("difference_count", "before_reachable_count", "after_reachable_count"),
        counts if counts is not None else (None, None, None),
        strict=True,
    ):
        changes[key] = value
    network = network.model_copy(update={"batfish": network.batfish.model_copy(update=changes)})
    report = build_candidate_review(
        generated,
        prepared=case.patch.prepared,
        before=case.before,
        scope=scope,
        network_result=network,
    )
    assert missing is None or missing in report.missing_checks
    assert "network_cleanup_unconfirmed" in report.missing_checks
    assert report.status == "needs_review" and report.approved is report.applied is False
    assert generated.metadata.review.preflight.formal_verification == "not_run"


def test_selected_category_coverage_is_not_model_quality_or_calibration():
    case, generated, scope, _ = inputs()
    report = build_candidate_review(
        generated,
        prepared=case.patch.prepared,
        before=case.before,
        scope=scope,
        ml_reviews=(selected_ml(generated, category="ssh_version_1"),),
        expected_model_sha256s=("1" * 64,),
    )
    assert "ml_selected_category_not_supported" not in report.missing_checks
    assert "ml_quality_not_qualified" in report.missing_checks
    assert report.semantic_truth_proven is report.execution_authenticated is False
    assert CandidateReviewReport.model_validate_json(report.model_dump_json()) == report


def test_explicit_not_selected_ml_requires_none_pin_and_remains_missing():
    case, generated, scope, _ = inputs()
    ml = MLChangeReview(
        local_review=generated.metadata.review,
        transformer=TransformerSupplement(status="not_selected", reason="not_selected"),
    )
    report = build_candidate_review(
        generated,
        prepared=case.patch.prepared,
        before=case.before,
        scope=scope,
        ml_reviews=(ml,),
        expected_model_sha256s=(None,),
    )
    assert "ml_model_not_selected" in report.missing_checks


@pytest.mark.parametrize(
    "field",
    [
        "approved",
        "applied",
        "requires_human_review",
        "execution_authenticated",
        "semantic_truth_proven",
        "confidential",
    ],
)
@pytest.mark.parametrize("value", [0, 1, None, "true"])
def test_report_flags_do_not_accept_boolean_coercion(field, value):
    case, generated, scope, _ = inputs()
    report = build_candidate_review(
        generated, prepared=case.patch.prepared, before=case.before, scope=scope
    )
    data = report.model_dump()
    data[field] = value
    with pytest.raises(ValidationError):
        CandidateReviewReport.model_validate(data)


@pytest.mark.parametrize(
    "mutation", ["status", "missing_checks", "too_many_models", "list_selection"]
)
def test_report_cannot_promote_or_forge_missing_checks_or_unbound_selection(mutation):
    case, generated, scope, _ = inputs()
    report = build_candidate_review(
        generated, prepared=case.patch.prepared, before=case.before, scope=scope
    )
    if mutation in {"status", "missing_checks"}:
        data = report.model_dump()
        data[mutation] = "validated" if mutation == "status" else ()
        with pytest.raises(ValidationError):
            CandidateReviewReport.model_validate(data)
    else:
        ml = selected_ml(generated)
        rows = (ml,) * 5 if mutation == "too_many_models" else [ml]
        with pytest.raises(CandidateReviewUnavailable):
            build_candidate_review(
                generated,
                prepared=case.patch.prepared,
                before=case.before,
                scope=scope,
                ml_reviews=rows,
                expected_model_sha256s=("1" * 64,) * len(rows),
            )
