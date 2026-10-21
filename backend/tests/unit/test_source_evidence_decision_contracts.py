"""Service-role disposition controls; fixtures do not attest an individual engineer."""

from datetime import UTC, datetime, timedelta, timezone
from hashlib import sha256
from uuid import uuid4

import pytest
from app.api import source_evidence_decision_contracts as decision_contracts
from app.api.source_evidence_decision_contracts import (
    ReviewSourceEvidenceReport,
    SourceEvidenceDecision,
    SourceEvidenceDecisionProjectionTooLarge,
    SourceEvidenceDecisionSummary,
)
from app.api.source_ml_contracts import ml_json
from test_original_deterministic_pair import prepared as prepared
from test_source_evidence_contracts import compose, joint_fixture


@pytest.fixture
def report(prepared):
    return compose(joint_fixture(prepared, statistical=True, neural=True, network_status="error"))


def request(report, **updates):
    return ReviewSourceEvidenceReport.model_validate(
        {
            "decision_id": uuid4(),
            "report_sha256": report.review_sha256,
            "verdict": "needs_more_information",
            "comment": "Authored service-role control; actual engineer identity is unavailable.",
        }
        | updates
    )


def saved(report):
    return SourceEvidenceDecision.from_report(
        report, request(report), service_role="engineer", created_at=datetime.now(UTC)
    )


def reseal(value):
    unsigned = {
        name: content
        for name, content in value.items()
        if name not in {"decision_json", "decision_sha256"}
    }
    proof = ml_json(unsigned)
    return unsigned | {
        "decision_json": proof,
        "decision_sha256": sha256(proof.encode()).hexdigest(),
    }


@pytest.mark.parametrize("role", ["engineer", "admin"])
@pytest.mark.parametrize("verdict", ["rejected", "needs_more_information"])
def test_service_role_can_record_only_a_non_approval_disposition(report, role, verdict):
    before = report.model_dump_json()
    view = SourceEvidenceDecision.from_report(
        report, request(report, verdict=verdict), service_role=role, created_at=datetime.now(UTC)
    )
    view.validate_report(report)
    assert SourceEvidenceDecision.model_validate_json(view.model_dump_json()) == view
    assert view.report_id == report.report_id and view.report_sha256 == report.review_sha256
    assert (view.before, view.after) == (report.before, report.after)
    assert view.service_role == role and view.request.verdict == verdict
    assert not any((view.individual_identity_verified, view.approved, view.applied))
    assert report.model_dump_json() == before
    assert report.network.result.status == "error" and report.formal_qualification == "not_proven"


@pytest.mark.parametrize("role", ["reader", "analyst", "unknown"])
def test_non_engineer_role_cannot_construct_a_disposition(report, role):
    with pytest.raises(ValueError):
        SourceEvidenceDecision.from_report(
            report, request(report), service_role=role, created_at=datetime.now(UTC)
        )


@pytest.mark.parametrize("field", ["individual_identity_verified", "approved", "applied"])
@pytest.mark.parametrize("value", [True, 0, 1, "false"])
def test_false_flags_are_exact_false_even_when_proof_is_resealed(report, field, value):
    candidate = saved(report).model_dump(mode="json") | {field: value}
    with pytest.raises(ValueError):
        SourceEvidenceDecision.model_validate(reseal(candidate))


@pytest.mark.parametrize(
    "updates",
    [
        {"comment": ""},
        {"comment": " \n\t"},
        {"comment": "x\x00"},
        {"comment": "x" * 1201},
        {"comment": 1},
        {"verdict": "approved"},
        {"service_role": "admin"},
        {"individual_identity_verified": True},
        {"report_sha256": "F" * 64},
        {"version": "source-evidence-decision-request-9.0.0"},
    ],
)
def test_request_cannot_supply_approval_actor_identity_or_invalid_comment(report, updates):
    with pytest.raises(ValueError):
        request(report, **updates)


def test_unicode_comment_and_non_utc_aware_time_roundtrip_exactly(report):
    comment = "😀" * 1200
    stamp = datetime.now(timezone(timedelta(hours=3)))
    view = SourceEvidenceDecision.from_report(
        report, request(report, comment=comment), service_role="admin", created_at=stamp
    )
    assert view.request.comment == comment and view.created_at == stamp
    assert len(view.model_dump_json().encode()) <= 32 * 1024
    view.validate_report(report)


@pytest.mark.parametrize("stamp_kind", ["naive", "past"])
def test_decision_requires_aware_time_after_selected_report(report, stamp_kind):
    stamp = (
        datetime.now(UTC).replace(tzinfo=None)
        if stamp_kind == "naive"
        else report.created_at - timedelta(microseconds=1)
    )
    with pytest.raises(ValueError):
        SourceEvidenceDecision.from_report(
            report, request(report), service_role="admin", created_at=stamp
        )


@pytest.mark.parametrize(
    "field,value",
    [
        ("patch_id", None),
        ("report_id", None),
        ("draft_sha256", "f" * 64),
        ("before_analysis_id", None),
        ("before_analysis_sha256", "f" * 64),
    ],
)
def test_coherently_resealed_projection_still_requires_exact_selected_report(report, field, value):
    candidate = saved(report).model_dump(mode="json") | {field: value or str(uuid4())}
    tampered = SourceEvidenceDecision.model_validate(reseal(candidate))
    with pytest.raises(ValueError):
        tampered.validate_report(report)


def test_resealed_canonical_projection_and_mismatched_report_pin_are_refused(report):
    candidate = saved(report).model_dump(mode="json")
    candidate["before"]["canonical_sha256"] = "f" * 64
    tampered = SourceEvidenceDecision.model_validate(reseal(candidate))
    with pytest.raises(ValueError):
        tampered.validate_report(report)
    with pytest.raises(ValueError):
        SourceEvidenceDecision.from_report(
            report,
            request(report, report_sha256="f" * 64),
            service_role="admin",
            created_at=datetime.now(UTC),
        )


def test_invalid_proof_and_request_decision_identity_are_rejected(report):
    candidate = saved(report).model_dump(mode="json")
    with pytest.raises(ValueError):
        SourceEvidenceDecision.model_validate(candidate | {"decision_sha256": "f" * 64})
    with pytest.raises(ValueError):
        SourceEvidenceDecision.model_validate(reseal(candidate | {"decision_id": str(uuid4())}))


def test_metadata_summary_omits_comment_and_proof_and_preserves_recorded_role(report):
    decision = saved(report)
    summary = SourceEvidenceDecisionSummary.from_decision(decision)
    assert summary.version == "source-evidence-decision-summary-0.1.0"
    assert summary.decision_id == decision.decision_id
    assert summary.report_sha256 == decision.report_sha256
    assert summary.decision_sha256 == decision.decision_sha256
    assert summary.created_at == decision.created_at and summary.service_role == "engineer"
    assert summary.verdict == decision.request.verdict
    assert (
        "comment" not in summary.model_dump_json()
        and "decision_json" not in SourceEvidenceDecisionSummary.model_fields
    )
    assert not any((summary.individual_identity_verified, summary.approved, summary.applied))


@pytest.mark.parametrize("field", ["individual_identity_verified", "approved", "applied"])
def test_summary_false_flags_are_not_numeric_aliases(report, field):
    summary = SourceEvidenceDecisionSummary.from_decision(saved(report))
    with pytest.raises(ValueError):
        SourceEvidenceDecisionSummary.model_validate(summary.model_dump() | {field: 0})


def test_summary_cannot_hide_an_invalid_decision_proof(report):
    decision = saved(report).model_copy(update={"decision_sha256": "f" * 64})
    with pytest.raises(ValueError):
        SourceEvidenceDecisionSummary.from_decision(decision)


def test_fresh_proof_budget_has_a_distinct_admission_failure(report, monkeypatch):
    monkeypatch.setattr(decision_contracts, "MAX_SOURCE_EVIDENCE_DECISION_BYTES", 16)
    with pytest.raises(SourceEvidenceDecisionProjectionTooLarge):
        saved(report)
