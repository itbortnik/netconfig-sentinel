"""Partial policy observations never become a numeric aggregate, approval or paired verdict."""

from datetime import timedelta
from uuid import uuid4

import pytest
from app.api.source_evidence_decision_partial_contracts import (
    ReviewSourceEvidenceReportV5,
    SourceEvidenceDecisionV5,
    parse_source_evidence_decision_json,
    source_evidence_decision,
    validate_source_evidence_decision,
)
from app.api.source_evidence_decision_scope_contracts import ReviewSourceEvidenceReportV4
from app.api.source_risk_partial_contracts import (
    CreateSourceRiskAssessmentV3,
    SourceRiskAssessmentV3,
    SourceRiskSummaryV3,
    parse_source_risk_json,
    source_risk_assessment,
    validate_source_risk_record,
)
from app.api.source_risk_scope_contracts import CreateSourceRiskAssessmentV2
from app.detection.fusion.source_partial_priority import SourcePriorityCompositionV3
from app.detection.fusion.source_scope_priority import PRIORITY_SOURCES
from test_partial_policy_diagnostic import rehash
from test_source_partial_evidence import joint_records


def assessed(vendor="cisco", partial="after", **options):
    draft, child, report = joint_records(vendor, partial, **options)
    request = CreateSourceRiskAssessmentV3(
        assessment_id=uuid4(),
        report_sha256=report.review_sha256,
        profile_version="source-priority-profile-0.1.0",
    )
    value = SourceRiskAssessmentV3.from_evidence(
        draft,
        report,
        request,
        child,
        service_role="engineer",
        created_at=report.created_at + timedelta(seconds=1),
    )
    return draft, child, report, value


@pytest.mark.parametrize("vendor", ["cisco", "juniper"])
@pytest.mark.parametrize("partial", ["before", "after", "both"])
def test_saved_partial_priority_suppresses_every_aggregate_weight(vendor, partial):
    draft, child, report, value = assessed(vendor, partial)
    comp = value.composition
    assert comp.coverage == "partial"
    assert comp.status == "unavailable"
    assert comp.score is comp.band is None
    assert tuple(row.source for row in comp.components) == PRIORITY_SOURCES
    assert all(row.effective_weight == 0.0 and row.contribution is None for row in comp.components)
    assert comp.availability_mask == ("policy",)
    assert comp.applied_guardrails == ()
    assert comp.components[0].status == "completed"
    assert all(row.raw_score is None and row.observation is None for row in comp.components[1:])
    assert parse_source_risk_json(value.model_dump_json()) == value
    validate_source_risk_record(value, draft, report, child)
    assert SourceRiskSummaryV3.from_assessment(value).score is None
    if partial == "before":
        assert comp.candidate_parser_confidence == 1.0
        assert comp.score is None


@pytest.mark.parametrize("vendor", ["cisco", "juniper"])
def test_critical_policy_guard_is_visible_without_applying_floor_to_null(vendor):
    _, _, _, value = assessed(vendor, critical=True)
    assert value.composition.components[0].observation.critical_policy_present is True
    assert [(row.kind, row.floor) for row in value.composition.applicable_guardrails] == [
        ("critical_policy", 0.90)
    ]
    assert value.composition.applied_guardrails == ()
    assert value.composition.score is None


@pytest.mark.parametrize(
    "case",
    [
        "score",
        "band",
        "weight",
        "contribution",
        "network_zero",
        "applied_guard",
        "coverage",
        "identity",
    ],
)
def test_partial_composition_refuses_safe_zero_and_qualification_promotions(case):
    _, _, _, value = assessed(critical=True)
    body = value.composition.model_dump(mode="json")
    if case == "score":
        body["score"] = 0.0
    elif case == "band":
        body["band"] = "low"
    elif case == "weight":
        body["components"][0]["effective_weight"] = 1.0
    elif case == "contribution":
        body["components"][0]["contribution"] = 0.0
    elif case == "network_zero":
        body["components"][4]["raw_score"] = 0.0
    elif case == "applied_guard":
        body["applied_guardrails"] = body["applicable_guardrails"]
    elif case == "coverage":
        body["coverage"] = "supported_complete"
    else:
        body["individual_identity_verified"] = 0
    with pytest.raises(ValueError):
        SourcePriorityCompositionV3.model_validate(body)


@pytest.mark.parametrize("field", ["individual_identity_verified", "approved", "applied"])
@pytest.mark.parametrize("bad", [0, True])
def test_resealed_typed_risk_record_cannot_promote_service_role(field, bad):
    _, _, _, value = assessed()
    with pytest.raises(ValueError):
        SourceRiskAssessmentV3.model_validate(rehash(value.model_dump(mode="json") | {field: bad}))
    with pytest.raises(ValueError):
        SourceRiskAssessmentV3.model_validate(value.model_copy(update={field: bad}))


def test_missing_adverse_guard_refuses_even_with_resealed_outer_proof():
    _, _, _, value = assessed(critical=True)
    body = value.model_dump(mode="json")
    body["composition"]["applicable_guardrails"] = []
    with pytest.raises(ValueError):
        SourceRiskAssessmentV3.model_validate(rehash(body))


def test_priority_history_validation_does_not_rerun_policy(monkeypatch):
    draft, child, report, value = assessed()
    monkeypatch.setattr(
        "app.detection.policy_diagnostic.evaluate_policies",
        lambda *args, **kwargs: pytest.fail("history cannot rerun policy"),
    )
    monkeypatch.setattr("app.detection.policy_engine.POLICY_CATALOGS", {})
    validate_source_risk_record(value, draft, report, child)


def test_old_priority_protocol_refuses_new_partial_report():
    draft, child, report, value = assessed()
    request = CreateSourceRiskAssessmentV2(
        assessment_id=uuid4(),
        report_sha256=report.review_sha256,
        profile_version="source-priority-profile-0.1.0",
    )
    with pytest.raises(ValueError, match="protocols differ"):
        source_risk_assessment(
            draft, report, request, child, service_role="engineer", created_at=value.created_at
        )


@pytest.mark.parametrize("verdict", ["rejected", "needs_more_information"])
def test_partial_report_service_dispositions_keep_identity_and_approval_false(verdict):
    _, _, report, _ = assessed()
    request = ReviewSourceEvidenceReportV5(
        decision_id=uuid4(),
        report_sha256=report.review_sha256,
        verdict=verdict,
        comment="Partial parsing requires individual review and more source context.",
    )
    value = source_evidence_decision(
        report,
        request,
        service_role="engineer",
        created_at=report.created_at + timedelta(seconds=2),
    )
    assert value.individual_identity_verified is value.approved is value.applied is False
    assert parse_source_evidence_decision_json(value.model_dump_json()) == value
    validate_source_evidence_decision(value, report)
    with pytest.raises(ValueError):
        SourceEvidenceDecisionV5.model_validate(value.model_copy(update={"approved": 0}))
    old_request = ReviewSourceEvidenceReportV4(
        decision_id=uuid4(),
        report_sha256=report.review_sha256,
        verdict=verdict,
        comment="More source context required.",
    )
    with pytest.raises(ValueError, match="protocols differ"):
        source_evidence_decision(
            report, old_request, service_role="engineer", created_at=value.created_at
        )
