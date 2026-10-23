"""Authored assessment contract controls; no SDK, models, API or persistence execution."""

from datetime import timedelta, timezone
from hashlib import sha256
from uuid import uuid4

import pytest
from app.api import source_risk_contracts as contracts
from app.api.source_evidence_direction_contracts import parse_source_evidence_report_json
from app.api.source_ml_contracts import ml_json
from app.api.source_risk_contracts import (
    CreateSourceRiskAssessment,
    SourceRiskAssessment,
    SourceRiskProjectionTooLarge,
    SourceRiskSummary,
)
from test_source_priority import controls, inputs, parent, partial


def selected(name="no_witnesses"):
    values = inputs(name)
    values[1] = parse_source_evidence_report_json(ml_json(controls()[name]["report"]))
    return values


def request(report, **updates):
    return CreateSourceRiskAssessment.model_validate(
        {
            "assessment_id": uuid4(),
            "report_sha256": report.review_sha256,
            "profile_version": "source-priority-profile-0.1.0",
            **updates,
        }
    )


def assess(values, *, options=None, role="engineer", at=None):
    draft, report, deterministic, forest, neural, network = values
    return SourceRiskAssessment.from_evidence(
        draft,
        report,
        options or request(report),
        deterministic,
        forest=forest,
        neural=neural,
        network=network,
        service_role=role,
        created_at=at or report.created_at + timedelta(seconds=1),
    )


def validate(assessment, values):
    draft, report, deterministic, forest, neural, network = values
    assessment.validate_evidence(
        draft, report, deterministic, forest=forest, neural=neural, network=network
    )


def reseal(body):
    proof = ml_json(
        {key: value for key, value in body.items() if key not in {"review_json", "review_sha256"}}
    )
    return body | {"review_json": proof, "review_sha256": sha256(proof.encode()).hexdigest()}


@pytest.mark.parametrize("name", list(controls()))
def test_normative_record_and_compact_summary_preserve_parent_and_priority_without_promotions(name):
    values = selected(name)
    record = assess(values)
    validate(record, values)
    assert record.report_id == values[1].report_id
    assert record.composition.report_sha256 == record.request.report_sha256
    assert record.created_at > values[1].created_at
    assert record.individual_identity_verified is record.approved is record.applied is False
    assert SourceRiskAssessment.model_validate_json(record.model_dump_json()) == record
    summary = SourceRiskSummary.from_assessment(record)
    assert summary.profile_version == record.request.profile_version
    assert summary.score == record.composition.score and summary.band == record.composition.band
    assert summary.applicable_guardrails == tuple(
        row.kind for row in record.composition.applicable_guardrails
    )
    assert not any(
        name in type(summary).model_fields for name in ("composition", "witnesses", "review_json")
    )


@pytest.mark.parametrize(
    "change",
    [
        {"profile_version": None},
        {"profile_version": "client-choice"},
        {"weights": {"policy": 1}},
        {"version": "source-risk-request-0.2.0"},
    ],
)
def test_request_disallows_missing_profile_client_weights_and_new_versions(change):
    body = request(selected()[1]).model_dump() | change
    if change == {"profile_version": None}:
        body.pop("profile_version")
    with pytest.raises(ValueError):
        CreateSourceRiskAssessment.model_validate(body)


@pytest.mark.parametrize("flag", ["individual_identity_verified", "approved", "applied"])
@pytest.mark.parametrize("invalid", [True, 0, "false"])
def test_outer_and_summary_flags_require_exact_false(flag, invalid):
    record = assess(selected())
    with pytest.raises(ValueError):
        SourceRiskAssessment.model_validate(
            reseal(record.model_dump(mode="json") | {flag: invalid})
        )
    with pytest.raises(ValueError):
        SourceRiskSummary.model_validate(
            SourceRiskSummary.from_assessment(record).model_dump() | {flag: invalid}
        )


@pytest.mark.parametrize(
    "field",
    ["assessment_id", "patch_id", "report_id", "report_sha256", "report_version", "draft_sha256"],
)
def test_resealed_duplicate_identity_fields_cannot_disagree_with_request_or_composition(field):
    record = assess(selected())
    changed = (
        str(uuid4())
        if field.endswith("_id")
        else "f" * 64
        if field.endswith("sha256")
        else "source-evidence-report-0.1.0"
    )
    with pytest.raises(ValueError):
        SourceRiskAssessment.model_validate(
            reseal(record.model_dump(mode="json") | {field: changed})
        )


@pytest.mark.parametrize("role", ["reader", "analyst"])
def test_constructor_requires_verify_role_and_chronology(role):
    values = selected()
    with pytest.raises(ValueError):
        assess(values, role=role)
    with pytest.raises(ValueError):
        assess(values, at=values[1].created_at - timedelta(microseconds=1))
    with pytest.raises(ValueError):
        assess(values, at=values[1].created_at.replace(tzinfo=None))


@pytest.mark.parametrize("offset", [-3, 3])
def test_normative_offset_and_server_first_role_are_retained(offset):
    values = selected()
    time = (values[1].created_at + timedelta(seconds=1)).astimezone(
        timezone(timedelta(hours=offset))
    )
    record = assess(values, role="admin", at=time)
    validate(record, values)
    assert record.created_at.isoformat() in record.review_json
    assert (
        SourceRiskAssessment.model_validate_json(record.model_dump_json()).review_json
        == record.review_json
    )
    assert record.service_role == "admin"


def test_partial_assessment_retains_applicable_loss_but_aggregate_is_unavailable():
    values = parent(partial(inputs("loss")))
    record = assess(values)
    validate(record, values)
    summary = SourceRiskSummary.from_assessment(record)
    assert summary.composition_status == "unavailable"
    assert summary.score is summary.band is None
    assert "observed_scoped_loss" in summary.applicable_guardrails
    assert record.composition.applied_guardrails == ()


def test_consistent_but_false_selected_model_value_is_rejected_against_full_children():
    values = selected()
    body = assess(values).model_dump(mode="json")
    composition = body["composition"]
    neural = composition["components"][3]
    neural["observation"]["anomaly_score"] = neural["raw_score"] = 0.4
    neural["contribution"] = 0.4 * neural["effective_weight"]
    composition["score"] = sum(row["contribution"] or 0 for row in composition["components"])
    forged = SourceRiskAssessment.model_validate(reseal(body))
    with pytest.raises(ValueError):
        validate(forged, values)


@pytest.mark.parametrize("target", ["record", "summary"])
def test_untrusted_nested_nonfinite_or_boolean_score_is_rejected(target):
    record = assess(selected())
    for bad in [True, float("nan"), float("inf")]:
        if target == "record":
            body = record.model_dump(mode="json")
            body["composition"]["score"] = bad
            with pytest.raises(ValueError):
                SourceRiskAssessment.model_validate(reseal(body))
        else:
            with pytest.raises(ValueError):
                SourceRiskSummary.model_validate(
                    SourceRiskSummary.from_assessment(record).model_dump() | {"score": bad}
                )


def test_proof_and_full_payload_budgets_fail_without_truncation(monkeypatch):
    values = selected()
    with monkeypatch.context() as narrow:
        narrow.setattr(contracts, "MAX_SOURCE_RISK_PROOF_BYTES", 1)
        with pytest.raises(SourceRiskProjectionTooLarge):
            assess(values)
    monkeypatch.setattr(contracts, "MAX_SOURCE_RISK_BYTES", 1)
    with pytest.raises(SourceRiskProjectionTooLarge):
        assess(values)


@pytest.mark.parametrize("version", ["0.1.0", "0.2.0"])
def test_assessment_can_select_historical_parent_protocol_without_rewriting_parent(version):
    values = inputs("legacy_child" if version == "0.1.0" else "sdk_child")
    parent(values, version)
    record = assess(values)
    validate(record, values)
    assert record.report_version == "source-evidence-report-" + version
    assert record.composition.components[-1].raw_score is None
