"""Scope-aware priority retains the historical profile without training or inference."""

from copy import deepcopy
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from app.api.source_risk_scope_contracts import (
    CreateSourceRiskAssessmentV2,
    SourceRiskAssessmentV2,
    parse_source_risk_json,
    parse_source_risk_request,
    source_risk_assessment,
    source_risk_summary,
    validate_source_risk_record,
)
from app.detection.fusion.source_priority import compose_source_priority as legacy_compose
from app.detection.fusion.source_scope_priority import (
    SourcePriorityCompositionV2,
    compose_source_priority,
    validate_source_priority,
)
from app.verification.ingress_scope_worker import derived_fields
from test_source_priority import compose as old_compose
from test_source_priority import inputs, parent, reseal
from test_source_scope_contracts import scoped_inputs, scoped_parent


def compose(value):
    draft, report, deterministic, forest, neural, network = value
    return compose_source_priority(
        draft, report, deterministic, forest=forest, neural=neural, network=network
    )


def assessment(value, version="0.2.0"):
    draft, report, deterministic, forest, neural, network = value
    request = parse_source_risk_request(
        dict(
            version="source-risk-request-" + version,
            assessment_id=uuid4(),
            report_sha256=report.review_sha256,
            profile_version="source-priority-profile-0.1.0",
        )
    )
    return source_risk_assessment(
        draft,
        report,
        request,
        deterministic,
        forest=forest,
        neural=neural,
        network=network,
        service_role="engineer",
        created_at=datetime.now(UTC),
    )


@pytest.mark.parametrize("name", ["loss", "gain", "mixed_equal_counts", "no_witnesses"])
@pytest.mark.parametrize("state", ["observed", "unknown", "eligibility_unknown"])
def test_scope_availability_never_rewrites_independent_direction_or_profile(name, state):
    historical = inputs(name)
    parent(historical)
    old = old_compose(historical)
    value = scoped_parent(scoped_inputs(name, state))
    result = compose(value)
    assert result.version == "source-priority-composition-0.2.0"
    assert result.profile_version == old.profile_version
    assert (result.score, result.band, result.availability_mask) == (
        old.score,
        old.band,
        old.availability_mask,
    )
    assert [(x.configured_weight, x.effective_weight, x.raw_score) for x in result.components] == [
        (x.configured_weight, x.effective_weight, x.raw_score) for x in old.components
    ]
    observation = result.components[-1].observation
    assert observation.execution.ingress_scope == value[-1].outcome.network_execution.ingress_scope
    assert [x.model_dump() for x in result.applicable_guardrails] == [
        x.model_dump() for x in old.applicable_guardrails
    ]
    if name in {"loss", "mixed_equal_counts"}:
        assert result.score >= 0.95
        assert result.components[-1].raw_score == 1
    else:
        assert result.components[-1].raw_score is None
    saved = assessment(value)
    assert saved.composition == result
    assert saved.version == "source-risk-assessment-0.2.0"
    assert parse_source_risk_json(saved.model_dump_json()) == saved
    assert source_risk_summary(saved).version == "source-risk-summary-0.2.0"
    assert saved.approved is saved.applied is saved.individual_identity_verified is False


def test_scope_resealed_factor_is_recomposed_from_complete_saved_chain():
    value = scoped_parent(scoped_inputs())
    result = compose(value)
    body = result.model_dump(mode="json")
    scope = body["components"][-1]["observation"]["execution"]["ingress_scope"]
    row = scope["after"]["interfaces"][0]
    row["active"], row["eligible"], row["eligibility_reason"] = False, False, "inactive"
    scope.update(derived_fields(scope["before"], scope["after"]))
    forged = SourcePriorityCompositionV2.model_validate(body)
    draft, report, deterministic, forest, neural, network = value
    with pytest.raises(ValueError):
        validate_source_priority(
            forged, draft, report, deterministic, forest=forest, neural=neural, network=network
        )
    saved = assessment(value)
    payload = saved.model_dump(mode="json")
    payload["composition"] = forged.model_dump(mode="json")
    forged_saved = SourceRiskAssessmentV2.model_validate(reseal(payload))
    with pytest.raises(ValueError):
        validate_source_risk_record(
            forged_saved,
            draft,
            report,
            deterministic,
            forest=forest,
            neural=neural,
            network=network,
        )


@pytest.mark.parametrize("version", ["0.1.0", "0.2.0", "0.3.0"])
def test_old_risk_request_keeps_original_assessment_and_new_request_rejects_old_report(version):
    value = inputs("no_network")
    parent(value, version)
    saved = assessment(value, "0.1.0")
    assert saved.version == "source-risk-assessment-0.1.0"
    assert saved.composition.version == "source-priority-composition-0.1.0"
    assert (
        parse_source_risk_json(saved.model_dump_json()).model_dump_json() == saved.model_dump_json()
    )
    with pytest.raises(ValueError):
        assessment(value)
    new = scoped_parent(scoped_inputs())
    with pytest.raises(ValueError):
        assessment(new, "0.1.0")
    with pytest.raises(ValueError):
        legacy_compose(new[0], new[1], new[2], forest=new[3], neural=new[4], network=new[5])


def test_new_request_cannot_choose_profile_weights_or_claim_quality():
    value = scoped_parent(scoped_inputs())
    request = assessment(value).request.model_dump()
    for update in [
        {"weights": {"verification": 1}},
        {"approved": False},
        {"profile_version": "source-priority-profile-0.2.0"},
    ]:
        with pytest.raises(ValueError):
            CreateSourceRiskAssessmentV2.model_validate(deepcopy(request) | update)
