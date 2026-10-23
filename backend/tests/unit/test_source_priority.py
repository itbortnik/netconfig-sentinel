"""Pure authored priority controls: no databases, model fits, SDK or source execution."""

import json
from copy import deepcopy
from functools import cache
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

import pytest
from app.api.patch_contracts import PatchDraft, draft_fingerprint
from app.api.source_deterministic_contracts import (
    SourceDeterministicOutcome,
    SourceDeterministicRecheck,
)
from app.api.source_evidence_direction_contracts import (
    CreateSourceEvidenceReportV3,
    source_evidence_report,
)
from app.api.source_forest_contracts import SourceForestRecheck
from app.api.source_ml_contracts import SourceMlRecheck, ml_json, source_ml_fingerprint
from app.api.source_patch_direction_contracts import (
    SourcePatchOutcomeV3,
    SourcePatchVerificationV3,
    parse_source_patch_review,
)
from app.detection.fusion.source_priority import (
    FindingPriorityObservation,
    ForestPriorityObservation,
    NeuralPriorityObservation,
    SourcePriorityComponent,
    SourcePriorityComposition,
    compose_source_priority,
    validate_source_priority,
)
from app.verification.reachability_impact import empty_reachability_impact


@cache
def controls():
    # This existing, immutable fixture has complete normative children and proofs.
    # Installed-test runners must retain this fixture path (or run from the repository).
    ancestors = (*Path(__file__).resolve().parents, Path.cwd())
    path = next(
        root / "frontend/src/testdata/sourceDirectionControls.json"
        for root in ancestors
        if (root / "frontend/src/testdata/sourceDirectionControls.json").is_file()
    )
    return {row["name"]: row for row in json.loads(path.read_bytes())["cases"]}


def inputs(name="no_witnesses"):
    row = deepcopy(controls()[name])
    children = row["children"]
    return [
        PatchDraft.model_validate(row["draft"]),
        None,
        SourceDeterministicRecheck.model_validate(children["deterministic"]),
        SourceForestRecheck.model_validate(children["forest"]) if children["forest"] else None,
        SourceMlRecheck.model_validate(children["neural"]) if children["neural"] else None,
        parse_source_patch_review(children["network"]) if children["network"] else None,
    ]


def parent(value, version="0.3.0"):
    draft, _, deterministic, forest, neural, network = value
    request = CreateSourceEvidenceReportV3(
        report_id=uuid4(),
        draft_sha256=draft.draft_sha256,
        **{
            kind: {
                "record_id": child.verification_id if kind == "network" else child.recheck_id,
                "review_sha256": child.review_sha256,
            }
            if child is not None
            else None
            for kind, child in [
                ("deterministic", deterministic),
                ("forest", forest),
                ("neural", neural),
                ("network", network),
            ]
        },
    )
    if version != "0.3.0":
        from app.api.source_evidence_direction_contracts import parse_source_evidence_request

        request = parse_source_evidence_request(
            request.model_dump() | {"version": "source-evidence-request-" + version}
        )
    value[1] = source_evidence_report(
        draft,
        request,
        deterministic,
        forest=forest,
        neural=neural,
        network=network,
        created_at=max(
            [draft.created_at]
            + [
                child.outcome.completed_at
                for child in (deterministic, forest, neural, network)
                if child is not None
            ]
        ),
    )
    return value


def compose(value):
    draft, report, deterministic, forest, neural, network = value
    if report is None:
        parent(value)
        report = value[1]
    return compose_source_priority(
        draft, report, deterministic, forest=forest, neural=neural, network=network
    )


def validate(result, value):
    draft, report, deterministic, forest, neural, network = value
    validate_source_priority(
        result, draft, report, deterministic, forest=forest, neural=neural, network=network
    )


def reseal(value):
    body = {
        key: field for key, field in value.items() if key not in {"review_json", "review_sha256"}
    }
    proof = ml_json(body)
    return value | {"review_json": proof, "review_sha256": sha256(proof.encode()).hexdigest()}


def policy(value, specs):
    child = value[2]
    body = child.outcome.model_dump(mode="json")
    report = body["report"]
    template = deepcopy(report["after"]["policy_findings"][0])
    rows = [
        template
        | {
            "finding_id": str(uuid4()),
            "category": "authored.priority." + str(index),
            "severity": severity,
            "confidence": confidence,
            "anomaly_score": anomaly,
        }
        for index, (severity, confidence, anomaly) in enumerate(specs)
    ]
    report["after"]["policy_findings"] = rows
    report["policy_changes"] = {
        "introduced": rows,
        "resolved": report["before"]["policy_findings"],
        "persistent": [],
    }
    value[2] = SourceDeterministicRecheck.from_records(
        child.intent, SourceDeterministicOutcome.model_validate(body)
    )
    value[1] = None
    return value


def forest_scores(value, score, minimum=0.1, maximum=0.9):
    child = value[3]
    body = child.model_dump(mode="json")
    for model in [
        body["intent"]["selection"]["original"]["model"],
        body["outcome"]["report"]["model"],
    ]:
        model["metadata"].update(training_score_min=minimum, training_score_max=maximum)
    body["outcome"]["intent_sha256"] = source_ml_fingerprint(
        type(child.intent).model_validate(body["intent"])
    )
    scores = body["outcome"]["report"]["scores"]
    decision = score - body["outcome"]["report"]["model"]["decision_offset"]
    scores.update(
        after_score_samples=score,
        after_decision_function=decision,
        after_prediction=-1 if decision < 0 else 1,
    )
    value[3] = SourceForestRecheck.model_validate(reseal(body))
    value[1] = None
    return value


@pytest.mark.parametrize("name", list(controls()))
def test_full_parent_chain_keeps_direction_and_raw_semantics_separate(name):
    value = inputs(name)
    # Use a current timestamp only for a new authored parent, never rewrite existing records.
    result = compose(value)
    validate(result, value)
    assert result.profile_version == "source-priority-profile-0.1.0" and result.side == "after"
    assert [row.configured_weight for row in result.components] == [0.35, 0.15, 0.10, 0.10, 0.30]
    assert result.report_sha256 == value[1].review_sha256
    assert result.review_status == "needs_review" and result.formal_qualification == "not_proven"
    assert result.calibrated is result.quality_proven is result.approved is result.applied is False
    network = result.components[-1]
    adverse = name in {"loss", "mixed_equal_counts", "metadata_unavailable"}
    assert (network.raw_score == 1.0) is adverse
    if adverse:
        assert (
            result.score >= 0.95 and result.applicable_guardrails[-1].kind == "observed_scoped_loss"
        )
    else:
        assert network.status == "unavailable" and network.raw_score is network.contribution is None
        assert network.effective_weight == 0
    assert SourcePriorityComposition.model_validate_json(result.model_dump_json()) == result


def test_known_numeric_mask_and_redistribution_excludes_verification_without_inventing_zero():
    result = compose(inputs())
    assert result.availability_mask == ("policy", "peer_group", "statistical", "transformer")
    assert [row.raw_score for row in result.components] == [0.75, 1.0, 0.0, 0.2, None]
    assert result.score == pytest.approx((0.35 * 0.75 + 0.15 * 1 + 0.10 * 0.2) / 0.70)
    assert result.components[2].status == "completed" and result.components[2].contribution == 0
    assert result.band == "high"


def test_critical_policy_with_zero_confidence_still_sets_floor_independent_of_strongest():
    result = compose(policy(inputs(), [("critical", 0.0, 0.0), ("high", 1.0, 0.0)]))
    observation = result.components[0].observation
    assert (
        observation.strongest.severity.value == "high"
        and observation.critical_policy_present is True
    )
    assert result.components[0].raw_score == 0.75
    assert result.score == 0.90 and result.applicable_guardrails[0].kind == "critical_policy"


def test_anomaly_confidence_and_severity_are_original_distinct_fields_not_interchangeable():
    result = compose(policy(inputs(), [("low", 0.5, 0.9)]))
    row = result.components[0]
    assert row.raw_score == 0.45
    assert row.observation.strongest.anomaly_score == 0.9
    assert row.observation.strongest.confidence == 0.5
    assert row.observation.strongest.severity.value == "low"


def test_completed_empty_findings_and_unavailable_peer_context_are_different():
    result = compose(policy(inputs(), []))
    assert result.components[0].raw_score == 0 and result.components[0].status == "completed"
    peer = result.components[1].model_dump()
    peer.update(
        observation=FindingPriorityObservation(
            detector="peer_baseline", finding_count=0, strongest=None, critical_policy_present=False
        ),
        raw_score=0.0,
        effective_weight=0.0,
        contribution=0.0,
    )
    completed = SourcePriorityComponent.model_validate(peer)
    missing = SourcePriorityComponent.model_validate(
        peer
        | {
            "status": "unavailable",
            "reason": "peer_context_unavailable",
            "observation": None,
            "raw_score": None,
            "contribution": None,
        }
    )
    assert completed.raw_score == 0.0 and missing.raw_score is None


@pytest.mark.parametrize(
    "score,minimum,maximum,normalized,priority",
    [
        (-0.3, 0.1, 0.9, 0.25, 0),
        (-0.8, 0.1, 0.9, 0.875, 0.14),
        (-0.8, 0.8, 0.8, 0.5, 0.08),
        (-0.9, 0.8, 0.8, 1.0, 0.16),
        (-0.7, 0.8, 0.8, 0.5, 0.08),
    ],
)
def test_forest_inlier_outlier_and_degenerate_training_range(
    score, minimum, maximum, normalized, priority
):
    result = compose(forest_scores(inputs(), score, minimum, maximum))
    row = result.components[2]
    assert isinstance(row.observation, ForestPriorityObservation)
    assert row.observation.raw_anomaly_score == -score
    assert row.observation.normalized_anomaly == pytest.approx(normalized)
    assert row.observation.proxy_confidence == 0.16
    assert row.raw_score == pytest.approx(priority)
    assert row.observation.after_score_samples == score


@pytest.mark.parametrize("semantics", ["injected_mutation", "confirmed_anomaly"])
@pytest.mark.parametrize("enabled", [True, False])
def test_neural_keeps_target_semantics_and_does_not_replace_disabled_anomaly_with_categories(
    semantics, enabled
):
    value = inputs()
    body = value[4].model_dump(mode="json")
    for side in ("before", "after"):
        model = body["outcome"]["report"][side]
        model["model"]["target_semantics"] = semantics
        model["model"]["enabled_heads"]["anomaly"] = enabled
        if not enabled:
            model["prediction"]["anomaly_score"] = None
    value[4] = SourceMlRecheck.model_validate(reseal(body))
    row = compose(value).components[3]
    assert isinstance(row.observation, NeuralPriorityObservation)
    assert row.observation.target_semantics == semantics
    assert row.observation.classes == ("telnet_enabled",)
    assert row.raw_score == (0.2 if enabled else None)
    assert row.reason == ("available" if enabled else "neural_anomaly_head_disabled")


def partial(value):
    draft = value[0].model_dump(mode="json")
    draft["diff"]["after"]["parser_confidence"] = 0.8
    draft["diff"]["coverage"] = "partial"
    from app.api.diff_contracts import SnapshotDiff

    draft["draft_sha256"] = draft_fingerprint(SnapshotDiff.model_validate(draft["diff"]))
    old = value[0].draft_sha256
    value[0] = PatchDraft.model_validate(draft)

    # Rebind every nested ordinary request/selection to this authored partial draft.
    def replace(node):
        if isinstance(node, dict):
            return {
                key: (
                    value[0].draft_sha256
                    if key == "draft_sha256" and field == old
                    else replace(field)
                )
                for key, field in node.items()
            }
        if isinstance(node, list):
            return [replace(field) for field in node]
        return node

    for index in (2, 3, 4, 5):
        child = value[index]
        if child is None:
            continue
        body = replace(child.model_dump(mode="json"))
        intent = type(child.intent).model_validate(body["intent"])
        body["outcome"]["intent_sha256"] = source_ml_fingerprint(intent)
        value[index] = type(child).model_validate(reseal(body))
    value[1] = None
    return value


def test_partial_coverage_keeps_critical_and_loss_observations_but_suppresses_entire_aggregate():
    result = compose(partial(policy(inputs("loss"), [("critical", 0.0, 0.0)])))
    assert result.status == "unavailable" and result.score is result.band is None
    assert len(result.applicable_guardrails) == 2 and result.applied_guardrails == ()
    assert (
        result.components[-1].raw_score == 1
        and result.components[0].observation.critical_policy_present
    )
    assert all(row.effective_weight == 0 and row.contribution is None for row in result.components)


@pytest.mark.parametrize(
    "status,reason",
    [("unavailable", "sdk_missing"), ("error", "timeout"), ("incomplete", "initialization_issues")],
)
def test_unperformed_network_states_are_unavailable_even_with_other_available_scores(
    status, reason
):
    value = inputs("loss")
    network = value[-1]
    body = network.outcome.model_dump()
    execution = body["network_execution"]
    execution.update(
        sdk_version=None,
        sdk_observation="not_observed" if status != "incomplete" else "metadata_unavailable",
        reachability_impact=empty_reachability_impact("not_observed", "not_run").model_dump(),
    )
    execution["result"].update(
        status=status,
        reason=reason,
        engine_version=None,
        difference_count=None,
        before_reachable_count=None,
        after_reachable_count=None,
        cleanup_complete=None,
    )
    value[-1] = SourcePatchVerificationV3.from_records(
        network.intent, SourcePatchOutcomeV3.model_validate(body)
    )
    result = compose(value)
    assert result.components[-1].raw_score is None and result.applicable_guardrails == ()


@pytest.mark.parametrize(
    "flag", ["calibrated", "quality_proven", "individual_identity_verified", "approved", "applied"]
)
@pytest.mark.parametrize("invalid", [True, 0, "false"])
def test_priority_flags_are_identity_strict_false(flag, invalid):
    body = compose(inputs()).model_dump()
    with pytest.raises(ValueError):
        SourcePriorityComposition.model_validate(body | {flag: invalid})


@pytest.mark.parametrize("invalid", [float("nan"), float("inf"), True, "0.5"])
def test_nonfinite_and_boolean_or_string_scores_cannot_enter_new_numeric_contracts(invalid):
    body = compose(inputs()).model_dump()
    body["components"][0]["observation"]["strongest"]["confidence"] = invalid
    with pytest.raises(ValueError):
        SourcePriorityComposition.model_validate(body)


@pytest.mark.parametrize(
    "field", ["configured_weight", "effective_weight", "contribution", "raw_score"]
)
def test_recomputed_component_rejects_forged_weights_or_contribution(field):
    body = compose(inputs()).model_dump()
    body["components"][0][field] = 0.01
    with pytest.raises(ValueError):
        SourcePriorityComposition.model_validate(body)


def test_self_consistent_false_original_observation_cannot_replace_full_selected_children():
    value = inputs()
    original = compose(value)
    forged = original.model_dump()
    # Consistent arithmetic still requires the exact original child observation.
    forged["components"][3]["observation"]["anomaly_score"] = 0.4
    forged["components"][3]["raw_score"] = 0.4
    forged["components"][3]["contribution"] = 0.4 * forged["components"][3]["effective_weight"]
    forged["score"] = sum(row["contribution"] or 0 for row in forged["components"])
    parsed = SourcePriorityComposition.model_validate(forged)
    with pytest.raises(ValueError):
        validate(parsed, value)


@pytest.mark.parametrize("where", ["parent", "child", "draft"])
def test_bypassed_mutable_instances_still_require_exact_full_chain(where):
    value = parent(inputs())
    if where == "parent":
        value[1] = value[1].model_copy(update={"review_sha256": "f" * 64})
    elif where == "child":
        value[2] = value[2].model_copy(update={"review_sha256": "f" * 64})
    else:
        value[0] = value[0].model_copy(update={"draft_sha256": "f" * 64})
    with pytest.raises(ValueError):
        compose(value)


@pytest.mark.parametrize("version", ["0.1.0", "0.2.0"])
def test_full_historical_joint_versions_are_accepted_without_reinterpreting_legacy_network(version):
    value = inputs("legacy_child" if version == "0.1.0" else "sdk_child")
    parent(value, version)
    result = compose(value)
    assert result.report_version.endswith(version)
    assert result.components[-1].reason == "legacy_network_protocol"
    validate(result, value)


def test_missing_optional_sources_keep_nulls_and_explicit_mask_instead_of_zero_scores():
    value = inputs()
    value[3:] = [None, None, None]
    result = compose(value)
    assert result.availability_mask == ("policy", "peer_group")
    assert result.score == pytest.approx((0.35 * 0.75 + 0.15) / 0.50)
    for row in result.components[2:]:
        assert row.reason == "not_selected" and row.evidence is row.observation is None
        assert row.raw_score is row.contribution is None and row.effective_weight == 0


def test_cleanup_unconfirmed_keeps_full_loss_query_but_no_adverse_priority_or_floor():
    value = inputs("loss")
    network = value[-1]
    body = network.outcome.model_dump()
    body["network_execution"]["result"]["cleanup_complete"] = False
    body["network_execution"]["reachability_impact"] = empty_reachability_impact(
        "unknown", "cleanup_unconfirmed"
    ).model_dump()
    value[-1] = SourcePatchVerificationV3.from_records(
        network.intent, SourcePatchOutcomeV3.model_validate(body)
    )
    result = compose(value)
    assert result.components[-1].observation.result.status == "differences_found"
    assert result.components[-1].raw_score is None and result.applicable_guardrails == ()


@pytest.mark.parametrize(
    "field", ["profile_version", "availability_mask", "components", "limitations"]
)
def test_fixed_profile_inventory_order_mask_and_limitations_cannot_be_redefined(field):
    body = compose(inputs()).model_dump()
    body[field] = {
        "profile_version": "client-selected-0.1.0",
        "availability_mask": ("policy",),
        "components": body["components"][::-1],
        "limitations": (),
    }[field]
    with pytest.raises(ValueError):
        SourcePriorityComposition.model_validate(body)


def test_boolean_prediction_cannot_masquerade_as_integer_inlier():
    observation = compose(inputs()).components[2].observation.model_dump()
    with pytest.raises(ValueError):
        ForestPriorityObservation.model_validate(observation | {"after_prediction": True})


def test_constructed_nested_finding_boolean_is_rejected_before_input_coercion():
    value = parent(inputs())
    child = value[2]
    finding = child.outcome.report.after.policy_findings[0]
    changed_finding = finding.model_copy(update={"confidence": True})
    changed_side = child.outcome.report.after.model_copy(
        update={
            "policy_findings": (changed_finding, *child.outcome.report.after.policy_findings[1:])
        }
    )
    changed_report = child.outcome.report.model_copy(update={"after": changed_side})
    changed_outcome = child.outcome.model_copy(update={"report": changed_report})
    value[2] = child.model_copy(update={"outcome": changed_outcome})
    with pytest.raises(ValueError, match="boolean coercion"):
        compose(value)
