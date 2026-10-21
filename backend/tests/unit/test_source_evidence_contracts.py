"""Joint saved-evidence contracts; authored numeric fixtures establish no model quality."""

import json
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from uuid import uuid4

import pytest
from app.api.contracts import AnalysisResult, ModelSummary, SnapshotBinding, StatisticalContext
from app.api.model_patch_review_contracts import StatisticalRecheck
from app.api.patch_contracts import PatchDraft, draft_fingerprint
from app.api.source_deterministic_contracts import (
    SourceDeterministicOutcome,
    SourceDeterministicRecheck,
)
from app.api.source_evidence_contracts import (
    MAX_SOURCE_EVIDENCE_BYTES,
    CreateSourceEvidenceReport,
    SelectedEvidenceRef,
    SourceEvidenceProjectionTooLarge,
    SourceEvidenceReport,
    SourceEvidenceSummary,
)
from app.api.source_forest_contracts import (
    RunSourceForestRecheck,
    SourceForestIntent,
    SourceForestMember,
    SourceForestOutcome,
    SourceForestRecheck,
    SourceForestReport,
    SourceForestSelection,
)
from app.api.source_ml_contracts import (
    RunSourceMlRecheck,
    SourceMlIntent,
    SourceMlMember,
    SourceMlOutcome,
    SourceMlRecheck,
    ml_json,
    source_ml_fingerprint,
)
from app.api.source_patch_contracts import (
    SourcePatchIntent,
    SourcePatchMember,
    SourcePatchOutcome,
    SourcePatchVerification,
    VerifySourcePatch,
    source_network_digest,
    source_review_fingerprint,
)
from app.comparison.snapshots import compare_snapshots
from app.detection.baseline import PeerGroupKey
from app.detection.fusion import RiskSource, fuse_risk
from app.detection.statistical.features import FEATURE_NAMES
from app.detection.statistical.isolation_forest import IsolationForestMetadata
from app.verification.batfish import BatfishResult
from app.verification.preflight import review_configuration_change
from test_original_deterministic_pair import prepared as prepared
from test_source_deterministic_contracts import records as deterministic_records
from test_source_deterministic_contracts import rehash

from ml.inference.config_contracts import ConfigurationInferenceReport
from ml.inference.pair_contracts import ConfigurationPairReport


def authored_statistical_context(before):
    """Valid numeric context with a tiny authored manifest, without training or scoring."""
    stamp = before.created_at - timedelta(days=1)
    model = ModelSummary(
        model_id=uuid4(),
        created_at=stamp,
        artifact_sha256="7" * 64,
        decision_offset=-0.5,
        metadata=IsolationForestMetadata(
            library_version="authored-numeric-fixture",
            group=PeerGroupKey.from_config(before.canonical),
            sample_count=8,
            contamination=0.1,
            random_state=42,
            estimator_count=1,
            training_score_min=0.1,
            training_score_max=0.9,
            feature_medians=(0.0,) * len(FEATURE_NAMES),
            feature_scales=(1.0,) * len(FEATURE_NAMES),
        ),
        training=tuple(
            SnapshotBinding(
                configuration_id=uuid4(),
                device_id=uuid4(),
                source_sha256=sha256(f"authored-training-{index}".encode()).hexdigest(),
                created_at=stamp - timedelta(hours=1),
            )
            for index in range(8)
        ),
        training_hostnames=tuple(f"authored-{index}" for index in range(8)),
    )
    score = -0.4
    return StatisticalContext(
        model=model,
        score_samples=score,
        decision_function=score - model.decision_offset,
        prediction=1,
    )


def authored_neural_report(member, *, anomaly_score=0.3):
    """A numeric protocol fixture, not actual inference or independent quality evidence."""
    return ConfigurationInferenceReport.model_validate(
        {
            "model": {
                "version": "config-model-card-0.1.0",
                "kind": "native",
                "model_sha256": "a" * 64,
                "training_format": "multitask-training-0.1.0",
                "report_sha256": "b" * 64,
                "encoder_sha256": "c" * 64,
                "tokenizer_sha256": "d" * 64,
                "source_manifest_sha256": None,
                "train_fingerprint": "e" * 64,
                "selection_fingerprint": "f" * 64,
                "classes": ["telnet_enabled"],
                "enabled_heads": {
                    "anomaly": True,
                    "category": True,
                    "localization": True,
                    "severity": False,
                    "contrastive": False,
                },
                "parameter_count": 200,
                "trainable_parameters": 100,
                "train_examples": 4,
                "selection_examples": 2,
                "target_semantics": "injected_mutation",
                "external_pretraining_exposure": "not_applicable",
            },
            "prediction": {
                "raw_source_sha256": member.source_sha256,
                "sanitized_source_sha256": "1" * 64,
                "model_sha256": "a" * 64,
                "total_lines": member.total_lines,
                "anomaly_score": anomaly_score,
                "category_scores": {"telnet_enabled": 0.4},
                "severity_scores": None,
                "line_scores": [0.2] * member.total_lines,
                "block_attention": [1.0],
                "embedding_sha256": None,
                "embedding_dimensions": 0,
                "replacement_counts": {},
            },
            "runtime_torch_version": "authored-numeric-fixture",
        }
    )


def joint_fixture(
    prepared,
    *,
    statistical=False,
    neural=False,
    network_status=None,
    version="0.3.0",
    cohort="combined",
):
    """Return draft/request/checked children using authored inputs and synthetic numeric results."""
    before, after, analysis, reference = prepared(version=version, cohort=cohort)
    if statistical:
        body = analysis.model_dump()
        body["statistical"] = authored_statistical_context(before)
        sources = [RiskSource.POLICY, RiskSource.STATISTICAL]
        if analysis.comparison is not None and analysis.comparison.peer_baseline is not None:
            sources.append(RiskSource.PEER_GROUP)
        body["risk"] = fuse_risk(
            [
                finding
                for finding in analysis.findings
                if finding.detector != "expected_configuration"
            ],
            device_id=before.device_id,
            completed_detectors=sources,
        )
        if version == "0.1.0" or analysis.comparison is None:
            body["version"] = "analysis-api-0.3.0"
        analysis = AnalysisResult.model_validate(body)
    diff = compare_snapshots(before, after)
    draft = PatchDraft(
        patch_id=uuid4(),
        created_at=datetime.now(UTC),
        draft_sha256=draft_fingerprint(diff),
        diff=diff,
    )
    intent, outcome = deterministic_records((before, after, analysis, reference))
    request = intent.request.model_copy(update={"draft_sha256": draft.draft_sha256})
    selection = intent.selection.model_copy(
        update={"patch_id": draft.patch_id, "draft_sha256": draft.draft_sha256}
    )
    intent = intent.model_copy(
        update={"patch_id": draft.patch_id, "request": request, "selection": selection}
    )
    outcome = outcome.model_copy(update={"intent_sha256": source_ml_fingerprint(intent)})
    deterministic = SourceDeterministicRecheck.from_records(intent, outcome)
    forest = None
    if statistical:
        original = analysis.statistical
        request = RunSourceForestRecheck(
            recheck_id=uuid4(),
            draft_sha256=draft.draft_sha256,
            before_analysis_id=analysis.analysis_id,
            before_analysis_sha256=deterministic.before_analysis_sha256,
            model_id=original.model.model_id,
            artifact_sha256=original.model.artifact_sha256,
            allow_local_model_context=True,
        )
        forest_intent = SourceForestIntent(
            patch_id=draft.patch_id,
            request=request,
            before=SourceForestMember.model_validate(intent.before.model_dump()),
            after=SourceForestMember.model_validate(intent.after.model_dump()),
            selection=SourceForestSelection(
                patch_id=draft.patch_id,
                draft_sha256=draft.draft_sha256,
                before=SnapshotBinding.from_snapshot(before),
                before_analysis_id=analysis.analysis_id,
                before_analysis_sha256=deterministic.before_analysis_sha256,
                before_analysis_created_at=analysis.created_at,
                original=original,
            ),
            created_at=datetime.now(UTC),
        )
        after_score = -0.3
        scores = StatisticalRecheck(
            model_id=original.model.model_id,
            artifact_sha256=original.model.artifact_sha256,
            before_score_samples=original.score_samples,
            after_score_samples=after_score,
            before_decision_function=original.decision_function,
            after_decision_function=after_score - original.model.decision_offset,
            before_prediction=original.prediction,
            after_prediction=1,
        )
        forest = SourceForestRecheck.from_records(
            forest_intent,
            SourceForestOutcome(
                recheck_id=request.recheck_id,
                intent_sha256=source_ml_fingerprint(forest_intent),
                completed_at=datetime.now(UTC),
                execution_status="completed",
                report=SourceForestReport(model=original.model, scores=scores),
            ),
        )
    neural_view = None
    if neural:
        request = RunSourceMlRecheck(
            recheck_id=uuid4(),
            draft_sha256=draft.draft_sha256,
            model_sha256="a" * 64,
            allow_local_model_context=True,
        )
        ml_intent = SourceMlIntent(
            patch_id=draft.patch_id,
            request=request,
            before=SourceMlMember.model_validate(intent.before.model_dump() | {"total_lines": 11}),
            after=SourceMlMember.model_validate(intent.after.model_dump() | {"total_lines": 10}),
            created_at=datetime.now(UTC),
        )
        neural_view = SourceMlRecheck.from_records(
            ml_intent,
            SourceMlOutcome(
                recheck_id=request.recheck_id,
                intent_sha256=source_ml_fingerprint(ml_intent),
                completed_at=datetime.now(UTC),
                execution_status="completed",
                report=ConfigurationPairReport(
                    before=authored_neural_report(ml_intent.before, anomaly_score=0.8),
                    after=authored_neural_report(ml_intent.after, anomaly_score=0.2),
                ),
            ),
        )
    network = None
    if network_status is not None:
        request = VerifySourcePatch(
            verification_id=uuid4(),
            draft_sha256=draft.draft_sha256,
            scope={"start_node": "target", "destination": "192.0.2.0/24"},
            allow_local_engine_upload=True,
        )
        old, new = (
            SourcePatchMember.model_validate(
                member.model_dump() | {"hostname": "target", "platform": "ios"}
            )
            for member in (intent.before, intent.after)
        )
        network_intent = SourcePatchIntent(
            patch_id=draft.patch_id,
            request=request,
            created_at=datetime.now(UTC),
            before=old,
            after=new,
            before_network_sha256=source_network_digest((old,)),
            after_network_sha256=source_network_digest((new,)),
            preflight=review_configuration_change(
                before.canonical,
                after.canonical,
                device_id=before.device_id,
                reference_id=str(before.configuration_id),
            ),
        )
        queried = network_status in {"no_differences_in_scope", "differences_found", "inconclusive"}
        result = BatfishResult(
            before_sha256=network_intent.before_network_sha256,
            after_sha256=network_intent.after_network_sha256,
            scope=request.scope,
            status=network_status,
            reason={
                "unavailable": "sdk_missing",
                "error": "engine_error",
                "incomplete": "initialization_issues",
                "inconclusive": "empty_reachable_scope",
            }.get(network_status, "query_completed"),
            engine_version="authored-network-fixture" if queried else None,
            difference_count=(1 if network_status == "differences_found" else 0)
            if queried
            else None,
            before_reachable_count=1 if queried else None,
            after_reachable_count=(0 if network_status == "inconclusive" else 1)
            if queried
            else None,
            cleanup_complete=queried,
        )
        network = SourcePatchVerification.from_records(
            network_intent,
            SourcePatchOutcome(
                verification_id=request.verification_id,
                intent_sha256=source_review_fingerprint(network_intent),
                completed_at=datetime.now(UTC),
                network_result=result,
            ),
        )
    request = CreateSourceEvidenceReport(
        report_id=uuid4(),
        draft_sha256=draft.draft_sha256,
        deterministic=SelectedEvidenceRef(
            record_id=deterministic.recheck_id, review_sha256=deterministic.review_sha256
        ),
        forest=SelectedEvidenceRef(record_id=forest.recheck_id, review_sha256=forest.review_sha256)
        if forest
        else None,
        neural=SelectedEvidenceRef(
            record_id=neural_view.recheck_id, review_sha256=neural_view.review_sha256
        )
        if neural_view
        else None,
        network=SelectedEvidenceRef(
            record_id=network.verification_id, review_sha256=network.review_sha256
        )
        if network
        else None,
    )
    return draft, request, deterministic, forest, neural_view, network


def compose(fixture):
    draft, request, deterministic, forest, neural, network = fixture
    return SourceEvidenceReport.from_evidence(
        draft,
        request,
        deterministic,
        forest=forest,
        neural=neural,
        network=network,
        created_at=datetime.now(UTC),
    )


def test_joint_projection_uses_exact_children_and_normative_proof(prepared):
    fixture = joint_fixture(
        prepared, statistical=True, neural=True, network_status="no_differences_in_scope"
    )
    draft, request, deterministic, forest, neural, network = fixture
    view = compose(fixture)
    assert SourceEvidenceReport.model_validate_json(view.model_dump_json()) == view
    assert json.loads(view.review_json) == view.model_dump(
        mode="json", exclude={"review_json", "review_sha256"}
    )
    assert sha256(view.review_json.encode()).hexdigest() == view.review_sha256
    view.validate_evidence(draft, deterministic, forest=forest, neural=neural, network=network)
    assert view.request == request
    assert view.deterministic.before.policy == len(
        deterministic.outcome.report.before.policy_findings
    )
    assert view.deterministic.policy_changes.resolved == len(
        deterministic.outcome.report.policy_changes.resolved
    )
    assert view.forest.scores == forest.outcome.report.scores
    assert view.forest.library_version == "authored-numeric-fixture"
    assert (view.neural.before.anomaly_score, view.neural.after.anomaly_score) == (0.8, 0.2)
    assert view.neural.classes == ("telnet_enabled",)
    assert view.neural.before.scored_line_count == 11
    assert "line_scores" not in view.neural.before.model_dump()
    assert view.network.result == network.outcome.network_result
    assert view.network.sdk_version is None and view.network.ml_status == "not_run"
    assert view.status == "needs_review" and view.formal_qualification == "not_proven"
    assert "original_statistical_not_selected" not in view.validation_blockers
    assert "formal_verification_not_run" not in view.validation_blockers
    summary = SourceEvidenceSummary.from_report(view)
    assert summary.selected_kinds == ("deterministic", "forest", "neural", "network")
    assert summary.review_sha256 == view.review_sha256


@pytest.mark.parametrize("cohort", ["policy_only", "reference_only", "peers_only"])
def test_unselected_groups_and_completed_zero_counts_remain_distinct(prepared, cohort):
    fixture = joint_fixture(prepared, cohort=cohort)
    view = compose(fixture)
    counts = view.deterministic.after
    assert (counts.reference is None) == (cohort != "reference_only")
    assert (counts.peer is None) == (cohort != "peers_only")
    assert counts.policy == len(fixture[2].outcome.report.after.policy_findings)
    assert view.forest is view.neural is view.network is None
    assert "original_statistical_not_selected" not in view.validation_blockers
    assert "neural_not_selected" in view.validation_blockers
    assert "network_not_selected" in view.validation_blockers
    assert SourceEvidenceSummary.from_report(view).selected_kinds == ("deterministic",)


def test_selected_reference_with_no_findings_is_completed_empty(prepared):
    def reference_equal_after(**kwargs):
        before, after, analysis, reference = prepared(**kwargs)
        after = after.model_copy(
            update={"canonical": reference.canonical, "parser_coverage": reference.parser_coverage}
        )
        return before, after, analysis, reference

    view = compose(joint_fixture(reference_equal_after, cohort="reference_only"))
    assert view.deterministic.after.reference == 0
    assert view.deterministic.after.peer is None
    assert view.deterministic.reference is not None


def test_original_forest_requirement_follows_actual_original_context(prepared):
    fixture = list(joint_fixture(prepared, statistical=True))
    fixture[1] = fixture[1].model_copy(update={"forest": None})
    fixture[3] = None
    view = compose(fixture)
    assert view.original_statistical_present is True
    assert "original_statistical_not_selected" in view.validation_blockers


@pytest.mark.parametrize(
    "status", ["error", "differences_found", "inconclusive", "incomplete", "unavailable"]
)
def test_completed_network_attempt_keeps_actual_failure_or_violation(prepared, status):
    view = compose(joint_fixture(prepared, network_status=status))
    assert view.network.result.status == status
    assert "formal_scope_not_passed" in view.validation_blockers
    assert "network_not_selected" not in view.validation_blockers
    assert view.formal_qualification == "not_proven"
    assert view.network.ml_status == "not_run"


@pytest.mark.parametrize("field", ["forest", "neural", "network"])
def test_nullable_request_selections_must_be_explicit(prepared, field):
    body = joint_fixture(prepared)[1].model_dump()
    del body[field]
    with pytest.raises(ValueError):
        CreateSourceEvidenceReport.model_validate(body)


@pytest.mark.parametrize("kind", ["deterministic", "forest", "neural", "network"])
@pytest.mark.parametrize("pin", ["record_id", "review_sha256"])
def test_request_cannot_substitute_record_or_proof(prepared, kind, pin):
    fixture = list(joint_fixture(prepared, statistical=True, neural=True, network_status="error"))
    body = fixture[1].model_dump()
    body[kind][pin] = uuid4() if pin == "record_id" else "0" * 64
    fixture[1] = CreateSourceEvidenceReport.model_validate(body)
    with pytest.raises(ValueError, match="selected identity"):
        compose(fixture)


@pytest.mark.parametrize(
    "flag", ["risk_fused", "calibrated", "quality_proven", "approved", "applied"]
)
@pytest.mark.parametrize("value", [True, 0, "false"])
def test_joint_report_flags_must_be_exact_false(prepared, flag, value):
    body = compose(joint_fixture(prepared)).model_dump(mode="json")
    body[flag] = value
    with pytest.raises(ValueError):
        SourceEvidenceReport.model_validate(rehash(body))


@pytest.mark.parametrize(
    "fault", ["hash", "whitespace", "blocked", "status", "version", "chronology"]
)
def test_rehashed_report_cannot_hide_internal_contract_drift(prepared, fault):
    body = compose(joint_fixture(prepared)).model_dump(mode="json")
    if fault == "hash":
        body["review_sha256"] = "0" * 64
    elif fault == "whitespace":
        body["review_json"] += " "
        body["review_sha256"] = sha256(body["review_json"].encode()).hexdigest()
    else:
        if fault == "blocked":
            body["validation_blockers"] = []
        elif fault == "status":
            body["status"] = "approved"
        elif fault == "version":
            body["deterministic"]["version"] = "source-deterministic-recheck-99.0.0"
        else:
            body["created_at"] = "2000-01-01T00:00:00Z"
        rehash(body)
    with pytest.raises(ValueError):
        SourceEvidenceReport.model_validate(body)


@pytest.mark.parametrize(
    "field",
    ["policy_catalog_version", "reference", "peer_profile_sha256", "before_analysis_sha256"],
)
def test_historical_reprojection_rejects_semantic_drift_even_after_rehash(prepared, field):
    fixture = joint_fixture(prepared)
    draft, _, deterministic, *_ = fixture
    body = compose(fixture).model_dump(mode="json")
    if field == "policy_catalog_version":
        body["deterministic"][field] = "another-historical-catalog"
    elif field == "reference":
        body["deterministic"][field]["canonical_sha256"] = "0" * 64
    elif field == "peer_profile_sha256":
        body["deterministic"][field] = "0" * 64
    else:
        body[field] = "0" * 64
    forged = SourceEvidenceReport.model_validate(rehash(body))
    with pytest.raises(ValueError, match="exact saved child"):
        forged.validate_evidence(draft, deterministic)


@pytest.mark.parametrize("kind", ["deterministic", "forest", "neural", "network"])
def test_pending_selected_execution_cannot_masquerade_as_completed(prepared, kind):
    fixture = list(joint_fixture(prepared, statistical=True, neural=True, network_status="error"))
    index = {"deterministic": 2, "forest": 3, "neural": 4, "network": 5}[kind]
    pending = type(fixture[index]).from_records(fixture[index].intent, None)
    fixture[index] = pending
    request_body = fixture[1].model_dump()
    request_body[kind]["review_sha256"] = pending.review_sha256
    fixture[1] = CreateSourceEvidenceReport.model_validate(request_body)
    with pytest.raises(ValueError, match="execution differs"):
        compose(fixture)


@pytest.mark.parametrize("kind", ["deterministic", "forest", "neural"])
def test_failed_selected_execution_cannot_masquerade_as_completed(prepared, kind):
    fixture = list(joint_fixture(prepared, statistical=True, neural=True))
    index = {"deterministic": 2, "forest": 3, "neural": 4}[kind]
    old = fixture[index]
    outcome_type, reason = {
        "deterministic": (
            SourceDeterministicOutcome,
            "original_context_or_deterministic_result_unavailable",
        ),
        "forest": (SourceForestOutcome, "original_baseline_or_numeric_result_unavailable"),
        "neural": (SourceMlOutcome, "worker_failed_or_unavailable"),
    }[kind]
    outcome = outcome_type(
        recheck_id=old.recheck_id,
        intent_sha256=source_ml_fingerprint(old.intent),
        completed_at=datetime.now(UTC),
        execution_status="failed",
        failure_reason=reason,
        report=None,
    )
    fixture[index] = type(old).from_records(old.intent, outcome)
    request_body = fixture[1].model_dump()
    request_body[kind]["review_sha256"] = fixture[index].review_sha256
    fixture[1] = CreateSourceEvidenceReport.model_validate(request_body)
    with pytest.raises(ValueError, match="execution differs"):
        compose(fixture)


@pytest.mark.parametrize(
    "fault", ["canonical", "source", "configuration", "device", "time", "draft", "patch"]
)
def test_valid_child_from_another_pair_or_canonical_projection_is_rejected(prepared, fault):
    fixture = list(joint_fixture(prepared, neural=True))
    body = fixture[4].model_dump(mode="json")
    old = body["intent"]["before"]
    if fault == "canonical":
        old["canonical_sha256"] = "0" * 64
    elif fault == "source":
        old["source_sha256"] = "0" * 64
        body["outcome"]["report"]["before"]["prediction"]["raw_source_sha256"] = "0" * 64
    elif fault == "configuration":
        old["configuration_id"] = str(uuid4())
    elif fault == "device":
        device = str(uuid4())
        old["device_id"] = device
        body["intent"]["after"]["device_id"] = device
    elif fault == "time":
        old["created_at"] = "2000-01-01T00:00:00Z"
    elif fault == "draft":
        body["intent"]["request"]["draft_sha256"] = "0" * 64
        body["draft_sha256"] = "0" * 64
    else:
        patch = str(uuid4())
        body["intent"]["patch_id"] = patch
        body["patch_id"] = patch
    body["outcome"]["intent_sha256"] = sha256(ml_json(body["intent"]).encode()).hexdigest()
    fixture[4] = SourceMlRecheck.model_validate(rehash(body))
    fixture[1] = fixture[1].model_copy(
        update={
            "neural": SelectedEvidenceRef(
                record_id=fixture[4].recheck_id, review_sha256=fixture[4].review_sha256
            )
        }
    )
    with pytest.raises(ValueError, match="selected evidence"):
        compose(fixture)


def test_selected_forest_cannot_contradict_absent_original_statistical_context(prepared):
    fixture = list(joint_fixture(prepared, statistical=True))
    deterministic = fixture[2]
    original = deterministic.intent.selection.original.model_copy(
        update={"statistical_present": False}
    )
    selection = deterministic.intent.selection.model_copy(update={"original": original})
    intent = deterministic.intent.model_copy(update={"selection": selection})
    outcome = deterministic.outcome.model_copy(
        update={"intent_sha256": source_ml_fingerprint(intent)}
    )
    fixture[2] = SourceDeterministicRecheck.from_records(intent, outcome)
    fixture[1] = fixture[1].model_copy(
        update={
            "deterministic": SelectedEvidenceRef(
                record_id=fixture[2].recheck_id, review_sha256=fixture[2].review_sha256
            )
        }
    )
    with pytest.raises(ValueError, match="parent, scope or qualification"):
        compose(fixture)


@pytest.mark.parametrize("field", ["before_analysis_id", "before_analysis_sha256"])
def test_original_forest_cannot_use_another_original_analysis(prepared, field):
    fixture = list(joint_fixture(prepared, statistical=True))
    value = uuid4() if field.endswith("_id") else "0" * 64
    forest = fixture[3]
    request = forest.intent.request.model_copy(update={field: value})
    selection = forest.intent.selection.model_copy(update={field: value})
    intent = forest.intent.model_copy(update={"request": request, "selection": selection})
    outcome = forest.outcome.model_copy(update={"intent_sha256": source_ml_fingerprint(intent)})
    fixture[3] = SourceForestRecheck.from_records(intent, outcome)
    fixture[1] = fixture[1].model_copy(
        update={
            "forest": SelectedEvidenceRef(
                record_id=fixture[3].recheck_id, review_sha256=fixture[3].review_sha256
            )
        }
    )
    with pytest.raises(ValueError, match="analyses differ"):
        compose(fixture)


def test_history_reprojection_is_data_only_and_accepts_old_json_arrays(prepared, monkeypatch):
    fixture = list(joint_fixture(prepared, version="0.1.0"))
    draft, _, deterministic, *_ = fixture
    # JSON-array observations originally reached the old contracts as Python tuples.
    saved = SourceDeterministicRecheck.model_validate_json(deterministic.model_dump_json())
    fixture[2] = saved
    view = compose(fixture)

    def forbidden(*args, **kwargs):
        pytest.fail("history attempted a detector, model, parser or catalog execution")

    for path in (
        "app.detection.baseline.pair.recheck_original_deterministic",
        "app.detection.baseline.pair.evaluate_policies",
        "app.detection.statistical.pair.recheck_original_forest",
        "app.parsers.parse_configuration",
        "app.verification.batfish.check_with_batfish",
        "app.patching.source_ml.run_configuration_pair_job",
    ):
        monkeypatch.setattr(path, forbidden)
    frozen = SourceEvidenceReport.model_validate_json(view.model_dump_json())
    frozen.validate_evidence(draft, saved)
    assert frozen.review_sha256 == view.review_sha256


def test_factory_rejects_chronology_before_draft_and_completion(prepared):
    fixture = joint_fixture(prepared)
    draft, request, deterministic, *_ = fixture
    for stamp in (draft.created_at - timedelta(days=1), draft.created_at, datetime.now()):
        with pytest.raises(ValueError):
            SourceEvidenceReport.from_evidence(draft, request, deterministic, created_at=stamp)


def test_neural_projection_keeps_class_presence_separate_from_qualification(prepared):
    view = compose(joint_fixture(prepared, neural=True))
    assert view.neural.enabled_heads["category"] and "telnet_enabled" in view.neural.classes
    assert "change_specific_ml_quality_not_proven" in view.validation_blockers
    assert "selected_model_independent_quality_not_proven" in view.validation_blockers
    assert view.quality_proven is view.calibrated is view.risk_fused is False


def test_projection_limit_is_typed_and_utf8_bytes(prepared, monkeypatch):
    fixture = joint_fixture(prepared)
    expected = len(compose(fixture).review_json.encode())
    assert expected < MAX_SOURCE_EVIDENCE_BYTES
    monkeypatch.setattr(
        "app.api.source_evidence_contracts.MAX_SOURCE_EVIDENCE_BYTES", expected - 100
    )
    with pytest.raises(SourceEvidenceProjectionTooLarge):
        compose(fixture)
