"""Pure replay of one original deterministic context; callers bind retained sources."""

from dataclasses import dataclass

from app.api.contracts import (
    AnalysisResult,
    ComparisonContext,
    ConfigurationSnapshot,
    ExpandedComparisonContext,
    MeasuredComparisonContext,
    SnapshotBinding,
)
from app.api.source_ml_contracts import ml_json
from app.detection.baseline import (
    ExpandedPeerEvaluation,
    ExpandedReference,
    ExpectedConfiguration,
    MeasuredPeerEvaluation,
    compare_expanded_reference,
    compare_expected_configuration,
    create_expanded_reference,
    create_expected_configuration,
    evaluate_expanded_peer_baseline,
    evaluate_measured_peer_baseline,
    evaluate_peer_baseline,
)
from app.detection.config_model_contracts import require_complete
from app.detection.policy_engine import evaluate_policies
from app.domain import Finding
from app.parsers.coverage import ParsedConfiguration
from app.policies import POLICY_CATALOGS
from app.verification.policy_changes import PolicyChanges, compare_policy_findings

type OriginalComparison = ComparisonContext | ExpandedComparisonContext | MeasuredComparisonContext
type OriginalReference = ExpectedConfiguration | ExpandedReference
type PeerEvaluation = ExpandedPeerEvaluation | MeasuredPeerEvaluation


@dataclass(frozen=True)
class DeterministicSide:
    policy_findings: tuple[Finding, ...]
    # None is not selected; an empty tuple is a selected, completed zero-finding run.
    reference_findings: tuple[Finding, ...] | None
    peer_findings: tuple[Finding, ...] | None
    # The historical 0.1 peer contract has no separate evaluation report.
    peer_evaluation: PeerEvaluation | None

    @property
    def findings(self) -> tuple[Finding, ...]:
        return self.policy_findings + (self.reference_findings or ()) + (self.peer_findings or ())


@dataclass(frozen=True)
class OriginalDeterministicPair:
    before: DeterministicSide
    after: DeterministicSide
    policy_changes: PolicyChanges
    reference: OriginalReference | None


def require_original_deterministic_context(analysis: AnalysisResult) -> None:
    """New-execution admission only; history must not consult today's catalog inventory."""
    if analysis.policy_catalog_version not in POLICY_CATALOGS:
        raise ValueError("original policy catalog is unavailable")
    context = analysis.comparison
    if (
        isinstance(context, ComparisonContext)
        and context.peer_baseline is not None
        and context.peer_baseline.model_version != "peer-baseline-0.1.0"
    ):
        raise ValueError("original peer profile version is unavailable")


def prepare_original_reference(
    before: ConfigurationSnapshot,
    analysis: AnalysisResult,
    reference_snapshot: ConfigurationSnapshot | None,
) -> OriginalReference | None:
    """Freeze the selected reference projection without evaluating either target side."""
    context = analysis.comparison
    selected = context.reference if context is not None else None
    if (reference_snapshot is not None) != (selected is not None):
        raise ValueError("original reference selection differs")
    if (analysis.configuration_id, analysis.device_id, analysis.source_sha256) != (
        before.configuration_id,
        before.device_id,
        before.canonical.source.sha256,
    ):
        raise ValueError("original reference target differs")
    if reference_snapshot is None:
        return None
    reference_snapshot = ConfigurationSnapshot.model_validate(
        reference_snapshot.model_dump(warnings=False)
    )
    if (
        SnapshotBinding.from_snapshot(reference_snapshot) != selected
        or reference_snapshot.device_id != before.device_id
        or reference_snapshot.created_at > before.created_at
    ):
        raise ValueError("original reference binding differs")
    if isinstance(context, (ExpandedComparisonContext, MeasuredComparisonContext)):
        return create_expanded_reference(
            reference_snapshot.canonical,
            device_id=before.device_id,
            reference_id=str(reference_snapshot.configuration_id),
        )
    return create_expected_configuration(
        reference_snapshot.canonical,
        device_id=before.device_id,
        reference_id=str(reference_snapshot.configuration_id),
    )


def _side(
    snapshot: ConfigurationSnapshot,
    analysis: AnalysisResult,
    context: OriginalComparison | None,
    reference: OriginalReference | None,
) -> DeterministicSide:
    policy = tuple(
        evaluate_policies(
            snapshot.canonical,
            device_id=snapshot.device_id,
            catalog_version=analysis.policy_catalog_version,
        )
    )
    expected = None
    if isinstance(reference, ExpandedReference):
        expected = tuple(
            compare_expanded_reference(snapshot.canonical, reference, device_id=snapshot.device_id)
        )
    elif reference is not None:
        expected = tuple(
            compare_expected_configuration(
                snapshot.canonical, reference, device_id=snapshot.device_id
            )
        )
    peers = None
    evaluation: PeerEvaluation | None = None
    if context is not None and context.peers:
        if isinstance(context, MeasuredComparisonContext):
            if snapshot.parser_coverage is None or context.peer_baseline is None:
                raise ValueError("original measured context is unavailable")
            evaluation = evaluate_measured_peer_baseline(
                ParsedConfiguration(snapshot.canonical, snapshot.parser_coverage),
                context.peer_baseline,
                device_id=snapshot.device_id,
            )
            peers = evaluation.findings
        elif isinstance(context, ExpandedComparisonContext):
            if context.peer_baseline is None:
                raise ValueError("original expanded context is unavailable")
            evaluation = evaluate_expanded_peer_baseline(
                snapshot.canonical, context.peer_baseline, device_id=snapshot.device_id
            )
            peers = evaluation.findings
        else:
            if context.peer_baseline is None:
                raise ValueError("original peer context is unavailable")
            peers = tuple(
                evaluate_peer_baseline(
                    snapshot.canonical, context.peer_baseline, device_id=snapshot.device_id
                )
            )
    return DeterministicSide(policy, expected, peers, evaluation)


def recheck_original_deterministic(
    before: ConfigurationSnapshot,
    after: ConfigurationSnapshot,
    analysis: AnalysisResult,
    reference_snapshot: ConfigurationSnapshot | None = None,
) -> OriginalDeterministicPair:
    """Replay recorded catalog/reference/profile, accepting only an exact original before.

    No store, profile builder, ML, risk fusion, formal engine or approval is invoked.
    This library result is not a durable product verification or a source-retention proof.
    """
    before = ConfigurationSnapshot.model_validate(before.model_dump(warnings=False))
    after = ConfigurationSnapshot.model_validate(after.model_dump(warnings=False))
    analysis = AnalysisResult.model_validate(analysis.model_dump(warnings=False))
    if (
        any(value.utcoffset() is None for value in (before.created_at, after.created_at))
        or analysis.created_at.utcoffset() is None
        or analysis.created_at < before.created_at
        or before.created_at > after.created_at
        or analysis.status != "completed"
        or (analysis.configuration_id, analysis.device_id, analysis.source_sha256)
        != (before.configuration_id, before.device_id, before.canonical.source.sha256)
        or before.configuration_id == after.configuration_id
        or before.device_id != after.device_id
        or before.canonical.source.sha256 == after.canonical.source.sha256
        or (
            before.canonical.device.vendor,
            before.canonical.device.platform,
            before.canonical.device.hostname,
        )
        != (
            after.canonical.device.vendor,
            after.canonical.device.platform,
            after.canonical.device.hostname,
        )
    ):
        raise ValueError("original deterministic analysis or source pair differs")
    for snapshot in (before, after):
        require_complete(snapshot)
    require_original_deterministic_context(analysis)
    context = analysis.comparison
    reference = prepare_original_reference(before, analysis, reference_snapshot)
    if context is not None:
        for snapshot in (before, after):
            if any(
                peer.device_id == snapshot.device_id
                or peer.configuration_id == snapshot.configuration_id
                or peer.source_sha256 == snapshot.canonical.source.sha256
                or peer.created_at > snapshot.created_at
                for peer in context.peers
            ):
                raise ValueError("original peer population includes target or future input")
    old = _side(before, analysis, context, reference)
    actual = ml_json([finding.model_dump(mode="json") for finding in old.findings])
    original = ml_json(
        [
            finding.model_dump(mode="json")
            for finding in analysis.findings
            if finding.detector in {"policy_engine", "expected_configuration", "peer_baseline"}
        ]
    )
    if actual != original:
        raise ValueError("original deterministic before findings differ")
    if isinstance(context, (ExpandedComparisonContext, MeasuredComparisonContext)):
        actual_report, original_report = old.peer_evaluation, context.peer_evaluation
        if ml_json(actual_report.model_dump(mode="json") if actual_report else None) != ml_json(
            original_report.model_dump(mode="json") if original_report else None
        ):
            raise ValueError("original deterministic before peer report differs")
    new = _side(after, analysis, context, reference)
    return OriginalDeterministicPair(
        old,
        new,
        compare_policy_findings(
            old.policy_findings, new.policy_findings, device_id=before.device_id
        ),
        reference,
    )
