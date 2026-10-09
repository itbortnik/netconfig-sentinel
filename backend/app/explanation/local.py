"""Deterministic explanations from recomputed facts and the versioned policy catalog."""

from __future__ import annotations

from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.detection.baseline import (
    ExpandedPeerBaseline,
    ExpandedReference,
    ExpectedConfiguration,
    MeasuredPeerBaseline,
    PeerBaseline,
    compare_expanded_reference,
    compare_expected_configuration,
    evaluate_expanded_peer_baseline,
    evaluate_measured_peer_baseline,
    evaluate_peer_baseline,
)
from app.detection.policy_engine import evaluate_policies
from app.detection.statistical.isolation_forest import (
    FittedIsolationForest,
    evaluate_isolation_forest,
)
from app.domain import CanonicalConfig, Finding, Severity
from app.domain.fingerprints import finding_fingerprint
from app.parsers.coverage import ParsedConfiguration, ParserCoverage
from app.policies import POLICY_CATALOGS


class EvidenceAnchor(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    lines: tuple[int, ...]
    statement_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class FindingExplanation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["local-explanation-0.1.0"] = "local-explanation-0.1.0"
    provider: Literal["deterministic_local"] = "deterministic_local"
    finding_id: UUID
    device_id: UUID
    finding_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    detector_version: str
    severity: Severity
    confidence: float = Field(ge=0, le=1)
    anomaly_score: float = Field(ge=0, le=1)
    summary: str
    technical_explanation: str
    recommendation: str
    anchors: tuple[EvidenceAnchor, ...]
    citations: tuple[str, ...]
    limitations: tuple[str, ...]
    formal_verification: Literal["not_run"] = "not_run"
    patch_draft: None = None
    requires_human_review: Literal[True] = True


def explain_finding(
    finding: Finding,
    config: CanonicalConfig,
    *,
    reference: ExpectedConfiguration | ExpandedReference | None = None,
    peer_baseline: PeerBaseline | ExpandedPeerBaseline | MeasuredPeerBaseline | None = None,
    statistical_model: FittedIsolationForest | None = None,
    parser_coverage: ParserCoverage | None = None,
) -> FindingExplanation:
    """Require a finding to match a fresh detector run before generating prose."""
    finding = Finding.model_validate(finding.model_dump())
    config = CanonicalConfig.model_validate(config.model_dump())
    if finding.detector == "policy_engine":
        catalog = POLICY_CATALOGS.get(finding.model_version)
        if catalog is None:
            raise ValueError("unsupported policy finding")
        candidates = evaluate_policies(
            config, device_id=finding.device_id, catalog_version=finding.model_version
        )
        rule = next((rule for rule in catalog if rule.rule_id == finding.category), None)
        if rule is None:
            raise ValueError("unsupported policy finding")
        summary = rule.title
        technical = rule.evidence_message
        recommendation = rule.remediation
        citations = rule.references
    elif finding.detector == "expected_configuration":
        if reference is None:
            raise ValueError("reference findings require the selected reference")
        if isinstance(reference, ExpandedReference):
            candidates = compare_expanded_reference(config, reference, device_id=finding.device_id)
        else:
            candidates = compare_expected_configuration(
                config, reference, device_id=finding.device_id
            )
        summary = "A supported parameter differs from the selected device reference."
        technical = (
            "The detector compared canonical values for the same object. "
            "Observed and expected values are retained in the original finding. "
            "Reference line numbers belong to the reference snapshot."
        )
        recommendation = "Review the intended change against the selected device reference."
        citations = (
            "docs/expected-configuration.md#expanded-supported-facts"
            if isinstance(reference, ExpandedReference)
            else "docs/expected-configuration.md",
        )
    elif finding.detector == "peer_baseline":
        if peer_baseline is None:
            raise ValueError("peer findings require the selected consensus profile")
        if isinstance(peer_baseline, MeasuredPeerBaseline):
            if parser_coverage is None:
                raise ValueError("measured peer findings require explicit source accounting")
            candidates = list(
                evaluate_measured_peer_baseline(
                    ParsedConfiguration(config, parser_coverage),
                    peer_baseline,
                    device_id=finding.device_id,
                ).findings
            )
        elif isinstance(peer_baseline, ExpandedPeerBaseline):
            peer_baseline = ExpandedPeerBaseline.model_validate(peer_baseline.model_dump())
            candidates = list(
                evaluate_expanded_peer_baseline(
                    config, peer_baseline, device_id=finding.device_id
                ).findings
            )
        else:
            peer_baseline = PeerBaseline.model_validate(peer_baseline.model_dump())
            candidates = evaluate_peer_baseline(config, peer_baseline, device_id=finding.device_id)
        summary = "A supported value differs from the selected peer consensus."
        technical = (
            "The detector compared canonical values with an explicitly selected peer group. "
            "Support counts and the expected value are retained in the finding. "
            "Peer agreement is not proof of compliance or correct network behavior."
        )
        recommendation = "Review peer selection, inventory labels and intended configuration."
        if isinstance(peer_baseline, ExpandedPeerBaseline) and (
            finding.category == "baseline.parser.unsupported_ratio_high"
        ):
            summary = "Parsing confidence is below the selected peer profile's tolerance."
            technical = (
                "The detector compared a parser-confidence deficit proxy with the profile limit. "
                "All property comparisons were skipped because parsing is incomplete. "
                "Unknown command counts and configuration safety were not established."
            )
        if isinstance(peer_baseline, MeasuredPeerBaseline) and (
            finding.category == "baseline.parser.unparsed_fraction_high"
        ):
            summary = (
                "Measured unsupported source-line fraction exceeds the selected peer tolerance."
            )
            technical = (
                f"Final source accounting records {finding.observed['unparsed_units']} unparsed "
                f"of {finding.observed['command_units']} command units. The measured fraction "
                "exceeds the explicit profile limit; all property comparisons were skipped. "
                "Confidence describes exact counting, not fault probability. "
                "Adapter acceptance is not full semantics, vendor syntax or network safety."
            )
        citations = (
            "docs/baseline.md#measured-parser-coverage"
            if isinstance(peer_baseline, MeasuredPeerBaseline)
            else "docs/baseline.md#expanded-peer-templates"
            if isinstance(peer_baseline, ExpandedPeerBaseline)
            else "docs/baseline.md",
        )
    elif finding.detector == "isolation_forest":
        if statistical_model is None:
            raise ValueError("statistical findings require their selected model")
        candidates = evaluate_isolation_forest(
            config,
            statistical_model,
            device_id=finding.device_id,
        )
        summary = "The selected experimental forest classified the structured vector as an outlier."
        technical = (
            "The score was recomputed with the selected numeric model. Highlighted median "
            "deviations are diagnostic context, not causal explanations or tree attributions. "
            "An outlier is not proof of a security violation or network impact."
        )
        recommendation = "Review training selection, intended changes and independent policy facts."
        citations = ("docs/statistical-baseline.md#finding-interpretation",)
    else:
        raise ValueError("unsupported explanation detector")
    if finding not in candidates:
        raise ValueError("finding is stale, modified or does not belong to this configuration")
    anchors = tuple(
        EvidenceAnchor(
            source_sha256=config.source.sha256,
            lines=tuple(evidence.source_location.source_lines),
            statement_sha256=evidence.source_location.raw_text_hash,
        )
        for evidence in finding.evidence
        if evidence.source_location is not None
    )
    limitations = list(finding.limitations)
    limitations.extend(
        [
            "This explanation uses local detector facts and catalog text; "
            "no language model was called.",
            "Citations identify internal policies, "
            "not retrieved or independently validated documents.",
            "Network impact was not simulated; any corrective action requires engineer review.",
        ]
    )
    if not anchors:
        limitations.append(
            "No current source line proves an absent parameter; no line anchor was invented."
        )
    if config.unparsed_fragments or config.parse_warnings or config.parser_confidence < 1:
        limitations.append(
            "Parsing is incomplete; unsupported configuration may change the conclusion."
        )
    return FindingExplanation(
        finding_id=finding.finding_id,
        device_id=finding.device_id,
        finding_sha256=finding_fingerprint(finding),
        source_sha256=config.source.sha256,
        detector_version=finding.model_version,
        severity=finding.severity,
        confidence=finding.confidence,
        anomaly_score=finding.anomaly_score,
        summary=summary,
        technical_explanation=technical,
        recommendation=recommendation,
        anchors=anchors,
        citations=citations,
        limitations=tuple(limitations),
    )
