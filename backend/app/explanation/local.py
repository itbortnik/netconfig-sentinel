"""Deterministic explanations from recomputed facts and the versioned policy catalog."""

from __future__ import annotations

import json
from hashlib import sha256
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.detection.baseline import (
    ExpectedConfiguration,
    PeerBaseline,
    compare_expected_configuration,
    evaluate_peer_baseline,
)
from app.detection.policy_engine import evaluate_policies
from app.domain import CanonicalConfig, Finding, Severity
from app.policies import POLICY_CATALOG_VERSION, POLICY_RULES


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
    reference: ExpectedConfiguration | None = None,
    peer_baseline: PeerBaseline | None = None,
) -> FindingExplanation:
    """Require a finding to match a fresh detector run before generating prose."""
    finding = Finding.model_validate(finding.model_dump())
    config = CanonicalConfig.model_validate(config.model_dump())
    if finding.detector == "policy_engine":
        candidates = evaluate_policies(config, device_id=finding.device_id)
        rule = next((rule for rule in POLICY_RULES if rule.rule_id == finding.category), None)
        if rule is None or finding.model_version != POLICY_CATALOG_VERSION:
            raise ValueError("unsupported policy finding")
        summary = rule.title
        technical = rule.evidence_message
        recommendation = rule.remediation
        citations = rule.references
    elif finding.detector == "expected_configuration":
        if reference is None:
            raise ValueError("reference findings require the selected reference")
        candidates = compare_expected_configuration(config, reference, device_id=finding.device_id)
        summary = "A supported parameter differs from the selected device reference."
        technical = (
            "The detector compared canonical values for the same object. "
            "Observed and expected values are retained in the original finding. "
            "Reference line numbers belong to the reference snapshot."
        )
        recommendation = "Review the intended change against the selected device reference."
        citations = ("docs/expected-configuration.md",)
    elif finding.detector == "peer_baseline":
        if peer_baseline is None:
            raise ValueError("peer findings require the selected consensus profile")
        peer_baseline = PeerBaseline.model_validate(peer_baseline.model_dump())
        candidates = evaluate_peer_baseline(config, peer_baseline, device_id=finding.device_id)
        summary = "A supported value differs from the selected peer consensus."
        technical = (
            "The detector compared canonical values with an explicitly selected peer group. "
            "Support counts and the expected value are retained in the finding. "
            "Peer agreement is not proof of compliance or correct network behavior."
        )
        recommendation = "Review peer selection, inventory labels and intended configuration."
        citations = ("docs/baseline.md",)
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
    fingerprint = sha256(
        json.dumps(finding.model_dump(mode="json"), sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    ).hexdigest()
    return FindingExplanation(
        finding_id=finding.finding_id,
        device_id=finding.device_id,
        finding_sha256=fingerprint,
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
