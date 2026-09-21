"""Local before/after review; never a formal verification or approval verdict."""

from __future__ import annotations

import json
from typing import Literal
from uuid import UUID, uuid5

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.detection.baseline import compare_expected_configuration, create_expected_configuration
from app.detection.fusion import RiskAssessment, RiskSource, fuse_risk
from app.detection.policy_engine import evaluate_policies
from app.domain import CanonicalConfig, Finding
from app.policies import POLICY_CATALOG_VERSION
from app.verification.policy_changes import PolicyChanges, compare_policy_findings

PREFLIGHT_NAMESPACE = UUID("c1fd4eec-d317-43c7-a049-d0f3b81e9bdf")


class ParseSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    confidence: float = Field(ge=0, le=1)
    warning_count: int = Field(ge=0)
    unparsed_count: int = Field(ge=0)
    complete: bool

    @model_validator(mode="after")
    def consistent_completeness(self) -> ParseSummary:
        if self.complete != (
            self.confidence == 1 and self.warning_count == 0 and self.unparsed_count == 0
        ):
            raise ValueError("parse completeness conflicts with diagnostics")
        return self


class PreflightReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["preflight-0.1.0"] = "preflight-0.1.0"
    report_id: UUID
    device_id: UUID
    reference_id: str = Field(min_length=1, max_length=256)
    policy_catalog_version: str
    before: ParseSummary
    after: ParseSummary
    before_policy_findings: tuple[Finding, ...]
    after_policy_findings: tuple[Finding, ...]
    policy_changes: PolicyChanges | None
    reference_status: Literal["completed", "unavailable"]
    reference_findings: tuple[Finding, ...]
    current_policy_risk: RiskAssessment | None
    review_status: Literal["needs_review"] = "needs_review"
    formal_verification: Literal["not_run"] = "not_run"
    ml_status: Literal["not_run"] = "not_run"
    requires_human_review: Literal[True] = True
    limitations: tuple[str, ...]

    @model_validator(mode="after")
    def consistent_checks(self) -> PreflightReport:
        if not self.reference_id.strip():
            raise ValueError("reference ID must not be blank")
        complete = self.before.complete and self.after.complete
        if (self.policy_changes is not None) != complete:
            raise ValueError("policy change availability must match parse completeness")
        if self.reference_status == "completed" and not complete:
            raise ValueError("reference comparison requires complete parsing")
        if self.reference_status == "unavailable" and self.reference_findings:
            raise ValueError("unavailable reference comparison cannot contain findings")
        if not self.after.complete and self.current_policy_risk is not None:
            raise ValueError("partial current configuration cannot have a risk assessment")
        for finding in (*self.before_policy_findings, *self.after_policy_findings):
            if (
                finding.device_id != self.device_id
                or finding.detector != "policy_engine"
                or finding.model_version != self.policy_catalog_version
            ):
                raise ValueError("policy finding identity or catalog mismatch")
        if any(
            finding.device_id != self.device_id or finding.detector != "expected_configuration"
            for finding in self.reference_findings
        ):
            raise ValueError("reference finding identity mismatch")
        if (
            self.current_policy_risk is not None
            and self.current_policy_risk.device_id != self.device_id
        ):
            raise ValueError("risk assessment identity mismatch")
        if self.policy_changes is not None and self.policy_changes != compare_policy_findings(
            self.before_policy_findings, self.after_policy_findings, device_id=self.device_id
        ):
            raise ValueError("policy changes do not match snapshot findings")
        return self


def _summary(config: CanonicalConfig) -> ParseSummary:
    return ParseSummary(
        source_sha256=config.source.sha256,
        confidence=config.parser_confidence,
        warning_count=len(config.parse_warnings),
        unparsed_count=len(config.unparsed_fragments),
        complete=(
            not config.parse_warnings
            and not config.unparsed_fragments
            and config.parser_confidence == 1
        ),
    )


def review_configuration_change(
    before: CanonicalConfig,
    after: CanonicalConfig,
    *,
    device_id: UUID,
    reference_id: str,
) -> PreflightReport:
    """Run supported local checks, retaining partial findings without false passes."""
    before = CanonicalConfig.model_validate(before.model_dump())
    after = CanonicalConfig.model_validate(after.model_dump())
    if not reference_id.strip() or len(reference_id) > 256:
        raise ValueError("reference ID must be nonempty and at most 256 characters")
    if (before.device.vendor, before.device.platform, before.device.hostname) != (
        after.device.vendor,
        after.device.platform,
        after.device.hostname,
    ):
        raise ValueError("configuration identity differs")
    previous, current = _summary(before), _summary(after)
    old_findings = evaluate_policies(before, device_id=device_id)
    new_findings = evaluate_policies(after, device_id=device_id)
    limitations = [
        "Local checks only: no reachability simulation, formal validation or approval.",
        "The selected reference may itself contain violations; review all current findings.",
        "Policy changes match exact observations, not line numbers or finding IDs. "
        "Changed observations appear as resolved/introduced pairs; "
        "resolved is not proof of repair.",
        "Reference differences are separate from the policy-only, uncalibrated risk score.",
        "ML, peer-group and statistical detectors were not run.",
        "Addresses and parameter values may be sensitive; keep this report private.",
    ]
    changes = None
    reference_findings: tuple[Finding, ...] = ()
    reference_status: Literal["completed", "unavailable"] = "unavailable"
    if previous.complete and current.complete:
        changes = compare_policy_findings(old_findings, new_findings, device_id=device_id)
        try:
            reference = create_expected_configuration(
                before, device_id=device_id, reference_id=reference_id
            )
            reference_findings = tuple(
                compare_expected_configuration(after, reference, device_id=device_id)
            )
            reference_status = "completed"
        except ValueError:
            limitations.append("Reference comparison unavailable: ambiguous or unsupported facts.")
    else:
        limitations.append(
            "Incomplete parsing: policy findings are partial; policy change classification "
            "and reference comparison are unavailable, not empty successful checks."
        )
    risk = (
        fuse_risk(new_findings, device_id=device_id, completed_detectors=[RiskSource.POLICY])
        if current.complete
        else None
    )
    # Hash the report inputs including canonical facts: callers can supply canonical models.
    identity = json.dumps(
        [
            str(device_id),
            reference_id,
            POLICY_CATALOG_VERSION,
            before.model_dump(mode="json", exclude={"source"}),
            after.model_dump(mode="json", exclude={"source"}),
            previous.source_sha256,
            current.source_sha256,
        ],
        sort_keys=True,
        separators=(",", ":"),
    )
    return PreflightReport(
        report_id=uuid5(PREFLIGHT_NAMESPACE, identity),
        device_id=device_id,
        reference_id=reference_id,
        policy_catalog_version=POLICY_CATALOG_VERSION,
        before=previous,
        after=current,
        before_policy_findings=tuple(old_findings),
        after_policy_findings=tuple(new_findings),
        policy_changes=changes,
        reference_status=reference_status,
        reference_findings=reference_findings,
        current_policy_risk=risk,
        limitations=tuple(limitations),
    )
