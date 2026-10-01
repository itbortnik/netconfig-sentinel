"""Generate explanations alongside a fresh local before/after report."""

from uuid import UUID

from pydantic import BaseModel, ConfigDict

from app.detection.baseline import create_expected_configuration
from app.domain import CanonicalConfig
from app.explanation.local import FindingExplanation, explain_finding
from app.verification.preflight import PreflightReport, review_configuration_change


class ExplainedPreflight(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    report: PreflightReport
    before_policy_explanations: tuple[FindingExplanation, ...]
    after_policy_explanations: tuple[FindingExplanation, ...]
    reference_explanations: tuple[FindingExplanation, ...]


def explain_configuration_change(
    before: CanonicalConfig, after: CanonicalConfig, *, device_id: UUID, reference_id: str
) -> ExplainedPreflight:
    report = review_configuration_change(
        before, after, device_id=device_id, reference_id=reference_id
    )
    reference = (
        create_expected_configuration(before, device_id=device_id, reference_id=reference_id)
        if report.reference_status == "completed"
        else None
    )
    return ExplainedPreflight(
        report=report,
        before_policy_explanations=tuple(
            explain_finding(finding, before) for finding in report.before_policy_findings
        ),
        after_policy_explanations=tuple(
            explain_finding(finding, after) for finding in report.after_policy_findings
        ),
        reference_explanations=tuple(
            explain_finding(finding, after, reference=reference)
            for finding in report.reference_findings
        ),
    )
