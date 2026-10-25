"""Original-catalog local policy execution over an explicitly partial configuration pair."""

from __future__ import annotations

from dataclasses import dataclass

from app.api.contracts import AnalysisResult, ConfigurationSnapshot
from app.api.source_deterministic_contracts import _findings_json
from app.api.source_partial_contracts import PolicyDiagnosticParse
from app.detection.policy_engine import evaluate_policies
from app.domain import Finding
from app.ingestion.source_retention import canonical_fingerprint


@dataclass(frozen=True)
class PreparedPartialPolicy:
    before: ConfigurationSnapshot
    after: ConfigurationSnapshot
    analysis: AnalysisResult
    before_findings: tuple[Finding, ...]
    before_canonical_sha256: str
    after_canonical_sha256: str


@dataclass(frozen=True)
class PartialPolicySide:
    canonical_sha256: str
    parse: PolicyDiagnosticParse
    policy_findings: tuple[Finding, ...]


@dataclass(frozen=True)
class PartialPolicyPair:
    policy_catalog_version: str
    before: PartialPolicySide
    after: PartialPolicySide


def _context(
    before: ConfigurationSnapshot, after: ConfigurationSnapshot, analysis: AnalysisResult
) -> tuple[ConfigurationSnapshot, ConfigurationSnapshot, AnalysisResult]:
    before = ConfigurationSnapshot.model_validate(before.model_dump(warnings=False))
    after = ConfigurationSnapshot.model_validate(after.model_dump(warnings=False))
    analysis = AnalysisResult.model_validate(analysis.model_dump(warnings=False))
    if any(
        stamp.utcoffset() is None
        for stamp in (before.created_at, after.created_at, analysis.created_at)
    ):
        raise ValueError("partial policy context requires timezone-aware timestamps")
    previous = PolicyDiagnosticParse.from_config(before.canonical)
    current = PolicyDiagnosticParse.from_config(after.canonical)
    if (
        before.device_id != after.device_id
        or before.configuration_id == after.configuration_id
        or before.canonical.source.sha256 == after.canonical.source.sha256
        or before.created_at > after.created_at
        or before.created_at > analysis.created_at
        or analysis.configuration_id != before.configuration_id
        or analysis.device_id != before.device_id
        or analysis.source_sha256 != before.canonical.source.sha256
        or analysis.comparison is not None
        or analysis.statistical is not None
        or analysis.status != ("completed" if previous.summary.complete else "partial")
        or (previous.summary.complete and current.summary.complete)
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
        or any(row.detector != "policy_engine" for row in analysis.findings)
    ):
        raise ValueError("partial policy diagnostic original context or target pair differs")
    return before, after, analysis


def prepare_partial_policy(
    before: ConfigurationSnapshot, after: ConfigurationSnapshot, analysis: AnalysisResult
) -> PreparedPartialPolicy:
    """Evaluate exact original before policies before a durable attempt is reserved.

    The source workflow separately obtains consent and freshly reparses both exact retained
    originals. This function accepts already bound canonical snapshots, without source IO.
    """
    before, after, analysis = _context(before, after, analysis)
    findings = tuple(
        evaluate_policies(
            before.canonical,
            device_id=before.device_id,
            catalog_version=analysis.policy_catalog_version,
        )
    )
    if _findings_json(findings) != _findings_json(analysis.findings):
        raise ValueError("original partial policy findings differ from the recorded catalog result")
    return PreparedPartialPolicy(
        before=before,
        after=after,
        analysis=analysis,
        before_findings=findings,
        before_canonical_sha256=canonical_fingerprint(before),
        after_canonical_sha256=canonical_fingerprint(after),
    )


def recheck_partial_policy(prepared: PreparedPartialPolicy) -> PartialPolicyPair:
    """Execute after policies as a terminal diagnostic, without comparison or risk fusion."""
    if not isinstance(prepared, PreparedPartialPolicy):
        raise ValueError("partial policy execution requires typed prepared inputs")
    before, after, analysis = _context(prepared.before, prepared.after, prepared.analysis)
    old = tuple(
        Finding.model_validate(row.model_dump(warnings=False)) for row in prepared.before_findings
    )
    if (
        canonical_fingerprint(before) != prepared.before_canonical_sha256
        or canonical_fingerprint(after) != prepared.after_canonical_sha256
        or _findings_json(old) != _findings_json(analysis.findings)
    ):
        raise ValueError("prepared partial policy bindings changed")
    new = tuple(
        evaluate_policies(
            after.canonical,
            device_id=after.device_id,
            catalog_version=analysis.policy_catalog_version,
        )
    )
    return PartialPolicyPair(
        policy_catalog_version=analysis.policy_catalog_version,
        before=PartialPolicySide(
            canonical_sha256=prepared.before_canonical_sha256,
            parse=PolicyDiagnosticParse.from_config(before.canonical),
            policy_findings=old,
        ),
        after=PartialPolicySide(
            canonical_sha256=prepared.after_canonical_sha256,
            parse=PolicyDiagnosticParse.from_config(after.canonical),
            policy_findings=new,
        ),
    )
