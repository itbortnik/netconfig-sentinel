"""Opt-in peer comparison with actual source-line coverage and unchanged property templates."""

from __future__ import annotations

import hashlib
import math
from collections.abc import Sequence
from typing import Literal
from uuid import UUID, uuid5

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.detection.baseline.expanded import MAX_PROJECTION_BYTES, encoded_value, value_digest
from app.detection.baseline.models import PeerGroupKey
from app.detection.baseline.peer_v2 import (
    EXPANDED_PEER_NAMESPACE,
    ExpandedPeerBaseline,
    ExpandedPeerFeature,
    PeerSample,
    build_expanded_peer_baseline,
    evaluate_expanded_peer_baseline,
)
from app.domain import CanonicalConfig, Evidence, Finding, Severity
from app.parsers.coverage import ParsedConfiguration, ParserCoverage

FRACTION_CATEGORY = "baseline.parser.unparsed_fraction_high"
MEASURED_REFERENCE = "docs/baseline.md#measured-parser-coverage"


def coverage_fingerprint(report: ParserCoverage) -> str:
    report = ParserCoverage.model_validate(report.model_dump())
    return hashlib.sha256(report.model_dump_json().encode()).hexdigest()


def _validated(parsed: ParsedConfiguration) -> ParsedConfiguration:
    if not isinstance(parsed, ParsedConfiguration) or not isinstance(
        parsed.coverage, ParserCoverage
    ):
        raise ValueError("measured comparison requires an explicit coverage report")
    canonical = CanonicalConfig.model_validate(parsed.canonical.model_dump())
    coverage = ParserCoverage.model_validate(parsed.coverage.model_dump())
    coverage.validate_binding(canonical)
    if coverage.unparsed_fraction is None:
        raise ValueError("measured comparison requires a nonzero command denominator")
    return ParsedConfiguration(canonical, coverage)


class MeasuredPeerBaseline(BaseModel):
    """Property component stays v2; its proxy is inert and never used for triage."""

    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)
    model_version: Literal["peer-baseline-0.3.0"] = "peer-baseline-0.3.0"
    properties: ExpandedPeerBaseline
    coverage: tuple[ParserCoverage, ...] = Field(min_length=3, max_length=20)
    unparsed_fraction_median: float = Field(default=0.0, strict=True, ge=0, le=0)
    unparsed_fraction_limit: float = Field(strict=True, ge=0, le=1)

    @model_validator(mode="after")
    def bound_coverage_population(self) -> MeasuredPeerBaseline:
        if self.properties.unsupported_ratio_limit != 1.0:
            raise ValueError("the property component's old confidence proxy must be inert")
        if tuple(report.source_sha256 for report in self.coverage) != tuple(
            item.source_sha256 for item in self.properties.samples
        ) or any(
            report.vendor != self.group.vendor
            or report.platform != self.group.platform
            or report.unparsed_fraction != 0.0
            or report.command_units == 0
            for report in self.coverage
        ):
            raise ValueError("measured peers must bind distinct complete property sources")
        if len(self.model_dump_json().encode()) > MAX_PROJECTION_BYTES:
            raise ValueError("measured peer profile exceeds its byte limit")
        return self

    @property
    def group(self) -> PeerGroupKey:
        return self.properties.group

    @property
    def sample_count(self) -> int:
        return self.properties.sample_count

    @property
    def samples(self) -> tuple[PeerSample, ...]:
        return self.properties.samples

    def fingerprint(self) -> str:
        return hashlib.sha256(self.model_dump_json().encode()).hexdigest()


def build_measured_peer_baseline(
    configs: Sequence[ParsedConfiguration],
    *,
    consensus_threshold: float = 0.75,
    unparsed_fraction_tolerance: float = 0.05,
) -> MeasuredPeerBaseline:
    if not 3 <= len(configs) <= 20:
        raise ValueError("measured peer baseline requires 3 to 20 configurations")
    if type(unparsed_fraction_tolerance) not in {int, float} or (
        not math.isfinite(unparsed_fraction_tolerance) or not 0 <= unparsed_fraction_tolerance <= 1
    ):
        raise ValueError("invalid finite measured-fraction tolerance")
    if type(consensus_threshold) not in {int, float} or (
        not math.isfinite(consensus_threshold) or not 0.5 < consensus_threshold <= 1
    ):
        raise ValueError("invalid finite consensus threshold")
    selected = [_validated(item) for item in configs]
    properties = build_expanded_peer_baseline(
        [item.canonical for item in selected],
        consensus_threshold=consensus_threshold,
        unsupported_ratio_tolerance=1.0,
    )
    return MeasuredPeerBaseline(
        properties=properties,
        coverage=tuple(
            sorted((item.coverage for item in selected), key=lambda item: item.source_sha256)
        ),
        unparsed_fraction_limit=float(unparsed_fraction_tolerance),
    )


def _score(fraction: float, limit: float) -> float:
    return min(1.0, (fraction - limit) / max(1.0 - limit, 0.01))


class MeasuredPeerEvaluation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)
    version: Literal["peer-comparison-report-0.3.0"] = "peer-comparison-report-0.3.0"
    device_id: UUID
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    baseline_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    status: Literal["completed", "partial"]
    coverage: ParserCoverage
    unparsed_fraction_limit: float = Field(strict=True, ge=0, le=1)
    peer_fraction_median: float = Field(default=0.0, strict=True, ge=0, le=0)
    profile_features: tuple[ExpandedPeerFeature, ...] = Field(max_length=len(ExpandedPeerFeature))
    compared_features: tuple[ExpandedPeerFeature, ...] = Field(max_length=len(ExpandedPeerFeature))
    skipped_features: tuple[ExpandedPeerFeature, ...] = Field(max_length=len(ExpandedPeerFeature))
    findings: tuple[Finding, ...] = Field(max_length=len(ExpandedPeerFeature) + 1)
    limitations: tuple[str, ...]

    @model_validator(mode="after")
    def exact_measured_result(self) -> MeasuredPeerEvaluation:
        ratio = self.coverage.unparsed_fraction
        if self.coverage.source_sha256 != self.source_sha256 or ratio is None:
            raise ValueError("measurement is missing or belongs to a different source")
        if self.profile_features != tuple(
            sorted(set(self.profile_features), key=lambda item: item.value)
        ):
            raise ValueError("invalid measured feature inventory")
        if self.status == "completed":
            if (
                ratio != 0
                or self.skipped_features
                or self.compared_features != self.profile_features
            ):
                raise ValueError(
                    "completed comparison requires complete measured/property coverage"
                )
        elif self.compared_features or self.skipped_features != self.profile_features:
            raise ValueError("partial comparison must skip every property feature")
        if len({item.finding_id for item in self.findings}) != len(self.findings):
            raise ValueError("duplicate measured peer findings")
        fraction_findings = []
        fingerprint = coverage_fingerprint(self.coverage)
        unparsed_lines = [
            item.source_line for item in self.coverage.units if item.disposition == "unparsed"
        ]
        for finding in self.findings:
            if (
                finding.device_id != self.device_id
                or finding.detector != "peer_baseline"
                or finding.model_version != "peer-baseline-0.3.0"
                or finding.severity != Severity.MEDIUM
                or finding.references != [MEASURED_REFERENCE]
                or finding.observed.get("source_sha256") != self.source_sha256
                or finding.observed.get("coverage_report_sha256") != fingerprint
                or finding.expected.get("baseline_sha256") != self.baseline_sha256
                or finding.finding_id
                != _bound_identity(
                    self.baseline_sha256,
                    self.coverage,
                    self.device_id,
                    finding.category,
                    finding.observed.get("value"),
                )
            ):
                raise ValueError("finding is not bound to the measured comparison")
            if finding.category == FRACTION_CATEGORY:
                fraction_findings.append(finding)
                if (
                    self.status != "partial"
                    or finding.observed.get("value") != ratio
                    or finding.observed.get("unparsed_units") != self.coverage.unparsed_units
                    or type(finding.observed.get("unparsed_units")) is not int
                    or finding.observed.get("command_units") != self.coverage.command_units
                    or type(finding.observed.get("command_units")) is not int
                    or finding.observed.get("unit") != self.coverage.unit
                    or finding.observed.get("adapter_version") != self.coverage.adapter_version
                    or finding.expected.get("maximum_unparsed_fraction")
                    != self.unparsed_fraction_limit
                    or finding.expected.get("peer_median") != self.peer_fraction_median
                    or type(finding.expected.get("peer_median")) not in {int, float}
                    or type(finding.expected.get("maximum_unparsed_fraction")) not in {int, float}
                    or finding.confidence != 1.0
                    or finding.anomaly_score != _score(ratio, self.unparsed_fraction_limit)
                    or finding.affected_lines != unparsed_lines
                    or not finding.evidence
                    or sorted(
                        {
                            line
                            for item in finding.evidence
                            if item.source_location is not None
                            for line in item.source_location.source_lines
                        }
                    )
                    != unparsed_lines
                    or any(
                        item.source_location is None
                        or any(
                            line not in unparsed_lines for line in item.source_location.source_lines
                        )
                        or (
                            len(item.source_location.source_lines) == 1
                            and item.source_location.raw_text_hash
                            != self.coverage.units[
                                item.source_location.source_lines[0] - 1
                            ].raw_text_sha256
                        )
                        for item in finding.evidence
                    )
                ):
                    raise ValueError("fraction finding differs from the observed counts or limit")
            elif self.status != "completed" or (
                finding.expected.get("feature") not in self.profile_features
                or finding.category != f"baseline.{finding.expected.get('feature')}_deviation"
                or encoded_value(finding.observed.get("value"))
                == encoded_value(finding.expected.get("value"))
            ):
                raise ValueError("uncompared feature cannot produce a property difference")
        if len(fraction_findings) != int(ratio > self.unparsed_fraction_limit):
            raise ValueError("measured fraction report is missing its required finding")
        if len(self.model_dump_json().encode()) > MAX_PROJECTION_BYTES:
            raise ValueError("measured peer evaluation exceeds its byte limit")
        return self

    def validate_profile(self, baseline: MeasuredPeerBaseline) -> None:
        if (
            self.baseline_sha256 != baseline.fingerprint()
            or self.profile_features != tuple(item.field for item in baseline.properties.features)
            or self.unparsed_fraction_limit != baseline.unparsed_fraction_limit
            or self.peer_fraction_median != baseline.unparsed_fraction_median
            or self.coverage.vendor != baseline.group.vendor
            or self.coverage.platform != baseline.group.platform
        ):
            raise ValueError("evaluation differs from its selected measured profile")
        features = {item.field.value: item for item in baseline.properties.features}
        for finding in self.findings:
            if finding.category == FRACTION_CATEGORY:
                continue
            feature = features.get(str(finding.expected.get("feature")))
            if feature is None or (
                encoded_value(finding.expected.get("value")) != encoded_value(feature.expected)
                or finding.expected.get("peer_support_count") != feature.support_count
                or finding.expected.get("peer_sample_count") != feature.sample_count
                or finding.confidence != feature.support_ratio
                or finding.anomaly_score != feature.support_ratio
            ):
                raise ValueError("property finding differs from its selected consensus feature")


def _bound_identity(
    baseline_sha256: str,
    report: ParserCoverage,
    device_id: UUID,
    category: str,
    value: object,
) -> UUID:
    return uuid5(
        EXPANDED_PEER_NAMESPACE,
        encoded_value(
            [
                str(device_id),
                "peer-baseline-0.3.0",
                baseline_sha256,
                report.source_sha256,
                coverage_fingerprint(report),
                category,
                value_digest(value),
            ]
        ),
    )


def _identity(
    baseline: MeasuredPeerBaseline,
    report: ParserCoverage,
    device_id: UUID,
    category: str,
    value: object,
) -> UUID:
    return _bound_identity(baseline.fingerprint(), report, device_id, category, value)


def evaluate_measured_peer_baseline(
    config: ParsedConfiguration, baseline: MeasuredPeerBaseline, *, device_id: UUID
) -> MeasuredPeerEvaluation:
    parsed = _validated(config)
    baseline = MeasuredPeerBaseline.model_validate(baseline.model_dump())
    # The released component computes property signatures/gates only: limit=1
    # suppresses its historical confidence-deficit finding for every valid input.
    properties = evaluate_expanded_peer_baseline(
        parsed.canonical, baseline.properties, device_id=device_id
    )
    fingerprint = coverage_fingerprint(parsed.coverage)
    findings = []
    for original in properties.findings:
        assert original.category != "baseline.parser.unsupported_ratio_high"
        changed = original.model_dump()
        changed.update(
            finding_id=_identity(
                baseline, parsed.coverage, device_id, original.category, original.observed["value"]
            ),
            model_version=baseline.model_version,
            observed={**original.observed, "coverage_report_sha256": fingerprint},
            expected={**original.expected, "baseline_sha256": baseline.fingerprint()},
            references=[MEASURED_REFERENCE],
        )
        findings.append(Finding.model_validate(changed))
    ratio = parsed.coverage.unparsed_fraction
    assert ratio is not None
    limitations = (
        "Measured adapter source lines are not universal vendor commands; "
        "block/set formats have different denominators.",
        "Accepted lines do not establish full semantic normalization, authoritative syntax, "
        "compliance or network safety.",
        "Only completely parsed peers supply the property consensus; "
        "measured peer fractions are zero by this eligibility gate.",
        "Peer identity, collection times and inventory labels are caller declarations, "
        "not independent attestations.",
        "Confidence 1 describes exact source accounting, not fault probability; "
        "severity is review priority and scores are uncalibrated.",
        "No policy, ML, formal verification or device change was run by this detector.",
    )
    if ratio > baseline.unparsed_fraction_limit:
        locations = [item.location for item in parsed.canonical.unparsed_fragments]
        findings.append(
            Finding(
                finding_id=_identity(
                    baseline, parsed.coverage, device_id, FRACTION_CATEGORY, ratio
                ),
                device_id=device_id,
                detector="peer_baseline",
                category=FRACTION_CATEGORY,
                title="Measured unsupported source-line fraction exceeds peer tolerance",
                severity=Severity.MEDIUM,
                confidence=1.0,
                anomaly_score=_score(ratio, baseline.unparsed_fraction_limit),
                affected_lines=sorted({line for loc in locations for line in loc.source_lines}),
                evidence=[
                    Evidence(
                        kind="measured_parser_coverage",
                        message="Final unsupported source units contribute "
                        "to the measured numerator.",
                        source_location=loc,
                    )
                    for loc in locations
                ],
                observed={
                    "value": ratio,
                    "source_sha256": parsed.coverage.source_sha256,
                    "coverage_report_sha256": fingerprint,
                    "unit": parsed.coverage.unit,
                    "adapter_version": parsed.coverage.adapter_version,
                    "unparsed_units": parsed.coverage.unparsed_units,
                    "command_units": parsed.coverage.command_units,
                },
                expected={
                    "baseline_sha256": baseline.fingerprint(),
                    "maximum_unparsed_fraction": baseline.unparsed_fraction_limit,
                    "peer_median": baseline.unparsed_fraction_median,
                },
                remediation="Review unsupported statements and parser limitations "
                "before interpreting any property comparison.",
                references=[MEASURED_REFERENCE],
                limitations=list(limitations),
                model_version=baseline.model_version,
            )
        )
    fields = tuple(item.field for item in baseline.properties.features)
    evaluation = MeasuredPeerEvaluation(
        device_id=device_id,
        source_sha256=parsed.coverage.source_sha256,
        baseline_sha256=baseline.fingerprint(),
        status=properties.status,
        coverage=parsed.coverage,
        unparsed_fraction_limit=baseline.unparsed_fraction_limit,
        profile_features=fields,
        compared_features=properties.compared_features,
        skipped_features=properties.skipped_features,
        findings=tuple(findings),
        limitations=(
            *limitations,
            *(
                ()
                if properties.status == "completed"
                else (
                    "Parsing is incomplete: every property comparison was skipped; "
                    "empty findings do not mean those properties were checked.",
                )
            ),
        ),
    )
    evaluation.validate_profile(baseline)
    return evaluation
