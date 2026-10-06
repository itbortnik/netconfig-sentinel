"""Bounded prediction/annotation contracts without configuration text."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, model_validator

Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
UnitScore = Annotated[float, Field(ge=0, le=1, strict=True)]
Count = Annotated[int, Field(ge=0, strict=True)]
Label = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_.-]{0,127}$")]
Cohort = Literal["synthetic", "laboratory", "real_confirmed"]
COHORTS: tuple[Cohort, ...] = ("synthetic", "laboratory", "real_confirmed")


class Frozen(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)


class Identity(Frozen):
    """Opaque stable grouping keys, namespaced consistently across partitions."""

    source_sha256: Digest
    family_key: Digest
    device_key: Digest
    site_key: Digest
    network_key: Digest


class ParserCoverage(Frozen):
    significant_lines: Count
    recognized_lines: Count

    @model_validator(mode="after")
    def bounded(self) -> ParserCoverage:
        if self.recognized_lines > self.significant_lines:
            raise ValueError("recognized line count exceeds significant line count")
        return self


class LineAnnotation(Frozen):
    total_lines: int = Field(ge=1, le=100000, strict=True)
    ignored_lines: tuple[StrictInt, ...] = ()
    positive_lines: tuple[StrictInt, ...] = ()
    scored_lines: tuple[StrictInt, ...] = ()
    predicted_lines: tuple[StrictInt, ...] = ()
    deletion_only: StrictBool = False

    @model_validator(mode="after")
    def anchors(self) -> LineAnnotation:
        groups = (self.ignored_lines, self.positive_lines, self.scored_lines, self.predicted_lines)
        for group in groups:
            if group != tuple(sorted(set(group))) or any(
                type(line) is not int or not 1 <= line <= self.total_lines for line in group
            ):
                raise ValueError("line anchors must be sorted unique one-based integers")
        ignored = set(self.ignored_lines)
        if any(ignored.intersection(group) for group in groups[1:]):
            raise ValueError("ignored lines cannot have truth or scores")
        if not set(self.predicted_lines).issubset(self.scored_lines):
            raise ValueError("predicted lines must have scores")
        if self.deletion_only and any(groups[1:]):
            raise ValueError("deletion-only changes have no current-file truth or predictions")
        return self


class EvaluationCase(Frozen):
    case_id: Digest
    identity: Identity
    source_review_sha256: Digest
    annotation_sha256: Digest
    cohort: Cohort
    vendor: Literal["cisco", "juniper"]
    device_role: Label | None = None
    anomaly_truth: StrictBool
    category_truth: tuple[Label, ...]
    detection_score: UnitScore
    category_scores: tuple[UnitScore, ...] = Field(max_length=64)
    unknown_truth: StrictBool | None = None
    unknown_score: UnitScore | None = None
    lines: LineAnnotation | None = None
    analysis_seconds: float | None = Field(default=None, ge=0, le=86400, strict=True)
    parser_coverage: ParserCoverage | None = None

    @model_validator(mode="after")
    def labels(self) -> EvaluationCase:
        if len(set(self.category_truth)) != len(self.category_truth):
            raise ValueError("category annotations must be unique")
        if not self.anomaly_truth and (self.category_truth or self.unknown_truth):
            raise ValueError("positive category/unknown annotations require positive anomaly truth")
        if (
            self.lines is not None
            and not self.anomaly_truth
            and (self.lines.positive_lines or self.lines.deletion_only)
        ):
            raise ValueError("positive localization requires positive anomaly truth")
        return self


class EvaluationProtocol(Frozen):
    version: Literal["offline-evaluation-0.1.0"] = "offline-evaluation-0.1.0"
    purpose: Literal["independent_test", "validation_diagnostic"] = "independent_test"
    target_semantics: Literal["confirmed_anomaly", "injected_mutation"] = "confirmed_anomaly"
    latency_scope: Literal["producer_measured", "parsing_and_inference"] = "producer_measured"
    model_version: str = Field(min_length=1, max_length=128)
    model_sha256: Digest
    tokenizer_sha256: Digest | None = None
    policy_version: str | None = Field(default=None, max_length=128)
    document_catalog_sha256: Digest | None = None
    calibration_sha256: Digest | None = None
    dataset_manifest_sha256: Digest
    threshold_policy_sha256: Digest
    classes: tuple[Label, ...] = Field(min_length=1, max_length=64)
    score_kind: Literal["probability", "ranking"] = "probability"
    detection_threshold: UnitScore = 0.5
    category_thresholds: tuple[UnitScore, ...] = Field(min_length=1, max_length=64)
    precision_at_k: tuple[StrictInt, ...] = (1, 5, 10)
    reliability_bins: int = Field(default=10, ge=2, le=50, strict=True)
    train: tuple[Identity, ...] = Field(min_length=1, max_length=20000)
    selection: tuple[Identity, ...] = Field(default=(), max_length=20000)
    calibration: tuple[Identity, ...] = Field(default=(), max_length=20000)

    @model_validator(mode="after")
    def alignment(self) -> EvaluationProtocol:
        if len(set(self.classes)) != len(self.classes):
            raise ValueError("class catalog must be unique")
        if len(self.classes) != len(self.category_thresholds):
            raise ValueError("thresholds must follow the complete class catalog")
        if (
            not self.precision_at_k
            or len(self.precision_at_k) > 20
            or (self.precision_at_k != tuple(sorted(set(self.precision_at_k))))
            or any(type(k) is not int or not 1 <= k <= 20000 for k in self.precision_at_k)
        ):
            raise ValueError("precision K values must be sorted unique positive integers")
        if (self.calibration_sha256 is None) != (not self.calibration):
            raise ValueError("calibration identity and exposure must be recorded together")
        return self


class EvaluationBatch(Frozen):
    protocol: EvaluationProtocol
    cases: tuple[EvaluationCase, ...] = Field(min_length=1, max_length=20000)

    @model_validator(mode="after")
    def alignment(self) -> EvaluationBatch:
        if len(self.cases) * len(self.protocol.classes) > 1000000:
            raise ValueError("prediction matrix budget exceeded")
        if len({case.case_id for case in self.cases}) != len(self.cases):
            raise ValueError("case IDs must be unique")
        if len({case.identity.source_sha256 for case in self.cases}) != len(self.cases):
            raise ValueError("evaluated configuration hashes must be unique")
        for case in self.cases:
            if case.cohort == "real_confirmed" and (
                self.protocol.target_semantics != "confirmed_anomaly"
            ):
                raise ValueError("real-confirmed metrics require confirmed-anomaly annotations")
            if len(case.category_scores) != len(self.protocol.classes) or not set(
                case.category_truth
            ).issubset(self.protocol.classes):
                raise ValueError("scores and annotations must use the complete class catalog")
        if len({case.device_role for case in self.cases}) > 64:
            raise ValueError("role slice budget exceeded")
        if sum(case.lines.total_lines for case in self.cases if case.lines) > 1000000:
            raise ValueError("localization line budget exceeded")
        return self
