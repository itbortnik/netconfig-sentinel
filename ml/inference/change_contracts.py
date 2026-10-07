"""Bounded numeric before/after diagnostics outside patch status and risk fusion."""

from __future__ import annotations

from typing import Literal, Self

from app.patching.review import PatchReview
from pydantic import BaseModel, ConfigDict, Field, StrictInt, model_validator

from ml.evaluation.contracts import Digest, Label, UnitScore


class Frozen(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)


class SidePrediction(Frozen):
    raw_source_sha256: Digest
    sanitized_source_sha256: Digest
    model_sha256: Digest
    total_lines: int = Field(ge=1, le=10000, strict=True)
    anomaly_score: UnitScore | None
    category_scores: dict[Label, UnitScore] | None
    severity_scores: dict[Literal["info", "low", "medium", "high", "critical"], UnitScore] | None
    line_scores: tuple[UnitScore | None, ...] = Field(max_length=10000)
    block_attention: tuple[UnitScore, ...] = Field(min_length=1, max_length=10000)
    embedding_sha256: Digest | None
    embedding_dimensions: int = Field(ge=0, le=1024, strict=True)
    replacement_counts: dict[Label, StrictInt]
    calibrated: Literal[False] = False

    @model_validator(mode="after")
    def dimensions(self) -> Self:
        if len(self.line_scores) != self.total_lines:
            raise ValueError("prediction lines do not match this side")
        if (self.embedding_sha256 is None) != (self.embedding_dimensions == 0):
            raise ValueError("embedding identity/dimension mismatch")
        if self.category_scores is not None and not 1 <= len(self.category_scores) <= 64:
            raise ValueError("invalid category score inventory")
        if self.severity_scores is not None and (
            set(self.severity_scores) != {"info", "low", "medium", "high", "critical"}
            or abs(sum(self.severity_scores.values()) - 1) > 1e-5
        ):
            raise ValueError("severity scores require the complete normalized head")
        if abs(sum(self.block_attention) - 1) > 1e-5:
            raise ValueError("block attention must be normalized")
        if len(self.replacement_counts) > 32 or any(
            not 1 <= value <= 100000 for value in self.replacement_counts.values()
        ):
            raise ValueError("invalid sanitization counters")
        return self


class TransformerSupplement(Frozen):
    status: Literal["not_selected", "unavailable", "completed"]
    reason: Literal["not_selected", "incomplete_parsing"] | None
    model_sha256: Digest | None = None
    tokenizer_sha256: Digest | None = None
    training_report_sha256: Digest | None = None
    training_format: (
        Literal[
            "multitask-training-0.1.0",
            "multitask-training-0.2.0",
            "foundation-config-transfer-0.1.0",
        ]
        | None
    ) = None
    runtime_torch_version: str | None = Field(default=None, min_length=1, max_length=64)
    sanitization_version: Literal["config-sanitizer-0.1.0"] | None = None
    before: SidePrediction | None = None
    after: SidePrediction | None = None
    risk_fused: Literal[False] = False
    quality_evaluated: Literal[False] = False
    calibrated: Literal[False] = False
    production_quality_proven: Literal[False] = False

    @model_validator(mode="after")
    def states(self) -> Self:
        bindings = (
            self.model_sha256,
            self.tokenizer_sha256,
            self.training_report_sha256,
            self.training_format,
            self.runtime_torch_version,
            self.sanitization_version,
        )
        if self.status == "not_selected":
            if self.reason != "not_selected" or any(value is not None for value in bindings):
                raise ValueError("unselected inference cannot contain model bindings")
        elif any(value is None for value in bindings):
            raise ValueError("selected inference requires exact model/runtime bindings")
        if self.status == "completed":
            if self.reason is not None or self.before is None or self.after is None:
                raise ValueError("completed inference requires both sides")
            if any(row.model_sha256 != self.model_sha256 for row in (self.before, self.after)):
                raise ValueError("both predictions must use the selected exact model")
            if (
                (self.before.category_scores is None) != (self.after.category_scores is None)
                or (self.before.severity_scores is None) != (self.after.severity_scores is None)
                or (self.before.anomaly_score is None) != (self.after.anomaly_score is None)
                or self.before.embedding_dimensions != self.after.embedding_dimensions
                or set(self.before.category_scores or {}) != set(self.after.category_scores or {})
            ):
                raise ValueError("before/after output channels differ")
        elif self.before is not None or self.after is not None:
            raise ValueError("unavailable inference cannot contain partial successful scores")
        if self.status == "unavailable" and self.reason != "incomplete_parsing":
            raise ValueError("unavailable inference must record its explicit limitation")
        return self


class MLChangeReview(Frozen):
    version: Literal["ml-change-review-0.1.0"] = "ml-change-review-0.1.0"
    local_review: PatchReview
    transformer: TransformerSupplement
    status: Literal["needs_review"] = "needs_review"
    formal_verification: Literal["not_run"] = "not_run"
    device_syntax_verified: Literal[False] = False
    management_access_verified: Literal[False] = False
    applied: Literal[False] = False
    independent_quality_evaluation: Literal[False] = False
    pseudonymization_key_persisted: Literal[False] = False

    @model_validator(mode="after")
    def source_binding(self) -> Self:
        model = self.transformer
        if model.status == "completed":
            assert model.before is not None and model.after is not None
            proposal = self.local_review.proposal
            for row, source, lines in (
                (model.before, proposal.before_sha256, proposal.before_line_count),
                (model.after, proposal.after_sha256, proposal.after_line_count),
            ):
                if row.raw_source_sha256 != source or row.total_lines != lines:
                    raise ValueError("prediction does not belong to the exact patch side")
            if not self.local_review.preflight.before.complete or not (
                self.local_review.preflight.after.complete
            ):
                raise ValueError("partial local parsing cannot have completed ML review")
        if model.status == "unavailable" and (
            self.local_review.preflight.before.complete
            and self.local_review.preflight.after.complete
        ):
            raise ValueError("incomplete-parsing limitation conflicts with local review")
        return self
