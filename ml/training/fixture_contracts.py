"""Lightweight fixture exposure contracts; metadata readers do not import model runtimes."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ml.evaluation.contracts import Digest


class FixtureTransferPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)
    max_comparisons: int = Field(default=200000, ge=1, le=2000000, strict=True)
    near_duplicate_threshold: float = Field(default=0.82, ge=0.5, le=1)


class FixtureExposureAudit(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: str = Field(
        default="fixture-transfer-exposure-0.1.0", pattern=r"^fixture-transfer-exposure-0\.1\.0$"
    )
    policy: FixtureTransferPolicy
    corpus_sha256: Digest
    downstream_manifest_sha256: Digest
    downstream_content_sha256: Digest
    source_intake_count: int = Field(ge=1)
    downstream_unique_content_count: int = Field(ge=1)
    comparisons: int = Field(ge=1)
    train_overlap_counts: dict[str, int]
    heldout_overlap_count: int = Field(default=0, ge=0, le=0)
    physical_pretraining_isolation_proven: bool = Field(default=False, strict=True)

    @model_validator(mode="after")
    def consistent(self) -> FixtureExposureAudit:
        if (
            self.comparisons != self.source_intake_count * self.downstream_unique_content_count
            or self.comparisons > self.policy.max_comparisons
            or set(self.train_overlap_counts)
            != {"source", "raw", "sanitized", "normalized", "template", "near"}
            or any(
                not 0 <= value <= self.downstream_unique_content_count
                for value in self.train_overlap_counts.values()
            )
            or self.physical_pretraining_isolation_proven
        ):
            raise ValueError("fixture exposure audit is inconsistent or overstates isolation")
        return self


class FixtureSourceBinding(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: str = Field(
        default="fixture-source-binding-0.1.0", pattern=r"^fixture-source-binding-0\.1\.0$"
    )
    pretraining_sha256: Digest
    report_sha256: Digest
    corpus_sha256: Digest
    source_manifest_sha256: Digest
    exposure: FixtureExposureAudit

    @model_validator(mode="after")
    def consistent(self) -> FixtureSourceBinding:
        if (
            self.corpus_sha256 != self.exposure.corpus_sha256
            or self.source_manifest_sha256 != self.exposure.downstream_manifest_sha256
        ):
            raise ValueError("fixture source/exposure binding differs")
        return self
