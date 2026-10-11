"""Allowlisted saved-analysis facts, never free-form report prose or safety verdicts."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class PeerReportFacts(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    version: Literal["peer-comparison-report-0.2.0", "peer-comparison-report-0.3.0"]
    status: Literal["completed", "partial"]
    selected_peer_count: int = Field(ge=3, le=20)
    profile_feature_count: int = Field(ge=0, le=1024)
    compared_feature_count: int = Field(ge=0, le=1024)
    skipped_feature_count: int = Field(ge=0, le=1024)

    @model_validator(mode="after")
    def exact_scope_counts(self) -> PeerReportFacts:
        if self.compared_feature_count + self.skipped_feature_count != self.profile_feature_count:
            raise ValueError("peer report scope counts differ")
        if self.status == "completed" and self.skipped_feature_count != 0:
            raise ValueError("completed peer report cannot skip selected features")
        if self.status == "partial" and self.compared_feature_count != 0:
            raise ValueError("partial peer report must skip all selected features")
        return self


class ExplanationAnalysisFacts(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    version: Literal["explanation-analysis-facts-0.1.0"] = "explanation-analysis-facts-0.1.0"
    analysis_status: Literal["completed", "partial", "not_supplied"] = "not_supplied"
    peer_report: PeerReportFacts | None = None

    @model_validator(mode="after")
    def bound_report_status(self) -> ExplanationAnalysisFacts:
        if self.peer_report is not None and self.peer_report.status != self.analysis_status:
            raise ValueError("peer report status differs from saved analysis")
        return self


class ExplanationInvocationFacts(BaseModel):
    """Current caller scope, not a deployment inventory or a storage/privacy guarantee."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    version: Literal["explanation-invocation-facts-0.1.0"] = "explanation-invocation-facts-0.1.0"
    entrypoint: Literal["saved_analysis_http", "not_supplied"] = "not_supplied"
    analysis_storage: Literal["stored_analysis", "not_supplied"] = "not_supplied"
    model_answer_storage: Literal["not_stored_in_analysis", "not_supplied"] = "not_supplied"
    selected_finding_peer_profile_storage: Literal[
        "stored_in_analysis", "not_applicable", "not_supplied"
    ] = "not_supplied"

    @model_validator(mode="after")
    def bound_caller_scope(self) -> ExplanationInvocationFacts:
        if self.entrypoint == "not_supplied":
            if any(
                value != "not_supplied"
                for value in (
                    self.analysis_storage,
                    self.model_answer_storage,
                    self.selected_finding_peer_profile_storage,
                )
            ):
                raise ValueError("unsupplied caller cannot establish storage facts")
        elif (
            self.analysis_storage != "stored_analysis"
            or self.model_answer_storage != "not_stored_in_analysis"
        ):
            raise ValueError("saved HTTP invocation requires its exact analysis storage scope")
        return self

    def validate_detector_scope(self, detector: str) -> None:
        storage = self.selected_finding_peer_profile_storage
        if (detector != "peer_baseline" and storage == "stored_in_analysis") or (
            detector == "peer_baseline" and storage == "not_applicable"
        ):
            raise ValueError("peer profile storage differs from selected finding scope")


# This explanation boundary does not perform or consume these checks. A completed
# detector report must never be promoted to a network/vendor/operational verdict.
VERIFICATION_SCOPE = {
    "vendor_syntax": "not_checked_in_this_explanation",
    "network_impact": "not_checked_in_this_explanation",
    "management_access": "not_checked_in_this_explanation",
    "rollback": "not_checked_in_this_explanation",
}
