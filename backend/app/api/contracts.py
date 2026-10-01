"""Versioned persistent API contracts; sensitive contents remain authenticated."""

from datetime import datetime
from pathlib import PurePath
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.detection.fusion import RiskAssessment
from app.domain import CanonicalConfig, Finding
from app.explanation.local import FindingExplanation


class UploadConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid")
    device_id: UUID
    filename: str = Field(min_length=1, max_length=255)
    content: str = Field(min_length=1, max_length=2 * 1024 * 1024)

    @field_validator("filename")
    @classmethod
    def safe_leaf(cls, value: str) -> str:
        if any(char in value for char in "/\\:") or any(ord(char) < 32 for char in value):
            raise ValueError("filename must be a leaf")
        if PurePath(value).suffix.lower() not in {".cfg", ".conf", ".txt"}:
            raise ValueError("unsupported text extension")
        return value


class ConfigurationSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")
    configuration_id: UUID
    device_id: UUID
    created_at: datetime
    canonical: CanonicalConfig


class ConfigurationSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")
    configuration_id: UUID
    device_id: UUID
    created_at: datetime
    filename: str
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    hostname: str | None
    vendor: str
    platform: str
    parser_confidence: float
    warning_count: int
    unparsed_count: int


class AnalysisResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: Literal["analysis-api-0.1.0"] = "analysis-api-0.1.0"
    analysis_id: UUID
    configuration_id: UUID
    device_id: UUID
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    created_at: datetime
    status: Literal["completed", "partial"]
    policy_catalog_version: str
    findings: tuple[Finding, ...]
    explanations: tuple[FindingExplanation, ...]
    risk: RiskAssessment | None
    limitations: tuple[str, ...]

    @model_validator(mode="after")
    def bound_results(self) -> "AnalysisResult":
        if (self.status == "completed") != (self.risk is not None):
            raise ValueError("only complete parsing permits a risk result")
        if len(self.findings) != len(self.explanations):
            raise ValueError("each finding requires an explanation")
        if len({finding.finding_id for finding in self.findings}) != len(self.findings):
            raise ValueError("finding identities must be unique")
        for finding, explanation in zip(self.findings, self.explanations, strict=True):
            if (
                finding.device_id != self.device_id
                or finding.detector != "policy_engine"
                or finding.model_version != self.policy_catalog_version
                or explanation.device_id != self.device_id
                or explanation.finding_id != finding.finding_id
                or explanation.source_sha256 != self.source_sha256
                or explanation.detector_version != finding.model_version
                or (explanation.severity, explanation.confidence, explanation.anomaly_score)
                != (finding.severity, finding.confidence, finding.anomaly_score)
            ):
                raise ValueError("finding or explanation belongs to a different analysis")
        if self.risk is not None and self.risk.device_id != self.device_id:
            raise ValueError("risk belongs to a different device")
        return self


class AnalysisSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")
    analysis_id: UUID
    configuration_id: UUID
    device_id: UUID
    created_at: datetime
    status: Literal["completed", "partial"]
    finding_count: int
    policy_catalog_version: str
