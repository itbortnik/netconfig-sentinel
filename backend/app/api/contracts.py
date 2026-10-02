"""Versioned persistent API contracts; sensitive contents remain authenticated."""

from datetime import datetime
from pathlib import PurePath
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.detection.baseline import PeerBaseline
from app.detection.fusion import RiskAssessment, RiskSource, fuse_risk
from app.domain import CanonicalConfig, Finding
from app.explanation.local import FindingExplanation


class InventoryLabels(BaseModel):
    """Explicit operator labels, not inferred or independently verified inventory."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    device_role: str = Field(min_length=1, max_length=64)
    site_class: str = Field(min_length=1, max_length=64)
    service_profile: str = Field(min_length=1, max_length=64)

    @field_validator("device_role", "site_class", "service_profile")
    @classmethod
    def bounded_label(cls, value: str) -> str:
        if value != value.strip() or not value.isprintable():
            raise ValueError("invalid inventory label")
        return value


class UploadConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid")
    device_id: UUID
    filename: str = Field(min_length=1, max_length=255)
    content: str = Field(min_length=1, max_length=2 * 1024 * 1024)
    inventory: InventoryLabels | None = None

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


class AnalysisOptions(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    reference_configuration_id: UUID | None = None
    peer_configuration_ids: tuple[UUID, ...] = Field(default=(), max_length=20)

    @model_validator(mode="after")
    def distinct_selections(self) -> "AnalysisOptions":
        if len(self.peer_configuration_ids) != len(set(self.peer_configuration_ids)):
            raise ValueError("duplicate peer snapshots")
        if self.peer_configuration_ids and len(self.peer_configuration_ids) < 3:
            raise ValueError("at least three peer snapshots are required")
        return self


class SnapshotBinding(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    configuration_id: UUID
    device_id: UUID
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    created_at: datetime

    @classmethod
    def from_snapshot(cls, snapshot: ConfigurationSnapshot) -> "SnapshotBinding":
        return cls(
            configuration_id=snapshot.configuration_id,
            device_id=snapshot.device_id,
            source_sha256=snapshot.canonical.source.sha256,
            created_at=snapshot.created_at,
        )


class ComparisonContext(BaseModel):
    """Immutable selected inputs and the exact consensus profile used by this run."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    reference: SnapshotBinding | None = None
    peers: tuple[SnapshotBinding, ...] = Field(default=(), max_length=20)
    peer_baseline: PeerBaseline | None = None

    @model_validator(mode="after")
    def bound_profile(self) -> "ComparisonContext":
        if self.reference is None and not self.peers:
            raise ValueError("comparison requires selected inputs")
        if bool(self.peers) != (self.peer_baseline is not None):
            raise ValueError("peer inputs and profile must be present together")
        if self.peers:
            if not 3 <= len(self.peers) <= 20:
                raise ValueError("invalid peer count")
            for values in (
                [item.configuration_id for item in self.peers],
                [item.device_id for item in self.peers],
                [item.source_sha256 for item in self.peers],
            ):
                if len(values) != len(set(values)):
                    raise ValueError("peer inputs must be independent snapshots")
            assert self.peer_baseline is not None
            if self.peer_baseline.model_version != "peer-baseline-0.1.0" or (
                self.peer_baseline.sample_count != len(self.peers)
            ):
                raise ValueError("peer profile count differs from selected inputs")
        return self


class AnalysisResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: Literal["analysis-api-0.1.0", "analysis-api-0.2.0"] = "analysis-api-0.1.0"
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
    comparison: ComparisonContext | None = None

    @model_validator(mode="after")
    def bound_results(self) -> "AnalysisResult":
        if (self.version == "analysis-api-0.2.0") != (self.comparison is not None):
            raise ValueError("comparison context requires the extended API version")
        versions = {"policy_engine": self.policy_catalog_version}
        if self.comparison is not None:
            reference = self.comparison.reference
            if reference is not None:
                if reference.device_id != self.device_id or (
                    reference.configuration_id == self.configuration_id
                ):
                    raise ValueError("reference must be a different snapshot of the same device")
                versions["expected_configuration"] = "expected-config-0.1.0"
            if self.comparison.peer_baseline is not None:
                if any(item.device_id == self.device_id for item in self.comparison.peers):
                    raise ValueError("target device cannot be its own peer")
                versions["peer_baseline"] = self.comparison.peer_baseline.model_version
        if (self.status == "completed") != (self.risk is not None):
            raise ValueError("only complete parsing permits a risk result")
        if len(self.findings) != len(self.explanations):
            raise ValueError("each finding requires an explanation")
        if len({finding.finding_id for finding in self.findings}) != len(self.findings):
            raise ValueError("finding identities must be unique")
        for finding, explanation in zip(self.findings, self.explanations, strict=True):
            if (
                finding.device_id != self.device_id
                or finding.detector not in versions
                or finding.model_version != versions.get(finding.detector)
                or explanation.device_id != self.device_id
                or explanation.finding_id != finding.finding_id
                or explanation.source_sha256 != self.source_sha256
                or explanation.detector_version != finding.model_version
                or (explanation.severity, explanation.confidence, explanation.anomaly_score)
                != (finding.severity, finding.confidence, finding.anomaly_score)
            ):
                raise ValueError("finding or explanation belongs to a different analysis")
            if finding.detector == "expected_configuration":
                assert self.comparison is not None and self.comparison.reference is not None
                reference = self.comparison.reference
                if finding.expected.get("reference_id") != str(reference.configuration_id) or (
                    finding.expected.get("source_sha256") != reference.source_sha256
                    or finding.observed.get("source_sha256") != self.source_sha256
                ):
                    raise ValueError("finding belongs to a different reference snapshot")
        if self.risk is not None and self.risk.device_id != self.device_id:
            raise ValueError("risk belongs to a different device")
        if self.comparison is not None and self.risk is not None:
            sources = [RiskSource.POLICY]
            if self.comparison.peer_baseline is not None:
                sources.append(RiskSource.PEER_GROUP)
            expected_risk = fuse_risk(
                [item for item in self.findings if item.detector != "expected_configuration"],
                device_id=self.device_id,
                completed_detectors=sources,
            )
            if self.risk != expected_risk:
                raise ValueError("risk differs from the completed detector results")
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
