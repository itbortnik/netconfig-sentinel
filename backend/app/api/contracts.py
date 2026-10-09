"""Versioned persistent API contracts; sensitive contents remain authenticated."""

from datetime import datetime
from pathlib import PurePath
from typing import Any, Literal
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SerializerFunctionWrapHandler,
    field_validator,
    model_serializer,
    model_validator,
)

from app.detection.baseline import ExpandedPeerBaseline, ExpandedPeerEvaluation, PeerBaseline
from app.detection.baseline.expanded import encoded_value
from app.detection.fusion import RiskAssessment, RiskSource, fuse_risk
from app.detection.statistical.artifact import ForestArtifact
from app.detection.statistical.features import FEATURE_SCHEMA_VERSION
from app.detection.statistical.isolation_forest import (
    ISOLATION_FOREST_MODEL_VERSION,
    IsolationForestMetadata,
)
from app.domain import CanonicalConfig, Finding
from app.explanation.local import FindingExplanation
from app.parsers.coverage import ParserCoverage


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
    retain_original_source: bool = Field(default=False, strict=True)

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
    parser_coverage: ParserCoverage | None = None

    @model_validator(mode="after")
    def coverage_binding(self) -> "ConfigurationSnapshot":
        if self.parser_coverage is not None:
            self.parser_coverage.validate_binding(self.canonical)
        return self

    @model_serializer(mode="wrap")
    def preserve_historical_shape(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        result: dict[str, Any] = handler(self)
        if self.parser_coverage is None:
            result.pop("parser_coverage", None)
        return result


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
    statistical_model_id: UUID | None = None
    comparison_version: Literal["0.1.0", "0.2.0"] = "0.1.0"

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

    @field_validator("created_at")
    @classmethod
    def aware_time(cls, value: datetime) -> datetime:
        if value.utcoffset() is None:
            raise ValueError("snapshot binding requires a timezone")
        return value

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


class ExpandedComparisonContext(BaseModel):
    """New wire contract; legacy profiles retain their original shape and meaning."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["comparison-context-0.2.0"] = "comparison-context-0.2.0"
    reference: SnapshotBinding | None = None
    peers: tuple[SnapshotBinding, ...] = Field(default=(), max_length=20)
    peer_baseline: ExpandedPeerBaseline | None = None
    peer_evaluation: ExpandedPeerEvaluation | None = None

    @model_validator(mode="after")
    def bound_profile(self) -> "ExpandedComparisonContext":
        if self.reference is None and not self.peers:
            raise ValueError("comparison requires selected inputs")
        if bool(self.peers) != (self.peer_baseline is not None) or (
            bool(self.peers) != (self.peer_evaluation is not None)
        ):
            raise ValueError("expanded peer inputs, profile and report must be present together")
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
            baseline, report = self.peer_baseline, self.peer_evaluation
            assert baseline is not None and report is not None
            indexed = {item.source_sha256: item for item in self.peers}
            if baseline.sample_count != len(self.peers) or (
                set(indexed) != {item.source_sha256 for item in baseline.samples}
                or any(
                    item.collected_at > indexed[item.source_sha256].created_at
                    for item in baseline.samples
                )
                or report.baseline_sha256 != baseline.fingerprint()
                or report.profile_features != tuple(item.field for item in baseline.features)
            ):
                raise ValueError("expanded peer profile differs from its selected inputs or report")
            features = {item.field.value: item for item in baseline.features}
            parser_findings = []
            for finding in report.findings:
                if finding.category == "baseline.parser.unsupported_ratio_high":
                    parser_findings.append(finding)
                    if (
                        report.status != "partial"
                        or report.unsupported_ratio <= baseline.unsupported_ratio_limit
                        or finding.observed.get("value") != report.unsupported_ratio
                        or finding.expected.get("maximum_unsupported_ratio")
                        != baseline.unsupported_ratio_limit
                        or finding.expected.get("peer_median") != baseline.unsupported_ratio_median
                        or finding.confidence != 1.0
                        or finding.anomaly_score
                        != min(
                            1.0,
                            (report.unsupported_ratio - baseline.unsupported_ratio_limit)
                            / max(1.0 - baseline.unsupported_ratio_limit, 0.01),
                        )
                    ):
                        raise ValueError(
                            "parser deficit finding differs from its profile or report"
                        )
                else:
                    feature = features.get(str(finding.expected.get("feature")))
                    if feature is None or (
                        finding.category != f"baseline.{feature.field.value}_deviation"
                        or encoded_value(finding.expected.get("value"))
                        != encoded_value(feature.expected)
                        or finding.expected.get("peer_support_count") != feature.support_count
                        or finding.expected.get("peer_sample_count") != feature.sample_count
                        or finding.confidence != feature.support_ratio
                        or finding.anomaly_score != feature.support_ratio
                    ):
                        raise ValueError("peer finding differs from its selected feature")
            if len(parser_findings) != int(
                report.unsupported_ratio > baseline.unsupported_ratio_limit
            ):
                raise ValueError("parser deficit report is missing its required finding")
        return self


class TrainModelOptions(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)
    configuration_ids: tuple[UUID, ...] = Field(min_length=8, max_length=100)
    contamination: float = Field(default=0.1, gt=0, le=0.5)

    @model_validator(mode="after")
    def distinct_inputs(self) -> "TrainModelOptions":
        if len(set(self.configuration_ids)) != len(self.configuration_ids):
            raise ValueError("training inputs must be distinct")
        return self


class ModelSummary(BaseModel):
    """An immutable experimental model, not a production approval or quality report."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["model-registry-0.1.0"] = "model-registry-0.1.0"
    model_id: UUID
    created_at: datetime
    status: Literal["experimental"] = "experimental"
    artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    decision_offset: float = Field(ge=-1, le=0)
    metadata: IsolationForestMetadata
    training: tuple[SnapshotBinding, ...] = Field(min_length=8, max_length=100)
    training_hostnames: tuple[str, ...] = Field(min_length=8, max_length=100)

    @field_validator("created_at")
    @classmethod
    def aware_time(cls, value: datetime) -> datetime:
        if value.utcoffset() is None:
            raise ValueError("model timestamp requires a timezone")
        return value

    @model_validator(mode="after")
    def bound_training(self) -> "ModelSummary":
        if self.metadata.model_version != ISOLATION_FOREST_MODEL_VERSION or (
            self.metadata.feature_schema_version != FEATURE_SCHEMA_VERSION
        ):
            raise ValueError("unsupported registry model")
        if self.metadata.sample_count != len(self.training) or (
            len(self.training_hostnames) != len(self.training)
            or any(not host for host in self.training_hostnames)
        ):
            raise ValueError("training population differs from metadata")
        for values in (
            [item.configuration_id for item in self.training],
            [item.device_id for item in self.training],
            [item.source_sha256 for item in self.training],
            list(self.training_hostnames),
        ):
            if len(values) != len(set(values)):
                raise ValueError("training snapshots must identify independent devices")
        if any(item.created_at > self.created_at for item in self.training):
            raise ValueError("training snapshots cannot be newer than the model")
        return self


class RegisteredModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    summary: ModelSummary
    artifact: ForestArtifact

    @model_validator(mode="after")
    def authenticated_artifact(self) -> "RegisteredModel":
        if self.summary.metadata != self.artifact.metadata or (
            self.summary.artifact_sha256 != self.artifact.fingerprint()
            or self.summary.decision_offset != self.artifact.offset
        ):
            raise ValueError("model manifest differs from its numeric artifact")
        return self


class StatisticalContext(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)
    model: ModelSummary
    score_samples: float = Field(ge=-1, le=0)
    decision_function: float = Field(ge=-1, le=1)
    prediction: Literal[-1, 1]

    @model_validator(mode="after")
    def consistent_prediction(self) -> "StatisticalContext":
        if abs(self.decision_function - (self.score_samples - self.model.decision_offset)) > 1e-14:
            raise ValueError("decision differs from the recorded model threshold")
        if self.prediction != (-1 if self.decision_function < 0 else 1):
            raise ValueError("prediction differs from decision")
        return self


class AnalysisResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: Literal[
        "analysis-api-0.1.0", "analysis-api-0.2.0", "analysis-api-0.3.0", "analysis-api-0.4.0"
    ] = "analysis-api-0.1.0"
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
    comparison: ComparisonContext | ExpandedComparisonContext | None = None
    statistical: StatisticalContext | None = None

    @model_validator(mode="after")
    def bound_results(self) -> "AnalysisResult":
        expanded = isinstance(self.comparison, ExpandedComparisonContext)
        if (self.version == "analysis-api-0.4.0") != expanded:
            raise ValueError("expanded comparisons require their own API version")
        if self.version not in {"analysis-api-0.3.0", "analysis-api-0.4.0"} and (
            (self.version == "analysis-api-0.2.0") != (self.comparison is not None)
        ):
            raise ValueError("comparison context requires the extended API version")
        if self.version != "analysis-api-0.4.0" and (
            (self.version == "analysis-api-0.3.0") != (self.statistical is not None)
        ):
            raise ValueError("statistical context requires the model API version")
        versions = {"policy_engine": self.policy_catalog_version}
        if self.statistical is not None:
            if self.status != "completed":
                raise ValueError("statistical model requires complete parsing")
            versions["isolation_forest"] = self.statistical.model.metadata.model_version
            if any(
                item.device_id == self.device_id or (item.source_sha256 == self.source_sha256)
                for item in self.statistical.model.training
            ):
                raise ValueError("target cannot belong to its training population")
            outliers = [item for item in self.findings if item.detector == "isolation_forest"]
            if len(outliers) != (1 if self.statistical.prediction == -1 else 0):
                raise ValueError("statistical finding differs from model prediction")
            for item in outliers:
                if item.observed.get("model_id") != str(self.statistical.model.model_id) or (
                    item.observed.get("artifact_sha256") != self.statistical.model.artifact_sha256
                ):
                    raise ValueError("statistical finding belongs to a different model")
                if item.observed.get("raw_anomaly_score") != -self.statistical.score_samples or (
                    item.observed.get("decision_function") != self.statistical.decision_function
                ):
                    raise ValueError("statistical finding differs from recorded scores")
        if self.comparison is not None:
            reference = self.comparison.reference
            if reference is not None:
                if reference.device_id != self.device_id or (
                    reference.configuration_id == self.configuration_id
                ):
                    raise ValueError("reference must be a different snapshot of the same device")
                versions["expected_configuration"] = (
                    "expected-config-0.2.0" if expanded else "expected-config-0.1.0"
                )
            if self.comparison.peer_baseline is not None:
                if any(item.device_id == self.device_id for item in self.comparison.peers):
                    raise ValueError("target device cannot be its own peer")
                versions["peer_baseline"] = self.comparison.peer_baseline.model_version
            if isinstance(self.comparison, ExpandedComparisonContext):
                report = self.comparison.peer_evaluation
                if report is not None and (
                    (report.device_id, report.source_sha256, report.status)
                    != (self.device_id, self.source_sha256, self.status)
                    or report.findings
                    != tuple(item for item in self.findings if item.detector == "peer_baseline")
                    or any(
                        item.source_sha256 == self.source_sha256 for item in self.comparison.peers
                    )
                ):
                    raise ValueError("expanded peer report differs from its analysis")
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
        if (self.comparison is not None or self.statistical is not None) and self.risk is not None:
            sources = [RiskSource.POLICY]
            if self.comparison is not None and self.comparison.peer_baseline is not None:
                sources.append(RiskSource.PEER_GROUP)
            if self.statistical is not None:
                sources.append(RiskSource.STATISTICAL)
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
