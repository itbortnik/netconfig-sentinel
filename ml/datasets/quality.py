"""Reproducible dataset quality, provenance, and readiness reporting."""

from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from collections.abc import Iterable
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ml.datasets.deduplication import (
    DatasetDeduplicationResult,
    DatasetRecordReference,
    normalize_configuration_text,
)
from ml.datasets.models import (
    DatasetSource,
    DatasetUse,
    ImportedDatasetRecord,
    LicenseReviewStatus,
)
from ml.datasets.splitting import DatasetSplit, DatasetSplitResult
from ml.preprocessing import SANITIZATION_VERSION

QUALITY_REPORT_VERSION = "dataset-quality-0.2.0"
_TOKEN = re.compile(r"<[^>]+>|[A-Za-z0-9_./:@-]+|[{};]")
_HOST_ALIAS = re.compile(r"^host-[0-9a-f]{12}[;]?$", re.I)
_USER_ALIAS = re.compile(r"^user-[0-9a-f]{12}[;]?$", re.I)
_DOMAIN_ALIAS = re.compile(r"^domain-[0-9a-f]{12}\.invalid[;]?$", re.I)
_SECRET_DIRECTIVE = re.compile(
    r"\b(?:password|secret|key-string|shared-secret|pre-shared-key|"
    r"authentication-key|encrypted-password)\b",
    re.I,
)
_NON_SECRET_PASSWORD_POLICY = re.compile(
    r"\bpassword\s+(?:minimum-length|minimum-changes|change-type|format|policy)\b",
    re.I,
)
_SNMP_COMMUNITY = re.compile(r"\b(?:snmp-server\s+community|snmp\s+community)\b", re.I)
_PEM_BEGIN = re.compile(r"-----BEGIN (?:[A-Z0-9 ]*PRIVATE KEY|CERTIFICATE)-----")
_PEM_END = re.compile(r"-----END (?:[A-Z0-9 ]*PRIVATE KEY|CERTIFICATE)-----")


class QualityIssueSeverity(StrEnum):
    """Impact of a data-quality observation on artifact persistence."""

    WARNING = "warning"
    BLOCKING = "blocking"


class DatasetScaleMetric(StrEnum):
    """Explicit PoC scale indicators from the project requirements."""

    CANDIDATE_CONFIGURATIONS = "candidate_configurations"
    UNIQUE_CONFIGURATIONS = "unique_configurations"
    INDEPENDENT_NETWORKS = "independent_networks"
    CONFIGURATION_BLOCKS = "configuration_blocks"
    TOKENS = "tokens"
    SYNTHETIC_LABELED_ANOMALIES = "synthetic_labeled_anomalies"
    CONFIRMED_ANOMALIES = "confirmed_anomalies"
    ISOLATED_TEST_NETWORKS = "isolated_test_networks"


class DatasetQualityPolicy(BaseModel):
    """Recorded thresholds for safety and balance diagnostics."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    required_unseen_test_entity_fraction: float = Field(default=0.20, ge=0.0, le=1.0)
    maximum_role_fraction: float = Field(default=0.50, gt=0.0, le=1.0)
    maximum_split_fraction_deviation: float = Field(default=0.05, ge=0.0, lt=1.0)
    minimum_unique_records_for_balance_checks: int = Field(default=20, ge=1)
    allowed_sanitization_versions: tuple[str, ...] = (SANITIZATION_VERSION,)

    @model_validator(mode="after")
    def sanitization_versions_must_be_unique(self) -> DatasetQualityPolicy:
        if not self.allowed_sanitization_versions:
            raise ValueError("at least one sanitization version must be allowed")
        if len(self.allowed_sanitization_versions) != len(
            set(self.allowed_sanitization_versions)
        ):
            raise ValueError("allowed sanitization versions must be unique")
        return self


class DatasetSourceAudit(BaseModel):
    """License and authorization provenance retained in the report."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_id: str
    source_type: str
    origin: str
    license_id: str
    license_url: str | None
    license_review: LicenseReviewStatus
    allowed_uses: frozenset[DatasetUse]
    collected_at: str
    authorization_reference: str | None


class DistributionEntry(BaseModel):
    """One observed categorical distribution entry."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    label: str
    count: int = Field(ge=1)
    fraction: float = Field(gt=0.0, le=1.0)


class DatasetQualityIssue(BaseModel):
    """Aggregated actionable issue with bounded record samples."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: str = Field(pattern=r"^[a-z][a-z0-9_.-]{2,127}$")
    severity: QualityIssueSeverity
    message: str = Field(min_length=1, max_length=512)
    affected_record_count: int = Field(ge=0)
    sample_records: tuple[DatasetRecordReference, ...] = Field(max_length=20)

    @model_validator(mode="after")
    def samples_must_be_bounded_by_count(self) -> DatasetQualityIssue:
        if len(self.sample_records) > self.affected_record_count:
            raise ValueError("issue samples exceed affected record count")
        return self


class ScaleTargetAssessment(BaseModel):
    """Actual value compared with one minimum PoC target."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    metric: DatasetScaleMetric
    actual: int = Field(ge=0)
    target_minimum: int = Field(ge=1)
    met: bool

    @model_validator(mode="after")
    def status_must_match_values(self) -> ScaleTargetAssessment:
        if self.met != (self.actual >= self.target_minimum):
            raise ValueError("scale target status does not match its values")
        return self


class DatasetQualityMetrics(BaseModel):
    """Observed counts based on candidates, representatives, and entities."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    candidate_configuration_count: int = Field(ge=1)
    unique_configuration_count: int = Field(ge=1)
    exact_duplicate_count: int = Field(ge=0)
    near_duplicate_count: int = Field(ge=0)
    source_count: int = Field(ge=1)
    independent_network_count: int = Field(ge=1)
    site_count: int = Field(ge=1)
    device_count: int = Field(ge=1)
    configuration_block_count: int = Field(ge=0)
    token_count: int = Field(ge=0)
    synthetic_anomaly_count: int = Field(ge=0)
    confirmed_anomaly_count: int = Field(ge=0)
    isolated_test_network_count: int = Field(ge=1)
    unseen_test_network_fraction: float = Field(ge=0.0, le=1.0)
    unseen_test_site_fraction: float = Field(ge=0.0, le=1.0)
    partition_unique_counts: dict[str, int]


class DatasetQualityReport(BaseModel):
    """Immutable quality decision input tied to exact pipeline outputs."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    report_version: str = Field(
        default=QUALITY_REPORT_VERSION,
        pattern=r"^dataset-quality-0\.2\.0$",
    )
    policy: DatasetQualityPolicy
    intended_use: DatasetUse
    pipeline_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    sources: tuple[DatasetSourceAudit, ...]
    metrics: DatasetQualityMetrics
    vendor_distribution: tuple[DistributionEntry, ...]
    role_distribution: tuple[DistributionEntry, ...]
    scale_targets: tuple[ScaleTargetAssessment, ...]
    issues: tuple[DatasetQualityIssue, ...]
    blocking_issue_count: int = Field(ge=0)
    warning_count: int = Field(ge=0)
    technically_valid: bool
    poc_scale_ready: bool

    @model_validator(mode="after")
    def status_must_match_issues_and_targets(self) -> DatasetQualityReport:
        source_ids = [source.source_id for source in self.sources]
        if len(source_ids) != len(set(source_ids)):
            raise ValueError("quality report source IDs must be unique")
        if self.technically_valid and len(source_ids) != self.metrics.source_count:
            raise ValueError("valid quality reports require provenance for every source")
        target_metrics = [target.metric for target in self.scale_targets]
        if len(target_metrics) != len(set(target_metrics)) or set(target_metrics) != set(
            DatasetScaleMetric
        ):
            raise ValueError("quality report must contain every scale target once")
        issue_codes = [issue.code for issue in self.issues]
        if len(issue_codes) != len(set(issue_codes)):
            raise ValueError("quality issue codes must be unique")
        blocking = sum(
            issue.severity is QualityIssueSeverity.BLOCKING for issue in self.issues
        )
        warnings = sum(
            issue.severity is QualityIssueSeverity.WARNING for issue in self.issues
        )
        if blocking != self.blocking_issue_count or warnings != self.warning_count:
            raise ValueError("quality issue counts do not match issue payload")
        if self.technically_valid != (blocking == 0):
            raise ValueError("technical validity does not match blocking issues")
        if self.poc_scale_ready != all(target.met for target in self.scale_targets):
            raise ValueError("PoC readiness does not match scale targets")
        return self


def build_dataset_quality_report(
    records: tuple[ImportedDatasetRecord, ...] | list[ImportedDatasetRecord],
    deduplication: DatasetDeduplicationResult,
    split_result: DatasetSplitResult,
    *,
    sources: tuple[DatasetSource, ...] | list[DatasetSource],
    intended_use: DatasetUse,
    synthetic_anomaly_count: int = 0,
    confirmed_anomaly_count: int = 0,
    policy: DatasetQualityPolicy | None = None,
) -> DatasetQualityReport:
    """Measure actual corpus quality without converting targets into claims."""

    if synthetic_anomaly_count < 0 or confirmed_anomaly_count < 0:
        raise ValueError("anomaly counts must not be negative")
    effective_policy = policy or DatasetQualityPolicy()
    record_by_reference = _validate_pipeline_inputs(
        records,
        deduplication,
        split_result,
    )
    source_by_id = _validate_sources(sources)
    issue_records: dict[
        tuple[str, QualityIssueSeverity, str], set[tuple[str, str]]
    ] = defaultdict(set)

    records_by_source: dict[str, set[tuple[str, str]]] = defaultdict(set)
    for reference, record in record_by_reference.items():
        records_by_source[record.source_id].add(reference)
        source = source_by_id.get(record.source_id)
        if source is None:
            _add_issue(
                issue_records,
                code="source.missing_provenance",
                severity=QualityIssueSeverity.BLOCKING,
                message="A dataset source has no provenance and license record.",
                references={reference},
            )
        for code, message in _scan_sanitized_record(
            record,
            allowed_versions=effective_policy.allowed_sanitization_versions,
        ):
            _add_issue(
                issue_records,
                code=code,
                severity=QualityIssueSeverity.BLOCKING,
                message=message,
                references={reference},
            )
    for source_id, references in records_by_source.items():
        source = source_by_id.get(source_id)
        if source is None:
            continue
        if source.license_review is not LicenseReviewStatus.APPROVED:
            _add_issue(
                issue_records,
                code="source.review_not_approved",
                severity=QualityIssueSeverity.BLOCKING,
                message="A used source has not passed license or authorization review.",
                references=references,
            )
        if intended_use not in source.allowed_uses:
            _add_issue(
                issue_records,
                code="source.use_not_permitted",
                severity=QualityIssueSeverity.BLOCKING,
                message="A used source does not permit the requested dataset use.",
                references=references,
            )

    unique_records = deduplication.unique_records
    metrics = _build_metrics(
        records,
        unique_records,
        deduplication,
        split_result,
        synthetic_anomaly_count,
        confirmed_anomaly_count,
    )
    if (
        metrics.unseen_test_network_fraction
        < effective_policy.required_unseen_test_entity_fraction
    ):
        _add_issue(
            issue_records,
            code="split.test_network_leakage",
            severity=QualityIssueSeverity.BLOCKING,
            message="Too few test networks are absent from training.",
        )
    if (
        metrics.unseen_test_site_fraction
        < effective_policy.required_unseen_test_entity_fraction
    ):
        _add_issue(
            issue_records,
            code="split.test_site_leakage",
            severity=QualityIssueSeverity.BLOCKING,
            message="Too few test sites are absent from training.",
        )
    if not split_result.temporal_audit.strict_order:
        _add_issue(
            issue_records,
            code="split.temporal_overlap",
            severity=QualityIssueSeverity.WARNING,
            message="Entity-isolated partitions have overlapping capture-time ranges.",
        )
    for partition in split_result.partitions:
        deviation = abs(partition.actual_fraction - partition.target_fraction)
        if deviation > effective_policy.maximum_split_fraction_deviation:
            _add_issue(
                issue_records,
                code=f"split.{partition.split.value}_fraction_deviation",
                severity=QualityIssueSeverity.WARNING,
                message="An indivisible-group split differs materially from its target.",
            )

    vendor_distribution = _distribution(
        record.vendor_hint.value if record.vendor_hint is not None else "unknown"
        for record in unique_records
    )
    role_distribution = _distribution(
        record.device_role or "unknown" for record in unique_records
    )
    if len(unique_records) >= effective_policy.minimum_unique_records_for_balance_checks:
        for role in role_distribution:
            if role.fraction > effective_policy.maximum_role_fraction:
                role_references = {
                    (record.source_id, record.record_id)
                    for record in unique_records
                    if (record.device_role or "unknown") == role.label
                }
                _add_issue(
                    issue_records,
                    code="balance.role_concentration",
                    severity=QualityIssueSeverity.WARNING,
                    message="One device role exceeds the configured corpus share.",
                    references=role_references,
                )

    issues = _render_issues(issue_records)
    scale_targets = _scale_targets(metrics)
    source_audits = tuple(
        _source_audit(source_by_id[source_id])
        for source_id in sorted(records_by_source)
        if source_id in source_by_id
    )
    blocking_count = sum(
        issue.severity is QualityIssueSeverity.BLOCKING for issue in issues
    )
    warning_count = sum(
        issue.severity is QualityIssueSeverity.WARNING for issue in issues
    )
    return DatasetQualityReport(
        policy=effective_policy,
        intended_use=intended_use,
        pipeline_fingerprint=compute_pipeline_fingerprint(
            records,
            deduplication,
            split_result,
        ),
        sources=source_audits,
        metrics=metrics,
        vendor_distribution=vendor_distribution,
        role_distribution=role_distribution,
        scale_targets=scale_targets,
        issues=issues,
        blocking_issue_count=blocking_count,
        warning_count=warning_count,
        technically_valid=blocking_count == 0,
        poc_scale_ready=all(target.met for target in scale_targets),
    )


def compute_pipeline_fingerprint(
    records: tuple[ImportedDatasetRecord, ...] | list[ImportedDatasetRecord],
    deduplication: DatasetDeduplicationResult,
    split_result: DatasetSplitResult,
) -> str:
    """Bind a report or artifact to exact inputs, algorithms, and assignments."""

    record_payload = [
        {
            "source_id": record.source_id,
            "record_id": record.record_id,
            "raw_sha256": record.raw_sha256,
            "sanitized_sha256": record.sanitized_sha256,
        }
        for record in sorted(records, key=lambda item: (item.source_id, item.record_id))
    ]
    assignment_payload = [
        {
            "source_id": assignment.record.source_id,
            "record_id": assignment.record.record_id,
            "split": assignment.split.value,
            "atomic_group_id": assignment.atomic_group_id,
            "is_representative": assignment.is_representative,
        }
        for assignment in split_result.assignments
    ]
    payload = {
        "records": record_payload,
        "deduplication_version": deduplication.algorithm_version,
        "deduplication_policy": deduplication.policy.model_dump(mode="json"),
        "splitting_version": split_result.algorithm_version,
        "splitting_policy": split_result.policy.model_dump(mode="json"),
        "assignments": assignment_payload,
    }
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _validate_pipeline_inputs(
    records: tuple[ImportedDatasetRecord, ...] | list[ImportedDatasetRecord],
    deduplication: DatasetDeduplicationResult,
    split_result: DatasetSplitResult,
) -> dict[tuple[str, str], ImportedDatasetRecord]:
    record_by_reference = {
        (record.source_id, record.record_id): record for record in records
    }
    if not records or len(record_by_reference) != len(records):
        raise ValueError("quality input records must be non-empty and uniquely referenced")
    fingerprint_references = {
        (item.record.source_id, item.record.record_id)
        for item in deduplication.fingerprints
    }
    assignment_references = {
        (item.record.source_id, item.record.record_id)
        for item in split_result.assignments
    }
    if set(record_by_reference) != fingerprint_references:
        raise ValueError("quality records do not match the deduplication result")
    if set(record_by_reference) != assignment_references:
        raise ValueError("quality records do not match the split result")
    if deduplication.unique_count != split_result.unique_count:
        raise ValueError("deduplication and split unique counts do not match")
    return record_by_reference


def _validate_sources(
    sources: tuple[DatasetSource, ...] | list[DatasetSource],
) -> dict[str, DatasetSource]:
    source_by_id = {source.source_id: source for source in sources}
    if len(source_by_id) != len(sources):
        raise ValueError("dataset source IDs must be unique")
    return source_by_id


def _scan_sanitized_record(
    record: ImportedDatasetRecord,
    *,
    allowed_versions: tuple[str, ...],
) -> list[tuple[str, str]]:
    issues: list[tuple[str, str]] = []
    actual_hash = hashlib.sha256(record.sanitized_text.encode("utf-8")).hexdigest()
    if actual_hash != record.sanitized_sha256:
        issues.append(
            ("integrity.sanitized_hash_mismatch", "Sanitized text does not match its SHA-256.")
        )
    if record.sanitization_version not in allowed_versions:
        issues.append(
            (
                "sanitization.unsupported_version",
                "A record uses a sanitization version not accepted by this report.",
            )
        )
    if not record.sanitized_text.strip():
        issues.append(("content.empty", "Sanitized configuration text is empty."))
    if _contains_control_character(record.sanitized_text):
        issues.append(
            ("content.control_character", "Sanitized text contains a control character.")
        )

    in_pem_block = False
    for raw_line in record.sanitized_text.splitlines():
        stripped = raw_line.strip()
        if _PEM_BEGIN.fullmatch(stripped):
            in_pem_block = True
            continue
        if _PEM_END.fullmatch(stripped):
            in_pem_block = False
            continue
        if in_pem_block and stripped and stripped != "<redacted-material>":
            issues.append(
                (
                    "sanitization.certificate_material",
                    "Certificate or private-key material remains after sanitization.",
                )
            )
        lowered = stripped.casefold()
        has_unredacted_secret = (
            _SECRET_DIRECTIVE.search(stripped)
            and not _NON_SECRET_PASSWORD_POLICY.search(stripped)
            and "<redacted-secret>" not in lowered
        )
        if has_unredacted_secret:
            issues.append(
                ("sanitization.secret_value", "A credential directive is not redacted.")
            )
        if _SNMP_COMMUNITY.search(stripped) and "<redacted-community>" not in lowered:
            issues.append(
                ("sanitization.snmp_community", "An SNMP community is not redacted.")
            )
        _scan_identity_line(stripped, lowered, issues)
    if in_pem_block:
        issues.append(
            (
                "sanitization.incomplete_certificate_block",
                "A certificate or key block has no closing boundary.",
            )
        )
    return sorted(set(issues))


def _scan_identity_line(
    stripped: str,
    lowered: str,
    issues: list[tuple[str, str]],
) -> None:
    tokens = stripped.split()
    if not tokens:
        return
    hostname_index = _value_index(lowered, ("hostname ", "host-name "))
    if hostname_index is not None and hostname_index < len(tokens):
        if not _HOST_ALIAS.fullmatch(tokens[hostname_index].strip('"\'')):
            issues.append(
                ("sanitization.hostname", "A hostname is not pseudonymized.")
            )
    username_index = _value_index(lowered, ("username ", " login user ", " user "))
    if username_index is not None and username_index < len(tokens):
        if not _USER_ALIAS.fullmatch(tokens[username_index].strip('"\'')):
            issues.append(
                ("sanitization.username", "A username is not pseudonymized.")
            )
    domain_index = _value_index(lowered, ("domain-name ", "domain name "))
    if domain_index is not None and domain_index < len(tokens):
        if not _DOMAIN_ALIAS.fullmatch(tokens[domain_index].strip('"\'')):
            issues.append(("sanitization.domain", "A domain is not pseudonymized."))
    if re.search(r"\b(?:contact|location)\s+", lowered):
        if "<redacted-contact>" not in lowered:
            issues.append(
                ("sanitization.contact", "Contact or location data is not redacted.")
            )


def _value_index(lowered: str, markers: tuple[str, ...]) -> int | None:
    for marker in markers:
        position = lowered.find(marker)
        if position < 0:
            continue
        return len(lowered[: position + len(marker)].split())
    return None


def _contains_control_character(text: str) -> bool:
    return any(ord(character) < 32 and character not in "\t\r\n" for character in text)


def _build_metrics(
    records: tuple[ImportedDatasetRecord, ...] | list[ImportedDatasetRecord],
    unique_records: tuple[ImportedDatasetRecord, ...],
    deduplication: DatasetDeduplicationResult,
    split_result: DatasetSplitResult,
    synthetic_anomaly_count: int,
    confirmed_anomaly_count: int,
) -> DatasetQualityMetrics:
    assignments_by_split = {
        split: [item for item in split_result.assignments if item.split is split]
        for split in DatasetSplit
    }
    train_networks = {
        (item.record.source_id, item.network_id)
        for item in assignments_by_split[DatasetSplit.TRAIN]
    }
    train_sites = {
        (item.record.source_id, item.site_id)
        for item in assignments_by_split[DatasetSplit.TRAIN]
    }
    test_networks = {
        (item.record.source_id, item.network_id)
        for item in assignments_by_split[DatasetSplit.TEST]
    }
    test_sites = {
        (item.record.source_id, item.site_id)
        for item in assignments_by_split[DatasetSplit.TEST]
    }
    unseen_test_networks = test_networks - train_networks
    unseen_test_sites = test_sites - train_sites
    return DatasetQualityMetrics(
        candidate_configuration_count=len(records),
        unique_configuration_count=len(unique_records),
        exact_duplicate_count=deduplication.exact_duplicate_count,
        near_duplicate_count=deduplication.near_duplicate_count,
        source_count=len({record.source_id for record in records}),
        independent_network_count=len(
            {(record.source_id, record.network_id) for record in records}
        ),
        site_count=len({(record.source_id, record.site_id) for record in records}),
        device_count=len(
            {(record.source_id, record.device_id) for record in records}
        ),
        configuration_block_count=sum(
            count_configuration_blocks(record.sanitized_text)
            for record in unique_records
        ),
        token_count=sum(
            count_configuration_tokens(record.sanitized_text)
            for record in unique_records
        ),
        synthetic_anomaly_count=synthetic_anomaly_count,
        confirmed_anomaly_count=confirmed_anomaly_count,
        isolated_test_network_count=len(unseen_test_networks),
        unseen_test_network_fraction=len(unseen_test_networks) / len(test_networks),
        unseen_test_site_fraction=len(unseen_test_sites) / len(test_sites),
        partition_unique_counts={
            partition.split.value: len(partition.records)
            for partition in split_result.partitions
        },
    )


def count_configuration_blocks(text: str) -> int:
    """Count deterministic command/stanza blocks without claiming semantic parsing."""

    block_count = 0
    active_key: str | None = None
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith(("!", "#", "//")):
            active_key = None
            continue
        lowered = stripped.casefold()
        if stripped.startswith("}"):
            if raw_line == raw_line.lstrip():
                active_key = None
            continue
        if lowered.startswith("set "):
            parts = lowered.split()
            key = " ".join(parts[: min(3, len(parts))])
            if key != active_key:
                block_count += 1
                active_key = key
            continue
        if raw_line == raw_line.lstrip() or active_key is None:
            block_count += 1
            active_key = lowered
    return block_count


def count_configuration_tokens(text: str) -> int:
    """Count stable lexical units in sanitized text for corpus accounting."""

    return len(_TOKEN.findall(normalize_configuration_text(text)))


def _distribution(values: Iterable[str]) -> tuple[DistributionEntry, ...]:
    counts: dict[str, int] = defaultdict(int)
    total = 0
    for value in values:
        counts[str(value)] += 1
        total += 1
    return tuple(
        DistributionEntry(label=label, count=count, fraction=count / total)
        for label, count in sorted(counts.items())
    )


def _scale_targets(metrics: DatasetQualityMetrics) -> tuple[ScaleTargetAssessment, ...]:
    actuals = {
        DatasetScaleMetric.CANDIDATE_CONFIGURATIONS: metrics.candidate_configuration_count,
        DatasetScaleMetric.UNIQUE_CONFIGURATIONS: metrics.unique_configuration_count,
        DatasetScaleMetric.INDEPENDENT_NETWORKS: metrics.independent_network_count,
        DatasetScaleMetric.CONFIGURATION_BLOCKS: metrics.configuration_block_count,
        DatasetScaleMetric.TOKENS: metrics.token_count,
        DatasetScaleMetric.SYNTHETIC_LABELED_ANOMALIES: (
            metrics.synthetic_anomaly_count
        ),
        DatasetScaleMetric.CONFIRMED_ANOMALIES: metrics.confirmed_anomaly_count,
        DatasetScaleMetric.ISOLATED_TEST_NETWORKS: metrics.isolated_test_network_count,
    }
    minimums = {
        DatasetScaleMetric.CANDIDATE_CONFIGURATIONS: 5_000,
        DatasetScaleMetric.UNIQUE_CONFIGURATIONS: 1_000,
        DatasetScaleMetric.INDEPENDENT_NETWORKS: 10,
        DatasetScaleMetric.CONFIGURATION_BLOCKS: 10_000,
        DatasetScaleMetric.TOKENS: 10_000_000,
        DatasetScaleMetric.SYNTHETIC_LABELED_ANOMALIES: 10_000,
        DatasetScaleMetric.CONFIRMED_ANOMALIES: 50,
        DatasetScaleMetric.ISOLATED_TEST_NETWORKS: 5,
    }
    return tuple(
        ScaleTargetAssessment(
            metric=metric,
            actual=actuals[metric],
            target_minimum=minimums[metric],
            met=actuals[metric] >= minimums[metric],
        )
        for metric in DatasetScaleMetric
    )


def _source_audit(source: DatasetSource) -> DatasetSourceAudit:
    return DatasetSourceAudit(
        source_id=source.source_id,
        source_type=source.source_type.value,
        origin=source.origin,
        license_id=source.license_id,
        license_url=source.license_url,
        license_review=source.license_review,
        allowed_uses=source.allowed_uses,
        collected_at=source.collected_at.isoformat(),
        authorization_reference=source.authorization_reference,
    )


def _add_issue(
    issues: dict[tuple[str, QualityIssueSeverity, str], set[tuple[str, str]]],
    *,
    code: str,
    severity: QualityIssueSeverity,
    message: str,
    references: set[tuple[str, str]] | None = None,
) -> None:
    issues[(code, severity, message)].update(references or set())


def _render_issues(
    issues: dict[tuple[str, QualityIssueSeverity, str], set[tuple[str, str]]],
) -> tuple[DatasetQualityIssue, ...]:
    rendered: list[DatasetQualityIssue] = []
    for (code, severity, message), references in sorted(
        issues.items(), key=lambda item: item[0]
    ):
        sorted_references = sorted(references)
        rendered.append(
            DatasetQualityIssue(
                code=code,
                severity=severity,
                message=message,
                affected_record_count=len(sorted_references),
                sample_records=tuple(
                    DatasetRecordReference(source_id=source_id, record_id=record_id)
                    for source_id, record_id in sorted_references[:20]
                ),
            )
        )
    return tuple(rendered)
