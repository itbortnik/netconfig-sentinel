"""Explicit metadata projection; never serialize arbitrary response/request bodies."""

from __future__ import annotations

from collections.abc import Sequence
from uuid import UUID

from fastapi import Request
from pydantic import BaseModel

from app.api.contracts import (
    AnalysisResult,
    AnalysisSummary,
    ConfigurationSnapshot,
    ConfigurationSummary,
    ModelSummary,
    SnapshotBinding,
)
from app.api.diff_contracts import SnapshotDiff
from app.api.explanation_contracts import (
    ExplanationCapabilities,
    ExplanationContext,
    ModelExplanationBundle,
)
from app.api.feedback_contracts import FeedbackRecord
from app.api.patch_contracts import PatchDraft, PatchSummary, VerificationRun, VerificationSummary
from app.audit.contracts import OperationPage, OperationRecord, ResultMetadata, metadata_hash
from app.domain import Finding
from app.domain.fingerprints import finding_fingerprint
from app.explanation.local import FindingExplanation

_IDENTIFIERS = (
    "configuration_id",
    "device_id",
    "analysis_id",
    "finding_id",
    "feedback_id",
    "model_id",
    "patch_id",
    "verification_id",
)
_HASHES = (
    "source_sha256",
    "finding_sha256",
    "artifact_sha256",
    "draft_sha256",
    "knowledge_sha256",
    "context_sha256",
    "projection_sha256",
)
_VERSIONS = (
    "version",
    "policy_catalog_version",
    "model_version",
    "detector_version",
    "knowledge_version",
    "privacy_version",
)
_SUPPORTED = (
    AnalysisResult,
    AnalysisSummary,
    ConfigurationSnapshot,
    ConfigurationSummary,
    ModelSummary,
    SnapshotBinding,
    SnapshotDiff,
    ExplanationContext,
    ExplanationCapabilities,
    FeedbackRecord,
    PatchDraft,
    PatchSummary,
    VerificationRun,
    VerificationSummary,
    Finding,
    FindingExplanation,
    OperationPage,
    OperationRecord,
)


def _selected(value: BaseModel) -> dict[str, object]:
    if not isinstance(value, _SUPPORTED):
        raise ValueError("unsupported audit result projection")
    selected: dict[str, object] = {"type": type(value).__name__}
    for name in _IDENTIFIERS:
        item = getattr(value, name, None)
        if isinstance(item, UUID):
            selected[name] = str(item)
    for name in (*_HASHES, *_VERSIONS):
        item = getattr(value, name, None)
        if isinstance(item, str):
            selected[name] = item
    if isinstance(value, ConfigurationSnapshot):
        selected["source_sha256"] = value.canonical.source.sha256
        selected["version"] = f"canonical-schema-{value.canonical.schema_version}"
    if isinstance(value, Finding):
        selected["finding_sha256"] = finding_fingerprint(value)
    if isinstance(value, ModelSummary):
        selected["versions"] = [
            value.metadata.model_version,
            value.metadata.feature_schema_version,
            f"scikit-learn-{value.metadata.library_version}",
        ]
        selected["training"] = [_selected(item) for item in value.training]
    if isinstance(value, AnalysisResult):
        selected["findings"] = [_selected(item) for item in value.findings]
        selected["explanations"] = [_selected(item) for item in value.explanations]
        if value.comparison is not None:
            selected["peers"] = [_selected(item) for item in value.comparison.peers]
            if value.comparison.reference is not None:
                selected["reference"] = _selected(value.comparison.reference)
            if value.comparison.peer_baseline is not None:
                selected["versions"] = [value.comparison.peer_baseline.model_version]
        if value.statistical is not None:
            selected["model"] = _selected(value.statistical.model)
    if isinstance(value, ExplanationContext):
        selected["explanation"] = _selected(value.explanation)
        selected["retrieval"] = value.retrieval
        selected["documents"] = [
            {"document_sha256": item.document_sha256, "content_sha256": item.content_sha256}
            for item in value.documents
        ]
        if value.semantic_retrieval is not None:
            semantic = value.semantic_retrieval
            selected["document_index_sha256"] = semantic.index_sha256
            selected["document_encoder_sha256"] = metadata_hash(
                semantic.encoder.model_dump(mode="json")
            )
            selected["query_sha256"] = semantic.query_sha256
            selected["versions"] = [semantic.encoder.pipeline_version]
        if isinstance(value, ModelExplanationBundle):
            selected["model_alias_sha256"] = metadata_hash(value.model_alias)
    if isinstance(value, (SnapshotDiff, PatchSummary, VerificationRun)):
        selected["before"] = _selected(value.before)
        selected["after"] = _selected(value.after)
    if isinstance(value, PatchDraft):
        selected["diff"] = _selected(value.diff)
    if isinstance(value, VerificationRun):
        report = value.preflight
        selected["versions"] = [report.version, report.policy_catalog_version]
        selected["findings"] = [
            _selected(item)
            for item in (
                *report.before_policy_findings,
                *report.after_policy_findings,
                *report.reference_findings,
            )
        ]
        selected["formal_verification"] = report.formal_verification
    if isinstance(value, OperationRecord):
        selected["operation_id"] = str(value.receipt.operation_id)
        selected["receipt_sha256"] = value.receipt.sha256
        selected["completion_sha256"] = (
            metadata_hash(value.completion.model_dump(mode="json")) if value.completion else None
        )
    if isinstance(value, OperationPage):
        selected["records"] = [_selected(item) for item in value.records]
    return selected


def _versions(value: object) -> set[str]:
    if isinstance(value, list):
        return set().union(*(_versions(item) for item in value))
    if isinstance(value, dict):
        collected = {
            item for name, item in value.items() if name in _VERSIONS and isinstance(item, str)
        }
        collected.update(item for item in value.get("versions", []) if isinstance(item, str))
        for item in value.values():
            if isinstance(item, (dict, list)):
                collected.update(_versions(item))
        return collected
    return set()


def result_metadata(value: BaseModel | Sequence[BaseModel]) -> ResultMetadata:
    values = [value] if isinstance(value, BaseModel) else value
    selected = [_selected(item) for item in values]
    # This bounded display preview is not the complete binding: the digest covers all selected rows.
    ids = tuple(
        dict.fromkeys(
            UUID(str(item[name])) for item in selected for name in _IDENTIFIERS if name in item
        )
    )[:16]
    root = selected[0] if len(selected) == 1 else {}
    optional = {
        name: root[name]
        for name in (
            "source_sha256",
            "finding_sha256",
            "knowledge_sha256",
            "context_sha256",
            "document_index_sha256",
            "document_encoder_sha256",
            "model_alias_sha256",
            "retrieval",
        )
        if name in root
    }
    return ResultMetadata.model_validate(
        {
            "metadata_sha256": metadata_hash(["operation-result-projection-0.1.0", selected]),
            "result_count": len(value.records) if isinstance(value, OperationPage) else len(values),
            "resource_ids": ids,
            "versions": tuple(sorted(_versions(selected))),
            **optional,
        }
    )


def capture_result[T: BaseModel | Sequence[BaseModel]](request: Request, value: T) -> T:
    request.state.operation_result = result_metadata(value)
    return value
