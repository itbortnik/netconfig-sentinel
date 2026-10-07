"""Repeat actual selected CPU inference on an exact private patch pair, without promotion."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from functools import partial
from typing import TYPE_CHECKING

from app.ingestion.local import validate_configuration_text
from app.patching.review import PatchReview, review_patch_proposal

from ml.datasets.models import ImportedDatasetRecord
from ml.evaluation.metrics import canonical_hash
from ml.inference.change_contracts import MLChangeReview, SidePrediction, TransformerSupplement
from ml.preprocessing import sanitize_configuration
from ml.preprocessing.blocks import digest

if TYPE_CHECKING:
    from ml.training.foundation_transfer import FoundationTransferResult
    from ml.training.multitask_training import MultiTaskPrediction, MultiTaskResult


def _record(text: str, review: PatchReview, key: bytes) -> ImportedDatasetRecord:
    # This is only the encoder's transient content envelope, not a licensed dataset
    # import, collected snapshot, split membership or an authorized training example.
    sanitized = sanitize_configuration(
        text, topology_id=str(review.proposal.device_id), pseudonymization_key=key
    )
    validate_configuration_text(sanitized.text)
    if len(text.splitlines()) != len(sanitized.text.splitlines()):
        raise ValueError("sanitization did not preserve side-specific line coordinates")
    return ImportedDatasetRecord(
        source_id="private-change-inference",
        record_id=digest(text),
        network_id="unasserted-network",
        site_id="unasserted-site",
        device_id="unasserted-device",
        captured_at=datetime(1970, 1, 1, tzinfo=UTC),
        vendor_hint=review.proposal.vendor,
        device_role=None,
        raw_sha256=digest(text),
        sanitized_sha256=digest(sanitized.text),
        sanitized_text=sanitized.text,
        raw_byte_count=len(text.encode("utf-8")),
        replacements=sanitized.replacements,
        sanitization_version=sanitized.version,
    )


def _side(record: ImportedDatasetRecord, prediction: MultiTaskPrediction) -> SidePrediction:
    if prediction.source_sha256 != record.sanitized_sha256:
        raise ValueError("prediction source differs from sanitized inference input")
    return SidePrediction(
        raw_source_sha256=record.raw_sha256,
        sanitized_source_sha256=record.sanitized_sha256,
        model_sha256=prediction.model_sha256,
        total_lines=len(record.sanitized_text.splitlines()),
        anomaly_score=prediction.anomaly_score,
        category_scores=prediction.category_scores,
        severity_scores=prediction.severity_scores,
        line_scores=prediction.line_scores,
        block_attention=prediction.block_attention,
        embedding_sha256=canonical_hash(prediction.embedding)
        if prediction.embedding is not None
        else None,
        embedding_dimensions=len(prediction.embedding) if prediction.embedding is not None else 0,
        replacement_counts=record.replacements,
    )


def review_patch_ml(
    review: PatchReview,
    before: str,
    after: str,
    *,
    model: MultiTaskResult | FoundationTransferResult | None = None,
    expected_model_sha256: str | None = None,
    pseudonymization_key: bytes | None = None,
) -> MLChangeReview:
    """Keep local checks intact; selected diagnostic scores are not calibrated risk."""
    review = PatchReview.model_validate(review.model_dump())
    fresh = review_patch_proposal(
        review.proposal, before, after, device_id=review.proposal.device_id
    )
    if fresh != review:
        raise ValueError("local review no longer matches current exact inputs/checks")
    if model is None:
        if expected_model_sha256 is not None or pseudonymization_key is not None:
            raise ValueError("model options require explicit model selection")
        return MLChangeReview(
            local_review=fresh,
            transformer=TransformerSupplement(status="not_selected", reason="not_selected"),
        )
    if pseudonymization_key is None or not 16 <= len(pseudonymization_key) <= 1024:
        raise ValueError("selected inference requires a private pseudonymization key")
    # No optional training runtime is imported in the unselected base path.
    import torch

    from ml.training.classification import _encoder_hash
    from ml.training.multitask_training import (
        MultiTaskResult,
        _MultiTaskReportFields,
        _verified_report,
        multitask_identity,
        predict_multitask,
    )

    report: _MultiTaskReportFields
    predict: Callable[[ImportedDatasetRecord], MultiTaskPrediction]
    recheck: Callable[[], tuple[str, str]]
    if isinstance(model, MultiTaskResult):
        native = model
        report = _verified_report(native)
        identity = multitask_identity(native)
        if (
            identity != expected_model_sha256
            or _encoder_hash(native.pretrained.model) != report.encoder_sha256
            or native.pretrained.tokenizer.tokenizer_sha256 != report.tokenizer_sha256
            or any(module.training for module in native.heads.modules())
            or any(module.training for module in native.pretrained.model.modules())
            or any(
                value.device.type != "cpu"
                or value.dtype != torch.float32
                or not bool(torch.isfinite(value).all())
                for module in (native.heads, native.pretrained.model)
                for value in module.parameters()
            )
        ):
            raise ValueError("selected model pin/bindings/evaluation mode differ")
        predict = partial(predict_multitask, native)

        def recheck_native() -> tuple[str, str]:
            return _encoder_hash(native.pretrained.model), multitask_identity(native)

        recheck = recheck_native
    else:
        # Foundation dependencies are never imported by unselected or native inference.
        from ml.training.foundation_transfer import (
            FoundationTransferResult,
            foundation_transfer_identity,
            predict_foundation_transfer,
            verify_transfer,
        )

        if not isinstance(model, FoundationTransferResult):
            raise ValueError("unsupported selected inference model")
        foundation = model
        report = verify_transfer(foundation)
        identity = foundation_transfer_identity(foundation)
        if identity != expected_model_sha256:
            raise ValueError("selected foundation model independent pin differs")
        predict = partial(predict_foundation_transfer, foundation)

        def recheck_foundation() -> tuple[str, str]:
            return (
                verify_transfer(foundation).encoder_sha256,
                foundation_transfer_identity(foundation),
            )

        recheck = recheck_foundation
    bindings = dict(
        model_sha256=identity,
        tokenizer_sha256=report.tokenizer_sha256,
        training_report_sha256=canonical_hash(report.model_dump(mode="json")),
        training_format=report.version,
        runtime_torch_version=str(torch.__version__),
        sanitization_version="config-sanitizer-0.1.0",
    )
    if not fresh.preflight.before.complete or not fresh.preflight.after.complete:
        return MLChangeReview(
            local_review=fresh,
            transformer=TransformerSupplement.model_validate(
                {
                    **bindings,
                    "status": "unavailable",
                    "reason": "incomplete_parsing",
                }
            ),
        )
    previous, candidate = (_record(text, fresh, pseudonymization_key) for text in (before, after))
    threads = torch.get_num_threads()
    try:
        torch.set_num_threads(1)
        with torch.random.fork_rng(devices=[]):
            old = _side(previous, predict(previous))
            new = _side(candidate, predict(candidate))
    finally:
        torch.set_num_threads(threads)
    if recheck() != (report.encoder_sha256, identity):
        raise ValueError("model changed during before/after inference")
    return MLChangeReview(
        local_review=fresh,
        transformer=TransformerSupplement.model_validate(
            {
                **bindings,
                "status": "completed",
                "reason": None,
                "before": old,
                "after": new,
            }
        ),
    )
