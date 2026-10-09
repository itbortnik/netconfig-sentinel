"""Actual native/foundation CPU inference on a transient sanitized configuration."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING
from uuid import UUID

from app.domain import Vendor
from app.ingestion.local import validate_configuration_text

from ml.datasets.models import ImportedDatasetRecord
from ml.inference.change_review import _side
from ml.inference.config_contracts import ConfigurationInferenceReport
from ml.preprocessing import sanitize_configuration
from ml.preprocessing.blocks import digest
from ml.registry.store import _model_card

if TYPE_CHECKING:
    from ml.training.foundation_transfer import FoundationTransferResult
    from ml.training.multitask_training import MultiTaskResult


def infer_configuration(
    content: str,
    *,
    vendor: Vendor,
    device_id: UUID,
    model: MultiTaskResult | FoundationTransferResult,
    expected_model_sha256: str,
    pseudonymization_key: bytes | None,
) -> ConfigurationInferenceReport:
    if (
        not isinstance(pseudonymization_key, bytes)
        or not 16 <= len(pseudonymization_key) <= 1024
        or not isinstance(device_id, UUID)
        or not isinstance(vendor, Vendor)
    ):
        raise ValueError("explicit source identity and private pseudonymization key required")
    validate_configuration_text(content)
    card = _model_card(model)
    if card.model_sha256 != expected_model_sha256:
        raise ValueError("selected model independent pin differs")
    import torch

    from ml.training.classification import _encoder_hash
    from ml.training.multitask_training import MultiTaskResult, predict_multitask

    if isinstance(model, MultiTaskResult):
        if (
            _encoder_hash(model.pretrained.model) != card.encoder_sha256
            or any(module.training for module in model.heads.modules())
            or any(module.training for module in model.pretrained.model.modules())
            or any(
                value.device.type != "cpu"
                or value.dtype != torch.float32
                or not bool(torch.isfinite(value).all())
                for module in (model.heads, model.pretrained.model)
                for value in module.parameters()
            )
        ):
            raise ValueError("native model bindings/evaluation runtime differ")
    sanitized = sanitize_configuration(
        content, topology_id=str(device_id), pseudonymization_key=pseudonymization_key
    )
    validate_configuration_text(sanitized.text)
    if len(content.splitlines()) != len(sanitized.text.splitlines()):
        raise ValueError("sanitization changed source line coordinates")
    # Content-only encoder envelope. It asserts no training consent, cohort or health label.
    record = ImportedDatasetRecord(
        source_id="private-configuration-inference",
        record_id=digest(content),
        network_id="unasserted-network",
        site_id="unasserted-site",
        device_id="unasserted-device",
        captured_at=datetime(1970, 1, 1, tzinfo=UTC),
        vendor_hint=vendor,
        device_role=None,
        raw_sha256=digest(content),
        sanitized_sha256=digest(sanitized.text),
        sanitized_text=sanitized.text,
        raw_byte_count=len(content.encode("utf-8")),
        replacements=sanitized.replacements,
        sanitization_version=sanitized.version,
    )
    threads = torch.get_num_threads()
    try:
        torch.set_num_threads(1)
        with torch.random.fork_rng(devices=[]):
            if isinstance(model, MultiTaskResult):
                prediction = predict_multitask(model, record)
            else:
                from ml.training.foundation_transfer import predict_foundation_transfer

                prediction = predict_foundation_transfer(model, record)
    finally:
        torch.set_num_threads(threads)
    if _model_card(model) != card or (
        isinstance(model, MultiTaskResult)
        and _encoder_hash(model.pretrained.model) != card.encoder_sha256
    ):
        raise ValueError("selected model changed during single-source inference")
    return ConfigurationInferenceReport(
        model=card,
        prediction=_side(record, prediction),
        runtime_torch_version=str(torch.__version__),
    )
