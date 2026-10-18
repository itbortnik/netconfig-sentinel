"""Two source-bound forward passes with the same supplied model and private key."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from app.domain import Vendor

from ml.inference.configuration import infer_configuration
from ml.inference.pair_contracts import ConfigurationPairReport

if TYPE_CHECKING:
    from ml.inference.config_contracts import ConfigurationInferenceReport
    from ml.training.foundation_transfer import FoundationTransferResult
    from ml.training.multitask_training import MultiTaskResult


def infer_configuration_pair(
    before: str,
    after: str,
    *,
    vendor: Vendor,
    device_id: UUID,
    model: MultiTaskResult | FoundationTransferResult,
    expected_model_sha256: str,
    pseudonymization_key: bytes,
) -> ConfigurationPairReport:
    def side(content: str) -> ConfigurationInferenceReport:
        return infer_configuration(
            content,
            vendor=vendor,
            device_id=device_id,
            model=model,
            expected_model_sha256=expected_model_sha256,
            pseudonymization_key=pseudonymization_key,
        )

    # Explicit calls preserve each side's source coordinates. The caller loads once.
    old = side(before)
    new = side(after)
    return ConfigurationPairReport(before=old, after=new)
