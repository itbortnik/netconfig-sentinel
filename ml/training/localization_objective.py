"""Explicit train-fitted line objective, separate from historical task weights/policies."""

from __future__ import annotations

import torch
from torch import Tensor

from ml.training.localization_contracts import (
    FittedLocalizationObjective as FittedLocalizationObjective,
)
from ml.training.localization_contracts import (
    TrainBalancedLocalization as TrainBalancedLocalization,
)
from ml.training.multitask import IGNORE_TARGET


def fit_localization_objective(
    targets: Tensor, train_fingerprint: str, policy: TrainBalancedLocalization
) -> FittedLocalizationObjective:
    """Count aligned TRAIN labels only; ignore unreviewed/deleted/ignored lines."""
    policy = TrainBalancedLocalization.model_validate(policy.model_dump())
    if (
        targets.ndim != 1
        or not bool(torch.isfinite(targets).all())
        or not bool(((targets == 0) | (targets == 1) | (targets == IGNORE_TARGET)).all())
    ):
        raise ValueError("localization balance requires aligned binary/ignored train targets")
    positive, negative = int((targets == 1).sum()), int((targets == 0).sum())
    if not positive or not negative:
        raise ValueError("train-balanced localization requires both train line classes")
    return FittedLocalizationObjective(
        policy=policy,
        train_fingerprint=train_fingerprint,
        positive_lines=positive,
        negative_lines=negative,
        eligible_lines=positive + negative,
        positive_weight=negative / positive,
    )
