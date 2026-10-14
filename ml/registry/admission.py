"""Bounded private fixture source/downstream inputs for explicit registry admission."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from pydantic import Field

from ml.datasets import DatasetFixtureManifest, DatasetSplitResult, ImportedDatasetFixtureRecord
from ml.datasets.fixture_training import prepare_fixture_training_corpus
from ml.datasets.models import ImportedDatasetRecord
from ml.evaluation.contracts import Digest, Frozen
from ml.inference.change_artifacts import safe_path
from ml.registry.store import FixtureAdmissionContext
from ml.training.fixture_pretraining_cli import _read_json
from ml.training.multitask_training import (
    FIXTURE_REPORTS,
    MultiTaskResult,
    SupervisedAnnotation,
    SupervisedExample,
    _verified_report,
)
from ml.training.pretraining import FixturePretrainingResult

if TYPE_CHECKING:
    from ml.training.foundation_transfer import FoundationTransferResult


class AdmissionExample(Frozen):
    record: ImportedDatasetRecord
    parent_sha256: Digest
    annotation: SupervisedAnnotation


class FixtureAdmissionInput(Frozen):
    version: str = Field(
        default="fixture-registry-input-0.1.0", pattern=r"^fixture-registry-input-0\.1\.0$"
    )
    manifest: DatasetFixtureManifest
    records: tuple[ImportedDatasetFixtureRecord, ...] = Field(min_length=1, max_length=2048)
    splits: DatasetSplitResult
    examples: tuple[AdmissionExample, ...] = Field(min_length=2, max_length=512)


def load_fixture_admission(
    path: Path,
    model: MultiTaskResult | FoundationTransferResult,
) -> FixtureAdmissionContext:
    if (
        not isinstance(model, MultiTaskResult)
        or not isinstance(model.pretrained, FixturePretrainingResult)
        or not isinstance(_verified_report(model), FIXTURE_REPORTS)
    ):
        raise ValueError("fixture admission input requires an explicit fixture transfer model")
    safe_path(path)
    data = FixtureAdmissionInput.model_validate(_read_json(path, 64 * 1024 * 1024))
    corpus = prepare_fixture_training_corpus(
        data.manifest, data.records, policy=model.pretrained.report.corpus.policy
    )
    return FixtureAdmissionContext(
        corpus,
        data.splits,
        tuple(
            SupervisedExample(row.record, row.parent_sha256, row.annotation)
            for row in data.examples
        ),
    )
