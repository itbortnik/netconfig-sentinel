"""Offline fixture intake -> audited BPE -> fixed-epoch objectives -> verified bundle."""

from __future__ import annotations

import argparse
import json
import time
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from ml.datasets.fixture_training import FixtureTrainingPolicy, prepare_fixture_training_corpus
from ml.datasets.importer import load_dataset_fixture_manifest
from ml.datasets.models import ImportedDatasetFixtureRecord
from ml.evaluation.cli import _unique_pairs
from ml.evaluation.metrics import canonical_hash
from ml.preprocessing.tokenization import TokenizerPolicy, train_fixture_tokenizer
from ml.training.checkpoint import _file_hash
from ml.training.pretraining import (
    PretrainingPolicy,
    load_fixture_pretraining,
    pretraining_identity,
    save_pretraining,
    train_fixture_objectives,
)
from ml.training.pretraining_data import PretrainingWeights
from ml.training.transformer import EncoderPolicy


class FixturePretrainingProtocol(BaseModel):
    """Operator-declared experiment, not a human-review or independent quality attestation."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    corpus: FixtureTrainingPolicy = Field(default_factory=FixtureTrainingPolicy)
    tokenizer: TokenizerPolicy = Field(default_factory=TokenizerPolicy)
    encoder: EncoderPolicy = Field(default_factory=EncoderPolicy)
    training: PretrainingPolicy = Field(default_factory=lambda: PretrainingPolicy(max_records=512))
    weights: PretrainingWeights = Field(
        default_factory=lambda: PretrainingWeights(
            replaced_line=0,
            same_device=0,
            cross_vendor=0,
        )
    )


def _read_json(path: Path, max_bytes: int) -> object:
    if path.is_symlink() or not path.is_file():
        raise ValueError("unsafe fixture training input")
    with path.open("rb") as stream:
        body = stream.read(max_bytes + 1)
    if len(body) > max_bytes:
        raise ValueError("fixture training input size limit exceeded")
    return json.loads(body, object_pairs_hook=_unique_pairs)


def run_fixture_pretraining(
    manifest_path: Path,
    records_path: Path,
    protocol_path: Path,
    output: Path,
) -> dict[str, object]:
    """Never truncate records, change permissions or synthesize a held-out partition."""
    protocol = FixturePretrainingProtocol.model_validate(_read_json(protocol_path, 1024 * 1024))
    manifest = load_dataset_fixture_manifest(manifest_path)
    payload = _read_json(records_path, 64 * 1024 * 1024)
    if not isinstance(payload, list) or not 1 <= len(payload) <= protocol.corpus.max_records:
        raise ValueError("fixture training records must be a complete bounded list")
    records = tuple(ImportedDatasetFixtureRecord.model_validate(row) for row in payload)
    # Validation and corpus review happen before creation of any output directory.
    corpus = prepare_fixture_training_corpus(manifest, records, policy=protocol.corpus)
    if (
        protocol.weights.replaced_line
        or protocol.weights.same_device
        or protocol.weights.cross_vendor
    ):
        raise ValueError("fixture protocol enables unsupported identity/semantic objectives")
    output.mkdir(exist_ok=False)
    marker = output / ".incomplete"
    marker.write_text("fixture pretraining running\n", encoding="utf-8")
    # Written before BPE/optimization: no post-hoc epoch/weight selection on source fixtures.
    frozen = protocol.model_dump(mode="json")
    (output / "protocol.json").write_text(json.dumps(frozen, sort_keys=True), encoding="utf-8")
    started = datetime.now(UTC)
    clock = time.monotonic()
    tokenizer = train_fixture_tokenizer(corpus, policy=protocol.tokenizer)
    result = train_fixture_objectives(
        corpus,
        tokenizer,
        encoder_policy=protocol.encoder,
        training_policy=protocol.training,
        weights=protocol.weights,
    )
    save_pretraining(result, output / "bundle")
    restored = load_fixture_pretraining(output / "bundle")
    identity = pretraining_identity(result)
    if identity != pretraining_identity(restored) or result.report != restored.report:
        raise ValueError("fixture pretraining saved bundle differs from memory")
    evidence: dict[str, object] = {
        "version": "fixture-pretraining-run-0.1.0",
        "started_at": started.isoformat(),
        "completed_at": datetime.now(UTC).isoformat(),
        "wall_seconds": time.monotonic() - clock,
        "declared_protocol_sha256": canonical_hash(frozen),
        "bound_protocol_sha256": result.report.protocol_sha256,
        "model_identity": identity,
        "manifest_file_sha256": _file_hash(manifest_path),
        "records_file_sha256": _file_hash(records_path),
        "protocol_file_sha256": _file_hash(protocol_path),
        "bundle_file_sha256": {
            item.name: _file_hash(item) for item in (output / "bundle").iterdir()
        },
        "input_count": corpus.audit.input_count,
        "unique_count": corpus.audit.unique_count,
        "training_count": corpus.audit.training_count,
        "block_count": corpus.audit.block_count,
        "structural_hold_count": len(corpus.audit.exclusions),
        "train_windows": result.report.train_windows,
        "target_counts": result.report.train_counts,
        "selected_epoch": result.report.selected_epoch,
        "bundle_round_trip_verified": True,
        "validation_metrics": None,
        "test_metrics": None,
        "independent_quality_proven": False,
        "online_activated": False,
    }
    (output / "run.json").write_text(json.dumps(evidence, sort_keys=True), encoding="utf-8")
    marker.unlink()
    return evidence


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--records", type=Path, required=True)
    parser.add_argument("--protocol", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        evidence = run_fixture_pretraining(args.manifest, args.records, args.protocol, args.output)
    except (ValueError, OSError, RuntimeError):
        # Input/config/model exceptions can include private text; never echo them in the CLI.
        parser.exit(1, "Fixture pretraining failed; inspect trusted local inputs/output state.\n")
    print(json.dumps(evidence, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
