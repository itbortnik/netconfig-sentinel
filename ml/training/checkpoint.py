"""Non-overwriting model bundles with explicit checksums and tensor-only load."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import torch

from ml.preprocessing.tokenization import load_tokenizer, save_tokenizer
from ml.training.transformer import ConfigEncoderMLM, TrainingReport, TrainingResult

CHECKPOINT_VERSION = "config-mlm-checkpoint-0.1.0"
_FILES = {"weights.pt", "tokenizer.json", "report.json"}


def save_checkpoint(result: TrainingResult, path: Path) -> None:
    """Save best validation weights for inference; optimizer resume is not supported."""
    path.mkdir(exist_ok=False)
    marker = path / ".incomplete"
    marker.write_text("incomplete\n", encoding="utf-8")
    save_tokenizer(result.tokenizer, path / "tokenizer.json")
    (path / "report.json").write_text(result.report.model_dump_json(), encoding="utf-8")
    with (path / "weights.pt").open("xb") as target:
        torch.save(result.model.state_dict(), target)
    manifest = {
        "version": CHECKPOINT_VERSION,
        "files": {name: _file_hash(path / name) for name in sorted(_FILES)},
    }
    (path / "manifest.json").write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
    marker.unlink()


def load_checkpoint(path: Path) -> TrainingResult:
    """Verify file inventory before loading a local state_dict on CPU."""
    if path.is_symlink() or not path.is_dir():
        raise ValueError("checkpoint directory is missing or unsafe")
    if {item.name for item in path.iterdir()} != _FILES | {"manifest.json"}:
        raise ValueError("checkpoint incomplete or file inventory differs")
    for item in path.iterdir():
        if item.is_symlink() or not item.is_file():
            raise ValueError("checkpoint contains an unsafe file")
        limit = 512 * 1024 * 1024 if item.name == "weights.pt" else 16 * 1024 * 1024
        if item.stat().st_size > limit:
            raise ValueError("checkpoint file exceeds size limit")
    manifest = json.loads((path / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("version") != CHECKPOINT_VERSION or set(manifest.get("files", {})) != _FILES:
        raise ValueError("unsupported checkpoint manifest")
    if any(_file_hash(path / name) != manifest["files"][name] for name in _FILES):
        raise ValueError("checkpoint checksum mismatch")
    tokenizer = load_tokenizer(path / "tokenizer.json")
    report = TrainingReport.model_validate_json((path / "report.json").read_bytes())
    if report.tokenizer_sha256 != tokenizer.tokenizer_sha256:
        raise ValueError("checkpoint tokenizer does not match training report")
    if report.training_fingerprint != tokenizer.training_fingerprint:
        raise ValueError("checkpoint training corpus does not match tokenizer")
    with torch.random.fork_rng(devices=[]):
        model = ConfigEncoderMLM(
            tokenizer.actual_vocab_size,
            tokenizer.policy.context_length,
            report.encoder_policy,
        )
    if sum(parameter.numel() for parameter in model.parameters()) != report.parameter_count:
        raise ValueError("checkpoint parameter count mismatch")
    state = torch.load(path / "weights.pt", map_location="cpu", weights_only=True)
    model.load_state_dict(state, strict=True)
    if any(not torch.isfinite(value).all() for value in model.state_dict().values()):
        raise ValueError("checkpoint contains non-finite weights")
    model.eval()
    return TrainingResult(model, tokenizer, report)


def _file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()
