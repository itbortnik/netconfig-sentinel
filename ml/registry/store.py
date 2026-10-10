"""New-only fixed-layout bundles; every selected load rechecks the independent pin."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

from ml.evaluation.cli import _unique_pairs
from ml.evaluation.metrics import canonical_hash
from ml.inference.change_artifacts import safe_path
from ml.registry.contracts import EntryEnvelope, ModelCard, RegistryManifest

if TYPE_CHECKING:
    from ml.training.foundation_transfer import FoundationTransferReport, FoundationTransferResult
    from ml.training.multitask_training import (
        MultiTaskFixtureTransferReport,
        MultiTaskReport,
        MultiTaskResult,
        MultiTaskTransferReport,
    )

MAX_ENTRIES = 256
MAX_METADATA_BYTES = 64 * 1024


def _pin(value: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ValueError("registry selection needs an independent full identity")
    return value


def _children(path: Path, limit: int) -> tuple[Path, ...]:
    safe_path(path)
    if not path.is_dir():
        raise ValueError("registry directory is unavailable")
    items: list[Path] = []
    for item in path.iterdir():
        if len(items) >= limit:
            raise ValueError("registry inventory exceeds budget")
        safe_path(item)
        items.append(item)
    return tuple(items)


def _read(path: Path) -> Any:
    safe_path(path)
    if not path.is_file() or path.stat().st_size > MAX_METADATA_BYTES:
        raise ValueError("registry metadata is not a bounded regular file")
    with path.open("rb") as stream:
        raw = stream.read(MAX_METADATA_BYTES + 1)
    if len(raw) > MAX_METADATA_BYTES:
        raise ValueError("registry metadata grew beyond budget")
    return json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs)


def _write(path: Path, content: str) -> None:
    safe_path(path)
    if len((content + "\n").encode("utf-8")) > MAX_METADATA_BYTES:
        raise ValueError("registry metadata exceeds budget")
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(content + "\n")


def initialize_registry(root: Path) -> None:
    safe_path(root)
    if not root.parent.is_dir():
        raise ValueError("registry needs an existing private parent directory")
    root.mkdir(exist_ok=False)
    _write(root / "registry.json", RegistryManifest().model_dump_json(indent=2))


def _entries(root: Path) -> tuple[Path, ...]:
    children = _children(root, MAX_ENTRIES + 1)
    RegistryManifest.model_validate(_read(root / "registry.json"))
    entries = []
    for item in children:
        if item.name == "registry.json":
            continue
        _pin(item.name)
        if not item.is_dir():
            raise ValueError("registry contains an unexpected file")
        entries.append(item)
    return tuple(sorted(entries, key=lambda item: item.name))


def _entry(path: Path) -> ModelCard:
    if {item.name for item in _children(path, 3)} != {"entry.json", "bundle"}:
        raise ValueError("registry entry inventory is incomplete or unsafe")
    envelope = EntryEnvelope.model_validate(_read(path / "entry.json"))
    if envelope.card.model_sha256 != _pin(path.name):
        raise ValueError("registry card does not match selected directory identity")
    bundle = path / "bundle"
    names = {item.name for item in _children(bundle, 3)}
    expected = {"heads.json", "heads.sha256"}
    if envelope.card.kind == "native":
        expected.add("encoder")
        encoder_files = _children(bundle / "encoder", 4)
        if {item.name for item in encoder_files} != {
            "manifest.json",
            "report.json",
            "tokenizer.json",
            "weights.pt",
        } or any(not item.is_file() for item in encoder_files):
            raise ValueError("registry native encoder inventory differs")
    if names != expected:
        raise ValueError("registry bundle inventory differs")
    for item in bundle.iterdir():
        if item.name != "encoder" and not item.is_file():
            raise ValueError("registry bundle has an unexpected directory")
    return envelope.card


def list_models(root: Path) -> tuple[ModelCard, ...]:
    """Metadata/inventory only: not inference, weight authentication or activation."""
    return tuple(_entry(path) for path in _entries(root))


def _model_card(model: MultiTaskResult | FoundationTransferResult) -> ModelCard:
    from ml.training.multitask_training import (
        MultiTaskFixtureTransferReport,
        MultiTaskResult,
        MultiTaskTransferReport,
        _verified_report,
        multitask_identity,
    )

    report: (
        MultiTaskReport
        | MultiTaskTransferReport
        | MultiTaskFixtureTransferReport
        | FoundationTransferReport
    )
    kind: Literal["native", "foundation"]
    if isinstance(model, MultiTaskResult):
        report = _verified_report(model)
        if isinstance(report, MultiTaskFixtureTransferReport):
            raise ValueError(
                "fixture-backed transfer is offline-only; registry admission is not supported"
            )
        identity = multitask_identity(model)
        manifest = (
            report.pretraining.source_manifest_sha256
            if isinstance(report, MultiTaskTransferReport)
            else None
        )
        kind = "native"
    else:
        from ml.training.foundation_transfer import (
            FoundationTransferResult,
            foundation_transfer_identity,
            verify_transfer,
        )

        if not isinstance(model, FoundationTransferResult):
            raise ValueError("registry model kind is unsupported")
        foundation_report = verify_transfer(model)
        report = foundation_report
        identity = foundation_transfer_identity(model)
        manifest = foundation_report.source_manifest_sha256
        kind = "foundation"
    return ModelCard(
        kind=kind,
        model_sha256=identity,
        training_format=report.version,
        report_sha256=canonical_hash(report.model_dump(mode="json")),
        encoder_sha256=report.encoder_sha256,
        tokenizer_sha256=report.tokenizer_sha256,
        source_manifest_sha256=manifest,
        train_fingerprint=report.train_fingerprint,
        selection_fingerprint=report.validation_fingerprint,
        classes=report.head_policy.classes,
        enabled_heads={
            name: weight > 0 for name, weight in report.loss_weights.model_dump().items()
        },
        parameter_count=report.parameter_count,
        trainable_parameters=report.trainable_parameters,
        train_examples=report.train_examples,
        selection_examples=report.validation_examples,
        target_semantics=report.target_semantics,
        external_pretraining_exposure="unknown" if kind == "foundation" else "not_applicable",
    )


def register_model(
    root: Path,
    model: MultiTaskResult | FoundationTransferResult,
    *,
    expected_identity: str,
    foundation_source: Path | None = None,
) -> ModelCard:
    pin = _pin(expected_identity)
    entries = _entries(root)
    path = root / pin
    if path.exists():
        raise FileExistsError("registry entry already exists")
    if len(entries) >= MAX_ENTRIES:
        raise ValueError("registry admission budget exceeded")
    card = _model_card(model)
    if card.model_sha256 != pin or (card.kind == "foundation") != (foundation_source is not None):
        raise ValueError("registry independent pin or explicit source selection differs")
    if foundation_source is not None:
        safe_path(foundation_source)
    path.mkdir(exist_ok=False)
    marker = path / ".incomplete"
    _write(marker, "registry enrollment writing")
    if card.kind == "native":
        from ml.training.multitask_training import MultiTaskResult, save_multitask

        if not isinstance(model, MultiTaskResult):
            raise ValueError("native registry model differs")
        save_multitask(model, path / "bundle")
    else:
        from ml.training.foundation_transfer import (
            FoundationTransferResult,
            save_foundation_transfer,
        )

        if not isinstance(model, FoundationTransferResult):
            raise ValueError("foundation registry model differs")
        save_foundation_transfer(model, path / "bundle")
    # Decode the serialized bundle again and bind a fresh card before committing entry.
    restored = _load_bundle(path / "bundle", card.kind, pin, foundation_source)
    if _model_card(restored) != card:
        raise ValueError("serialized registry card differs from the selected model")
    _write(
        path / "entry.json",
        EntryEnvelope(
            card=card, sha256=canonical_hash(card.model_dump(mode="json"))
        ).model_dump_json(indent=2),
    )
    marker.unlink()
    return card


def _load_bundle(
    bundle: Path, kind: str, pin: str, foundation_source: Path | None
) -> MultiTaskResult | FoundationTransferResult:
    if kind == "native":
        if foundation_source is not None:
            raise ValueError("native registry selection cannot use external source")
        from ml.inference.change_cli import _native_inventory
        from ml.training.multitask_training import load_multitask, multitask_identity

        _native_inventory(bundle)
        native = load_multitask(bundle)
        if multitask_identity(native) != pin:
            raise ValueError("registered native independent identity differs")
        return native
    if kind != "foundation" or foundation_source is None:
        raise ValueError("external registry selection needs explicit trusted publisher source")
    safe_path(foundation_source)
    from ml.training.foundation_transfer import load_foundation_transfer

    return load_foundation_transfer(bundle, source_root=foundation_source, expected_identity=pin)


def load_registered_model(
    root: Path, expected_identity: str, *, foundation_source: Path | None = None
) -> MultiTaskResult | FoundationTransferResult:
    pin = _pin(expected_identity)
    if root / pin not in _entries(root):
        raise ValueError("selected registry entry is unavailable")
    card = _entry(root / pin)
    model = _load_bundle(root / pin / "bundle", card.kind, pin, foundation_source)
    if _model_card(model) != card:
        raise ValueError("registered metadata differs from the freshly verified model")
    return model
