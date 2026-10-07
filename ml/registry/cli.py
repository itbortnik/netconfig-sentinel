"""Explicit private registry commands; no download, HTTP activation or approval."""

from __future__ import annotations

import argparse
import json
import pickle
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from app.explanation.vector_index import RetrievalUnavailable

from ml.inference.change_artifacts import safe_path
from ml.registry.contracts import RegistryManifest
from ml.registry.store import (
    _model_card,
    _pin,
    initialize_registry,
    list_models,
    load_registered_model,
    register_model,
)

if TYPE_CHECKING:
    from ml.training.foundation_transfer import FoundationTransferResult
    from ml.training.multitask_training import MultiTaskResult


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for action in ("init", "list", "register", "check"):
        command = commands.add_parser(action)
        command.add_argument("--root", type=Path, required=True)
        if action in ("register", "check"):
            command.add_argument("--model-sha256", required=True)
            command.add_argument("--foundation-source", type=Path)
        if action == "register":
            command.add_argument("--model", type=Path, required=True)
            command.add_argument("--model-kind", default="native")
    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            initialize_registry(args.root)
            summary: dict[str, object] = {
                "version": RegistryManifest().version,
                "initialized": True,
                "activated": False,
            }
        elif args.command == "list":
            cards = list_models(args.root)
            summary = {
                "version": RegistryManifest().version,
                "models": [card.model_dump(mode="json") for card in cards],
                "binding_rechecked": False,
                "activated": False,
            }
        elif args.command == "check":
            pin = _pin(args.model_sha256)
            checked = load_registered_model(
                args.root, pin, foundation_source=args.foundation_source
            )
            summary = {
                "card": _model_card(checked).model_dump(mode="json"),
                "binding_rechecked": True,
                "activated": False,
            }
        else:
            pin = _pin(args.model_sha256)
            safe_path(args.model)
            if args.model_kind not in ("native", "foundation") or (
                (args.model_kind == "foundation") != (args.foundation_source is not None)
            ):
                raise ValueError("registry source selection differs")
            model: MultiTaskResult | FoundationTransferResult
            if args.model_kind == "native":
                from ml.inference.change_cli import _native_inventory
                from ml.training.multitask_training import load_multitask

                _native_inventory(args.model)
                model = load_multitask(args.model)
            else:
                safe_path(args.foundation_source)
                from ml.training.foundation_transfer import load_foundation_transfer

                model = load_foundation_transfer(
                    args.model, source_root=args.foundation_source, expected_identity=pin
                )
            card = register_model(
                args.root, model, expected_identity=pin, foundation_source=args.foundation_source
            )
            summary = {
                "card": card.model_dump(mode="json"),
                "binding_rechecked": True,
                "activated": False,
            }
    except (
        OSError,
        ValueError,
        RuntimeError,
        ImportError,
        pickle.UnpicklingError,
        EOFError,
        RecursionError,
        RetrievalUnavailable,
    ):
        print(
            "Registry command refused: check private layout, independent pin, trusted source "
            "and new entry.",
            file=sys.stderr,
        )
        return 2
    print(json.dumps(summary, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
