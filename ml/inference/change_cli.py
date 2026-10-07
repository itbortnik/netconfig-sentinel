"""Private local pre/post diagnostics for a selected trusted model; never an approval."""

from __future__ import annotations

import argparse
import json
import os
import pickle
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from app.explanation.vector_index import RetrievalUnavailable
from app.ingestion.local import read_local_configuration
from app.patching.artifacts import load_patch_review

from ml.inference.change_artifacts import (
    load_ml_change_review,
    safe_path,
    save_ml_change_review,
)
from ml.inference.change_review import review_patch_ml

KEY_ENV = "NETCONFIG_ML_PSEUDONYMIZATION_KEY"

if TYPE_CHECKING:
    from ml.training.foundation_transfer import FoundationTransferResult
    from ml.training.multitask_training import MultiTaskResult


def _native_inventory(path: Path) -> None:
    # Inspect the fixed two-level bundle, never recursively enumerate user directories.
    safe_path(path)
    if not path.is_dir() or {item.name for item in path.iterdir()} != {
        "encoder",
        "heads.json",
        "heads.sha256",
    }:
        raise ValueError("trusted native model inventory differs")
    for item in path.iterdir():
        safe_path(item)
    encoder = path / "encoder"
    if not encoder.is_dir() or {item.name for item in encoder.iterdir()} != {
        "manifest.json",
        "report.json",
        "tokenizer.json",
        "weights.pt",
    }:
        raise ValueError("trusted native encoder inventory differs")
    for item in encoder.iterdir():
        safe_path(item)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for action in ("review", "check"):
        command = commands.add_parser(action)
        command.add_argument("--before", type=Path, required=True)
        command.add_argument("--after", type=Path, required=True)
        command.add_argument("--model", type=Path)
        command.add_argument("--model-sha256")
        command.add_argument("--model-kind", choices=("native", "foundation"), default="native")
        command.add_argument("--foundation-source", type=Path)
        if action == "review":
            command.add_argument("--patch-review", type=Path, required=True)
            command.add_argument("--output", type=Path, required=True)
        else:
            command.add_argument("--artifact", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        for source in (args.before, args.after):
            safe_path(source)
        previous, candidate = (read_local_configuration(path) for path in (args.before, args.after))
        saved = None
        if args.command == "review":
            safe_path(args.patch_review)
            local = load_patch_review(args.patch_review)
        else:
            saved = load_ml_change_review(args.artifact)
            local = saved.local_review
        model: MultiTaskResult | FoundationTransferResult | None = None
        key = None
        if (args.model is None) != (args.model_sha256 is None):
            raise ValueError("model path and independent identity pin must be selected together")
        if args.model is None and (
            args.model_kind != "native" or args.foundation_source is not None
        ):
            raise ValueError("foundation options require explicit model selection")
        if args.model_kind == "native" and args.foundation_source is not None:
            raise ValueError("native selection cannot use an external source")
        if args.model_kind == "foundation" and args.foundation_source is None:
            raise ValueError("foundation selection requires explicit external source")
        if args.model is not None:
            if len(args.model_sha256) != 64 or any(
                value not in "0123456789abcdef" for value in args.model_sha256
            ):
                raise ValueError("invalid independent model identity pin")
            safe_path(args.model)
            raw_key = os.environ.get(KEY_ENV, "")
            if len(raw_key) != 64:
                raise ValueError("configure a private 32-byte hex pseudonymization key")
            key = bytes.fromhex(raw_key)
            if len(key) != 32:
                raise ValueError("invalid private pseudonymization key")
            if args.model_kind == "native":
                _native_inventory(args.model)
                # Native CPU weights_only=True tensor checkpoint, not an untrusted uploader.
                from ml.training.multitask_training import load_multitask

                model = load_multitask(args.model)
            else:
                safe_path(args.foundation_source)
                from ml.training.foundation_transfer import load_foundation_transfer

                model = load_foundation_transfer(
                    args.model,
                    source_root=args.foundation_source,
                    expected_identity=args.model_sha256,
                )
        result = review_patch_ml(
            local,
            previous,
            candidate,
            model=model,
            expected_model_sha256=args.model_sha256,
            pseudonymization_key=key,
        )
        if saved is not None:
            if saved != result:
                raise ValueError("saved numeric diagnostics no longer match exact recomputation")
        else:
            save_ml_change_review(result, args.output)
    except (
        OSError,
        ValueError,
        RuntimeError,
        pickle.UnpicklingError,
        EOFError,
        RecursionError,
        RetrievalUnavailable,
    ):
        print(
            "ML change review refused: check exact private inputs, trusted pinned model, "
            "private key and unused output path.",
            file=sys.stderr,
        )
        return 2
    print(
        json.dumps(
            {
                "version": result.version,
                "proposal_id": str(result.local_review.proposal.proposal_id),
                "review_status": result.status,
                "transformer_status": result.transformer.status,
                "model_sha256": result.transformer.model_sha256,
                "formal_verification": result.formal_verification,
                "applied": result.applied,
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
