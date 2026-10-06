"""Fit calibration separately, then apply the bound artifact without refitting test."""

from __future__ import annotations

import argparse
from pathlib import Path

from pydantic import BaseModel

from ml.evaluation.calibration import CalibrationArtifact, apply_calibration, fit_calibration
from ml.evaluation.cli import load_batch, load_json


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    fit = sub.add_parser("fit")
    fit.add_argument("--input", type=Path, required=True)
    fit.add_argument("--output", type=Path, required=True)
    apply = sub.add_parser("apply")
    apply.add_argument("--input", type=Path, required=True)
    apply.add_argument("--calibration", type=Path, required=True)
    apply.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.output.exists() or args.output.is_symlink():
            raise ValueError("output already exists")
        batch = load_batch(args.input)
        result: BaseModel
        if args.command == "fit":
            result = fit_calibration(batch)
        else:
            artifact = CalibrationArtifact.model_validate(load_json(args.calibration))
            result = apply_calibration(batch, artifact)
        with args.output.open("x", encoding="utf-8") as stream:
            stream.write(result.model_dump_json(indent=2) + "\n")
    except (OSError, ValueError):
        parser.exit(2, "Offline calibration failed: check local support, binding and exposure.\n")
    print("Local calibration artifact written; no refit on test, online-risk or quality claim.")


if __name__ == "__main__":
    main()
