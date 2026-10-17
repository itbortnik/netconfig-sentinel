"""Fit calibration separately, then apply the bound artifact without refitting test."""

from __future__ import annotations

import argparse
from pathlib import Path

from pydantic import BaseModel

from ml.evaluation.calibration import CalibrationArtifact, apply_calibration, fit_calibration
from ml.evaluation.cli import load_batch, load_json, load_severity_batch
from ml.evaluation.severity import (
    SeverityCalibrationArtifact,
    apply_severity_calibration,
    fit_severity_calibration,
)


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
    severity_fit = sub.add_parser("fit-severity")
    severity_fit.add_argument("--input", type=Path, required=True)
    severity_fit.add_argument("--output", type=Path, required=True)
    severity_apply = sub.add_parser("apply-severity")
    severity_apply.add_argument("--input", type=Path, required=True)
    severity_apply.add_argument("--calibration", type=Path, required=True)
    severity_apply.add_argument("--calibration-input", type=Path, required=True)
    severity_apply.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.output.exists() or args.output.is_symlink():
            raise ValueError("output already exists")
        result: BaseModel
        if args.command == "fit-severity":
            result = fit_severity_calibration(load_severity_batch(args.input))
        elif args.command == "apply-severity":
            raw = load_json(args.calibration)
            if not isinstance(raw, dict) or raw.get("version") != "severity-calibration-0.1.0":
                raise ValueError("explicit severity artifact version is required")
            result = apply_severity_calibration(
                load_severity_batch(args.input),
                SeverityCalibrationArtifact.model_validate(raw),
                calibration_input=load_severity_batch(args.calibration_input),
            )
        elif args.command == "fit":
            result = fit_calibration(load_batch(args.input))
        else:
            artifact = CalibrationArtifact.model_validate(load_json(args.calibration))
            result = apply_calibration(load_batch(args.input), artifact)
        with args.output.open("x", encoding="utf-8") as stream:
            stream.write(result.model_dump_json(indent=2) + "\n")
    except (OSError, ValueError, RecursionError):
        parser.exit(2, "Offline calibration failed: check local support, binding and exposure.\n")
    print("Local calibration artifact written; no refit on test, online-risk or quality claim.")


if __name__ == "__main__":
    main()
