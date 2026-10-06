"""Evaluate bounded local prediction JSON and optionally render reliability SVG."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from pydantic import ValidationError

from ml.evaluation.contracts import COHORTS, EvaluationBatch
from ml.evaluation.metrics import EvaluationReport, evaluate

MAX_JSON_BYTES = 64 * 1024 * 1024


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON keys are not permitted")
        result[key] = value
    return result


def load_json(path: Path) -> object:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_JSON_BYTES:
        raise ValueError("prediction input must be a bounded regular file")
    with path.open("rb") as stream:
        content = stream.read(MAX_JSON_BYTES + 1)
    if len(content) > MAX_JSON_BYTES:
        raise ValueError("prediction input exceeds the byte budget")
    return json.loads(content.decode("utf-8"), object_pairs_hook=_unique_pairs)


def load_batch(path: Path) -> EvaluationBatch:
    return EvaluationBatch.model_validate(load_json(path))


def reliability_svg(report: EvaluationReport) -> str:
    """Fixed labels and numeric coordinates only; never render user-supplied text."""
    parts = [
        '<svg xmlns="http://www.w3.org/2000/svg" width="960" height="380" '
        'viewBox="0 0 960 380" role="img" aria-label="Binary anomaly reliability by origin">',
        '<rect width="960" height="380" fill="white"/>',
    ]
    for index, cohort in enumerate(COHORTS):
        x, y, size = 50 + index * 320, 55, 230
        parts.append(
            f'<text x="{x}" y="30" font-family="sans-serif" font-size="16">{cohort}</text>'
        )
        parts.append(f'<path d="M{x},{y} V{y + size} H{x + size}" stroke="#333" fill="none"/>')
        parts.append(
            f'<path d="M{x},{y + size} L{x + size},{y}" stroke="#777" stroke-dasharray="4"/>'
        )
        summary = report.cohorts[cohort].summary
        calibration = summary.detection.calibration if summary else None
        if calibration is not None and summary is not None:
            points = []
            for bucket in calibration.bins:
                if bucket.mean_probability is not None and bucket.positive_fraction is not None:
                    px, py = (
                        x + size * bucket.mean_probability,
                        y + size * (1 - bucket.positive_fraction),
                    )
                    points.append(f"{px:.3f},{py:.3f}")
                    parts.append(
                        f'<circle cx="{px:.3f}" cy="{py:.3f}" r="4" fill="#1456a1">'
                        f"<title>n={bucket.count}</title></circle>"
                    )
            parts.append(f'<polyline points="{" ".join(points)}" stroke="#1456a1" fill="none"/>')
            note = f"ECE={calibration.ece:.4f}; n={summary.configurations}"
        else:
            note = "missing data" if summary is None else "ranking scores: calibration unavailable"
        parts.append(f'<text x="{x}" y="315" font-family="sans-serif" font-size="12">{note}</text>')
        parts.append(
            f'<text x="{x}" y="338" font-family="sans-serif" font-size="12">'
            "x: predicted probability; y: observed fraction</text>"
        )
    parts.append(
        '<text x="50" y="365" font-family="sans-serif" font-size="13">'
        "Offline annotations only; no production-quality or network-safety attestation."
        "</text></svg>"
    )
    return "\n".join(parts) + "\n"


def write_report(report: EvaluationReport, output: Path, diagram: Path | None = None) -> None:
    if (
        output.exists()
        or output.is_symlink()
        or (
            diagram is not None
            and (diagram.exists() or diagram.is_symlink() or diagram.resolve() == output.resolve())
        )
    ):
        raise ValueError("output targets must be distinct new files")
    if not output.parent.is_dir() or (diagram is not None and not diagram.parent.is_dir()):
        raise ValueError("output parent directories must already exist")
    with output.open("x", encoding="utf-8") as stream:
        stream.write(report.model_dump_json(indent=2) + "\n")
    if diagram is not None:
        with diagram.open("x", encoding="utf-8") as stream:
            stream.write(reliability_svg(report))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--reliability-svg", type=Path)
    args = parser.parse_args()
    try:
        report = evaluate(load_batch(args.input))
        write_report(report, args.output, args.reliability_svg)
    except (OSError, ValueError, ValidationError):
        parser.exit(
            2, "Offline evaluation failed: check local input, exposure and output contracts.\n"
        )
    print("Offline report written; missing cohorts remain missing; no production-quality claim.")


if __name__ == "__main__":
    main()
