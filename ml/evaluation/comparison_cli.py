"""Bounded offline paired anomaly comparison; no model loading or online mutation."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ml.evaluation.cli import MAX_JSON_BYTES, _unique_pairs
from ml.evaluation.comparison import ComparisonInput, compare_detectors


def safe_path(path: Path) -> None:
    selected = path.absolute()
    if any(item.is_symlink() or item.is_junction() for item in (selected, *selected.parents)):
        raise ValueError("linked comparison path")


def load_comparison(path: Path) -> ComparisonInput:
    safe_path(path)
    if not path.is_file() or path.stat().st_size > MAX_JSON_BYTES:
        raise ValueError("comparison input exceeds budget or is not regular")
    with path.open("rb") as stream:
        raw = stream.read(MAX_JSON_BYTES + 1)
    if len(raw) > MAX_JSON_BYTES:
        raise ValueError("comparison input grew beyond budget")
    return ComparisonInput.model_validate(
        json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs)
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        safe_path(args.output)
        if args.output.suffix.lower() != ".json" or not args.output.parent.is_dir():
            raise ValueError("comparison output requires existing parent and JSON suffix")
        report = compare_detectors(load_comparison(args.input))
        encoded = report.model_dump_json(indent=2) + "\n"
        if len(encoded.encode("utf-8")) > MAX_JSON_BYTES:
            raise ValueError("comparison output exceeds budget")
        with args.output.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(encoded)
    except (OSError, ValueError, RecursionError):
        print(
            "Comparison refused: check reviewed shared cases, exposure and unused output.",
            file=sys.stderr,
        )
        return 2
    print(
        json.dumps(
            {
                "version": report.version,
                "models": len(report.models),
                "purpose": report.purpose,
                "input_sha256": report.input_sha256,
                "production_quality_proven": False,
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
