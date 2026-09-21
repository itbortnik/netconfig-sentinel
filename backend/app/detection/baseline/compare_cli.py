"""Compare two local configuration files against an explicitly selected reference."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from uuid import UUID

from app.detection.baseline.expected import (
    compare_expected_configuration,
    create_expected_configuration,
)
from app.ingestion.local import MAX_INPUT_BYTES, MAX_INPUT_LINES, read_local_configuration
from app.parsers import parse_configuration


def _read_configuration(path: Path) -> str:
    return read_local_configuration(path, max_bytes=MAX_INPUT_BYTES, max_lines=MAX_INPUT_LINES)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--current", type=Path, required=True)
    parser.add_argument("--device-id", type=UUID, required=True)
    parser.add_argument("--reference-id", required=True)
    args = parser.parse_args(argv)
    try:
        reference_config = parse_configuration(
            _read_configuration(args.reference), filename=args.reference.name
        )
        current_config = parse_configuration(
            _read_configuration(args.current), filename=args.current.name
        )
        reference = create_expected_configuration(
            reference_config, device_id=args.device_id, reference_id=args.reference_id
        )
        findings = compare_expected_configuration(
            current_config, reference, device_id=args.device_id
        )
    except (OSError, ValueError):
        # Parser/validation errors can contain raw configuration values. Do not echo them.
        print(
            "Comparison refused: check readable UTF-8 .cfg/.conf/.txt files, "
            "input limits, fully supported syntax, device identity and reference ID.",
            file=sys.stderr,
        )
        return 2
    report = {
        "version": "expected-comparison-report-0.1.0",
        "device_id": str(args.device_id),
        "reference_id": reference.reference_id,
        "reference_sha256": reference.source_sha256,
        "current_sha256": current_config.source.sha256,
        "status": "differences_found" if findings else "no_supported_differences",
        "finding_count": len(findings),
        "findings": [finding.model_dump(mode="json") for finding in findings],
        "limitations": [
            "Only supported reference facts are compared; this is not a safety verdict.",
            "Reference selection is external; no formal network verification was run.",
            "Report values may contain sensitive network addressing; keep output private.",
        ],
    }
    print(json.dumps(report, indent=2, ensure_ascii=True))
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
