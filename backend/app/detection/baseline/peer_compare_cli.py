"""Compare explicitly selected local peers using an explicit versioned detector."""

from __future__ import annotations

import argparse
import json
import math
import sys
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from app.detection.baseline.peer_v2 import (
    build_expanded_peer_baseline,
    evaluate_expanded_peer_baseline,
)
from app.detection.baseline.peer_v3 import (
    build_measured_peer_baseline,
    evaluate_measured_peer_baseline,
)
from app.domain import CanonicalConfig
from app.ingestion.local import MAX_INPUT_BYTES, MAX_INPUT_LINES, read_local_configuration
from app.parsers import parse_configuration
from app.parsers.coverage import ParsedConfiguration, parse_configuration_with_coverage


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--peer", type=Path, action="append", required=True)
    parser.add_argument("--current", type=Path, required=True)
    parser.add_argument("--device-id", type=UUID, required=True)
    parser.add_argument("--device-role", required=True)
    parser.add_argument("--site-class", required=True)
    parser.add_argument("--service-profile", required=True)
    parser.add_argument("--collected-at")
    parser.add_argument("--comparison-version", choices=["0.2.0", "0.3.0"], default="0.2.0")
    parser.add_argument("--consensus-threshold", type=float, default=0.75)
    parser.add_argument("--unsupported-ratio-tolerance", type=float)
    parser.add_argument("--unparsed-fraction-tolerance", type=float)
    args = parser.parse_args(argv)
    try:
        if not 3 <= len(args.peer) <= 20:
            raise ValueError("invalid peer count")
        if not math.isfinite(args.consensus_threshold) or not 0.5 < args.consensus_threshold <= 1:
            raise ValueError("invalid consensus threshold")
        measured = args.comparison_version == "0.3.0"
        if (measured and args.unsupported_ratio_tolerance is not None) or (
            not measured and args.unparsed_fraction_tolerance is not None
        ):
            raise ValueError("tolerance flag belongs to a different detector version")
        tolerance = (
            args.unparsed_fraction_tolerance if measured else args.unsupported_ratio_tolerance
        )
        tolerance = 0.05 if tolerance is None else tolerance
        if not math.isfinite(tolerance) or not 0 <= tolerance <= 1:
            raise ValueError("invalid finite comparison tolerance")
        labels = (args.device_role, args.site_class, args.service_profile)
        if any(
            not value or len(value) > 64 or not value.isprintable() or value != value.strip()
            for value in labels
        ):
            raise ValueError("invalid explicit inventory labels")
        collected_at = (
            datetime.now(UTC)
            if args.collected_at is None
            else datetime.fromisoformat(args.collected_at)
        )
        if collected_at.utcoffset() is None:
            raise ValueError("declared collection time requires a timezone")

        def content(path: Path) -> str:
            return read_local_configuration(
                path, max_bytes=MAX_INPUT_BYTES, max_lines=MAX_INPUT_LINES
            )

        def read(path: Path) -> CanonicalConfig:
            config = parse_configuration(
                content(path), filename=path.name, collected_at=collected_at
            )
            config.device.role, config.device.site_class, config.device.service_profile = labels
            return config

        def read_measured(path: Path) -> ParsedConfiguration:
            parsed = parse_configuration_with_coverage(
                content(path), filename=path.name, collected_at=collected_at
            )
            device = parsed.canonical.device
            device.role, device.site_class, device.service_profile = labels
            return parsed

        if measured:
            measured_baseline = build_measured_peer_baseline(
                [read_measured(path) for path in args.peer],
                consensus_threshold=args.consensus_threshold,
                unparsed_fraction_tolerance=tolerance,
            )
            measured_report = evaluate_measured_peer_baseline(
                read_measured(args.current), measured_baseline, device_id=args.device_id
            )
            baseline_wire = measured_baseline.model_dump(mode="json")
            evaluation_wire = measured_report.model_dump(mode="json")
            status, found = measured_report.status, bool(measured_report.findings)
        else:
            baseline = build_expanded_peer_baseline(
                [read(path) for path in args.peer],
                consensus_threshold=args.consensus_threshold,
                unsupported_ratio_tolerance=tolerance,
            )
            evaluation = evaluate_expanded_peer_baseline(
                read(args.current), baseline, device_id=args.device_id
            )
            baseline_wire = baseline.model_dump(mode="json")
            evaluation_wire = evaluation.model_dump(mode="json")
            status, found = evaluation.status, bool(evaluation.findings)
    except (OSError, ValueError):
        # Neither parser diagnostics nor file names or uploaded values are error output.
        print(
            "Peer comparison refused: check bounded UTF-8 text inputs, 3-20 completely "
            "parsed distinct peers, matching vendor/platform, explicit labels "
            "and finite thresholds.",
            file=sys.stderr,
        )
        return 2
    report = {
        "version": f"peer-comparison-cli-{args.comparison_version}",
        "baseline": baseline_wire,
        "evaluation": evaluation_wire,
        "collection_time_basis": "current_run"
        if args.collected_at is None
        else "explicit_argument",
        "device_collection_time_verified": False,
        "security_baseline_approved": False,
        "network_safety_verified": False,
        "configuration_applied": False,
        "limitations": [
            "All inventory labels and collection dates are caller declarations, "
            "not verified device history.",
            "This command does not run policy, ML, formal checks or contact network devices.",
            "Report values may contain sensitive addressing and account metadata; "
            "keep output private.",
            "Without --collected-at the current local run time is used, "
            "not file modification time.",
        ],
    }
    print(json.dumps(report, indent=2, ensure_ascii=True, allow_nan=False))
    if status == "partial":
        return 3
    return 1 if found else 0


if __name__ == "__main__":
    raise SystemExit(main())
