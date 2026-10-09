"""Compare explicitly selected local peers using the opt-in 0.2.0 detector."""

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
from app.domain import CanonicalConfig
from app.ingestion.local import MAX_INPUT_BYTES, MAX_INPUT_LINES, read_local_configuration
from app.parsers import parse_configuration


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--peer", type=Path, action="append", required=True)
    parser.add_argument("--current", type=Path, required=True)
    parser.add_argument("--device-id", type=UUID, required=True)
    parser.add_argument("--device-role", required=True)
    parser.add_argument("--site-class", required=True)
    parser.add_argument("--service-profile", required=True)
    parser.add_argument("--collected-at")
    parser.add_argument("--consensus-threshold", type=float, default=0.75)
    parser.add_argument("--unsupported-ratio-tolerance", type=float, default=0.05)
    args = parser.parse_args(argv)
    try:
        if not 3 <= len(args.peer) <= 20:
            raise ValueError("invalid peer count")
        if not math.isfinite(args.consensus_threshold) or not 0.5 < args.consensus_threshold <= 1:
            raise ValueError("invalid consensus threshold")
        if not math.isfinite(args.unsupported_ratio_tolerance) or (
            not 0 <= args.unsupported_ratio_tolerance <= 1
        ):
            raise ValueError("invalid parser-confidence tolerance")
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

        def read(path: Path) -> CanonicalConfig:
            content = read_local_configuration(
                path, max_bytes=MAX_INPUT_BYTES, max_lines=MAX_INPUT_LINES
            )
            config = parse_configuration(content, filename=path.name, collected_at=collected_at)
            config.device.role, config.device.site_class, config.device.service_profile = labels
            return config

        baseline = build_expanded_peer_baseline(
            [read(path) for path in args.peer],
            consensus_threshold=args.consensus_threshold,
            unsupported_ratio_tolerance=args.unsupported_ratio_tolerance,
        )
        evaluation = evaluate_expanded_peer_baseline(
            read(args.current), baseline, device_id=args.device_id
        )
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
        "version": "peer-comparison-cli-0.2.0",
        "baseline": baseline.model_dump(mode="json"),
        "evaluation": evaluation.model_dump(mode="json"),
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
    if evaluation.status == "partial":
        return 3
    return 1 if evaluation.findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
