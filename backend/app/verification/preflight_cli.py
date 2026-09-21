"""Run a local pre-change review without applying or formally validating changes."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from uuid import UUID

from app.ingestion.local import read_local_configuration
from app.parsers import parse_configuration
from app.verification.preflight import review_configuration_change


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--before", type=Path, required=True)
    parser.add_argument("--after", type=Path, required=True)
    parser.add_argument("--device-id", type=UUID, required=True)
    parser.add_argument("--reference-id", required=True)
    args = parser.parse_args(argv)
    try:
        before = parse_configuration(
            read_local_configuration(args.before), filename=args.before.name
        )
        after = parse_configuration(read_local_configuration(args.after), filename=args.after.name)
        report = review_configuration_change(
            before, after, device_id=args.device_id, reference_id=args.reference_id
        )
    except (OSError, ValueError):
        print(
            "Preflight refused: check readable bounded UTF-8 configuration files, "
            "supported vendor, matching device identity and a nonempty reference ID.",
            file=sys.stderr,
        )
        return 2
    print(report.model_dump_json(indent=2))
    if report.policy_changes is None or report.reference_status != "completed":
        return 3
    if (
        report.after_policy_findings
        or report.reference_findings
        or report.policy_changes.resolved
        or report.policy_changes.introduced
    ):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
