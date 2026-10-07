"""Explicit local native drafts/checks; no apply, approve, commit or device connection."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from uuid import UUID

from app.detection.policy_engine import evaluate_policies
from app.ingestion.local import read_local_configuration
from app.parsers import parse_configuration
from app.patching.vendor_artifacts import recheck_vendor_draft, save_vendor_draft
from app.patching.vendor_drafts import create_vendor_draft


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    create = subparsers.add_parser("generate")
    create.add_argument("--before", type=Path, required=True)
    create.add_argument("--device-id", type=UUID, required=True)
    create.add_argument("--reference-id", required=True)
    create.add_argument("--source-sha256", required=True)
    create.add_argument(
        "--category",
        choices=("management.telnet_enabled", "management.ssh_version_1"),
        required=True,
    )
    create.add_argument("--output", type=Path, required=True)
    check = subparsers.add_parser("check")
    check.add_argument("--before", type=Path, required=True)
    check.add_argument("--artifact", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "generate":
            before = read_local_configuration(args.before)
            parsed = parse_configuration(before, filename="before.cfg")
            selected = next(
                (
                    row
                    for row in evaluate_policies(parsed, device_id=args.device_id)
                    if row.category == args.category
                ),
                None,
            )
            if selected is None:
                raise ValueError("selected policy finding is unavailable")
            generated = create_vendor_draft(
                before,
                finding=selected,
                source_sha256=args.source_sha256,
                reference_id=args.reference_id,
            )
            save_vendor_draft(generated, args.output, before=before)
        else:
            generated = recheck_vendor_draft(args.artifact, args.before)
    except (OSError, ValueError):
        print(
            "Vendor draft refused: check trusted unchanged inputs, supported exact syntax, "
            "artifact integrity and unused output directory. No change was applied.",
            file=sys.stderr,
        )
        return 2
    metadata = generated.metadata
    print(
        json.dumps(
            {
                "operation": args.command,
                "proposal_id": str(metadata.review.proposal.proposal_id),
                "report_id": str(metadata.review.preflight.report_id),
                "category": metadata.category,
                "before_sha256": metadata.review.proposal.before_sha256,
                "after_sha256": metadata.review.proposal.after_sha256,
                "status": metadata.review.status,
                "formal_verification": metadata.review.preflight.formal_verification,
                "device_syntax_verified": False,
                "management_access_verified": False,
                "applied": False,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
