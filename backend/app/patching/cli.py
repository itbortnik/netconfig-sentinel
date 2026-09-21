"""Create or recheck private local draft artifacts; no apply or approve commands."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from uuid import UUID

from app.ingestion.local import read_local_configuration
from app.patching.artifacts import recheck_patch_review, save_patch_review
from app.patching.proposal import create_patch_proposal
from app.patching.review import review_patch_proposal


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("create", "check"):
        child = subparsers.add_parser(command)
        child.add_argument("--before", type=Path, required=True)
        child.add_argument("--after", type=Path, required=True)
        child.add_argument("--device-id", type=UUID, required=True)
        if command == "create":
            child.add_argument("--reference-id", required=True)
            child.add_argument("--output", type=Path, required=True)
        else:
            child.add_argument("--artifact", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        before, after = read_local_configuration(args.before), read_local_configuration(args.after)
        if args.command == "create":
            draft = create_patch_proposal(
                before, after, device_id=args.device_id, reference_id=args.reference_id
            )
            review = review_patch_proposal(draft, before, after, device_id=args.device_id)
            save_patch_review(review, args.output)
        else:
            review = recheck_patch_review(args.artifact, before, after, device_id=args.device_id)
    except (OSError, ValueError):
        print(
            "Draft operation refused: check input limits and identity, changed snapshots, "
            "artifact integrity and a new output path for create. "
            "Stale reviews require recreation.",
            file=sys.stderr,
        )
        return 2
    print(
        json.dumps(
            {
                "operation": args.command,
                "proposal_id": str(review.proposal.proposal_id),
                "report_id": str(review.preflight.report_id),
                "proposal_status": review.proposal.status,
                "review_status": review.status,
                "formal_verification": review.preflight.formal_verification,
                "validation_blockers": review.validation_blockers,
                "applied": False,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
