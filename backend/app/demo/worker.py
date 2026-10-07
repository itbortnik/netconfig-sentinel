"""Fixed owned-fixture worker, called by the environment-isolated demonstration CLI."""

import argparse
import json
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    from app.demo.workflow import run_demonstration

    result = run_demonstration(args.output)
    print(
        json.dumps(
            {
                "version": result.version,
                "devices": len(result.devices),
                "operation_records_checked": result.operation_records_checked,
                "customer_data_used": result.customer_data_used,
                "formal_verification": "not_run",
                "mvp_accepted": result.mvp_accepted,
            }
        )
    )


if __name__ == "__main__":
    main()
