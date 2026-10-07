"""Owned-fixture API demonstration in a new directory; never MVP/production acceptance."""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        environment = {
            name: value
            for name, value in os.environ.items()
            if name.upper() in {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP"}
        }
        code = (
            "import sys; sys.path.insert(0,sys.argv.pop(1)); "
            "from app.demo.worker import main; main()"
        )
        completed = subprocess.run(
            [
                sys.executable,
                "-I",
                "-c",
                code,
                str(Path(__file__).resolve().parents[2]),
                "--output",
                str(args.output.absolute()),
            ],
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            encoding="utf-8",
            timeout=60,
            check=False,
        )
        if completed.returncode != 0 or len(completed.stdout.encode("utf-8")) > 4096:
            raise ValueError("owned worker did not complete within the selected limits")
        summary = json.loads(completed.stdout)
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired):
        print(
            "Owned demonstration failed: check development dependencies "
            "and a new output directory.",
            file=sys.stderr,
        )
        return 2
    print(json.dumps(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
