"""Explicit operator-only acquisition of the pinned public document model, never API startup."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
from time import monotonic
from urllib.error import URLError
from urllib.request import urlopen

from app.explanation.vector_index import RetrievalUnavailable

from ml.retrieval.minilm import FILES, MODEL_ID, REVISION, verify_model_files


def acquire_model(root: Path) -> None:
    """Download only allowlisted public artifacts; refuse any existing output directory."""
    if any(path.is_symlink() or path.is_junction() for path in (root, *root.parents)):
        raise ValueError("model acquisition is unavailable")
    root.mkdir()
    (root / "1_Pooling").mkdir()
    began = monotonic()
    for name, (size, expected_sha) in FILES.items():
        # No private configs, API keys or caller-selected hosts/URLs are accepted.
        url = f"https://huggingface.co/{MODEL_ID}/resolve/{REVISION}/{name}"
        digest = hashlib.sha256()
        count = 0
        with urlopen(url, timeout=30) as response, (root / name).open("xb") as output:
            if not response.geturl().startswith("https://"):
                raise ValueError("model acquisition is unavailable")
            while raw := response.read(min(1024 * 1024, size - count + 1)):
                count += len(raw)
                if count > size or monotonic() - began > 600:
                    raise ValueError("model acquisition is unavailable")
                digest.update(raw)
                output.write(raw)
        if count != size or digest.hexdigest() != expected_sha:
            raise ValueError("model acquisition is unavailable")
    verify_model_files(root)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", required=True, type=Path)
    args = parser.parse_args()
    try:
        acquire_model(args.output_root)
    except (OSError, ValueError, URLError, RetrievalUnavailable):
        parser.exit(1, "Public model acquisition failed; output is not a verified artifact.\n")
    print(f"Verified public document model revision {REVISION}.")


if __name__ == "__main__":
    main()
