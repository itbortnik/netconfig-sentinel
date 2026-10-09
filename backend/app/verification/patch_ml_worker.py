"""Offline CPU registry inference in an explicitly invoked installed worker."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app.api.configurations import _unique_keys
from app.verification.patch_ml_contracts import MAX_JOB_BYTES, MAX_RESULT_BYTES, PatchMLJob


def main() -> None:
    try:
        raw = sys.stdin.buffer.read(MAX_JOB_BYTES + 1)
        if len(raw) > MAX_JOB_BYTES:
            raise ValueError("oversized job")
        job = PatchMLJob.model_validate(json.loads(raw, object_pairs_hook=_unique_keys))
        from ml.inference.change_review import review_patch_ml
        from ml.registry.store import load_registered_model

        model = load_registered_model(
            Path(job.registry_root),
            job.model_sha256,
            foundation_source=Path(job.foundation_source) if job.foundation_source else None,
        )
        result = review_patch_ml(
            job.local_review,
            job.before,
            job.after,
            model=model,
            expected_model_sha256=job.model_sha256,
            pseudonymization_key=bytes.fromhex(job.key_hex),
        )
        output = result.model_dump_json().encode()
        if len(output) > MAX_RESULT_BYTES:
            raise ValueError("oversized result")
        sys.stdout.buffer.write(output)
    except Exception:
        sys.exit(1)


if __name__ == "__main__":
    main()
