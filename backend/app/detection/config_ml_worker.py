"""Explicitly invoked offline CPU inference; no source text is returned."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app.api.configurations import _unique_keys
from app.detection.config_model_contracts import (
    MAX_JOB_BYTES,
    MAX_RESULT_BYTES,
    ConfigurationModelJob,
    require_complete,
)
from app.ingestion.source_retention import prepare_original_source


def main() -> None:
    try:
        raw = sys.stdin.buffer.read(MAX_JOB_BYTES + 1)
        if len(raw) > MAX_JOB_BYTES:
            raise ValueError("oversized job")
        job = ConfigurationModelJob.model_validate(json.loads(raw, object_pairs_hook=_unique_keys))
        require_complete(job.snapshot)
        if prepare_original_source(job.snapshot, job.source.content) != job.source:
            raise ValueError("original source and canonical snapshot differ")
        from ml.inference.configuration import infer_configuration
        from ml.registry.store import load_registered_model

        model = load_registered_model(
            Path(job.registry_root),
            job.model_sha256,
            foundation_source=Path(job.foundation_source) if job.foundation_source else None,
        )
        result = infer_configuration(
            job.source.content,
            vendor=job.snapshot.canonical.device.vendor,
            device_id=job.snapshot.device_id,
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
