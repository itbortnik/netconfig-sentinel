"""One loaded model and ephemeral key for both exact retained sources."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app.api.configurations import _unique_keys
from app.detection.config_pair_contracts import (
    MAX_PAIR_JOB_BYTES,
    MAX_PAIR_RESULT_BYTES,
    ConfigurationPairJob,
)
from app.ingestion.source_retention import prepare_original_source


def main() -> None:
    try:
        raw = sys.stdin.buffer.read(MAX_PAIR_JOB_BYTES + 1)
        if len(raw) > MAX_PAIR_JOB_BYTES:
            raise ValueError("oversized pair job")
        job = ConfigurationPairJob.model_validate(json.loads(raw, object_pairs_hook=_unique_keys))
        for snapshot, source in ((job.before, job.before_source), (job.after, job.after_source)):
            if prepare_original_source(snapshot, source.content) != source:
                raise ValueError("retained pair source differs")
        from ml.inference.configuration_pair import infer_configuration_pair
        from ml.registry.store import load_registered_model

        model = load_registered_model(
            Path(job.registry_root),
            job.model_sha256,
            foundation_source=Path(job.foundation_source) if job.foundation_source else None,
        )
        result = infer_configuration_pair(
            job.before_source.content,
            job.after_source.content,
            vendor=job.before.canonical.device.vendor,
            device_id=job.before.device_id,
            model=model,
            expected_model_sha256=job.model_sha256,
            pseudonymization_key=bytes.fromhex(job.key_hex),
        )
        output = result.model_dump_json().encode()
        if len(output) > MAX_PAIR_RESULT_BYTES:
            raise ValueError("oversized paired result")
        sys.stdout.buffer.write(output)
    except Exception:
        sys.exit(1)


if __name__ == "__main__":
    main()
