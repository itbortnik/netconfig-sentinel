# Sanitized dataset artifacts

Artifact format `sanitized-dataset-artifact-0.1.0` persists a technically valid
quality-report run as a new directory. The writer never overwrites an existing
target. The default top-level `artifacts/` directory is ignored by Git so a
generated corpus is not committed accidentally.

## Directory layout

```text
artifact-name/
  manifest.json
  quality-report.json
  records/
    train.jsonl
    validation.jsonl
    test.jsonl
  audit/
    deduplication.json
    splitting.json
```

Only the three JSON Lines files contain configuration text, and that text is
the sanitized text from deduplicated representatives. Deduplication and split
audit files retain fingerprints, cluster evidence, entity assignments, policy,
counts, time ranges, and limitations without copying configuration bodies.
Raw source bytes, source paths, reversible identity mappings, and
pseudonymization keys are never written.

All JSON is emitted canonically with sorted keys and stable ordering. No write
timestamp is injected, so identical input and policies produce identical
content and the same content-derived artifact ID.

## Finalization and verification

Writing requires an existing output root, a safe single-component artifact
name, a technically valid quality report, exact report/pipeline agreement, one
sanitizer version, and approved sources that allow the report's intended use.

The writer creates files exclusively and places an `.incomplete` marker before
content is emitted. A failed run is deliberately left recognizable for manual
inspection; it is never mistaken for a completed artifact. On success the
writer creates `manifest.json`, removes the marker, and reloads the directory
through the same verifier used by consumers.

`load_dataset_artifact` rejects:

- a missing, empty, oversized, or schema-invalid manifest;
- an incomplete marker;
- symbolic links anywhere in the artifact;
- missing or unexpected files;
- a byte count or SHA-256 mismatch for any listed content file;
- a manifest whose content-derived artifact ID does not match its entries.

The manifest itself is validated structurally, while its artifact ID binds the
pipeline fingerprint and all listed content files. SHA-256 provides integrity
checking, not publisher authentication. Distribution across trust boundaries
therefore needs a separate signing or authenticated transport mechanism.

## Usage

```python
from pathlib import Path

from ml.datasets import load_dataset_artifact, write_dataset_artifact

result = write_dataset_artifact(
    sanitized_records,
    deduplication_result,
    split_result,
    quality_report,
    output_root=Path("artifacts"),
    artifact_name="training-v1",
)

verified_manifest = load_dataset_artifact(result.path)
```

Callers must create and secure the output root themselves. Artifact directories
should be treated as append-only outputs and distributed according to the
licenses and intended use retained in the quality report.
