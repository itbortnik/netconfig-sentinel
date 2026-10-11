"""Native fixture-pretraining bindings and exhaustive bounded downstream overlap audit."""

from __future__ import annotations

from ml.datasets import DatasetSplit, DatasetSplitResult, ImportedDatasetRecord
from ml.datasets.deduplication import _jaccard_similarity, _prepare_record
from ml.datasets.fixture_training import FixtureTrainingCorpus, validate_fixture_training_corpus
from ml.datasets.quality import scan_sanitized_content
from ml.evaluation.metrics import canonical_hash
from ml.preprocessing.sanitization import SUPPORTED_SANITIZATION_VERSIONS
from ml.training.fixture_contracts import FixtureExposureAudit as FixtureExposureAudit
from ml.training.fixture_contracts import FixtureSourceBinding as FixtureSourceBinding
from ml.training.fixture_contracts import FixtureTransferPolicy as FixtureTransferPolicy
from ml.training.pretraining import FixturePretrainingResult, pretraining_identity
from ml.training.pretraining_data import fixture_audit_identity, prepare_fixture_pretraining
from ml.training.pretraining_transfer import objective_split_identity, validate_fixture_model


def _report_hash(source: FixturePretrainingResult) -> str:
    payload = source.report.model_dump(mode="json")
    payload["corpus"]["source"]["allowed_uses"] = sorted(source.report.corpus.source.allowed_uses)
    return canonical_hash(payload)


def verify_fixture_binding(source: FixturePretrainingResult, binding: FixtureSourceBinding) -> None:
    binding = FixtureSourceBinding.model_validate(binding.model_dump())
    validate_fixture_model(source)
    if (
        binding.pretraining_sha256 != pretraining_identity(source)
        or binding.report_sha256 != _report_hash(source)
        or binding.corpus_sha256 != fixture_audit_identity(source.report.corpus)
    ):
        raise ValueError("fixture pretraining model/report/exposure binding differs")


def audit_fixture_exposure(
    corpus: FixtureTrainingCorpus,
    splits: DatasetSplitResult,
    derived_records: tuple[ImportedDatasetRecord, ...],
    *,
    policy: FixtureTransferPolicy,
) -> FixtureExposureAudit:
    """Hash/template/all-pair Jaccard checks, not invented physical/time isolation.

    Reserved test text is used only for overlap checks, never encoded or labeled.
    Every review-stage fixture, including holds/duplicate members, stays conservative.
    No target subset is selected after observing a failed overlap.
    """
    corpus = validate_fixture_training_corpus(corpus)
    splits = DatasetSplitResult.model_validate(splits.model_dump())
    policy = FixtureTransferPolicy.model_validate(policy.model_dump())
    parents = {
        (row.source_id, row.record_id): part.split
        for part in splits.partitions
        for row in part.records
    }
    candidates = [(part.split, row) for part in splits.partitions for row in part.records]
    for row in derived_records:
        part = parents.get((row.source_id, row.record_id))
        if part is None or part is DatasetSplit.TEST:
            raise ValueError("derived fixture-transfer input has no non-test split parent")
        candidates.append((part, row))
    inventory: dict[str, list[tuple[DatasetSplit, ImportedDatasetRecord]]] = {}
    for part, row in candidates:
        row = ImportedDatasetRecord.model_validate(row.model_dump())
        if (
            not row.sanitized_text.strip()
            or len(row.sanitized_text.encode("utf-8")) > 1024 * 1024
            or scan_sanitized_content(
                row.sanitized_text,
                sanitized_sha256=row.sanitized_sha256,
                sanitization_version=row.sanitization_version,
                allowed_versions=SUPPORTED_SANITIZATION_VERSIONS,
            )
        ):
            raise ValueError("fixture-transfer downstream input failed current content checks")
        members = inventory.setdefault(row.sanitized_sha256, [])
        if members and members[0][0] is not part:
            raise ValueError("identical downstream content crosses fixture-transfer splits")
        members.append((part, row))
    comparisons = len(corpus.imported) * len(inventory)
    if not 1 <= comparisons <= policy.max_comparisons:
        raise ValueError("fixture-transfer comparison budget exceeded; no subset/truncation")
    dedup_policy = corpus.audit.policy.deduplication
    source = tuple(_prepare_record(row, dedup_policy) for row in corpus.imported)
    counts = dict.fromkeys(("source", "raw", "sanitized", "normalized", "template", "near"), 0)
    fingerprints = []
    for _, members in sorted(inventory.items()):
        members = sorted(
            members,
            key=lambda item: (
                item[1].source_id,
                item[1].record_id,
                item[1].raw_sha256,
            ),
        )
        part, row = members[0]
        source_ids = {item.source_id for _, item in members}
        raw_hashes = {item.raw_sha256 for _, item in members}
        target = _prepare_record(row, dedup_policy)
        flags = dict.fromkeys(counts, False)
        for upstream in source:
            # Content deduplication must not hide another member's source/raw provenance.
            flags["source"] |= upstream.record.source_id in source_ids
            flags["raw"] |= upstream.fingerprint.raw_sha256 in raw_hashes
            for name, field in (
                ("sanitized", "sanitized_sha256"),
                ("normalized", "normalized_sha256"),
                ("template", "template_sha256"),
            ):
                flags[name] |= getattr(target.fingerprint, field) == getattr(
                    upstream.fingerprint, field
                )
            flags["near"] |= _jaccard_similarity(target.tokens, upstream.tokens) >= (
                policy.near_duplicate_threshold
            )
        if part is not DatasetSplit.TRAIN and any(flags.values()):
            raise ValueError(
                "fixture pretraining overlaps a downstream heldout source/template/content"
            )
        for name, value in flags.items():
            counts[name] += int(value)
        fingerprints.append(
            {
                "partition": part.value,
                "fingerprint": target.fingerprint.model_dump(mode="json"),
                "members": [
                    (item.source_id, item.record_id, item.raw_sha256) for _, item in members
                ],
            }
        )
    return FixtureExposureAudit(
        policy=policy,
        corpus_sha256=fixture_audit_identity(corpus.audit),
        downstream_manifest_sha256=objective_split_identity(splits),
        downstream_content_sha256=canonical_hash(fingerprints),
        source_intake_count=len(corpus.imported),
        downstream_unique_content_count=len(inventory),
        comparisons=comparisons,
        train_overlap_counts=counts,
    )


def validate_fixture_source(
    corpus: FixtureTrainingCorpus,
    source: FixturePretrainingResult,
    splits: DatasetSplitResult,
    derived_records: tuple[ImportedDatasetRecord, ...],
    *,
    policy: FixtureTransferPolicy | None = None,
) -> FixtureSourceBinding:
    """Regenerate exact Stage A targets and full bounded downstream exposure before fitting."""
    validate_fixture_model(source)
    corpus = validate_fixture_training_corpus(corpus)
    if source.report.corpus != corpus.audit:
        raise ValueError("fixture pretraining corpus differs from retained private inputs")
    recorded = source.report.training_policy
    data = prepare_fixture_pretraining(
        corpus,
        source.tokenizer,
        seed=recorded.seed,
        max_records=recorded.max_records,
        max_windows=recorded.max_windows,
        max_examples=recorded.max_examples,
    )
    if (
        data.fingerprint != source.report.train_fingerprint
        or data.source_fingerprint != source.report.train_source_fingerprint
        or data.counts() != source.report.train_counts
        or data.windows != source.report.train_windows
    ):
        raise ValueError("fixture pretraining objective exposure differs")
    exposure = audit_fixture_exposure(
        corpus, splits, derived_records, policy=policy or FixtureTransferPolicy()
    )
    binding = FixtureSourceBinding(
        pretraining_sha256=pretraining_identity(source),
        report_sha256=_report_hash(source),
        corpus_sha256=fixture_audit_identity(corpus.audit),
        source_manifest_sha256=exposure.downstream_manifest_sha256,
        exposure=exposure,
    )
    verify_fixture_binding(source, binding)
    return binding
