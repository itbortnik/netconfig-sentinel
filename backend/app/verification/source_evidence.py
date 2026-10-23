"""Pure selected-evidence compatibility; no joint product report or qualification yet."""

from dataclasses import dataclass
from typing import Literal
from uuid import UUID

from app.api.patch_contracts import PatchDraft
from app.api.source_deterministic_contracts import SourceDeterministicRecheck
from app.api.source_forest_contracts import SourceForestRecheck
from app.api.source_ml_contracts import SourceMlRecheck
from app.api.source_patch_contracts import SourcePatchVerification
from app.api.source_patch_sdk_contracts import (
    SourcePatchReview,
    SourcePatchVerificationV2,
    parse_source_patch_review,
)

type EvidenceKind = Literal["deterministic", "forest", "neural", "network"]
type Evidence = (
    SourceDeterministicRecheck | SourceForestRecheck | SourceMlRecheck | SourcePatchReview
)


@dataclass(frozen=True)
class SelectedSourceEvidence:
    kind: EvidenceKind
    record_id: UUID
    review_sha256: str


def bind_selected_source_evidence(
    draft: PatchDraft,
    deterministic: SourceDeterministicRecheck,
    *,
    forest: SourceForestRecheck | None = None,
    neural: SourceMlRecheck | None = None,
    network: SourcePatchReview | None = None,
) -> tuple[SelectedSourceEvidence, ...]:
    """Bind completed selected records, without implying all required checks exist.

    Callers must obtain records through their existing integrity-checked repositories.
    The network result can still be error/violation/inconclusive: completion here
    describes a stored attempt, not successful formal verification. Missing optional
    inputs are not selected; their qualification remains the future report's concern.
    """
    draft = PatchDraft.model_validate(draft.model_dump(warnings=False))
    deterministic = SourceDeterministicRecheck.model_validate(
        deterministic.model_dump(warnings=False)
    )
    selected: list[tuple[EvidenceKind, Evidence]] = [("deterministic", deterministic)]
    if forest is not None:
        forest = SourceForestRecheck.model_validate(forest.model_dump(warnings=False))
        if (forest.before_analysis_id, forest.before_analysis_sha256) != (
            deterministic.before_analysis_id,
            deterministic.before_analysis_sha256,
        ):
            raise ValueError("selected original analyses differ")
        selected.append(("forest", forest))
    if neural is not None:
        selected.append(
            ("neural", SourceMlRecheck.model_validate(neural.model_dump(warnings=False)))
        )
    if network is not None:
        selected.append(("network", parse_source_patch_review(network)))
    result = []
    for kind, record in selected:
        if (
            record.patch_id != draft.patch_id
            or record.draft_sha256 != draft.draft_sha256
            or record.execution_status != "completed"
            or record.outcome is None
        ):
            raise ValueError("selected evidence parent or execution differs")
        for member, anchor, original in (
            (record.intent.before, draft.diff.before, deterministic.intent.before),
            (record.intent.after, draft.diff.after, deterministic.intent.after),
        ):
            if (
                member.configuration_id,
                member.device_id,
                member.source_sha256,
                member.created_at,
            ) != (
                anchor.configuration_id,
                anchor.device_id,
                anchor.source_sha256,
                anchor.created_at,
            ) or member.canonical_sha256 != original.canonical_sha256:
                raise ValueError("selected evidence target source or canonical binding differs")
        result.append(
            SelectedSourceEvidence(
                kind,
                record.verification_id
                if isinstance(record, (SourcePatchVerification, SourcePatchVerificationV2))
                else record.recheck_id,
                record.review_sha256,
            )
        )
    return tuple(result)
