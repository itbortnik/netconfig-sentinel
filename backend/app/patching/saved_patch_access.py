"""One explicit declared-version replay accessor for public reads and candidate review."""

from dataclasses import dataclass, field
from uuid import UUID

from app.api.grounded_patch_contracts import (
    GroundedModelPatchIntent,
    GroundedModelPatchOutcome,
    SavedModelPatchProposal,
    SavedPatchIntent,
    SavedPatchOutcome,
)
from app.api.model_patch_contracts import ModelPatchOutcome, ModelPatchProposal
from app.api.service import AnalysisService
from app.db.model_patch_records import ModelPatchRecords
from app.db.store import StorageIntegrityError
from app.explanation.patch_provider import GeneratedModelPatch, PreparedPatchPrompt
from app.patching.saved_grounded import SavedGroundedPatchWorkflow
from app.patching.saved_model import SavedModelPatchNotFound, SavedModelPatchWorkflow


@dataclass(frozen=True)
class ReplayedSavedPatch:
    intent: SavedPatchIntent = field(repr=False)
    outcome: SavedPatchOutcome | None = field(repr=False)
    public: SavedModelPatchProposal = field(repr=False)
    projection: ModelPatchProposal = field(repr=False)
    edit_prepared: PreparedPatchPrompt = field(repr=False)
    generated: GeneratedModelPatch | None = field(repr=False)


class SavedModelPatchAccess:
    def __init__(self, service: AnalysisService) -> None:
        self.records = ModelPatchRecords(service.store)
        self.legacy = SavedModelPatchWorkflow(service)
        self.grounded = SavedGroundedPatchWorkflow(service)

    def replay(self, patch_id: UUID) -> ReplayedSavedPatch:
        saved = self.records.get(patch_id)
        if saved is None:
            raise SavedModelPatchNotFound()
        intent, outcome = saved
        if isinstance(intent, GroundedModelPatchIntent):
            if outcome is not None and not isinstance(outcome, GroundedModelPatchOutcome):
                raise StorageIntegrityError("Stored data is unavailable.")
            prepared, generated, public = self.grounded.replay(intent, outcome)
            return ReplayedSavedPatch(
                intent,
                outcome,
                public,
                public.projection,
                prepared.legacy,
                generated.generated if generated is not None else None,
            )
        if outcome is not None and not isinstance(outcome, ModelPatchOutcome):
            raise StorageIntegrityError("Stored data is unavailable.")
        edit_prepared, legacy_generated, projection = self.legacy.replay(intent, outcome)
        return ReplayedSavedPatch(
            intent,
            outcome,
            projection,
            projection,
            edit_prepared,
            legacy_generated,
        )

    def get(self, patch_id: UUID) -> SavedModelPatchProposal:
        return self.replay(patch_id).public
