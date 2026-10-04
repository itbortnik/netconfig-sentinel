"""Explicit saved-snapshot change plans; no raw reconstruction, commands or network calls."""

from datetime import UTC, datetime
from uuid import UUID

from app.api.contracts import SnapshotBinding
from app.api.patch_contracts import (
    MAX_RECORD_BYTES,
    CreatePatchDraft,
    PatchDraft,
    VerificationRun,
    VerifyPatch,
    draft_fingerprint,
)
from app.comparison.snapshots import DiffConflict, DiffLimitExceeded, compare_snapshots
from app.db.patch_records import PatchConflict, PatchRecords
from app.db.store import StorageIntegrityError, Store
from app.patching.review import local_validation_blockers
from app.verification.preflight import review_configuration_change


class PatchNotFound(Exception):
    pass


class FormalVerificationUnavailable(Exception):
    pass


class PatchWorkflow:
    def __init__(self, store: Store) -> None:
        self.store = store
        self.records = PatchRecords(store)

    def create(self, options: CreatePatchDraft) -> tuple[PatchDraft, bool]:
        existing = self.records.get_draft(options.patch_id)
        if existing is not None:
            if existing.intent() != options:
                raise PatchConflict("draft identity is already bound")
            return existing, False
        before = self.store.get_configuration(options.before_configuration_id)
        after = self.store.get_configuration(options.after_configuration_id)
        if before is None or after is None:
            raise PatchNotFound()
        if (before.canonical.source.sha256, after.canonical.source.sha256) != (
            options.before_source_sha256,
            options.after_source_sha256,
        ):
            raise PatchConflict("selected source hashes differ")
        diff = compare_snapshots(before, after)
        if not diff.changes:
            raise DiffConflict("no supported object changes")
        draft = PatchDraft(
            patch_id=options.patch_id,
            created_at=datetime.now(UTC),
            diff=diff,
            draft_sha256=draft_fingerprint(diff),
        )
        if len(draft.model_dump_json().encode("utf-8")) > MAX_RECORD_BYTES:
            raise DiffLimitExceeded("draft exceeds budget")
        return self.records.add_draft(draft)

    def draft(self, patch_id: UUID) -> PatchDraft:
        draft = self.records.get_draft(patch_id)
        if draft is None:
            raise PatchNotFound()
        return draft

    def verify(self, patch_id: UUID, options: VerifyPatch) -> tuple[VerificationRun, bool]:
        draft = self.draft(patch_id)
        if draft.draft_sha256 != options.draft_sha256:
            raise PatchConflict("selected draft fingerprint differs")
        if options.mode != "local_preflight":
            raise FormalVerificationUnavailable()
        existing = self.records.get_review(options.verification_id)
        if existing is not None:
            if existing.patch_id != patch_id or existing.draft_sha256 != options.draft_sha256:
                raise PatchConflict("verification identity is already bound")
            return existing, False
        before = self.store.get_configuration(draft.diff.before.configuration_id)
        after = self.store.get_configuration(draft.diff.after.configuration_id)
        if before is None or after is None:
            raise StorageIntegrityError("Stored data is unavailable.")
        report = review_configuration_change(
            before.canonical,
            after.canonical,
            device_id=after.device_id,
            reference_id=str(before.configuration_id),
        )
        run = VerificationRun(
            verification_id=options.verification_id,
            patch_id=patch_id,
            draft_sha256=draft.draft_sha256,
            created_at=datetime.now(UTC),
            before=SnapshotBinding.from_snapshot(before),
            after=SnapshotBinding.from_snapshot(after),
            preflight=report,
            validation_blockers=local_validation_blockers(report),
        )
        if len(run.model_dump_json().encode("utf-8")) > MAX_RECORD_BYTES:
            raise DiffLimitExceeded("review exceeds budget")
        return self.records.add_review(run)
