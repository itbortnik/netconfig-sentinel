"""Saved ordinary source pairs to scoped network evidence; no executable patch or approval."""

import json
from datetime import UTC, datetime
from uuid import UUID

from app.api.contracts import ConfigurationSnapshot, SnapshotBinding
from app.api.source_patch_contracts import (
    MAX_SOURCE_REVIEW_BYTES,
    SourcePatchIntent,
    SourcePatchMember,
    SourcePatchOutcome,
    SourcePatchVerification,
    VerifySourcePatch,
    source_review_fingerprint,
)
from app.db.patch_records import PatchConflict
from app.db.source_patch_records import SourcePatchRecords
from app.db.source_records import OriginalSourceUnavailable, SourceRecords
from app.db.store import Store
from app.ingestion.source_retention import prepare_original_source
from app.patching.persistent import PatchNotFound, PatchWorkflow
from app.verification.batfish import BatfishResult, check_with_batfish
from app.verification.patch_runtime import PatchVerificationDisabled, PatchVerificationRuntime
from app.verification.preflight import review_configuration_change
from app.verification.snapshots import NetworkSnapshot, prepare_snapshot, validate_snapshot_pair

MAX_NETWORK_RESULT_JSON_BYTES = 256 * 1024
# The completed record also adds IDs, timestamps, state and blocker projections.
COMPLETION_HEADROOM_BYTES = MAX_NETWORK_RESULT_JSON_BYTES + 8192


class SourcePatchConsentRequired(Exception):
    pass


class SourcePatchReviewTooLarge(Exception):
    pass


class SourcePatchWorkflow:
    def __init__(self, store: Store) -> None:
        self.store = store
        self.drafts = PatchWorkflow(store)
        self.records = SourcePatchRecords(store)

    @staticmethod
    def _view(pair: tuple[SourcePatchIntent, SourcePatchOutcome | None]) -> SourcePatchVerification:
        view = SourcePatchVerification.from_records(*pair)
        if len(view.model_dump_json().encode()) > MAX_SOURCE_REVIEW_BYTES * 4:
            raise SourcePatchReviewTooLarge()
        return view

    def get(self, patch_id: UUID, verification_id: UUID) -> SourcePatchVerification:
        pair = self.records.get(verification_id)
        if pair is None or pair[0].patch_id != patch_id:
            raise PatchNotFound()
        return self._view(pair)

    def _source(self, snapshot: ConfigurationSnapshot) -> tuple[SourcePatchMember, str]:
        record = SourceRecords(self.store).get(
            snapshot.configuration_id,
            expected_source_sha256=snapshot.canonical.source.sha256,
            allow_local_read=True,
        )
        # Reading a stored binding alone is not a fresh source syntax/IR check.
        fresh = prepare_original_source(snapshot, record.content)
        if fresh != record:
            raise ValueError("retained source differs")
        return SourcePatchMember.model_validate(
            SnapshotBinding.from_snapshot(snapshot).model_dump()
            | {
                "canonical_sha256": record.canonical_sha256,
                "hostname": snapshot.canonical.device.hostname,
                "platform": snapshot.canonical.device.platform,
            }
        ), record.content

    def _prepare(
        self, patch_id: UUID, options: VerifySourcePatch
    ) -> tuple[NetworkSnapshot, NetworkSnapshot, SourcePatchIntent]:
        draft = self.drafts.draft(patch_id)
        if draft.draft_sha256 != options.draft_sha256:
            raise PatchConflict("Selected draft differs.")
        before = self.store.get_configuration(draft.diff.before.configuration_id)
        after = self.store.get_configuration(draft.diff.after.configuration_id)
        if before is None or after is None:
            raise PatchNotFound()
        try:
            old, old_text = self._source(before)
            new, new_text = self._source(after)
            contents = {}
            companions = []
            for selected in options.companions:
                snapshot = self.store.get_configuration(selected.configuration_id)
                if snapshot is None or snapshot.canonical.source.sha256 != selected.source_sha256:
                    raise ValueError("selected companion differs")
                member, content = self._source(snapshot)
                if member.device_id in contents or member.device_id == before.device_id:
                    raise ValueError("duplicate target or companion device")
                companions.append(member)
                contents[member.device_id] = content
            previous = prepare_snapshot(contents | {before.device_id: old_text})
            current = prepare_snapshot(contents | {after.device_id: new_text})
            validate_snapshot_pair(previous, current)
            preflight = review_configuration_change(
                before.canonical,
                after.canonical,
                device_id=after.device_id,
                reference_id=str(before.configuration_id),
            )
            intent = SourcePatchIntent(
                patch_id=patch_id,
                request=options,
                created_at=datetime.now(UTC),
                before=old,
                after=new,
                companions=tuple(companions),
                before_network_sha256=previous.digest,
                after_network_sha256=current.digest,
                preflight=preflight,
            )
            # Budget the proof as well as the decoded typed record before any SDK call.
            if len(
                json.dumps(
                    intent.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
                ).encode()
            ) > (MAX_SOURCE_REVIEW_BYTES - COMPLETION_HEADROOM_BYTES):
                raise SourcePatchReviewTooLarge()
            self._view((intent, None))
            return previous, current, intent
        except (OriginalSourceUnavailable, ValueError):
            raise PatchConflict(
                "Selected retained source pair, companions or scope conflict."
            ) from None

    def verify(
        self, patch_id: UUID, options: VerifySourcePatch, runtime: PatchVerificationRuntime
    ) -> tuple[SourcePatchVerification, bool]:
        options = VerifySourcePatch.model_validate(options.model_dump(warnings=False))
        existing = self.records.get(options.verification_id)
        if existing is not None:
            if existing[0].patch_id != patch_id or existing[0].request != options:
                raise PatchConflict("Source review identity conflicts.")
            return self._view(existing), False
        if not options.allow_local_engine_upload:
            raise SourcePatchConsentRequired()
        if not runtime.settings.allow_engine_upload:
            raise PatchVerificationDisabled()
        with runtime.selected_worker():
            before, after, intent = self._prepare(patch_id, options)
            if not self.records.reserve(intent):
                return self.get(patch_id, options.verification_id), False
            try:
                result = check_with_batfish(
                    before,
                    after,
                    options.scope,
                    allow_local_upload=True,
                    timeout_seconds=runtime.settings.engine_timeout_seconds,
                )
                result = BatfishResult.model_validate(result.model_dump(warnings=False))
                if (
                    len(
                        json.dumps(
                            result.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
                        ).encode()
                    )
                    > MAX_NETWORK_RESULT_JSON_BYTES
                ):
                    raise ValueError("network result exceeds completion budget")
                outcome = SourcePatchOutcome(
                    verification_id=options.verification_id,
                    intent_sha256=source_review_fingerprint(intent),
                    completed_at=datetime.now(UTC),
                    network_result=result,
                )
                self._view((intent, outcome))
            except Exception:
                # Keep the successful local preflight; never persist raw SDK/worker diagnostics.
                outcome = SourcePatchOutcome(
                    verification_id=options.verification_id,
                    intent_sha256=source_review_fingerprint(intent),
                    completed_at=datetime.now(UTC),
                    network_result=BatfishResult(
                        before_sha256=intent.before_network_sha256,
                        after_sha256=intent.after_network_sha256,
                        scope=options.scope,
                        status="error",
                        reason="worker_failed",
                    ),
                )
            self.records.complete(outcome)
            return self._view((intent, outcome)), True
