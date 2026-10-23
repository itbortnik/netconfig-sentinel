"""Immutable encrypted ordinary source-review attempts, atomic domain audit and replay."""

from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.contracts import SnapshotBinding
from app.api.source_patch_contracts import MAX_SOURCE_REVIEW_BYTES
from app.api.source_patch_direction_contracts import (
    SourcePatchIntentRecord,
    SourcePatchOutcomeRecord,
    parse_source_patch_intent_json,
    parse_source_patch_outcome_json,
    source_patch_view,
)
from app.db.patch_records import PatchConflict, PatchRecords
from app.db.store import StorageIntegrityError, Store
from app.db.tables import (
    AuditRow,
    ConfigurationRow,
    PatchRow,
    SourcePatchIntentRow,
    SourcePatchOutcomeRow,
)
from app.ingestion.source_retention import canonical_fingerprint


class SourcePatchRecords:
    def __init__(self, store: Store) -> None:
        self.store = store

    def _plain(self, value: str, kind: str, key: str) -> str:
        if len(value) > MAX_SOURCE_REVIEW_BYTES * 4:
            raise ValueError("oversized source review ciphertext")
        raw = self.store._decode(value, kind=kind, row_id=key)
        if len(raw.encode()) > MAX_SOURCE_REVIEW_BYTES:
            raise ValueError("oversized source review record")
        return raw

    def _encode(self, value: str, kind: str, key: str) -> str:
        if len(value.encode()) > MAX_SOURCE_REVIEW_BYTES:
            raise StorageIntegrityError("Stored data is unavailable.")
        return self.store._encode(value, kind=kind, row_id=key)

    def _intent(self, session: Session, row: SourcePatchIntentRow) -> SourcePatchIntentRecord:
        try:
            intent = parse_source_patch_intent_json(
                self._plain(row.payload, "source_patch_intent", row.id)
            )
            timestamp = (
                row.created_at if row.created_at.tzinfo else row.created_at.replace(tzinfo=UTC)
            )
            if (str(intent.request.verification_id), str(intent.patch_id), intent.created_at) != (
                row.id,
                row.patch_id,
                timestamp,
            ):
                raise ValueError("source review metadata differs")
            parent = session.get(PatchRow, row.patch_id)
            if parent is None:
                raise ValueError("source review parent missing")
            draft = PatchRecords(self.store)._draft(session, parent)
            if (
                draft.draft_sha256 != intent.request.draft_sha256
                or intent.created_at < draft.created_at
                or (intent.before.configuration_id, intent.after.configuration_id)
                != (draft.diff.before.configuration_id, draft.diff.after.configuration_id)
            ):
                raise ValueError("source review parent binding differs")
            for member in (intent.before, intent.after, *intent.companions):
                snapshot_row = session.get(ConfigurationRow, str(member.configuration_id))
                if snapshot_row is None:
                    raise ValueError("source review member missing")
                snapshot = self.store._snapshot(snapshot_row)
                if (
                    member.model_dump(exclude={"canonical_sha256", "hostname", "platform"})
                    != SnapshotBinding.from_snapshot(snapshot).model_dump()
                    or member.canonical_sha256 != canonical_fingerprint(snapshot)
                    or member.hostname != snapshot.canonical.device.hostname
                    or member.platform != snapshot.canonical.device.platform
                ):
                    raise ValueError("source review member binding differs")
            for summary, diff_snapshot in (
                (intent.preflight.before, draft.diff.before),
                (intent.preflight.after, draft.diff.after),
            ):
                if (summary.confidence, summary.warning_count, summary.unparsed_count) != (
                    diff_snapshot.parser_confidence,
                    diff_snapshot.warning_count,
                    diff_snapshot.unparsed_count,
                ):
                    raise ValueError("source review parser summary differs")
            return intent
        except ValueError:
            raise StorageIntegrityError("Stored data is unavailable.") from None

    def _outcome(
        self, row: SourcePatchOutcomeRow, intent: SourcePatchIntentRecord
    ) -> SourcePatchOutcomeRecord:
        try:
            outcome = parse_source_patch_outcome_json(
                self._plain(row.payload, "source_patch_outcome", row.verification_id)
            )
            if str(outcome.verification_id) != row.verification_id:
                raise ValueError("source review result metadata differs")
            source_patch_view(intent, outcome)
            return outcome
        except ValueError:
            raise StorageIntegrityError("Stored data is unavailable.") from None

    def _get(
        self, session: Session, key: UUID
    ) -> tuple[SourcePatchIntentRecord, SourcePatchOutcomeRecord | None] | None:
        row = session.get(SourcePatchIntentRow, str(key))
        if row is None:
            return None
        intent = self._intent(session, row)
        result = session.get(SourcePatchOutcomeRow, row.id)
        return intent, self._outcome(result, intent) if result is not None else None

    def get(
        self, key: UUID
    ) -> tuple[SourcePatchIntentRecord, SourcePatchOutcomeRecord | None] | None:
        with self.store._sessions() as session:
            return self._get(session, key)

    @staticmethod
    def _same(stored: SourcePatchIntentRecord, incoming: SourcePatchIntentRecord) -> None:
        if stored.patch_id != incoming.patch_id or stored.request != incoming.request:
            raise PatchConflict("Source review identity conflicts.")

    @staticmethod
    def _audit(session: Session, action: str, key: str) -> None:
        session.add(
            AuditRow(id=str(uuid4()), action=action, resource_id=key, created_at=datetime.now(UTC))
        )

    def reserve(self, intent: SourcePatchIntentRecord) -> bool:
        intent = parse_source_patch_intent_json(intent.model_dump_json(warnings=False))
        key = str(intent.request.verification_id)
        try:
            with self.store._sessions.begin() as session:
                existing = session.get(SourcePatchIntentRow, key)
                if existing is not None:
                    self._same(self._intent(session, existing), intent)
                    return False
                row = SourcePatchIntentRow(
                    id=key,
                    patch_id=str(intent.patch_id),
                    created_at=intent.created_at.astimezone(UTC),
                    payload=self._encode(intent.model_dump_json(), "source_patch_intent", key),
                )
                self._intent(session, row)
                session.add(row)
                self._audit(session, "patch.network_verification_requested", key)
            return True
        except IntegrityError:
            raced = self.get(intent.request.verification_id)
            if raced is None:
                raise
            self._same(raced[0], intent)
            return False

    def complete(self, outcome: SourcePatchOutcomeRecord) -> None:
        outcome = parse_source_patch_outcome_json(outcome.model_dump_json(warnings=False))
        key = str(outcome.verification_id)
        with self.store._sessions.begin() as session:
            saved = self._get(session, outcome.verification_id)
            if saved is None:
                raise StorageIntegrityError("Stored data is unavailable.")
            intent, existing = saved
            if existing is not None:
                if existing != outcome:
                    raise PatchConflict("Source review result conflicts.")
                return
            row = SourcePatchOutcomeRow(
                verification_id=key,
                payload=self._encode(outcome.model_dump_json(), "source_patch_outcome", key),
            )
            self._outcome(row, intent)
            session.add(row)
            self._audit(session, "patch.network_verification_completed", key)

    def list_ids(self, patch_id: UUID, *, limit: int, offset: int) -> list[UUID]:
        query = (
            select(SourcePatchIntentRow.id)
            .where(SourcePatchIntentRow.patch_id == str(patch_id))
            .order_by(SourcePatchIntentRow.created_at.desc(), SourcePatchIntentRow.id.desc())
        )
        with self.store._sessions() as session:
            return [UUID(key) for key in session.scalars(query.limit(limit).offset(offset))]
