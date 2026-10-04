"""Bound encrypted draft/review records with atomic audit and racing intent replay."""

from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.contracts import SnapshotBinding
from app.api.patch_contracts import MAX_RECORD_BYTES, PatchDraft, VerificationRun
from app.comparison.snapshots import compare_snapshots
from app.db.store import StorageIntegrityError, Store
from app.db.tables import AuditRow, ConfigurationRow, PatchRow, VerificationRow


class PatchConflict(ValueError):
    """An existing intent ID or draft fingerprint is bound differently."""


class PatchRecords:
    def __init__(self, store: Store) -> None:
        self.store = store

    @staticmethod
    def _time(value: datetime) -> datetime:
        return value if value.tzinfo is not None else value.replace(tzinfo=UTC)

    def _draft(self, session: Session, row: PatchRow) -> PatchDraft:
        try:
            if len(row.payload) > 8 * 1024 * 1024:
                raise ValueError("oversized encrypted draft")
            contents = self.store._decode(row.payload, kind="patch", row_id=row.id)
            if len(contents.encode("utf-8")) > MAX_RECORD_BYTES:
                raise ValueError("oversized stored draft")
            draft = PatchDraft.model_validate_json(contents)
            if (
                str(draft.patch_id),
                str(draft.diff.before.configuration_id),
                str(draft.diff.after.configuration_id),
                draft.created_at,
            ) != (
                row.id,
                row.before_configuration_id,
                row.after_configuration_id,
                self._time(row.created_at),
            ):
                raise ValueError("draft metadata differs")
            before = session.get(ConfigurationRow, row.before_configuration_id)
            after = session.get(ConfigurationRow, row.after_configuration_id)
            if (
                before is None
                or after is None
                or compare_snapshots(self.store._snapshot(before), self.store._snapshot(after))
                != draft.diff
            ):
                raise ValueError("draft snapshots differ")
            return draft
        except ValueError:
            raise StorageIntegrityError("Stored data is unavailable.") from None

    def get_draft(self, patch_id: UUID) -> PatchDraft | None:
        with self.store._sessions() as session:
            row = session.get(PatchRow, str(patch_id))
            return self._draft(session, row) if row is not None else None

    def _draft_replay(self, session: Session, row: PatchRow, incoming: PatchDraft) -> PatchDraft:
        stored = self._draft(session, row)
        if stored.intent() != incoming.intent():
            raise PatchConflict("draft identity is already bound")
        return stored

    def add_draft(self, draft: PatchDraft) -> tuple[PatchDraft, bool]:
        draft = PatchDraft.model_validate_json(draft.model_dump_json())
        key = str(draft.patch_id)
        try:
            with self.store._sessions.begin() as session:
                existing = session.get(PatchRow, key)
                if existing is not None:
                    return self._draft_replay(session, existing, draft), False
                row = PatchRow(
                    id=key,
                    before_configuration_id=str(draft.diff.before.configuration_id),
                    after_configuration_id=str(draft.diff.after.configuration_id),
                    created_at=draft.created_at,
                    payload=self.store._encode(draft.model_dump_json(), kind="patch", row_id=key),
                )
                self._draft(session, row)
                session.add(row)
                session.add(
                    AuditRow(
                        id=str(uuid4()),
                        action="patch.draft_created",
                        resource_id=key,
                        created_at=datetime.now(UTC),
                    )
                )
            return draft, True
        except IntegrityError:
            with self.store._sessions() as session:
                existing = session.get(PatchRow, key)
                if existing is None:
                    raise
                return self._draft_replay(session, existing, draft), False

    def list_drafts(self, *, after_id: UUID, limit: int, offset: int) -> list[PatchDraft]:
        query = (
            select(PatchRow)
            .where(PatchRow.after_configuration_id == str(after_id))
            .order_by(PatchRow.created_at.desc(), PatchRow.id.desc())
        )
        with self.store._sessions() as session:
            return [
                self._draft(session, row)
                for row in session.scalars(query.limit(limit).offset(offset))
            ]

    def _review(self, row: VerificationRow, draft: PatchDraft) -> VerificationRun:
        try:
            if len(row.payload) > 8 * 1024 * 1024:
                raise ValueError("oversized encrypted review")
            contents = self.store._decode(row.payload, kind="verification", row_id=row.id)
            if len(contents.encode("utf-8")) > MAX_RECORD_BYTES:
                raise ValueError("oversized stored review")
            run = VerificationRun.model_validate_json(contents)
            for parse, snapshot in (
                (run.preflight.before, draft.diff.before),
                (run.preflight.after, draft.diff.after),
            ):
                if (parse.confidence, parse.warning_count, parse.unparsed_count) != (
                    snapshot.parser_confidence,
                    snapshot.warning_count,
                    snapshot.unparsed_count,
                ):
                    raise ValueError("review parser diagnostics differ")
            summary = (str(run.verification_id), str(run.patch_id), run.created_at)
            if summary != (row.id, row.patch_id, self._time(row.created_at)) or (
                run.patch_id != draft.patch_id
                or run.draft_sha256 != draft.draft_sha256
                or run.created_at < draft.created_at
                or run.before
                != SnapshotBinding.model_validate(
                    draft.diff.before.model_dump(
                        include={
                            "configuration_id",
                            "device_id",
                            "source_sha256",
                            "created_at",
                        }
                    )
                )
                or run.after
                != SnapshotBinding.model_validate(
                    draft.diff.after.model_dump(
                        include={
                            "configuration_id",
                            "device_id",
                            "source_sha256",
                            "created_at",
                        }
                    )
                )
            ):
                raise ValueError("review binding differs")
            return run
        except ValueError:
            raise StorageIntegrityError("Stored data is unavailable.") from None

    def get_review(self, verification_id: UUID) -> VerificationRun | None:
        with self.store._sessions() as session:
            row = session.get(VerificationRow, str(verification_id))
            if row is None:
                return None
            parent = session.get(PatchRow, row.patch_id)
            if parent is None:
                raise StorageIntegrityError("Stored data is unavailable.")
            return self._review(row, self._draft(session, parent))

    def _review_replay(
        self, session: Session, row: VerificationRow, incoming: VerificationRun
    ) -> VerificationRun:
        parent = session.get(PatchRow, row.patch_id)
        if parent is None:
            raise StorageIntegrityError("Stored data is unavailable.")
        stored = self._review(row, self._draft(session, parent))
        if (stored.patch_id, stored.draft_sha256, stored.kind) != (
            incoming.patch_id,
            incoming.draft_sha256,
            incoming.kind,
        ):
            raise PatchConflict("verification identity is already bound")
        return stored

    def add_review(self, run: VerificationRun) -> tuple[VerificationRun, bool]:
        run = VerificationRun.model_validate_json(run.model_dump_json())
        key = str(run.verification_id)
        try:
            with self.store._sessions.begin() as session:
                existing = session.get(VerificationRow, key)
                if existing is not None:
                    return self._review_replay(session, existing, run), False
                parent = session.get(PatchRow, str(run.patch_id))
                if parent is None:
                    raise StorageIntegrityError("Stored data is unavailable.")
                row = VerificationRow(
                    id=key,
                    patch_id=str(run.patch_id),
                    created_at=run.created_at,
                    payload=self.store._encode(
                        run.model_dump_json(), kind="verification", row_id=key
                    ),
                )
                self._review(row, self._draft(session, parent))
                session.add(row)
                session.add(
                    AuditRow(
                        id=str(uuid4()),
                        action="patch.local_review_recorded",
                        resource_id=key,
                        created_at=datetime.now(UTC),
                    )
                )
            return run, True
        except IntegrityError:
            with self.store._sessions() as session:
                existing = session.get(VerificationRow, key)
                if existing is None:
                    raise
                return self._review_replay(session, existing, run), False

    def list_reviews(self, draft: PatchDraft, *, limit: int, offset: int) -> list[VerificationRun]:
        query = (
            select(VerificationRow)
            .where(VerificationRow.patch_id == str(draft.patch_id))
            .order_by(VerificationRow.created_at.desc(), VerificationRow.id.desc())
        )
        with self.store._sessions() as session:
            return [
                self._review(row, draft)
                for row in session.scalars(query.limit(limit).offset(offset))
            ]
