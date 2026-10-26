"""Encrypted immutable native candidates with pure history checks and atomic domain audit."""

from datetime import UTC, datetime
from uuid import UUID, uuid4

from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.contracts import AnalysisResult, ConfigurationSnapshot
from app.api.native_patch_contracts import (
    NativePatchBudgetError,
    NativePatchPrivate,
    validate_native_patch_parent,
)
from app.db.patch_records import PatchConflict
from app.db.store import StorageIntegrityError, Store
from app.db.tables import AnalysisRow, AuditRow, ConfigurationRow, NativePatchCandidateRow

MAX_NATIVE_PATCH_TEXT_BYTES = 2 * 1024 * 1024
MAX_NATIVE_PATCH_LINES = 10_000
MAX_NATIVE_PATCH_PROOF_BYTES = 512 * 1024
MAX_NATIVE_PATCH_PUBLIC_BYTES = 2 * 1024 * 1024
MAX_NATIVE_PATCH_PRIVATE_BYTES = 8 * 1024 * 1024
MAX_NATIVE_PATCH_CIPHERTEXT_BYTES = 12 * 1024 * 1024


class NativePatchInputNotFound(ValueError):
    """An explicitly selected configuration or analysis does not exist."""


class NativePatchTooLarge(ValueError):
    """A new candidate exceeds its text, proof, payload or encryption budget."""


class NativePatchRecords:
    def __init__(self, store: Store) -> None:
        self.store = store

    @staticmethod
    def _sql_time(value: datetime) -> datetime:
        # SQLite strips timezone information. Only values read from SQL get this rule.
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)

    def _snapshot(self, row: ConfigurationRow) -> ConfigurationSnapshot:
        snapshot = self.store._snapshot(row)
        if snapshot.created_at.utcoffset() is None or (
            snapshot.created_at != self._sql_time(row.created_at)
        ):
            raise StorageIntegrityError("Stored data is unavailable.")
        return snapshot

    def _parents(
        self, session: Session, configuration_id: UUID, analysis_id: UUID
    ) -> tuple[ConfigurationSnapshot, AnalysisResult]:
        configuration = session.get(ConfigurationRow, str(configuration_id))
        analysis_row = session.get(AnalysisRow, str(analysis_id))
        if configuration is None or analysis_row is None:
            raise NativePatchInputNotFound("Selected native candidate inputs are unavailable.")
        snapshot = self._snapshot(configuration)
        analysis = self.store._analysis(analysis_row)
        if analysis.created_at.utcoffset() is None or (
            analysis.created_at != self._sql_time(analysis_row.created_at)
        ):
            raise StorageIntegrityError("Stored data is unavailable.")
        return snapshot, analysis

    def _validate_parents(self, session: Session, private: NativePatchPrivate) -> None:
        snapshot, analysis = self._parents(
            session, private.public.configuration_id, private.public.request.analysis_id
        )
        validate_native_patch_parent(private.public, snapshot, analysis)

    @staticmethod
    def _payload(private: NativePatchPrivate) -> str:
        for value in (private.before_text, private.candidate_text):
            if len(value.encode("utf-8")) > MAX_NATIVE_PATCH_TEXT_BYTES or (
                len(value.splitlines()) > MAX_NATIVE_PATCH_LINES
            ):
                raise NativePatchTooLarge("Native candidate exceeds its retained text budget.")
        if len(private.public.review_json.encode("utf-8")) > MAX_NATIVE_PATCH_PROOF_BYTES:
            raise NativePatchTooLarge("Native candidate exceeds its proof budget.")
        if len(private.public.model_dump_json(warnings=False).encode("utf-8")) > (
            MAX_NATIVE_PATCH_PUBLIC_BYTES
        ):
            raise NativePatchTooLarge("Native candidate exceeds its public payload budget.")
        raw = private.model_dump_json(warnings=False)
        if len(raw.encode("utf-8")) > MAX_NATIVE_PATCH_PRIVATE_BYTES:
            raise NativePatchTooLarge("Native candidate exceeds its private payload budget.")
        return raw

    def _candidate(self, session: Session, row: NativePatchCandidateRow) -> NativePatchPrivate:
        try:
            if len(row.payload.encode("utf-8")) > MAX_NATIVE_PATCH_CIPHERTEXT_BYTES:
                raise ValueError("oversized native candidate ciphertext")
            raw = self.store._decode(row.payload, kind="native_patch_candidate", row_id=row.id)
            if len(raw.encode("utf-8")) > MAX_NATIVE_PATCH_PRIVATE_BYTES:
                raise ValueError("oversized native candidate payload")
            private = NativePatchPrivate.model_validate_json(raw)
            self._payload(private)
            public = private.public
            if (
                str(public.candidate_id),
                str(public.configuration_id),
                str(public.request.analysis_id),
                public.created_at,
                public.review_sha256,
            ) != (
                row.id,
                row.configuration_id,
                row.analysis_id,
                self._sql_time(row.created_at),
                row.public_sha256,
            ):
                raise ValueError("native candidate metadata differs")
            self._validate_parents(session, private)
            return private
        except (ValueError, TypeError, AttributeError):
            raise StorageIntegrityError("Stored data is unavailable.") from None

    def _get(self, session: Session, candidate_id: UUID) -> NativePatchPrivate | None:
        row = session.get(NativePatchCandidateRow, str(candidate_id))
        return self._candidate(session, row) if row is not None else None

    def get(self, candidate_id: UUID) -> NativePatchPrivate | None:
        with self.store._sessions() as session:
            return self._get(session, candidate_id)

    def configuration_exists(self, configuration_id: UUID) -> bool:
        with self.store._sessions() as session:
            row = session.get(ConfigurationRow, str(configuration_id))
            if row is None:
                return False
            self._snapshot(row)
            return True

    def list_ids(self, configuration_id: UUID, *, limit: int, offset: int) -> list[UUID]:
        query = (
            select(NativePatchCandidateRow)
            .where(NativePatchCandidateRow.configuration_id == str(configuration_id))
            .order_by(NativePatchCandidateRow.created_at.desc(), NativePatchCandidateRow.id.desc())
        )
        with self.store._sessions() as session:
            return [
                self._candidate(session, row).public.candidate_id
                for row in session.scalars(query.limit(limit).offset(offset))
            ]

    @staticmethod
    def _same(stored: NativePatchPrivate, incoming: NativePatchPrivate) -> None:
        if (stored.public.configuration_id, stored.public.request) != (
            incoming.public.configuration_id,
            incoming.public.request,
        ):
            raise PatchConflict("Native candidate identity is already bound.")

    @staticmethod
    def _audit(session: Session, key: str) -> None:
        session.add(
            AuditRow(
                id=str(uuid4()),
                action="native_patch.created",
                resource_id=key,
                created_at=datetime.now(UTC),
            )
        )

    def save(self, private: NativePatchPrivate) -> tuple[NativePatchPrivate, bool]:
        try:
            raw = self._payload(private)
            # Typed copies can bypass nested validators; only serialized revalidation is trusted.
            private = NativePatchPrivate.model_validate_json(raw)
        except NativePatchTooLarge:
            raise
        except NativePatchBudgetError:
            raise NativePatchTooLarge("Native candidate exceeds its artifact budget.") from None
        except ValidationError as exc:
            # Pydantic retains a validator's budget exception in its structured context.
            if any(
                isinstance(error.get("ctx", {}).get("error"), NativePatchBudgetError)
                for error in exc.errors(include_input=False, include_url=False)
            ):
                raise NativePatchTooLarge("Native candidate exceeds its artifact budget.") from None
            raise PatchConflict("Native candidate bindings conflict.") from None
        except (ValueError, TypeError, AttributeError):
            raise PatchConflict("Native candidate bindings conflict.") from None
        key = str(private.public.candidate_id)
        try:
            with self.store._sessions.begin() as session:
                existing = self._get(session, private.public.candidate_id)
                if existing is not None:
                    self._same(existing, private)
                    return existing, False
                try:
                    self._validate_parents(session, private)
                except (NativePatchInputNotFound, StorageIntegrityError):
                    raise
                except ValueError:
                    raise PatchConflict("Selected native candidate bindings conflict.") from None
                payload = self.store._encode(raw, kind="native_patch_candidate", row_id=key)
                if len(payload.encode("utf-8")) > MAX_NATIVE_PATCH_CIPHERTEXT_BYTES:
                    raise NativePatchTooLarge("Native candidate exceeds its storage budget.")
                session.add(
                    NativePatchCandidateRow(
                        id=key,
                        configuration_id=str(private.public.configuration_id),
                        analysis_id=str(private.public.request.analysis_id),
                        created_at=private.public.created_at.astimezone(UTC),
                        public_sha256=private.public.review_sha256,
                        payload=payload,
                    )
                )
                self._audit(session, key)
            return private, True
        except IntegrityError:
            # A losing unique-ID insert has rolled back, including its attempted domain audit.
            winner = self.get(private.public.candidate_id)
            if winner is None:
                raise
            self._same(winner, private)
            return winner, False
