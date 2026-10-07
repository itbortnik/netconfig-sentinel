"""Bounded encrypted storage, immutable completion, and stable keyset pagination."""

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import and_, or_, select
from sqlalchemy.exc import IntegrityError

from app.audit.contracts import Completion, OperationPage, OperationRecord, Receipt
from app.db.store import StorageIntegrityError, Store
from app.db.tables import OperationCompletionRow, OperationReceiptRow

MAX_PAYLOAD_BYTES = 64 * 1024


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


class OperationJournal:
    def __init__(self, store: Store) -> None:
        self.store = store

    def ready(self) -> bool:
        # Schema metadata only, independent of permission-gated domain lookup methods.
        return self.store.schema_ready()

    def _receipt(self, row: OperationReceiptRow) -> Receipt:
        try:
            if len(row.payload) > MAX_PAYLOAD_BYTES:
                raise ValueError("oversized receipt")
            receipt = Receipt.model_validate_json(
                self.store._decode(row.payload, kind="operation_receipt", row_id=row.id)
            )
            if str(receipt.operation_id) != row.id or receipt.started_at != _aware(row.created_at):
                raise ValueError("receipt metadata differs from ciphertext")
            return receipt
        except ValueError:
            raise StorageIntegrityError("Stored data is unavailable.") from None

    def _completion(self, row: OperationCompletionRow) -> Completion:
        try:
            if len(row.payload) > MAX_PAYLOAD_BYTES:
                raise ValueError("oversized completion")
            result = Completion.model_validate_json(
                self.store._decode(
                    row.payload, kind="operation_completion", row_id=row.operation_id
                )
            )
            if str(result.operation_id) != row.operation_id or result.completed_at != _aware(
                row.completed_at
            ):
                raise ValueError("completion metadata differs from ciphertext")
            return result
        except ValueError:
            raise StorageIntegrityError("Stored data is unavailable.") from None

    def start(self, receipt: Receipt) -> None:
        receipt = Receipt.model_validate_json(receipt.model_dump_json())
        identity = str(receipt.operation_id)
        with self.store._sessions.begin() as session:
            session.add(
                OperationReceiptRow(
                    id=identity,
                    created_at=receipt.started_at,
                    payload=self.store._encode(
                        receipt.model_dump_json(), kind="operation_receipt", row_id=identity
                    ),
                )
            )

    def complete(self, receipt: Receipt, completion: Completion) -> None:
        completion = Completion.model_validate_json(completion.model_dump_json())
        OperationRecord.combine(receipt, completion)
        identity = str(receipt.operation_id)
        try:
            with self.store._sessions.begin() as session:
                parent = session.get(OperationReceiptRow, identity)
                if parent is None or self._receipt(parent) != receipt:
                    raise StorageIntegrityError("Stored data is unavailable.")
                existing = session.get(OperationCompletionRow, identity)
                if existing is not None:
                    if self._completion(existing) != completion:
                        raise StorageIntegrityError("Stored data is unavailable.")
                    return
                raw = completion.model_dump_json()
                if len(raw.encode("utf-8")) > 32 * 1024:
                    raise ValueError("completion exceeds budget")
                session.add(
                    OperationCompletionRow(
                        operation_id=identity,
                        completed_at=completion.completed_at,
                        payload=self.store._encode(
                            raw, kind="operation_completion", row_id=identity
                        ),
                    )
                )
        except IntegrityError:
            # A duplicate completion may replay exactly, never replace a recorded outcome.
            current = self.get(receipt.operation_id)
            if current is None or current.completion != completion:
                raise StorageIntegrityError("Stored data is unavailable.") from None

    def get(self, operation_id: UUID) -> OperationRecord | None:
        with self.store._sessions() as session:
            row = session.get(OperationReceiptRow, str(operation_id))
            if row is None:
                return None
            complete = session.get(OperationCompletionRow, row.id)
            try:
                return OperationRecord.combine(
                    self._receipt(row), self._completion(complete) if complete else None
                )
            except ValueError:
                raise StorageIntegrityError("Stored data is unavailable.") from None

    def page(
        self,
        *,
        limit: int = 20,
        before: UUID | None = None,
        exclude: UUID | None = None,
    ) -> OperationPage:
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("unsupported journal limit")
        query = select(OperationReceiptRow, OperationCompletionRow).outerjoin(
            OperationCompletionRow, OperationCompletionRow.operation_id == OperationReceiptRow.id
        )
        if exclude is not None:
            query = query.where(OperationReceiptRow.id != str(exclude))
        with self.store._sessions() as session:
            if before is not None:
                cursor = session.get(OperationReceiptRow, str(before))
                if cursor is None:
                    raise ValueError("unknown journal cursor")
                # Authenticate cursor metadata before it can influence the page boundary.
                self._receipt(cursor)
                query = query.where(
                    or_(
                        OperationReceiptRow.created_at < cursor.created_at,
                        and_(
                            OperationReceiptRow.created_at == cursor.created_at,
                            OperationReceiptRow.id < cursor.id,
                        ),
                    )
                )
            rows = session.execute(
                query.order_by(
                    OperationReceiptRow.created_at.desc(), OperationReceiptRow.id.desc()
                ).limit(limit + 1)
            ).all()
            try:
                records = tuple(
                    OperationRecord.combine(
                        self._receipt(row), self._completion(done) if done else None
                    )
                    for row, done in rows[:limit]
                )
                return OperationPage(
                    records=records,
                    next_before=records[-1].receipt.operation_id if len(rows) > limit else None,
                )
            except ValueError:
                raise StorageIntegrityError("Stored data is unavailable.") from None
