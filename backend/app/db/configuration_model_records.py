"""Reserve one immutable model attempt; save terminal result and audit atomically."""

from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.configuration_model_contracts import (
    MAX_CONFIGURATION_MODEL_BYTES,
    ConfigurationModelIntent,
    ConfigurationModelOutcome,
    ConfigurationModelRun,
    fingerprint,
)
from app.api.contracts import SnapshotBinding
from app.db.store import StorageIntegrityError, Store
from app.db.tables import (
    AnalysisRow,
    AuditRow,
    ConfigurationModelIntentRow,
    ConfigurationModelOutcomeRow,
    ConfigurationRow,
)


class ConfigurationModelConflict(ValueError):
    pass


class ConfigurationModelRecords:
    def __init__(self, store: Store) -> None:
        self.store = store

    def _plain(self, ciphertext: str, kind: str, key: str) -> str:
        if len(ciphertext) > MAX_CONFIGURATION_MODEL_BYTES * 4:
            raise ValueError("oversized configuration model ciphertext")
        value = self.store._decode(ciphertext, kind=kind, row_id=key)
        if len(value.encode()) > MAX_CONFIGURATION_MODEL_BYTES:
            raise ValueError("oversized configuration model record")
        return value

    def _intent(
        self, session: Session, row: ConfigurationModelIntentRow
    ) -> ConfigurationModelIntent:
        try:
            intent = ConfigurationModelIntent.model_validate_json(
                self._plain(row.payload, "configuration_model_intent", row.id)
            )
            timestamp = (
                row.created_at if row.created_at.tzinfo else row.created_at.replace(tzinfo=UTC)
            )
            if (
                str(intent.request.inference_id),
                str(intent.request.analysis_id),
                str(intent.source.configuration_id),
                intent.created_at,
            ) != (row.id, row.analysis_id, row.configuration_id, timestamp):
                raise ValueError("configuration model row differs")
            analysis_row = session.get(AnalysisRow, row.analysis_id)
            source_row = session.get(ConfigurationRow, row.configuration_id)
            if analysis_row is None or source_row is None:
                raise ValueError("configuration model parent missing")
            analysis, snapshot = (
                self.store._analysis(analysis_row),
                self.store._snapshot(source_row),
            )
            if (
                SnapshotBinding.from_snapshot(snapshot) != intent.source
                or analysis.configuration_id != intent.source.configuration_id
                or analysis.device_id != intent.source.device_id
                or analysis.source_sha256 != intent.source.source_sha256
                or analysis.created_at > intent.created_at
                or fingerprint(analysis) != intent.analysis_sha256
            ):
                raise ValueError("configuration model selected analysis differs")
            return intent
        except ValueError:
            raise StorageIntegrityError("Stored data is unavailable.") from None

    def _outcome(
        self, row: ConfigurationModelOutcomeRow, intent: ConfigurationModelIntent
    ) -> ConfigurationModelOutcome:
        try:
            outcome = ConfigurationModelOutcome.model_validate_json(
                self._plain(row.payload, "configuration_model_outcome", row.inference_id)
            )
            if (
                outcome.inference_id != intent.request.inference_id
                or str(outcome.inference_id) != row.inference_id
                or outcome.intent_sha256 != fingerprint(intent)
            ):
                raise ValueError("configuration model outcome differs")
            ConfigurationModelRun.from_records(intent, outcome)
            return outcome
        except ValueError:
            raise StorageIntegrityError("Stored data is unavailable.") from None

    def get(
        self, inference_id: UUID
    ) -> tuple[ConfigurationModelIntent, ConfigurationModelOutcome | None] | None:
        with self.store._sessions() as session:
            row = session.get(ConfigurationModelIntentRow, str(inference_id))
            if row is None:
                return None
            intent = self._intent(session, row)
            outcome = session.get(ConfigurationModelOutcomeRow, str(inference_id))
            return intent, self._outcome(outcome, intent) if outcome else None

    @staticmethod
    def _same_intent(stored: ConfigurationModelIntent, incoming: ConfigurationModelIntent) -> None:
        if stored.request != incoming.request:
            raise ConfigurationModelConflict("Configuration model identity conflicts.")

    def reserve(self, intent: ConfigurationModelIntent) -> bool:
        intent = ConfigurationModelIntent.model_validate_json(intent.model_dump_json())
        key = str(intent.request.inference_id)
        try:
            with self.store._sessions.begin() as session:
                existing = session.get(ConfigurationModelIntentRow, key)
                if existing is not None:
                    self._same_intent(self._intent(session, existing), intent)
                    return False
                row = ConfigurationModelIntentRow(
                    id=key,
                    analysis_id=str(intent.request.analysis_id),
                    configuration_id=str(intent.source.configuration_id),
                    created_at=intent.created_at,
                    payload=self.store._encode(
                        intent.model_dump_json(), kind="configuration_model_intent", row_id=key
                    ),
                )
                self._intent(session, row)
                session.add(row)
                session.add(
                    AuditRow(
                        id=str(uuid4()),
                        action="configuration_model.requested",
                        resource_id=key,
                        created_at=datetime.now(UTC),
                    )
                )
            return True
        except IntegrityError:
            stored = self.get(intent.request.inference_id)
            if stored is None:
                raise
            self._same_intent(stored[0], intent)
            return False

    def complete(self, outcome: ConfigurationModelOutcome) -> None:
        outcome = ConfigurationModelOutcome.model_validate_json(outcome.model_dump_json())
        key = str(outcome.inference_id)
        with self.store._sessions.begin() as session:
            parent = session.get(ConfigurationModelIntentRow, key)
            if parent is None:
                raise StorageIntegrityError("Stored data is unavailable.")
            intent = self._intent(session, parent)
            existing = session.get(ConfigurationModelOutcomeRow, key)
            if existing is not None:
                if self._outcome(existing, intent) != outcome:
                    raise ConfigurationModelConflict("Configuration model outcome conflicts.")
                return
            row = ConfigurationModelOutcomeRow(
                inference_id=key,
                payload=self.store._encode(
                    outcome.model_dump_json(), kind="configuration_model_outcome", row_id=key
                ),
            )
            self._outcome(row, intent)
            session.add(row)
            session.add(
                AuditRow(
                    id=str(uuid4()),
                    action="configuration_model.completed",
                    resource_id=key,
                    created_at=datetime.now(UTC),
                )
            )

    def list_ids(self, *, analysis_id: UUID, limit: int, offset: int) -> list[UUID]:
        query = (
            select(ConfigurationModelIntentRow.id)
            .where(ConfigurationModelIntentRow.analysis_id == str(analysis_id))
            .order_by(
                ConfigurationModelIntentRow.created_at.desc(), ConfigurationModelIntentRow.id.desc()
            )
        )
        with self.store._sessions() as session:
            return [UUID(value) for value in session.scalars(query.limit(limit).offset(offset))]
