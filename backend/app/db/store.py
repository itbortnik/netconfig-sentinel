"""Short transactional sessions and authenticated encryption of sensitive payloads."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from uuid import UUID, uuid4

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import Engine, create_engine, event, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from app.api.contracts import AnalysisResult, ConfigurationSnapshot, RegisteredModel
from app.api.feedback_contracts import FeedbackRecord
from app.core.settings import ApiSettings
from app.db.migrate import SCHEMA_REVISION
from app.db.tables import AnalysisRow, AuditRow, ConfigurationRow, DeviceRow, FeedbackRow, ModelRow
from app.domain.fingerprints import finding_fingerprint


class DeviceIdentityConflict(ValueError):
    pass


class StorageIntegrityError(Exception):
    """Stored content could not be authenticated or validated; never expose its details."""


class FeedbackConflict(ValueError):
    """An assessment is stale or its idempotency identity is already bound differently."""


def make_engine(database_url: str) -> Engine:
    engine = create_engine(database_url, echo=False, hide_parameters=True, pool_pre_ping=True)
    if engine.dialect.name == "sqlite":

        @event.listens_for(engine, "connect")
        def sqlite_foreign_keys(connection: object, _: object) -> None:
            # SQLAlchemy's connect event supplies a DBAPI connection.
            connection.execute("PRAGMA foreign_keys=ON")  # type: ignore[attr-defined]

    return engine


class Store:
    def __init__(self, settings: ApiSettings) -> None:
        self.engine = make_engine(settings.database_url)
        self._cipher = Fernet(settings.encryption_key.encode("ascii"))
        self._sessions = sessionmaker(self.engine, expire_on_commit=False)

    def close(self) -> None:
        self.engine.dispose()

    def ready(self) -> bool:
        try:
            with self.engine.connect() as connection:
                revisions = (
                    connection.execute(text("SELECT version_num FROM alembic_version"))
                    .scalars()
                    .all()
                )
                if revisions != [SCHEMA_REVISION]:
                    return False
                for table in (
                    "devices",
                    "configurations",
                    "analyses",
                    "audit_events",
                    "models",
                    "finding_feedback",
                    "patch_proposals",
                    "verification_runs",
                ):
                    connection.execute(text(f"SELECT 1 FROM {table} WHERE 1=0"))
            return True
        except Exception:
            return False

    def _encode(self, contents: str, *, kind: str, row_id: str) -> str:
        envelope = json.dumps(
            {"kind": kind, "id": row_id, "contents": contents}, separators=(",", ":")
        )
        return self._cipher.encrypt(envelope.encode("utf-8")).decode("ascii")

    def _decode(self, ciphertext: str, *, kind: str, row_id: str) -> str:
        try:
            envelope = json.loads(self._cipher.decrypt(ciphertext.encode("ascii")))
            if envelope["kind"] != kind or envelope["id"] != row_id:
                raise ValueError("payload binding mismatch")
            contents = envelope["contents"]
            if not isinstance(contents, str):
                raise ValueError("invalid payload")
            return contents
        except (InvalidToken, ValueError, KeyError, TypeError):
            raise StorageIntegrityError("Stored data is unavailable.") from None

    def _snapshot(self, row: ConfigurationRow) -> ConfigurationSnapshot:
        try:
            result = ConfigurationSnapshot.model_validate_json(
                self._decode(row.payload, kind="configuration", row_id=row.id)
            )
        except ValueError:
            raise StorageIntegrityError("Stored data is unavailable.") from None
        if (
            str(result.configuration_id),
            str(result.device_id),
            result.canonical.source.sha256,
        ) != (row.id, row.device_id, row.source_sha256):
            raise StorageIntegrityError("Stored data is unavailable.")
        return result

    def _analysis(self, row: AnalysisRow) -> AnalysisResult:
        try:
            result = AnalysisResult.model_validate_json(
                self._decode(row.payload, kind="analysis", row_id=row.id)
            )
        except ValueError:
            raise StorageIntegrityError("Stored data is unavailable.") from None
        if (str(result.analysis_id), str(result.configuration_id)) != (
            row.id,
            row.configuration_id,
        ):
            raise StorageIntegrityError("Stored data is unavailable.")
        return result

    def _model(self, row: ModelRow) -> RegisteredModel:
        try:
            if len(row.payload) > 32 * 1024 * 1024:
                raise ValueError("model payload exceeds limits")
            result = RegisteredModel.model_validate_json(
                self._decode(row.payload, kind="model", row_id=row.id)
            )
            if (str(result.summary.model_id), result.summary.artifact_sha256) != (
                row.id,
                row.artifact_sha256,
            ):
                raise ValueError("model row differs from manifest")
        except ValueError:
            raise StorageIntegrityError("Stored data is unavailable.") from None
        return result

    def add_model(self, model: RegisteredModel) -> None:
        # Revalidate even when callers used model_copy/model_construct.
        model = RegisteredModel.model_validate_json(model.model_dump_json())
        model_id = str(model.summary.model_id)
        with self._sessions.begin() as session:
            session.add(
                ModelRow(
                    id=model_id,
                    created_at=model.summary.created_at,
                    artifact_sha256=model.summary.artifact_sha256,
                    payload=self._encode(model.model_dump_json(), kind="model", row_id=model_id),
                )
            )
            session.add(
                AuditRow(
                    id=str(uuid4()),
                    action="model.trained",
                    resource_id=model_id,
                    created_at=datetime.now(UTC),
                )
            )

    def get_model(self, model_id: UUID) -> RegisteredModel | None:
        with self._sessions() as session:
            row = session.get(ModelRow, str(model_id))
            return self._model(row) if row is not None else None

    def list_models(self, *, limit: int, offset: int) -> list[RegisteredModel]:
        query = select(ModelRow).order_by(ModelRow.created_at.desc(), ModelRow.id.desc())
        with self._sessions() as session:
            return [self._model(row) for row in session.scalars(query.limit(limit).offset(offset))]

    def add_configuration(self, snapshot: ConfigurationSnapshot) -> None:
        config = snapshot.canonical
        device_id, snapshot_id = str(snapshot.device_id), str(snapshot.configuration_id)
        identity = json.dumps(
            [config.device.vendor.value, config.device.platform, config.device.hostname]
        )
        with self._sessions.begin() as session:
            device = session.get(DeviceRow, device_id)
            if device is None:
                session.add(
                    DeviceRow(
                        id=device_id,
                        identity_payload=self._encode(identity, kind="device", row_id=device_id),
                    )
                )
                session.flush()
            elif self._decode(device.identity_payload, kind="device", row_id=device_id) != identity:
                raise DeviceIdentityConflict("device identity differs from existing history")
            session.add(
                ConfigurationRow(
                    id=snapshot_id,
                    device_id=device_id,
                    source_sha256=config.source.sha256,
                    created_at=snapshot.created_at,
                    payload=self._encode(
                        snapshot.model_dump_json(), kind="configuration", row_id=snapshot_id
                    ),
                )
            )
            session.add(
                AuditRow(
                    id=str(uuid4()),
                    action="configuration.created",
                    resource_id=snapshot_id,
                    created_at=datetime.now(UTC),
                )
            )

    def get_configuration(self, configuration_id: UUID) -> ConfigurationSnapshot | None:
        with self._sessions() as session:
            row = session.get(ConfigurationRow, str(configuration_id))
            return self._snapshot(row) if row is not None else None

    def list_configurations(
        self, *, device_id: UUID | None, limit: int, offset: int
    ) -> list[ConfigurationSnapshot]:
        query = select(ConfigurationRow).order_by(
            ConfigurationRow.created_at.desc(), ConfigurationRow.id.desc()
        )
        if device_id is not None:
            query = query.where(ConfigurationRow.device_id == str(device_id))
        with self._sessions() as session:
            return [
                self._snapshot(row) for row in session.scalars(query.limit(limit).offset(offset))
            ]

    def add_analysis(self, result: AnalysisResult) -> None:
        analysis_id = str(result.analysis_id)
        with self._sessions.begin() as session:
            session.add(
                AnalysisRow(
                    id=analysis_id,
                    configuration_id=str(result.configuration_id),
                    created_at=result.created_at,
                    payload=self._encode(
                        result.model_dump_json(), kind="analysis", row_id=analysis_id
                    ),
                )
            )
            session.add(
                AuditRow(
                    id=str(uuid4()),
                    action="analysis.completed",
                    resource_id=analysis_id,
                    created_at=datetime.now(UTC),
                )
            )

    def get_analysis(self, analysis_id: UUID) -> AnalysisResult | None:
        with self._sessions() as session:
            row = session.get(AnalysisRow, str(analysis_id))
            return self._analysis(row) if row is not None else None

    def list_analyses(
        self, *, configuration_id: UUID | None, limit: int, offset: int
    ) -> list[AnalysisResult]:
        query = select(AnalysisRow).order_by(AnalysisRow.created_at.desc(), AnalysisRow.id.desc())
        if configuration_id is not None:
            query = query.where(AnalysisRow.configuration_id == str(configuration_id))
        with self._sessions() as session:
            return [
                self._analysis(row) for row in session.scalars(query.limit(limit).offset(offset))
            ]

    @staticmethod
    def _check_feedback_binding(record: FeedbackRecord, analysis: AnalysisResult) -> None:
        finding = next(
            (item for item in analysis.findings if item.finding_id == record.finding_id), None
        )
        if finding is None or (
            record.analysis_id != analysis.analysis_id
            or record.configuration_id != analysis.configuration_id
            or record.device_id != analysis.device_id
            or record.source_sha256 != analysis.source_sha256
            or record.finding_sha256 != finding_fingerprint(finding)
        ):
            raise StorageIntegrityError("Stored data is unavailable.")

    def _feedback(self, row: FeedbackRow, analysis: AnalysisResult) -> FeedbackRecord:
        try:
            record = FeedbackRecord.model_validate_json(
                self._decode(row.payload, kind="feedback", row_id=row.id)
            )
        except ValueError:
            raise StorageIntegrityError("Stored data is unavailable.") from None
        row_time = (
            row.created_at
            if row.created_at.tzinfo is not None
            else row.created_at.replace(tzinfo=UTC)
        )
        if (
            str(record.feedback_id),
            str(record.analysis_id),
            str(record.finding_id),
            record.created_at,
        ) != (
            row.id,
            row.analysis_id,
            row.finding_id,
            row_time,
        ):
            raise StorageIntegrityError("Stored data is unavailable.")
        self._check_feedback_binding(record, analysis)
        return record

    def _feedback_replay(
        self, session: Session, row: FeedbackRow, incoming: FeedbackRecord
    ) -> FeedbackRecord:
        parent = session.get(AnalysisRow, row.analysis_id)
        if parent is None:
            raise StorageIntegrityError("Stored data is unavailable.")
        stored = self._feedback(row, self._analysis(parent))
        if stored.model_dump(exclude={"created_at"}) != incoming.model_dump(exclude={"created_at"}):
            raise FeedbackConflict("feedback identity is already bound")
        return stored

    def add_feedback(self, record: FeedbackRecord) -> tuple[FeedbackRecord, bool]:
        record = FeedbackRecord.model_validate_json(record.model_dump_json())
        feedback_id = str(record.feedback_id)
        try:
            with self._sessions.begin() as session:
                existing = session.get(FeedbackRow, feedback_id)
                if existing is not None:
                    return self._feedback_replay(session, existing, record), False
                parent = session.get(AnalysisRow, str(record.analysis_id))
                if parent is None:
                    raise StorageIntegrityError("Stored data is unavailable.")
                self._check_feedback_binding(record, self._analysis(parent))
                session.add(
                    FeedbackRow(
                        id=feedback_id,
                        analysis_id=str(record.analysis_id),
                        finding_id=str(record.finding_id),
                        created_at=record.created_at,
                        payload=self._encode(
                            record.model_dump_json(), kind="feedback", row_id=feedback_id
                        ),
                    )
                )
                session.add(
                    AuditRow(
                        id=str(uuid4()),
                        action="finding.feedback_recorded",
                        resource_id=feedback_id,
                        created_at=datetime.now(UTC),
                    )
                )
            return record, True
        except IntegrityError:
            # A racing replay may lose the unique-ID insert; its transaction has rolled back.
            with self._sessions() as session:
                existing = session.get(FeedbackRow, feedback_id)
                if existing is None:
                    raise
                return self._feedback_replay(session, existing, record), False

    def list_feedback(
        self, *, analysis: AnalysisResult, finding_id: UUID, limit: int, offset: int
    ) -> list[FeedbackRecord]:
        query = (
            select(FeedbackRow)
            .where(
                FeedbackRow.analysis_id == str(analysis.analysis_id),
                FeedbackRow.finding_id == str(finding_id),
            )
            .order_by(FeedbackRow.created_at.desc(), FeedbackRow.id.desc())
        )
        with self._sessions() as session:
            return [
                self._feedback(row, analysis)
                for row in session.scalars(query.limit(limit).offset(offset))
            ]
