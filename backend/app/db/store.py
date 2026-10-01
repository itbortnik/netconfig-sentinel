"""Short transactional sessions and authenticated encryption of sensitive payloads."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from uuid import UUID, uuid4

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import Engine, create_engine, event, select, text
from sqlalchemy.orm import sessionmaker

from app.api.contracts import AnalysisResult, ConfigurationSnapshot
from app.core.settings import ApiSettings
from app.db.migrate import SCHEMA_REVISION
from app.db.tables import AnalysisRow, AuditRow, ConfigurationRow, DeviceRow


class DeviceIdentityConflict(ValueError):
    pass


class StorageIntegrityError(Exception):
    """Stored content could not be authenticated or validated; never expose its details."""


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
                for table in ("devices", "configurations", "analyses", "audit_events"):
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
