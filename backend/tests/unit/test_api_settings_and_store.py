"""Explicit settings, idempotent migrations, foreign keys and atomic audit writes."""

from pathlib import Path
from uuid import UUID

import app.db.migrate as migration_module
import pytest
from alembic import command
from alembic.config import Config
from app.api.contracts import UploadConfiguration
from app.api.service import AnalysisService
from app.core.settings import ApiSettings
from app.db.migrate import main, upgrade_database
from app.db.store import Store
from cryptography.fernet import Fernet
from sqlalchemy import inspect, text
from sqlalchemy.exc import IntegrityError, OperationalError


def settings_for(tmp_path: Path) -> ApiSettings:
    return ApiSettings(
        f"sqlite:///{tmp_path / 'history.sqlite3'}",
        "test-service-token-minimum-32-characters",
        Fernet.generate_key().decode("ascii"),
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("database_url", "invalid-private-database"),
        ("database_url", "sqlite:///:memory:"),
        ("database_url", "mysql://private:password@host/db"),
        ("api_token", "short"),
        ("api_token", "a" * 32 + "\x00"),
        ("encryption_key", "private-invalid-key"),
    ],
)
def test_settings_fail_without_disclosing_values(tmp_path: Path, field: str, value: str) -> None:
    original = settings_for(tmp_path)
    values = {
        name: getattr(original, name) for name in ("database_url", "api_token", "encryption_key")
    } | {field: value}
    with pytest.raises(ValueError) as error:
        ApiSettings(**values)
    assert value not in str(error.value)
    assert error.value.__suppress_context__
    assert original.api_token not in repr(original)
    assert original.encryption_key not in repr(original)


def test_environment_is_opt_in_and_partial_config_is_rejected(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    for name in ("NETCONFIG_DATABASE_URL", "NETCONFIG_API_TOKEN", "NETCONFIG_ENCRYPTION_KEY"):
        monkeypatch.delenv(name, raising=False)
    assert ApiSettings.from_environment() is None
    selected = settings_for(tmp_path)
    monkeypatch.setenv("NETCONFIG_DATABASE_URL", selected.database_url)
    with pytest.raises(ValueError, match="configured together"):
        ApiSettings.from_environment()
    monkeypatch.setenv("NETCONFIG_API_TOKEN", selected.api_token)
    monkeypatch.setenv("NETCONFIG_ENCRYPTION_KEY", selected.encryption_key)
    assert ApiSettings.from_environment() == selected


def test_migration_is_explicit_idempotent_and_preserves_records(tmp_path: Path) -> None:
    store = Store(settings_for(tmp_path))
    try:
        assert not store.ready()
        upgrade_database(store.engine)
        assert store.ready()
        snapshot = AnalysisService(store).upload(
            UploadConfiguration(
                device_id="00000000-0000-0000-0000-000000000001",
                filename="edge.cfg",
                content="hostname edge\n",
            )
        )
        upgrade_database(store.engine)
        assert store.get_configuration(snapshot.configuration_id) == snapshot
        assert set(inspect(store.engine).get_table_names()) == {
            "alembic_version",
            "devices",
            "configurations",
            "analyses",
            "audit_events",
            "models",
        }
        with store.engine.begin() as connection, pytest.raises(IntegrityError):
            connection.execute(
                text(
                    "INSERT INTO analyses (id, configuration_id, created_at, payload) "
                    "VALUES ('orphan', 'missing', CURRENT_TIMESTAMP, 'encrypted')"
                )
            )
    finally:
        store.close()


def test_registry_migration_preserves_initial_schema_history(tmp_path: Path) -> None:
    store = Store(settings_for(tmp_path))
    try:
        migration = Config()
        migration.set_main_option(
            "script_location", str(Path(migration_module.__file__).parent / "migrations")
        )
        with store.engine.begin() as connection:
            migration.attributes["connection"] = connection
            command.upgrade(migration, "0001_initial")
        assert not store.ready()
        service = AnalysisService(store)
        snapshot = service.upload(
            UploadConfiguration(
                device_id=UUID(int=1),
                filename="legacy.cfg",
                content="hostname legacy\n",
            )
        )
        result = service.analyze(snapshot.configuration_id)
        assert result is not None
        # Simulate the previously persisted v0.1 payload with no statistical field.
        payload = store._encode(
            result.model_dump_json(exclude={"statistical"}),
            kind="analysis",
            row_id=str(result.analysis_id),
        )
        with store.engine.begin() as connection:
            connection.execute(
                text("UPDATE analyses SET payload=:payload WHERE id=:id"),
                {"payload": payload, "id": str(result.analysis_id)},
            )
        upgrade_database(store.engine)
        assert store.ready()
        assert store.get_configuration(snapshot.configuration_id) == snapshot
        assert store.get_analysis(result.analysis_id) == result
        assert store.list_models(limit=20, offset=0) == []
        upgrade_database(store.engine)
        assert store.get_analysis(result.analysis_id) == result
    finally:
        store.close()


def test_failed_audit_rolls_back_whole_upload(tmp_path: Path) -> None:
    store = Store(settings_for(tmp_path))
    try:
        upgrade_database(store.engine)
        with store.engine.begin() as connection:
            connection.execute(text("DROP TABLE audit_events"))
        with pytest.raises(OperationalError):
            AnalysisService(store).upload(
                UploadConfiguration(
                    device_id="00000000-0000-0000-0000-000000000001",
                    filename="edge.cfg",
                    content="hostname edge\n",
                )
            )
        with store.engine.connect() as connection:
            for table in ("devices", "configurations"):
                assert connection.execute(text(f"SELECT count(*) FROM {table}")).scalar_one() == 0
    finally:
        store.close()


def test_migration_command_requires_explicit_database(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    monkeypatch.delenv("NETCONFIG_DATABASE_URL", raising=False)
    assert main() == 2
    assert "required" in capsys.readouterr().out
    monkeypatch.setenv("NETCONFIG_DATABASE_URL", settings_for(tmp_path).database_url)
    assert main() == 0
    assert "upgraded" in capsys.readouterr().out
