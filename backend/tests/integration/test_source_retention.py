"""Explicit original text retention, encrypted exact-byte binding and no HTTP raw read."""

import json
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from alembic import command
from alembic.config import Config
from app.api.contracts import UploadConfiguration
from app.api.service import AnalysisService
from app.core.settings import ApiSettings
from app.db import migrate
from app.db.migrate import upgrade_database
from app.db.source_records import OriginalSourceUnavailable, SourceRecords
from app.db.store import StorageIntegrityError, Store
from app.main import create_app
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.exc import OperationalError

TOKEN = "owned-source-retention-test-service-token-001"
HEADERS = {"Authorization": f"Bearer {TOKEN}"}
SOURCE = "hostname edge\r\nip ssh version 1\r\nusername owned secret 0 owned-password-never-log\r\n"


@pytest.fixture
def storage(tmp_path):
    settings = ApiSettings(
        f"sqlite:///{tmp_path / 'source.sqlite3'}", TOKEN, Fernet.generate_key().decode("ascii")
    )
    store = Store(settings)
    upgrade_database(store.engine)
    yield store, settings
    store.close()


def upload_source(store, *, retain=True, content=SOURCE):
    return AnalysisService(store).upload(
        UploadConfiguration(
            device_id=uuid4(), filename="owned.cfg", content=content, retain_original_source=retain
        )
    )


def read_source(store, snapshot, **changes):
    return SourceRecords(store).get(
        snapshot.configuration_id,
        expected_source_sha256=snapshot.canonical.source.sha256,
        allow_local_read=True,
        **changes,
    )


def test_default_upload_discards_original_and_never_reconstructs_it(storage):
    store, _ = storage
    snapshot = upload_source(store, retain=False)
    with store.engine.connect() as connection:
        assert (
            connection.execute(text("SELECT count(*) FROM configuration_sources")).scalar_one() == 0
        )
    with pytest.raises(OriginalSourceUnavailable, match=r"^Original source is unavailable\.$"):
        read_source(store, snapshot)


def test_opt_in_retains_exact_utf8_crlf_with_encrypted_bound_restart(storage):
    store, settings = storage
    snapshot = upload_source(store)
    record = read_source(store, snapshot)
    assert record.content.encode() == SOURCE.encode()
    assert "owned-password-never-log" not in repr(record) and "owned.cfg" not in repr(record)
    assert "owned-password-never-log" not in snapshot.model_dump_json()
    with store.engine.connect() as connection:
        ciphertext = connection.execute(
            text("SELECT payload FROM configuration_sources")
        ).scalar_one()
        assert SOURCE not in ciphertext and "owned-password-never-log" not in ciphertext
        assert (
            connection.execute(
                text(
                    "SELECT count(*) FROM audit_events WHERE action='configuration.source_retained'"
                )
            ).scalar_one()
            == 1
        )
    restarted = Store(settings)
    try:
        assert read_source(restarted, snapshot) == record
    finally:
        restarted.close()


@pytest.mark.parametrize("permission", [False, None, 1, "true"])
def test_original_read_requires_exact_explicit_permission_before_storage(
    storage, monkeypatch, permission
):
    store, _ = storage
    monkeypatch.setattr(store, "_sessions", lambda: pytest.fail("read without explicit permission"))
    with pytest.raises(OriginalSourceUnavailable):
        SourceRecords(store).get(
            uuid4(), expected_source_sha256="a" * 64, allow_local_read=permission
        )


def test_foreign_selected_source_hash_is_refused_without_disclosure(storage):
    store, _ = storage
    snapshot = upload_source(store)
    with pytest.raises(OriginalSourceUnavailable, match=r"^Original source is unavailable\.$"):
        SourceRecords(store).get(
            snapshot.configuration_id, expected_source_sha256="f" * 64, allow_local_read=True
        )


@pytest.mark.parametrize(
    "mutation",
    [
        "ciphertext",
        "content",
        "filename",
        "canonical_sha256",
        "configuration_id",
        "device_id",
        "created_at",
    ],
)
def test_corrupt_or_foreign_authenticated_source_record_fails_closed(storage, mutation):
    store, _ = storage
    snapshot = upload_source(store)
    key = str(snapshot.configuration_id)
    with store.engine.begin() as connection:
        ciphertext = connection.execute(
            text("SELECT payload FROM configuration_sources WHERE configuration_id=:id"),
            {"id": key},
        ).scalar_one()
        if mutation == "ciphertext":
            changed = "corrupted-private-payload"
        else:
            payload = json.loads(store._decode(ciphertext, kind="configuration_source", row_id=key))
            if mutation in {"configuration_id", "device_id", "created_at"}:
                payload["snapshot"][mutation] = (
                    "2000-01-01T00:00:00Z" if mutation == "created_at" else str(uuid4())
                )
            else:
                payload[mutation] = (
                    "hostname different\n"
                    if mutation == "content"
                    else "foreign.cfg"
                    if mutation == "filename"
                    else "f" * 64
                )
            changed = store._encode(json.dumps(payload), kind="configuration_source", row_id=key)
        connection.execute(
            text("UPDATE configuration_sources SET payload=:payload WHERE configuration_id=:id"),
            {"payload": changed, "id": key},
        )
    with pytest.raises(StorageIntegrityError, match=r"^Stored data is unavailable\.$") as failure:
        read_source(store, snapshot)
    assert SOURCE not in str(failure.value) and failure.value.__suppress_context__


def test_wrong_key_and_ciphertext_row_swap_are_not_valid_sources(storage):
    store, settings = storage
    first = upload_source(store)
    second = upload_source(store, content="hostname another\nip ssh version 1\n")
    wrong = Store(ApiSettings(settings.database_url, TOKEN, Fernet.generate_key().decode("ascii")))
    try:
        with pytest.raises(StorageIntegrityError):
            read_source(wrong, first)
    finally:
        wrong.close()
    with store.engine.begin() as connection:
        ciphertext = connection.execute(
            text("SELECT payload FROM configuration_sources WHERE configuration_id=:id"),
            {"id": str(first.configuration_id)},
        ).scalar_one()
        connection.execute(
            text("UPDATE configuration_sources SET payload=:payload WHERE configuration_id=:id"),
            {"payload": ciphertext, "id": str(second.configuration_id)},
        )
    with pytest.raises(StorageIntegrityError):
        read_source(store, second)


def test_failed_audit_rolls_back_source_snapshot_and_device_together(storage):
    store, _ = storage
    with store.engine.begin() as connection:
        connection.execute(text("DROP TABLE audit_events"))
    with pytest.raises(OperationalError):
        upload_source(store)
    with store.engine.connect() as connection:
        for table in ("configuration_sources", "configurations", "devices"):
            assert connection.execute(text(f"SELECT count(*) FROM {table}")).scalar_one() == 0


@pytest.mark.parametrize("permission", [None, 1, "true", 0])
def test_http_retention_permission_is_strict_and_bad_request_does_not_store(storage, permission):
    store, settings = storage
    with TestClient(create_app(settings)) as client:
        response = client.post(
            "/api/v1/configurations",
            headers=HEADERS,
            json={
                "device_id": str(uuid4()),
                "filename": "owned.cfg",
                "content": SOURCE,
                "retain_original_source": permission,
            },
        )
        assert response.status_code == 400 and "owned-password" not in response.text
    with store.engine.connect() as connection:
        assert connection.execute(text("SELECT count(*) FROM configurations")).scalar_one() == 0


def test_http_opt_in_uses_existing_auth_and_returns_no_raw_source(storage):
    store, settings = storage
    body = {
        "device_id": str(uuid4()),
        "filename": "owned.cfg",
        "content": SOURCE,
        "retain_original_source": True,
        "inventory": {"device_role": "edge", "site_class": "lab", "service_profile": "owned"},
    }
    with TestClient(create_app(settings)) as client:
        assert client.post("/api/v1/configurations", json=body).status_code == 401
        response = client.post("/api/v1/configurations", headers=HEADERS, json=body)
        assert response.status_code == 201 and "owned-password" not in response.text
        cid = response.json()["configuration_id"]
        assert (
            client.get(f"/api/v1/configurations/{cid}/source", headers=HEADERS).status_code == 404
        )
        snapshot = store.get_configuration(UUID(cid))
        assert read_source(store, snapshot).content == SOURCE


def test_legacy_schema_upgrade_preserves_history_without_invented_source(tmp_path):
    settings = ApiSettings(
        f"sqlite:///{tmp_path / 'legacy.sqlite3'}", TOKEN, Fernet.generate_key().decode("ascii")
    )
    store = Store(settings)
    try:
        config = Config()
        config.set_main_option("script_location", str(Path(migrate.__file__).parent / "migrations"))
        with store.engine.begin() as connection:
            config.attributes["connection"] = connection
            command.upgrade(config, "0005_operation_journal")
        snapshot = upload_source(store, retain=False)
        assert not store.ready()
        upgrade_database(store.engine)
        upgrade_database(store.engine)
        assert store.ready() and store.get_configuration(snapshot.configuration_id) == snapshot
        with pytest.raises(OriginalSourceUnavailable):
            read_source(store, snapshot)
    finally:
        store.close()


@pytest.mark.parametrize(
    "content",
    [
        "hostname edge\n! owned Unicode comment: проверка\n",
        "set system host-name edge\r\nset system services ssh protocol-version v1\r\n",
        "hostname edge\nunsupported owned command\n",
    ],
)
def test_owned_vendor_unicode_and_partial_text_is_preserved_without_claiming_parse_completeness(
    storage, content
):
    store, _ = storage
    snapshot = upload_source(store, content=content)
    assert read_source(store, snapshot).content.encode() == content.encode()


@pytest.mark.parametrize(
    "permission,content", [(1, SOURCE), (None, SOURCE), (True, None), (False, SOURCE)]
)
def test_store_retention_refuses_inconsistent_or_coerced_permission_before_write(
    storage, permission, content
):
    store, _ = storage
    from datetime import UTC, datetime

    from app.api.contracts import ConfigurationSnapshot
    from app.parsers import parse_configuration

    snapshot = ConfigurationSnapshot(
        configuration_id=uuid4(),
        device_id=uuid4(),
        created_at=datetime.now(UTC),
        canonical=parse_configuration(SOURCE, filename="owned.cfg"),
    )
    with pytest.raises(ValueError, match=r"^Original source retention is unavailable\.$"):
        store.add_configuration(
            snapshot, retain_original_source=permission, original_source=content
        )
    with store.engine.connect() as connection:
        assert connection.execute(text("SELECT count(*) FROM configurations")).scalar_one() == 0


def test_same_declared_hash_but_forged_canonical_is_not_retained(storage):
    store, _ = storage
    from datetime import UTC, datetime

    from app.api.contracts import ConfigurationSnapshot
    from app.parsers import parse_configuration

    canonical = parse_configuration(SOURCE, filename="owned.cfg")
    canonical = canonical.model_copy(
        update={"management": canonical.management.model_copy(update={"ssh_version": "2"})}
    )
    snapshot = ConfigurationSnapshot(
        configuration_id=uuid4(),
        device_id=uuid4(),
        created_at=datetime.now(UTC),
        canonical=canonical,
    )
    with pytest.raises(ValueError, match=r"^Original source retention is unavailable\.$"):
        store.add_configuration(snapshot, retain_original_source=True, original_source=SOURCE)


def test_source_table_is_required_by_readiness(storage):
    store, _ = storage
    assert store.ready()
    with store.engine.begin() as connection:
        connection.execute(text("DROP TABLE configuration_sources"))
    assert not store.ready()
