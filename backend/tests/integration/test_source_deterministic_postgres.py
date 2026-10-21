"""Opt-in original-context durability in an isolated PostgreSQL test schema."""

import os
from uuid import uuid4

import app.patching.source_deterministic as workflow_module
import pytest
from app.core.settings import ApiSettings
from app.db.migrate import upgrade_database
from app.db.source_records import SourceRecords
from app.db.store import make_engine
from app.main import create_app
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.engine import make_url
from test_source_deterministic_api import get, options, post, prepare
from test_source_patch_review_api import TOKEN


def test_postgres_original_context_replay_without_reference_or_raw_sources(monkeypatch):
    configured = os.environ.get("NETCONFIG_TEST_DATABASE_URL", "")
    if not configured:
        pytest.skip("requires explicitly selected PostgreSQL test database")
    url = make_url(configured)
    if url.drivername != "postgresql+psycopg" or not (url.database or "").endswith("_test"):
        pytest.fail("requires a postgresql+psycopg *_test database")
    schema = f"sentinel_deterministic_{uuid4().hex}"
    admin = make_engine(configured)
    with admin.begin() as connection:
        connection.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
    selected_url = url.update_query_dict({"options": f"-csearch_path={schema}"})
    settings = ApiSettings(
        selected_url.render_as_string(hide_password=False), TOKEN, Fernet.generate_key().decode()
    )
    application = create_app(settings)
    store = application.state.analysis_service.store
    try:
        upgrade_database(store.engine)
        with TestClient(application) as client:
            selected = prepare(client)
            body = options(selected)
            response = post(client, selected, body)
            assert response.status_code == 201, response.text
            result = response.json()
            assert result["execution_status"] == "completed"
            assert post(client, selected, body).json() == result
        with store.engine.begin() as connection:
            connection.execute(text("DELETE FROM configuration_sources"))
            connection.execute(
                text("DELETE FROM configurations WHERE id=:key"),
                {"key": selected[4]["configuration_id"]},
            )

        def forbidden(*args, **kwargs):
            pytest.fail("history executed a detector or read original sources")

        monkeypatch.setattr(workflow_module, "recheck_original_deterministic", forbidden)
        monkeypatch.setattr(SourceRecords, "get", forbidden)
        with TestClient(create_app(settings)) as restarted:
            assert get(restarted, selected, body).json() == result
            assert post(restarted, selected, body).json() == result
        with store.engine.connect() as connection:
            for table in (
                "patch_deterministic_recheck_intents",
                "patch_deterministic_recheck_outcomes",
            ):
                assert connection.execute(text(f"SELECT count(*) FROM {table}")).scalar_one() == 1
            assert (
                connection.execute(
                    text(
                        "SELECT count(*) FROM audit_events WHERE resource_id=:key "
                        "AND action LIKE 'patch.deterministic_recheck_%'"
                    ),
                    {"key": body["recheck_id"]},
                ).scalar_one()
                == 2
            )
    finally:
        store.close()
        with admin.begin() as connection:
            connection.exec_driver_sql(f'DROP SCHEMA "{schema}" CASCADE')
        admin.dispose()
