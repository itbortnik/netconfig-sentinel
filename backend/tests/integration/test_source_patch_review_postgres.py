"""Opt-in PostgreSQL durability, isolated in a new schema; synthetic SDK only."""

import os
from uuid import UUID, uuid4

import app.patching.source_review as workflow_module
import pytest
from app.core.patch_verification import PatchVerificationSettings
from app.core.settings import ApiSettings
from app.db.migrate import upgrade_database
from app.db.store import make_engine
from app.main import create_app
from app.verification.batfish import BatfishResult
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.engine import make_url
from test_source_patch_review_api import TOKEN, draft_pair, get, options, post


def test_postgres_source_review_atomic_storage_and_disabled_restart(monkeypatch):
    configured = os.environ.get("NETCONFIG_TEST_DATABASE_URL", "")
    if not configured:
        pytest.skip("requires explicitly selected PostgreSQL test database")
    url = make_url(configured)
    if url.drivername != "postgresql+psycopg" or not (url.database or "").endswith("_test"):
        pytest.fail("requires a postgresql+psycopg *_test database")
    schema = f"sentinel_source_review_{uuid4().hex}"
    admin = make_engine(configured)
    with admin.begin() as connection:
        connection.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
    selected = url.update_query_dict({"options": f"-csearch_path={schema}"})
    settings = ApiSettings(
        selected.render_as_string(hide_password=False), TOKEN, Fernet.generate_key().decode()
    )
    application = create_app(
        settings,
        patch_verification=PatchVerificationSettings(
            allow_engine_upload=True,
        ),
    )
    store = application.state.analysis_service.store
    calls = []

    def worker(before, after, scope, **kwargs):
        calls.append(scope)
        return BatfishResult(
            before_sha256=before.digest,
            after_sha256=after.digest,
            scope=scope,
            status="error",
            reason="timeout",
            cleanup_complete=None,
        )

    monkeypatch.setattr(workflow_module, "check_with_batfish", worker)
    try:
        upgrade_database(store.engine)
        with TestClient(application) as client:
            draft, *_ = draft_pair(client)
            body = options(draft)
            result = post(client, draft, body)
            assert result.status_code == 201
            saved = result.json()
            assert saved["outcome"]["network_result"]["cleanup_complete"] is None
            assert post(client, draft, body).json() == saved and len(calls) == 1
        with TestClient(create_app(settings)) as restarted:
            assert get(restarted, draft, body).json() == saved
            assert post(restarted, draft, body).json() == saved and len(calls) == 1
        with store.engine.connect() as connection:
            assert (
                connection.execute(
                    text("SELECT count(*) FROM patch_network_review_intents")
                ).scalar_one()
                == 1
            )
            assert (
                connection.execute(
                    text("SELECT count(*) FROM patch_network_review_outcomes")
                ).scalar_one()
                == 1
            )
            assert (
                connection.execute(
                    text(
                        "SELECT count(*) FROM audit_events WHERE resource_id=:id "
                        "AND action LIKE 'patch.network%'"
                    ),
                    {"id": str(UUID(body["verification_id"]))},
                ).scalar_one()
                == 2
            )
    finally:
        store.close()
        with admin.begin() as connection:
            connection.exec_driver_sql(f'DROP SCHEMA "{schema}" CASCADE')
        admin.dispose()
