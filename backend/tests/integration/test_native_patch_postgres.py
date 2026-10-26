"""Opt-in native candidate durability in an explicitly selected owned PostgreSQL schema."""

import os
from uuid import uuid4

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
from test_native_patch_api import ADMIN, ANALYST, ENGINEER, READER, headers, post, prepare, url


@pytest.mark.parametrize("vendor", ["cisco", "juniper"])
def test_owned_postgres_native_history_without_originals(monkeypatch, vendor):
    configured = os.environ.get("NETCONFIG_TEST_DATABASE_URL", "")
    if not configured:
        pytest.skip("requires explicitly selected PostgreSQL test database")
    selected = make_url(configured)
    if selected.drivername != "postgresql+psycopg" or not (selected.database or "").endswith(
        "_test"
    ):
        pytest.fail("requires a postgresql+psycopg *_test database")
    schema = "sentinel_native_" + uuid4().hex
    admin = make_engine(configured)
    with admin.begin() as connection:
        connection.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
    selected = selected.update_query_dict({"options": f"-csearch_path={schema}"})
    settings = ApiSettings(
        selected.render_as_string(hide_password=False),
        ADMIN,
        Fernet.generate_key().decode(),
        reader_token=READER,
        analyst_token=ANALYST,
        engineer_token=ENGINEER,
    )
    application = create_app(settings)
    store = application.state.analysis_service.store
    try:
        upgrade_database(store.engine)
        with TestClient(application) as client:
            snapshot, _analysis, options = prepare(client, vendor)
            response = post(client, snapshot, options)
            assert response.status_code == 201, response.text
            saved = response.json()
        with store.engine.begin() as connection:
            connection.execute(text("DELETE FROM configuration_sources"))

        def forbidden(*args, **kwargs):
            pytest.fail("saved native history cannot read originals or rerun runtime checks")

        monkeypatch.setattr(SourceRecords, "get", forbidden)
        for name in (
            "app.patching.native_patches.create_vendor_draft",
            "app.patching.native_patches.prepare_original_source",
            "app.patching.native_patches.evaluate_policies",
            "app.patching.vendor_drafts.parse_configuration",
        ):
            monkeypatch.setattr(name, forbidden)
        monkeypatch.setattr("app.detection.policy_engine.POLICY_CATALOGS", {})
        with TestClient(create_app(settings)) as restarted:
            loaded = restarted.get(
                url(snapshot) + "/" + options["candidate_id"], headers=headers(READER)
            )
            assert loaded.status_code == 200, loaded.text
            assert loaded.json() == saved
            replay = post(restarted, snapshot, options, ADMIN)
            assert replay.status_code == 200, replay.text
            assert replay.json() == saved
            listing = restarted.get(url(snapshot), headers=headers(READER))
            assert listing.status_code == 200, listing.text
            assert listing.json()[0]["review_sha256"] == saved["review_sha256"]
        with store.engine.connect() as connection:
            assert (
                connection.execute(
                    text("SELECT count(*) FROM native_patch_candidates")
                ).scalar_one()
                == 1
            )
            assert (
                connection.execute(
                    text("SELECT count(*) FROM audit_events WHERE action='native_patch.created'")
                ).scalar_one()
                == 1
            )
    finally:
        store.close()
        with admin.begin() as connection:
            connection.exec_driver_sql(f'DROP SCHEMA "{schema}" CASCADE')
        admin.dispose()
