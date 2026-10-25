"""Opt-in saved partial chains in an owned isolated PostgreSQL test schema."""

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
from test_source_partial_evidence_api import chain, replay
from test_source_patch_review_api import ANALYST, ENGINEER, READER, TOKEN


@pytest.mark.parametrize("vendor", ["cisco", "juniper"])
@pytest.mark.parametrize("partial", ["before", "after", "both"])
def test_owned_postgres_partial_history_without_originals(monkeypatch, vendor, partial):
    configured = os.environ.get("NETCONFIG_TEST_DATABASE_URL", "")
    if not configured:
        pytest.skip("requires explicitly selected PostgreSQL test database")
    url = make_url(configured)
    if url.drivername != "postgresql+psycopg" or not (url.database or "").endswith("_test"):
        pytest.fail("requires a postgresql+psycopg *_test database")
    schema = "sentinel_partial_" + uuid4().hex
    admin = make_engine(configured)
    with admin.begin() as connection:
        connection.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
    selected_url = url.update_query_dict({"options": f"-csearch_path={schema}"})
    settings = ApiSettings(
        selected_url.render_as_string(hide_password=False),
        TOKEN,
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
            saved = chain(client, vendor, partial)
        with store.engine.begin() as connection:
            connection.execute(text("DELETE FROM configuration_sources"))

        def forbidden(*args, **kwargs):
            pytest.fail("saved PostgreSQL partial history cannot rerun or read sources")

        monkeypatch.setattr(SourceRecords, "get", forbidden)
        for name in (
            "app.patching.source_deterministic.prepare_partial_policy",
            "app.patching.source_deterministic.recheck_partial_policy",
            "app.patching.source_deterministic.prepare_original_source",
            "app.detection.policy_diagnostic.evaluate_policies",
            "app.ingestion.source_retention.parse_configuration",
        ):
            monkeypatch.setattr(name, forbidden)
        monkeypatch.setattr("app.detection.policy_engine.POLICY_CATALOGS", {})
        with TestClient(create_app(settings)) as restarted:
            replay(restarted, saved)
        with store.engine.connect() as connection:
            for table, expected in (
                ("patch_deterministic_recheck_intents", 1),
                ("patch_deterministic_recheck_outcomes", 1),
                ("patch_evidence_reports", 1),
                ("patch_risk_assessments", 1),
                ("patch_evidence_decisions", 2),
            ):
                assert (
                    connection.execute(text(f"SELECT count(*) FROM {table}")).scalar_one()
                    == expected
                )
    finally:
        store.close()
        with admin.begin() as connection:
            connection.exec_driver_sql(f'DROP SCHEMA "{schema}" CASCADE')
        admin.dispose()
