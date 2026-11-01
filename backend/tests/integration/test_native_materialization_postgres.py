"""Opt-in native bridge checks in an explicitly selected isolated PostgreSQL schema."""

import os
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Barrier
from uuid import UUID, uuid4

import pytest
from app.api.native_materialization_contracts import (
    CreateNativeMaterialization,
    native_materialization_record,
)
from app.core.settings import ApiSettings
from app.db.migrate import upgrade_database
from app.db.native_materialization_records import NativeMaterializationRecords
from app.db.native_patch_records import NativePatchRecords
from app.db.patch_records import PatchConflict
from app.db.source_records import SourceRecords
from app.db.store import make_engine
from app.main import create_app
from app.patching.native_materialization_preparation import prepare_native_materialization
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import event, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import OperationalError
from test_native_materialization_api import candidate, materialize, path, request_for
from test_native_patch_api import ADMIN, ANALYST, ENGINEER, MARKERS, READER, headers


@pytest.fixture
def postgres_native_materialization():
    configured = os.environ.get("NETCONFIG_TEST_DATABASE_URL", "")
    if not configured:
        pytest.skip("requires explicitly selected PostgreSQL test database")
    selected = make_url(configured)
    if selected.drivername != "postgresql+psycopg" or not (selected.database or "").endswith(
        "_test"
    ):
        pytest.fail("requires a postgresql+psycopg *_test database")
    schema = "sentinel_native_materialization_" + uuid4().hex
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
        yield application, settings
    finally:
        store.close()
        with admin.begin() as connection:
            connection.exec_driver_sql(f'DROP SCHEMA "{schema}" CASCADE')
        admin.dispose()


def prepared_case(application, *, native=None, outputs=None, role="engineer", created_at=None):
    store = application.state.analysis_service.store
    if native is None:
        with TestClient(application) as client:
            _before, _analysis, public = candidate(client)
        native = NativePatchRecords(store).get(UUID(public["candidate_id"]))
    before = store.get_configuration(native.public.configuration_id)
    analysis = store.get_analysis(native.public.request.analysis_id)
    retained = SourceRecords(store).get(
        before.configuration_id,
        expected_source_sha256=before.canonical.source.sha256,
        allow_local_read=True,
    )
    after_id, patch_id = outputs or (uuid4(), uuid4())
    created_at = created_at or datetime.now(UTC)
    options = CreateNativeMaterialization(
        version="native-materialization-request-0.1.0",
        after_configuration_id=after_id,
        patch_id=patch_id,
        native_review_sha256=native.public.review_sha256,
        allow_local_source_materialization=True,
        allow_private_candidate_source_retention=True,
    )
    prepared = prepare_native_materialization(
        native, before, analysis, retained,
        after_configuration_id=after_id, patch_id=patch_id, created_at=created_at,
    )
    record = native_materialization_record(
        before.configuration_id, native.public.candidate_id, options, native, before, prepared,
        created_at=created_at, service_role=role,
    )
    return record, prepared, retained


def table_counts(store):
    with store.engine.connect() as connection:
        return tuple(
            connection.execute(text(f"SELECT count(*) FROM {name}")).scalar_one()
            for name in (
                "devices", "configurations", "configuration_sources", "patch_proposals",
                "native_patch_candidates", "native_materializations", "audit_events",
            )
        )


@pytest.mark.parametrize("vendor", ["cisco", "juniper"])
def test_postgres_actual_http_bridge_and_source_free_restart(
    postgres_native_materialization, monkeypatch, vendor
):
    application, settings = postgres_native_materialization
    store = application.state.analysis_service.store
    with TestClient(application) as client:
        before, _analysis, native = candidate(client, vendor)
        options = request_for(native)
        response = materialize(client, before, native, options)
        assert response.status_code == 201, response.text
        saved = response.json()
        private = NativePatchRecords(store).get(UUID(native["candidate_id"]))
        retained = SourceRecords(store).get(
            UUID(options["after_configuration_id"]),
            expected_source_sha256=saved["after"]["source_sha256"], allow_local_read=True,
        )
        assert retained.content.encode() == private.candidate_text.encode()
        assert all(marker in retained.content and marker not in response.text for marker in MARKERS)
    with store.engine.begin() as connection:
        connection.execute(text("DELETE FROM configuration_sources"))

    def forbidden(*args, **kwargs):
        pytest.fail("saved materialization history invoked source or runtime execution")

    for name in (
        "app.db.source_records.SourceRecords.get",
        "app.patching.native_materialization.prepare_native_materialization",
        "app.patching.native_materialization_preparation.prepare_native_materialization",
        "app.patching.native_materialization_preparation.parse_configuration_with_coverage",
        "app.ingestion.source_retention.prepare_original_source",
        "app.patching.native_patches.create_vendor_draft",
        "app.detection.policy_engine.evaluate_policies",
    ):
        monkeypatch.setattr(name, forbidden)
    monkeypatch.setattr("app.detection.policy_engine.POLICY_CATALOGS", {})
    restarted_app = create_app(settings)
    try:
        with TestClient(restarted_app) as restarted:
            assert restarted.get(path(before, native), headers=headers(READER)).json() == saved
            origin = restarted.get(
                f"/api/v2/configurations/{options['after_configuration_id']}/native-origin",
                headers=headers(READER),
            )
            assert origin.status_code == 200 and origin.json() == saved
            replay = materialize(restarted, before, native, options, ADMIN)
            assert replay.status_code == 200 and replay.json() == saved
            assert saved["service_role"] == "engineer"
    finally:
        restarted_app.state.analysis_service.store.close()


@pytest.mark.parametrize("vendor", ["cisco", "juniper"])
def test_postgres_fresh_missing_source_cannot_use_native_private_before_copy(
    postgres_native_materialization, vendor
):
    application, _settings = postgres_native_materialization
    store = application.state.analysis_service.store
    with TestClient(application) as client:
        before, _analysis, native = candidate(client, vendor)
        with store.engine.begin() as connection:
            connection.execute(text("DELETE FROM configuration_sources"))
        options = request_for(native)
        response = materialize(client, before, native, options)
        assert response.status_code == 409, response.text
        assert table_counts(store)[1:6] == (1, 0, 0, 1, 0)


@pytest.mark.parametrize("stage", range(1, 9))
def test_postgres_each_domain_row_and_audit_failure_rolls_back(
    postgres_native_materialization, stage
):
    application, _settings = postgres_native_materialization
    store = application.state.analysis_service.store
    values = prepared_case(application)
    baseline = table_counts(store)
    observed = 0

    def fail_insert(connection, cursor, statement, parameters, context, many):
        nonlocal observed
        if statement.startswith("INSERT INTO"):
            observed += 1
            if observed == stage:
                raise RuntimeError("owned PostgreSQL materialization injection")

    event.listen(store.engine, "before_cursor_execute", fail_insert)
    try:
        with pytest.raises(RuntimeError, match="owned PostgreSQL materialization injection"):
            NativeMaterializationRecords(store).save(*values)
    finally:
        event.remove(store.engine, "before_cursor_execute", fail_insert)
    assert observed == stage and table_counts(store) == baseline


@pytest.mark.parametrize("same", [True, False])
def test_postgres_raced_creation_has_one_atomic_winner(postgres_native_materialization, same):
    application, _settings = postgres_native_materialization
    store = application.state.analysis_service.store
    first = prepared_case(application)
    native = NativePatchRecords(store).get(first[0].candidate_id)
    second = prepared_case(
        application, native=native,
        outputs=(first[0].after.configuration_id, first[0].patch_id) if same else None,
        role="admin", created_at=first[0].created_at + timedelta(seconds=1),
    )
    baseline = table_counts(store)
    gate = Barrier(2)

    def worker(values):
        records = NativeMaterializationRecords(store)
        original = records.get
        reads = 0

        def rendezvous(candidate_id):
            nonlocal reads
            result = original(candidate_id)
            reads += 1
            if reads == 1:
                assert result is None
                gate.wait(timeout=15)
            return result

        records.get = rendezvous
        try:
            return records.save(*values)
        except PatchConflict:
            return "conflict"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(worker, (first, second)))
    assert sum(item != "conflict" and item[1] for item in results) == 1
    if same:
        assert results[0][0] == results[1][0]
        assert sorted(item[1] for item in results) == [False, True]
    else:
        assert results.count("conflict") == 1
    assert tuple(a - b for a, b in zip(table_counts(store), baseline, strict=True)) == (
        0, 1, 1, 1, 0, 1, 4,
    )


def test_postgres_parent_locks_precede_source_recheck_and_block_concurrent_delete(
    postgres_native_materialization, monkeypatch
):
    application, _settings = postgres_native_materialization
    store = application.state.analysis_service.store
    values = prepared_case(application)
    records = NativeMaterializationRecords(store)
    original = records._source
    locked = []

    def capture(connection, cursor, statement, parameters, context, many):
        if "FOR UPDATE" in statement:
            locked.append(statement.split("FROM ", 1)[1].split()[0])

    def probe(session, retained):
        assert locked == [
            "native_patch_candidates", "devices", "configurations", "analyses",
            "configuration_sources",
        ]
        with store.engine.connect() as peer:
            peer.execute(text("SET LOCAL lock_timeout = '100ms'"))
            with pytest.raises(OperationalError):
                peer.execute(text("DELETE FROM configuration_sources"))
        return original(session, retained)

    event.listen(store.engine, "before_cursor_execute", capture)
    monkeypatch.setattr(records, "_source", probe)
    try:
        assert records.save(*values)[1] is True
    finally:
        event.remove(store.engine, "before_cursor_execute", capture)


def test_postgres_source_pin_is_freshly_rechecked_after_preparation(
    postgres_native_materialization,
):
    application, _settings = postgres_native_materialization
    store = application.state.analysis_service.store
    values = prepared_case(application)
    with store.engine.begin() as connection:
        connection.execute(text("DELETE FROM configuration_sources"))
    baseline = table_counts(store)
    with pytest.raises(PatchConflict):
        NativeMaterializationRecords(store).save(*values)
    assert table_counts(store) == baseline
