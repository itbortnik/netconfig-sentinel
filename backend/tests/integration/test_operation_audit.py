"""Real encrypted SQLite/opt-in PostgreSQL requests; no customer data or live model claims."""

import asyncio
import json
import os
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from alembic import command
from alembic.config import Config
from app.api.contracts import AnalysisResult, ConfigurationSnapshot, UploadConfiguration
from app.api.service import AnalysisService
from app.audit.contracts import (
    OperationPage,
    OperationRecord,
    PermissionDecision,
    Receipt,
)
from app.audit.http import journal_response
from app.audit.journal import OperationJournal
from app.audit.results import result_metadata
from app.core.permissions import PERMISSIONS
from app.core.settings import ApiSettings
from app.db import migrate as migration_module
from app.db.migrate import upgrade_database
from app.db.store import StorageIntegrityError, Store, make_engine
from app.db.tables import OperationCompletionRow, OperationReceiptRow
from app.main import create_app
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import IntegrityError
from starlette.requests import Request

TOKENS = {role: f"synthetic-audit-{role}-token-000000001" for role in PERMISSIONS}
PRIVATE = "private-audit-config-marker"


def headers(role="admin"):
    return {"Authorization": "Bearer " + TOKENS[role]}


@pytest.fixture
def audit_api(tmp_path: Path) -> Iterator[tuple]:
    database = f"sqlite:///{tmp_path / 'operations.sqlite3'}"
    admin = None
    schema = f"sentinel_audit_test_{uuid4().hex}"
    configured = os.environ.get("NETCONFIG_TEST_DATABASE_URL", "")
    if configured:
        url = make_url(configured)
        if url.drivername != "postgresql+psycopg" or not (url.database or "").endswith("_test"):
            pytest.fail(
                "audit tests require an explicitly selected postgresql+psycopg *_test database"
            )
        admin = make_engine(configured)
        with admin.begin() as connection:
            connection.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
        database = url.update_query_dict({"options": f"-csearch_path={schema}"}).render_as_string(
            hide_password=False
        )
    settings = ApiSettings(
        database,
        TOKENS["admin"],
        Fernet.generate_key().decode(),
        reader_token=TOKENS["reader"],
        analyst_token=TOKENS["analyst"],
        engineer_token=TOKENS["engineer"],
    )
    try:
        app = create_app(settings)
        upgrade_database(app.state.analysis_service.store.engine)
        with TestClient(app) as client:
            yield client, app.state.operation_journal, settings
    finally:
        if admin is not None:
            with admin.begin() as connection:
                connection.exec_driver_sql(f'DROP SCHEMA "{schema}" CASCADE')
            admin.dispose()


def uploaded(client, *, content=None, device=None):
    response = client.post(
        "/api/v1/configurations",
        headers=headers(),
        json={
            "device_id": str(device or uuid4()),
            "filename": PRIVATE + ".cfg",
            "content": content or f"hostname {PRIVATE}\nline vty 0 4\n transport input telnet\n!\n",
        },
    )
    assert response.status_code == 201, response.text
    return response


def record(journal, response):
    result = journal.get(UUID(response.headers["X-Operation-Id"]))
    assert result is not None
    return result


def test_real_request_bindings_versions_and_redacted_append_only_history(audit_api):
    client, journal, settings = audit_api
    upload = uploaded(client)
    snapshot = ConfigurationSnapshot.model_validate(upload.json())
    saved = record(journal, upload)
    assert saved.receipt.operation == "upload_configuration"
    assert saved.receipt.service_role == "admin"
    assert saved.authorization == "allowed" and saved.outcome == "successful_response"
    assert saved.completion.result == result_metadata(snapshot)
    analyzed = client.post(
        f"/api/v1/configurations/{snapshot.configuration_id}/analyze", headers=headers()
    )
    assert analyzed.status_code == 201
    analysis = AnalysisResult.model_validate(analyzed.json())
    assert record(journal, analyzed).completion.result == result_metadata(analysis)
    finding = analysis.findings[0]
    explained = client.post(
        f"/api/v1/findings/{finding.finding_id}/explain",
        headers=headers(),
        json={
            "analysis_id": str(analysis.analysis_id),
            "finding_sha256": analysis.explanations[0].finding_sha256,
        },
    )
    assert explained.status_code == 200
    context = record(journal, explained).completion.result
    assert context.source_sha256 == analysis.source_sha256
    assert context.finding_sha256 == analysis.explanations[0].finding_sha256
    assert context.knowledge_sha256 == explained.json()["knowledge_sha256"]
    assert finding.model_version in context.versions
    page = client.get("/api/v1/operation-audit", headers=headers())
    assert page.status_code == 200
    parsed = OperationPage.model_validate(page.json())
    assert UUID(page.headers["X-Operation-Id"]) not in {
        item.receipt.operation_id for item in parsed.records
    }
    assert {item.receipt.operation for item in parsed.records} == {
        "upload_configuration",
        "analyze_configuration",
        "explain_finding",
    }
    receipt_read = record(journal, page)
    assert receipt_read.receipt.operation == "list_operation_audit"
    assert receipt_read.completion.permissions == (
        PermissionDecision(permission="read_audit", granted=True),
    )
    detail = client.get(f"/api/v1/operation-audit/{saved.receipt.operation_id}", headers=headers())
    assert OperationRecord.model_validate(detail.json()) == saved
    assert record(journal, detail).receipt.operation == "get_operation_audit"
    raw = journal.page(limit=100).model_dump_json()
    assert all(token not in raw for token in TOKENS.values())
    assert all(
        marker not in raw
        for marker in (PRIVATE, "transport input", "technical_explanation", "summary")
    )
    with journal.store.engine.connect() as connection:
        payloads = (
            connection.execute(
                text(
                    "SELECT payload FROM operation_receipts UNION ALL "
                    "SELECT payload FROM operation_completions"
                )
            )
            .scalars()
            .all()
        )
        assert payloads and all(
            payload.startswith("gAAAA") and "admin" not in payload for payload in payloads
        )
    with TestClient(create_app(settings)) as restarted:
        assert restarted.get(
            f"/api/v1/operation-audit/{saved.receipt.operation_id}", headers=headers()
        ).json() == saved.model_dump(mode="json")


@pytest.mark.parametrize("role", ["reader", "analyst", "engineer", None])
def test_audit_reads_are_admin_only_and_denials_are_recorded_without_body(
    audit_api, role, monkeypatch
):
    client, journal, _ = audit_api

    def forbidden_domain():
        raise AssertionError("denied request accessed domain readiness")

    monkeypatch.setattr(journal.store, "ready", forbidden_domain)
    response = client.get("/api/v1/operation-audit", headers=headers(role) if role else {})
    assert response.status_code == (403 if role else 401)
    saved = record(journal, response)
    assert saved.receipt.service_role == role
    assert saved.outcome == "rejected_response"
    assert saved.authorization == ("denied" if role else "not_authenticated")
    assert saved.completion.result is None
    assert saved.completion.permissions == (
        PermissionDecision(permission="read_audit", granted=False),
    )


@pytest.mark.parametrize(
    "method,path,status,operation",
    [
        ("GET", "/api/v1/configurations", 200, "list_configurations"),
        ("GET", "/api/v1/models", 200, "list_models"),
        ("GET", "/api/v1/analyses", 200, "list_analyses"),
        ("GET", "/api/v1/session", 200, "session_access"),
        ("GET", "/api/v1/explanation-capabilities", 200, "explanation_capabilities"),
        ("GET", "/api/v1/configurations/not-a-uuid", 422, "get_configuration"),
        ("DELETE", "/api/v1/configurations", 405, "upload_configuration"),
        ("GET", "/api/v1/private-url-marker?private-query-marker=secret", 404, "unmatched_api"),
        ("TRACE", "/api/v1/private-url-marker", 404, "unmatched_api"),
    ],
)
def test_operation_route_and_method_are_allowlisted_not_raw_paths(
    audit_api, method, path, status, operation
):
    client, journal, _ = audit_api
    response = client.request(method, path, headers=headers())
    assert response.status_code == status
    saved = record(journal, response)
    assert saved.receipt.operation == operation
    assert saved.receipt.method == ("OTHER" if method == "TRACE" else method)
    assert "private-url-marker" not in saved.model_dump_json()
    assert "private-query-marker" not in saved.model_dump_json()


def test_receipt_failure_prevents_handler_and_domain_mutation(audit_api, monkeypatch):
    client, journal, _ = audit_api

    def reject_start(_):
        raise RuntimeError(PRIVATE)

    monkeypatch.setattr(journal, "start", reject_start)
    response = client.post("/api/v1/configurations", headers=headers(), json={"content": PRIVATE})
    assert response.status_code == 503 and PRIVATE not in response.text
    assert response.headers["Cache-Control"] == "no-store"
    assert journal.page().records == ()
    with journal.store.engine.connect() as connection:
        assert connection.execute(text("SELECT count(*) FROM configurations")).scalar_one() == 0


def test_initial_schema_unavailability_cannot_be_bypassed_by_later_ready_check(
    audit_api, monkeypatch
):
    client, journal, _ = audit_api
    assert journal.store.ready()
    monkeypatch.setattr(journal, "ready", lambda: False)
    response = client.post(
        "/api/v1/configurations",
        headers=headers(),
        json={
            "device_id": str(uuid4()),
            "filename": "synthetic.cfg",
            "content": "hostname synthetic\n",
        },
    )
    assert response.status_code == 503
    assert journal.page().records == ()
    with journal.store.engine.connect() as connection:
        assert connection.execute(text("SELECT count(*) FROM configurations")).scalar_one() == 0
    assert client.get("/api/v1/configurations").status_code == 401
    assert (
        client.post(
            "/api/v1/configurations", headers=headers("reader"), content=PRIVATE
        ).status_code
        == 403
    )


def test_completion_failure_keeps_pending_receipt_and_committed_domain_data(audit_api, monkeypatch):
    client, journal, _ = audit_api
    original = journal.complete

    def reject_completion(*_):
        raise RuntimeError(PRIVATE)

    monkeypatch.setattr(journal, "complete", reject_completion)
    response = client.post(
        "/api/v1/configurations",
        headers=headers(),
        json={
            "device_id": str(uuid4()),
            "filename": "private.cfg",
            "content": "hostname edge\n",
        },
    )
    assert response.status_code == 503 and PRIVATE not in response.text
    saved = record(journal, response)
    assert (
        saved.outcome == "pending"
        and saved.completion is None
        and saved.authorization == "not_checked"
    )
    with journal.store.engine.connect() as connection:
        assert connection.execute(text("SELECT count(*) FROM configurations")).scalar_one() == 1
        assert connection.execute(text("SELECT count(*) FROM audit_events")).scalar_one() == 1
    monkeypatch.setattr(journal, "complete", original)
    response = client.get(
        f"/api/v1/operation-audit/{saved.receipt.operation_id}", headers=headers()
    )
    assert OperationRecord.model_validate(response.json()) == saved


def test_domain_exception_is_generic_and_not_assumed_to_have_rolled_back(audit_api, monkeypatch):
    client, journal, _ = audit_api
    original = client.app.state.analysis_service.upload

    def commit_then_fail(options):
        original(options)
        raise RuntimeError(PRIVATE)

    monkeypatch.setattr(client.app.state.analysis_service, "upload", commit_then_fail)
    response = client.post(
        "/api/v1/configurations",
        headers=headers(),
        json={
            "device_id": str(uuid4()),
            "filename": "private.cfg",
            "content": "hostname edge\n",
        },
    )
    assert response.status_code == 500 and PRIVATE not in response.text
    saved = record(journal, response)
    assert saved.outcome == "failed_response" and saved.completion.result is None
    with journal.store.engine.connect() as connection:
        assert connection.execute(text("SELECT count(*) FROM configurations")).scalar_one() == 1


def test_pages_use_stable_authenticated_keyset_and_ignore_newer_reads(audit_api):
    client, journal, _ = audit_api
    at = datetime.now(UTC) - timedelta(minutes=1)
    for identity in (3, 1, 2, 4):
        journal.start(
            Receipt(
                operation_id=UUID(int=identity),
                started_at=at,
                operation="session_access",
                method="GET",
                service_role="admin",
            )
        )
    first = client.get("/api/v1/operation-audit?limit=2", headers=headers()).json()
    assert [UUID(item["receipt"]["operation_id"]).int for item in first["records"]] == [4, 3]
    second = client.get(
        "/api/v1/operation-audit",
        headers=headers(),
        params={"limit": 2, "before": first["next_before"]},
    ).json()
    assert [UUID(item["receipt"]["operation_id"]).int for item in second["records"]] == [2, 1]
    assert second["next_before"] is None
    assert (
        client.get(
            "/api/v1/operation-audit", headers=headers(), params={"before": str(uuid4())}
        ).status_code
        == 400
    )
    for limit in (0, 101, -1):
        assert (
            client.get(
                "/api/v1/operation-audit", headers=headers(), params={"limit": limit}
            ).status_code
            == 422
        )
    assert client.get(f"/api/v1/operation-audit/{uuid4()}", headers=headers()).status_code == 404


@pytest.mark.parametrize(
    "table,corruption",
    [
        ("receipt", "ciphertext"),
        ("receipt", "timestamp"),
        ("receipt", "oversize"),
        ("completion", "ciphertext"),
        ("completion", "timestamp"),
        ("completion", "receipt_binding"),
        ("completion", "permission"),
        ("completion", "oversize"),
    ],
)
def test_encrypted_record_corruption_fails_closed(audit_api, table, corruption):
    client, journal, _ = audit_api
    saved = record(journal, uploaded(client))
    identity = str(saved.receipt.operation_id)
    with journal.store._sessions.begin() as session:
        row = session.get(
            OperationReceiptRow if table == "receipt" else OperationCompletionRow, identity
        )
        if corruption == "timestamp":
            if table == "receipt":
                row.created_at = datetime.now(UTC) + timedelta(days=1)
            else:
                row.completed_at = datetime.now(UTC) + timedelta(days=1)
        elif corruption in {"ciphertext", "oversize"}:
            row.payload = "private-corrupt-marker" if corruption == "ciphertext" else "x" * 65_537
        else:
            raw = saved.completion.model_dump(mode="json")
            if corruption == "receipt_binding":
                raw["receipt_sha256"] = "f" * 64
            else:
                raw["permissions"] = [{"permission": "upload", "granted": False}]
            row.payload = journal.store._encode(
                json.dumps(raw), kind="operation_completion", row_id=identity
            )
    response = client.get(f"/api/v1/operation-audit/{identity}", headers=headers())
    assert response.status_code == 503 and "private-corrupt-marker" not in response.text
    with pytest.raises(StorageIntegrityError):
        journal.get(saved.receipt.operation_id)
    assert client.get("/api/v1/operation-audit", headers=headers()).status_code == 503


def test_completion_cannot_be_overwritten_or_moved_to_another_receipt(audit_api):
    client, journal, _ = audit_api
    saved = record(journal, uploaded(client))
    journal.complete(saved.receipt, saved.completion)
    changed = saved.completion.model_copy(update={"duration_ms": saved.completion.duration_ms + 1})
    with pytest.raises(StorageIntegrityError):
        journal.complete(saved.receipt, changed)
    with pytest.raises(IntegrityError):
        journal.start(saved.receipt)
    assert journal.get(saved.receipt.operation_id) == saved
    other = Receipt(
        operation_id=uuid4(),
        started_at=datetime.now(UTC),
        operation="session_access",
        method="GET",
        service_role="admin",
    )
    journal.start(other)
    with pytest.raises(ValueError):
        journal.complete(other, saved.completion)


def test_public_health_and_ui_do_not_create_journal_rows(audit_api):
    client, journal, _ = audit_api
    assert client.get("/health").status_code == 200
    client.get("/ui/")
    assert journal.page().records == ()


def test_real_upgrade_from_prior_revision_preserves_domain_without_inventing_history(tmp_path):
    settings = ApiSettings(
        f"sqlite:///{tmp_path / 'legacy.sqlite3'}", TOKENS["admin"], Fernet.generate_key().decode()
    )
    store = Store(settings)
    migration = Config()
    migration.set_main_option(
        "script_location", str(Path(migration_module.__file__).parent / "migrations")
    )
    try:
        with store.engine.begin() as connection:
            migration.attributes["connection"] = connection
            command.upgrade(migration, "0004_patch_reviews")
        assert not store.ready()
        snapshot = AnalysisService(store).upload(
            UploadConfiguration(
                device_id=uuid4(),
                filename="legacy.cfg",
                content="hostname legacy-edge\n",
            )
        )
        with TestClient(create_app(settings)) as client:
            assert client.get("/api/v1/session", headers=headers()).status_code == 503
        upgrade_database(store.engine)
        assert store.ready()
        assert store.get_configuration(snapshot.configuration_id) == snapshot
        assert OperationJournal(store).page().records == ()
        upgrade_database(store.engine)
    finally:
        store.close()


def test_cancellation_does_not_invent_a_completed_result(audit_api):
    client, journal, settings = audit_api
    request = Request(
        {
            "type": "http",
            "path": "/api/v1/configurations",
            "root_path": "",
            "method": "GET",
            "headers": [(b"authorization", ("Bearer " + TOKENS["admin"]).encode())],
            "app": client.app,
        }
    )

    async def cancelled(_):
        raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(journal_response(request, cancelled, journal, settings))
    records = journal.page().records
    assert len(records) == 1 and records[0].completion is None and records[0].outcome == "pending"
