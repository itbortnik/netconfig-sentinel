"""Server-enforced service roles, including denied bodies and restarted key configuration."""

import os
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path
from uuid import uuid4

import pytest
from app.core.permissions import PERMISSIONS
from app.core.settings import ApiSettings
from app.db.migrate import upgrade_database
from app.db.store import make_engine
from app.main import create_app
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.engine import make_url

TOKENS = {role: f"synthetic-role-test-{role}-token-000000001" for role in PERMISSIONS}


def headers(role):
    return {"Authorization": "Bearer " + TOKENS[role]}


@pytest.fixture
def role_api(tmp_path: Path) -> Iterator[tuple]:
    database = f"sqlite:///{tmp_path / 'roles.sqlite3'}"
    admin = None
    schema = f"sentinel_roles_test_{uuid4().hex}"
    configured = os.environ.get("NETCONFIG_TEST_DATABASE_URL", "")
    if configured:
        url = make_url(configured)
        if url.drivername != "postgresql+psycopg" or not (url.database or "").endswith("_test"):
            pytest.fail("role tests require a postgresql+psycopg *_test database")
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
            yield client, settings
    finally:
        if admin is not None:
            with admin.begin() as connection:
                connection.exec_driver_sql(f'DROP SCHEMA "{schema}" CASCADE')
            admin.dispose()


@pytest.mark.parametrize("role", PERMISSIONS)
def test_session_has_exact_permissions_without_credentials_or_identity_claim(role_api, role):
    client, _ = role_api
    response = client.get("/api/v1/session", headers=headers(role))
    assert response.status_code == 200
    assert response.json() == {
        "version": "service-access-0.2.0",
        "role": role,
        "permissions": list(PERMISSIONS[role]),
        "individual_identity_verified": False,
        "device_scope": "all_saved_devices",
    }
    assert response.headers["Cache-Control"] == "no-store"
    assert not any(token in response.text for token in TOKENS.values())
    assert client.get("/api/v1/configurations", headers=headers(role)).status_code == 200


OPERATIONS = [
    ("upload", "/api/v1/configurations"),
    ("analyze", f"/api/v1/configurations/{uuid4()}/analyze"),
    ("train_model", "/api/v1/models/isolation-forest"),
    ("feedback", f"/api/v1/findings/{uuid4()}/feedback"),
    ("draft", "/api/v1/patches"),
    ("verify", f"/api/v1/patches/{uuid4()}/verify"),
]


@pytest.mark.parametrize("role", PERMISSIONS)
@pytest.mark.parametrize("permission,path", OPERATIONS)
def test_every_write_permission_is_enforced_before_body_or_storage(
    role_api, role, permission, path, monkeypatch
):
    client, _ = role_api
    if permission not in PERMISSIONS[role]:

        def forbidden_ready():
            raise AssertionError("denied role must not query storage")

        monkeypatch.setattr(client.app.state.analysis_service.store, "ready", forbidden_ready)
    response = client.post(
        path,
        headers=headers(role) | {"Content-Type": "application/json"},
        content=b"private-body" * 20000,
    )
    if permission not in PERMISSIONS[role]:
        assert response.status_code == 403
        assert response.json() == {"detail": "Operation is not permitted for this role."}
    else:
        assert response.status_code in {400, 413}
    assert "private-body" not in response.text


def test_authentication_and_model_permission_cannot_be_chosen_in_body(role_api):
    client, _ = role_api
    assert client.get("/api/v1/session").status_code == 401
    assert (
        client.get("/api/v1/session", headers={"Authorization": "Bearer invalid"}).status_code
        == 401
    )
    uploaded = client.post(
        "/api/v1/configurations",
        headers=headers("analyst"),
        json={
            "device_id": str(uuid4()),
            "filename": "synthetic.cfg",
            "content": "hostname test\n",
        },
    ).json()
    result = client.post(
        f"/api/v1/configurations/{uploaded['configuration_id']}/analyze", headers=headers("analyst")
    ).json()
    target = f"/api/v1/findings/{result['findings'][0]['finding_id']}/explain"
    request = {
        "analysis_id": result["analysis_id"],
        "finding_sha256": result["explanations"][0]["finding_sha256"],
    }
    for role in PERMISSIONS:
        assert client.post(target, headers=headers(role), json=request).status_code == 200
        model = client.post(
            target,
            headers=headers(role),
            json=request
            | {
                "provider": "llm",
                "allow_local_model_context": True,
            },
        )
        assert model.status_code == (503 if "model_explanation" in PERMISSIONS[role] else 403)
        assert (
            client.post(target, headers=headers(role), json=request | {"role": "admin"}).status_code
            == 400
        )
    assert (
        client.get(f"/api/v1/analyses/{result['analysis_id']}", headers=headers("reader")).json()
        == result
    )
    with client.app.state.analysis_service.store.engine.connect() as connection:
        assert connection.execute(text("SELECT count(*) FROM audit_events")).scalar_one() == 2


def test_role_key_removal_on_restart_revokes_only_that_key_without_altering_history(role_api):
    client, settings = role_api
    assert client.get("/api/v1/session", headers=headers("reader")).status_code == 200
    with TestClient(create_app(replace(settings, reader_token=""))) as restarted:
        assert restarted.get("/api/v1/session", headers=headers("reader")).status_code == 401
        assert restarted.get("/api/v1/session", headers=headers("admin")).json()["role"] == "admin"


@pytest.mark.parametrize("token", [TOKENS["admin"], "short", "x" * 513, "x" * 40 + "\n"])
def test_role_keys_are_distinct_bounded_and_never_reflected(token):
    with pytest.raises(ValueError) as error:
        ApiSettings(
            "sqlite:///test.sqlite3",
            TOKENS["admin"],
            Fernet.generate_key().decode(),
            reader_token=token,
        )
    assert token not in str(error.value)


def test_optional_role_environment_cannot_enable_partial_api(monkeypatch):
    for name in (
        "NETCONFIG_DATABASE_URL",
        "NETCONFIG_API_TOKEN",
        "NETCONFIG_ENCRYPTION_KEY",
        "NETCONFIG_READER_TOKEN",
        "NETCONFIG_ANALYST_TOKEN",
        "NETCONFIG_ENGINEER_TOKEN",
    ):
        monkeypatch.delenv(name, raising=False)
    assert ApiSettings.from_environment() is None
    monkeypatch.setenv("NETCONFIG_READER_TOKEN", TOKENS["reader"])
    with pytest.raises(ValueError):
        ApiSettings.from_environment()
    monkeypatch.setenv("NETCONFIG_DATABASE_URL", "sqlite:///test.sqlite3")
    monkeypatch.setenv("NETCONFIG_API_TOKEN", TOKENS["admin"])
    monkeypatch.setenv("NETCONFIG_ENCRYPTION_KEY", Fernet.generate_key().decode())
    settings = ApiSettings.from_environment()
    assert settings is not None and settings.role_for_token(TOKENS["reader"]) == "reader"
    assert not any(token in repr(settings) for token in TOKENS.values())


@pytest.mark.parametrize("permission,path", OPERATIONS)
def test_missing_credentials_are_rejected_before_any_write_body(role_api, permission, path):
    client, _ = role_api
    response = client.post(path, content=b"private-invalid-body" * 20000)
    assert response.status_code == 401
    assert "private-invalid-body" not in response.text


def test_engineer_can_append_feedback_draft_and_review_but_reader_cannot(role_api):
    client, _ = role_api
    device = str(uuid4())
    snapshots = []
    for content in ("hostname access-test\n", "hostname access-test\nntp server 192.0.2.1\n"):
        response = client.post(
            "/api/v1/configurations",
            headers=headers("analyst"),
            json={
                "device_id": device,
                "filename": "synthetic.cfg",
                "content": content,
            },
        )
        assert response.status_code == 201
        snapshots.append(response.json())
    before, after = snapshots
    analyzed = client.post(
        f"/api/v1/configurations/{after['configuration_id']}/analyze", headers=headers("analyst")
    )
    assert analyzed.status_code == 201
    result = analyzed.json()
    feedback_path = f"/api/v1/findings/{result['findings'][0]['finding_id']}/feedback"
    feedback = {
        "feedback_id": str(uuid4()),
        "analysis_id": result["analysis_id"],
        "finding_sha256": result["explanations"][0]["finding_sha256"],
        "verdict": "needs_investigation",
        "comment": "Synthetic review.",
    }
    assert client.post(feedback_path, headers=headers("reader"), json=feedback).status_code == 403
    assert client.post(feedback_path, headers=headers("engineer"), json=feedback).status_code == 201
    draft = {
        "patch_id": str(uuid4()),
        "before_configuration_id": before["configuration_id"],
        "after_configuration_id": after["configuration_id"],
        "before_source_sha256": before["canonical"]["source"]["sha256"],
        "after_source_sha256": after["canonical"]["source"]["sha256"],
    }
    assert client.post("/api/v1/patches", headers=headers("analyst"), json=draft).status_code == 403
    created = client.post("/api/v1/patches", headers=headers("engineer"), json=draft)
    assert created.status_code == 201
    patch = created.json()
    path = f"/api/v1/patches/{patch['patch_id']}"
    options = {
        "verification_id": str(uuid4()),
        "draft_sha256": patch["draft_sha256"],
        "mode": "local_preflight",
    }
    assert client.post(path + "/verify", headers=headers("reader"), json=options).status_code == 403
    assert (
        client.post(path + "/verify", headers=headers("engineer"), json=options).status_code == 201
    )
    assert client.get(path, headers=headers("reader")).status_code == 200
    assert client.get(path + "/verifications", headers=headers("reader")).status_code == 200
