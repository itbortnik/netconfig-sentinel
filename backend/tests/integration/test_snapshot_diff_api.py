"""Read-only, bounded saved-snapshot comparisons, auth and explicit selection."""

from collections.abc import Iterator
from pathlib import Path
from uuid import uuid4

import pytest
from app.core.settings import ApiSettings
from app.db.migrate import upgrade_database
from app.db.store import Store
from app.main import create_app
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import text

TOKEN = "snapshot-diff-test-service-token-32-characters"
HEADERS = {"Authorization": f"Bearer {TOKEN}"}


@pytest.fixture
def diff_api(tmp_path: Path) -> Iterator[tuple[TestClient, Store, ApiSettings]]:
    settings = ApiSettings(
        f"sqlite:///{tmp_path / 'diff.sqlite3'}", TOKEN, Fernet.generate_key().decode()
    )
    application = create_app(settings)
    store = application.state.analysis_service.store
    upgrade_database(store.engine)
    with TestClient(application) as client:
        yield client, store, settings


def upload(client: TestClient, content: str, *, device: str | None = None) -> dict:
    response = client.post(
        "/api/v1/configurations",
        headers=HEADERS,
        json={
            "device_id": device or str(uuid4()),
            "filename": "edge.cfg",
            "content": content,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def diff(client: TestClient, before: dict, after: dict):
    return client.get(
        f"/api/v1/configurations/{after['configuration_id']}/diff",
        params={"reference_configuration_id": before["configuration_id"]},
        headers=HEADERS,
    )


def test_read_only_restart_safe_comparison_has_no_analysis_or_audit_side_effect(diff_api) -> None:
    client, store, settings = diff_api
    before = upload(client, "hostname edge\nntp server 192.0.2.1\n")
    after = upload(client, "hostname edge\nntp server 192.0.2.2\n", device=before["device_id"])
    response = diff(client, before, after)
    assert response.status_code == 200, response.text
    report = response.json()
    assert report["representation"] == "normalized_objects"
    assert report["modified_count"] == 1 and report["changes"][0]["section"] == "management"
    assert report["before"]["source_sha256"] == before["canonical"]["source"]["sha256"]
    assert report["after"]["source_sha256"] == after["canonical"]["source"]["sha256"]
    assert response.headers["Cache-Control"] == "no-store"
    with TestClient(create_app(settings)) as restarted:
        assert diff(restarted, before, after).json() == report
    with store.engine.connect() as connection:
        assert connection.execute(text("SELECT count(*) FROM audit_events")).scalar_one() == 2
        assert connection.execute(text("SELECT count(*) FROM analyses")).scalar_one() == 0
    assert (
        client.get(f"/api/v1/configurations/{before['configuration_id']}", headers=HEADERS).json()
        == before
    )


def test_explicit_query_auth_missing_identity_future_and_same_snapshot(diff_api) -> None:
    client, _, _ = diff_api
    before = upload(client, "hostname edge\n")
    after = upload(client, "hostname edge\n", device=before["device_id"])
    other = upload(client, "hostname edge\n")
    path = f"/api/v1/configurations/{after['configuration_id']}/diff"
    assert client.get(path).status_code == 401
    assert client.get(path, headers=HEADERS).status_code == 422
    assert client.get(
        path, params={"reference_configuration_id": "private-invalid"}, headers=HEADERS
    ).json() == {"detail": "Invalid request parameters."}
    assert diff(client, {"configuration_id": str(uuid4())}, after).status_code == 404
    for reference, current in ((other, after), (after, before), (after, after)):
        assert diff(client, reference, current).status_code == 409


def test_junos_partial_scope_and_removed_object_anchors(diff_api) -> None:
    client, _, _ = diff_api
    before = upload(
        client,
        "set system host-name edge\nset interfaces ge-0/0/0 disable\nset unknown PRIVATE-BEFORE\n",
    )
    after = upload(
        client, "set system host-name edge\nset unknown PRIVATE-AFTER\n", device=before["device_id"]
    )
    response = diff(client, before, after)
    assert response.status_code == 200, response.text
    report = response.json()
    assert report["coverage"] == "partial"
    assert report["removed_count"] == 1
    removed = report["changes"][0]
    assert removed["after_locations"] == [] and removed["after_value"] is None
    assert removed["before_locations"] and "PRIVATE" not in response.text


def test_input_output_and_change_budgets_return_explicit_refusal(diff_api, monkeypatch) -> None:
    client, _, _ = diff_api
    before = upload(client, "hostname edge\n")
    after = upload(client, "hostname edge\nntp server 192.0.2.1\n", device=before["device_id"])
    for limit in ("MAX_INPUT_BYTES", "MAX_OUTPUT_BYTES", "MAX_CHANGES"):
        with monkeypatch.context() as selected:
            selected.setattr(f"app.comparison.snapshots.{limit}", 0)
            response = diff(client, before, after)
            assert response.status_code == 413
            assert response.json() == {"detail": "Selected comparison exceeds size limits."}


def test_corrupt_snapshot_is_not_an_empty_comparison(diff_api) -> None:
    client, store, _ = diff_api
    before = upload(client, "hostname edge\n")
    after = upload(client, "hostname edge\n", device=before["device_id"])
    with store.engine.begin() as connection:
        connection.execute(
            text("UPDATE configurations SET payload='private-invalid' WHERE id=:id"),
            {"id": before["configuration_id"]},
        )
    response = diff(client, before, after)
    assert response.status_code == 503 and response.json() == {
        "detail": "Stored data is unavailable."
    }
