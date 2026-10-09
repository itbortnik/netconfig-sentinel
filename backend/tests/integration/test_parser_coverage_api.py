"""Measured upload coverage survives encryption/history; legacy snapshots stay legacy."""

import json
from collections.abc import Iterator
from copy import deepcopy
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from app.api.contracts import ConfigurationSnapshot
from app.core.settings import ApiSettings
from app.db.migrate import upgrade_database
from app.db.source_records import OriginalSourceUnavailable, SourceRecords
from app.db.store import Store
from app.main import create_app
from app.parsers import parse_configuration
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import text

TOKEN = "parser-coverage-owned-service-token-000001"
HEADERS = {"Authorization": f"Bearer {TOKEN}"}


@pytest.fixture
def api(tmp_path: Path) -> Iterator[tuple[TestClient, Store, ApiSettings]]:
    settings = ApiSettings(
        f"sqlite:///{tmp_path / 'coverage.sqlite3'}", TOKEN, Fernet.generate_key().decode()
    )
    application = create_app(settings)
    store = application.state.analysis_service.store
    upgrade_database(store.engine)
    with TestClient(application) as client:
        yield client, store, settings


def upload(client: TestClient, source: str) -> dict:
    response = client.post(
        "/api/v1/configurations",
        headers=HEADERS,
        json={
            "device_id": str(uuid4()),
            "filename": "owned.cfg",
            "content": source,
            "inventory": {
                "device_role": "edge",
                "site_class": "branch",
                "service_profile": "owned",
            },
        },
    )
    assert response.status_code == 201, response.status_code
    return response.json()


@pytest.mark.parametrize(
    "source,fraction",
    [
        ("! owned\r\nhostname owned\r\nunknown PRIVATE_VALUE\r\nend\r\n", 0.5),
        ("set system host-name owned\nset unknown PRIVATE_VALUE\n", 0.5),
        ("system {\n host-name owned;\n unknown PRIVATE_VALUE;\n}\n", 1 / 3),
    ],
)
def test_upload_get_restart_and_partial_analysis_preserve_measured_report(api, source, fraction):
    client, store, settings = api
    snapshot = upload(client, source)
    report = snapshot["parser_coverage"]
    assert report["unparsed_fraction"] == fraction
    assert report["source_sha256"] == snapshot["canonical"]["source"]["sha256"]
    assert "PRIVATE_VALUE" not in str(report)
    canonical = parse_configuration(
        source,
        filename="owned.cfg",
        collected_at=ConfigurationSnapshot.model_validate(snapshot).canonical.source.collected_at,
    )
    assert canonical.parser_confidence == snapshot["canonical"]["parser_confidence"]
    assert (
        canonical.unparsed_fragments
        == ConfigurationSnapshot.model_validate(snapshot).canonical.unparsed_fragments
    )
    assert snapshot["canonical"]["device"]["role"] == "edge"
    cid = snapshot["configuration_id"]
    path = f"/api/v1/configurations/{cid}"
    assert client.get(path).status_code == 401
    assert client.get(path, headers=HEADERS).json() == snapshot
    analysis = client.post(path + "/analyze", headers=HEADERS)
    assert analysis.status_code == 201
    assert analysis.json()["status"] == "partial" and analysis.json()["risk"] is None
    aid = analysis.json()["analysis_id"]
    # No retention consent: line hashes do not silently retain the original input.
    with pytest.raises(OriginalSourceUnavailable):
        SourceRecords(store).get(
            UUID(cid), expected_source_sha256=report["source_sha256"], allow_local_read=True
        )
    with store.engine.connect() as connection:
        encrypted = connection.execute(
            text("SELECT payload FROM configurations WHERE id=:id"), {"id": cid}
        ).scalar_one()
        assert "parser-coverage" not in encrypted and "PRIVATE_VALUE" not in encrypted
        assert connection.execute(text("SELECT count(*) FROM audit_events")).scalar_one() == 2
    with TestClient(create_app(settings)) as restarted:
        assert restarted.get(path, headers=HEADERS).json() == snapshot
        assert restarted.get(f"/api/v1/analyses/{aid}", headers=HEADERS).json() == analysis.json()
    summary = client.get(
        "/api/v1/configurations", params={"device_id": snapshot["device_id"]}, headers=HEADERS
    )
    assert summary.status_code == 200
    assert "units" not in str(summary.json())


def test_legacy_saved_payload_is_read_without_reparsing_or_inventing_coverage(api, monkeypatch):
    client, store, _ = api
    canonical = parse_configuration("hostname legacy\n", filename="legacy.cfg")
    snapshot = ConfigurationSnapshot(
        configuration_id=uuid4(),
        device_id=uuid4(),
        created_at=canonical.source.collected_at,
        canonical=canonical,
    )
    original = snapshot.model_dump_json()
    assert "parser_coverage" not in original
    store.add_configuration(snapshot)
    monkeypatch.setattr(
        "app.parsers.registry.parse_configuration",
        lambda *args, **kwargs: pytest.fail("history must not reparse"),
    )
    response = client.get(f"/api/v1/configurations/{snapshot.configuration_id}", headers=HEADERS)
    assert response.status_code == 200
    assert "parser_coverage" not in response.json()
    assert ConfigurationSnapshot.model_validate_json(original).model_dump_json() == original


@pytest.mark.parametrize("changed_field", ["source", "platform", "unknown-anchor", "line-hash"])
def test_bound_snapshot_and_storage_refuse_corrupt_coverage(api, changed_field):
    client, store, _ = api
    snapshot = upload(client, "hostname owned\nunknown PRIVATE_VALUE\n")
    changed = deepcopy(snapshot)
    if changed_field == "source":
        changed["parser_coverage"]["source_sha256"] = "a" * 64
    elif changed_field == "platform":
        changed["canonical"]["device"]["platform"] = "ios-xe"
    elif changed_field == "unknown-anchor":
        changed["canonical"]["unparsed_fragments"][0]["location"]["source_lines"] = [1]
    else:
        changed["parser_coverage"]["units"][1]["raw_text_sha256"] = "b" * 64
    with pytest.raises(ValueError):
        ConfigurationSnapshot.model_validate(changed)
    cid = snapshot["configuration_id"]
    encrypted = store._encode(json.dumps(changed), kind="configuration", row_id=cid)
    with store.engine.begin() as connection:
        connection.execute(
            text("UPDATE configurations SET payload=:payload WHERE id=:id"),
            {"payload": encrypted, "id": cid},
        )
    response = client.get(f"/api/v1/configurations/{cid}", headers=HEADERS)
    assert response.status_code == 503
    assert response.json() == {"detail": "Stored data is unavailable."}
