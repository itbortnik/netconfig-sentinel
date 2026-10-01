"""Authenticated upload, deterministic analysis and encrypted restart-safe history."""

import json
from collections.abc import Iterator
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from app.api import configurations
from app.api.contracts import AnalysisResult
from app.core.settings import ApiSettings
from app.db.migrate import upgrade_database
from app.db.store import Store
from app.main import create_app
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import text

TOKEN = "persistent-test-token-not-for-deployment-001"
HEADERS = {"Authorization": f"Bearer {TOKEN}"}
DEVICE = str(UUID(int=1))
PRIVATE = "private-test-sentinel-DO-NOT-LOG"


@pytest.fixture
def settings(tmp_path: Path) -> ApiSettings:
    return ApiSettings(
        database_url=f"sqlite:///{tmp_path / 'history.sqlite3'}",
        api_token=TOKEN,
        encryption_key=Fernet.generate_key().decode("ascii"),
    )


@pytest.fixture
def api(settings: ApiSettings) -> Iterator[tuple[TestClient, Store]]:
    application = create_app(settings)
    store = application.state.analysis_service.store
    upgrade_database(store.engine)
    with TestClient(application) as client:
        yield client, store


def upload(client: TestClient, content: str = "hostname edge\n", device: str = DEVICE) -> dict:
    response = client.post(
        "/api/v1/configurations",
        headers=HEADERS,
        json={"device_id": device, "filename": "edge.cfg", "content": content},
    )
    assert response.status_code == 201, response.text
    return response.json()


@pytest.mark.parametrize(
    "content,vendor",
    [("hostname edge\n", "cisco"), ("set system host-name edge\n", "juniper")],
)
def test_upload_analyze_and_restart(
    api: tuple[TestClient, Store], settings: ApiSettings, content: str, vendor: str
) -> None:
    client, store = api
    snapshot = upload(client, content)
    cid = snapshot["configuration_id"]
    assert snapshot["canonical"]["device"]["vendor"] == vendor
    assert snapshot["canonical"]["parser_confidence"] == 1
    response = client.post(f"/api/v1/configurations/{cid}/analyze", headers=HEADERS)
    assert response.status_code == 201, response.text
    result = response.json()
    assert result["status"] == "completed"
    assert result["risk"]["device_id"] == DEVICE
    assert result["findings"]
    assert len(result["findings"]) == len(result["explanations"])
    assert all(item["formal_verification"] == "not_run" for item in result["explanations"])
    assert result["source_sha256"] == snapshot["canonical"]["source"]["sha256"]
    aid = result["analysis_id"]
    assert (
        client.get(f"/api/v1/analyses/{aid}/findings", headers=HEADERS).json() == result["findings"]
    )
    assert client.get("/ready").json()["checks"] == {
        "vendor_parsers": True,
        "persistent_api": True,
        "database_schema": True,
    }
    with store.engine.connect() as connection:
        assert connection.execute(text("SELECT count(*) FROM audit_events")).scalar_one() == 2
    with TestClient(create_app(settings)) as restarted:
        assert restarted.get(f"/api/v1/configurations/{cid}", headers=HEADERS).json() == snapshot
        assert restarted.get(f"/api/v1/analyses/{aid}", headers=HEADERS).json() == result


def test_history_filters_pagination_and_repeated_analysis(api: tuple[TestClient, Store]) -> None:
    client, _ = api
    first = upload(client)
    second = upload(client, "hostname edge\n! newer snapshot\n")
    other = str(uuid4())
    third = upload(client, "hostname other\n", other)
    items = client.get("/api/v1/configurations", headers=HEADERS).json()
    assert [item["configuration_id"] for item in items] == [
        third["configuration_id"],
        second["configuration_id"],
        first["configuration_id"],
    ]
    assert "canonical" not in items[0]
    page = client.get(
        "/api/v1/configurations",
        params={"device_id": DEVICE, "limit": 1, "offset": 1},
        headers=HEADERS,
    ).json()
    assert [item["configuration_id"] for item in page] == [first["configuration_id"]]
    cid = first["configuration_id"]
    one = client.post(f"/api/v1/configurations/{cid}/analyze", headers=HEADERS).json()
    two = client.post(f"/api/v1/configurations/{cid}/analyze", headers=HEADERS).json()
    assert one["analysis_id"] != two["analysis_id"]
    assert one["findings"] == two["findings"]
    history = client.get(
        "/api/v1/analyses", params={"configuration_id": cid}, headers=HEADERS
    ).json()
    assert [item["analysis_id"] for item in history] == [two["analysis_id"], one["analysis_id"]]
    assert (
        client.get(
            "/api/v1/analyses", params={"configuration_id": str(uuid4())}, headers=HEADERS
        ).json()
        == []
    )


def test_partial_parse_has_no_aggregate_risk_and_stays_encrypted(
    api: tuple[TestClient, Store], caplog: pytest.LogCaptureFixture
) -> None:
    client, store = api
    snapshot = upload(client, f"hostname edge\nunknown-command {PRIVATE}\n")
    cid = snapshot["configuration_id"]
    result = client.post(f"/api/v1/configurations/{cid}/analyze", headers=HEADERS).json()
    assert result["status"] == "partial"
    assert result["risk"] is None
    assert result["findings"]
    assert PRIVATE not in json.dumps(result)
    assert PRIVATE in json.dumps(snapshot)
    with store.engine.connect() as connection:
        for table, column in (
            ("devices", "identity_payload"),
            ("configurations", "payload"),
            ("analyses", "payload"),
        ):
            payloads = connection.execute(text(f"SELECT {column} FROM {table}")).scalars().all()
            assert all(PRIVATE not in value and "hostname" not in value for value in payloads)
    assert PRIVATE not in caplog.text


@pytest.mark.parametrize(
    "method,path",
    [
        ("POST", "/configurations"),
        ("GET", "/configurations"),
        ("GET", f"/configurations/{UUID(int=3)}"),
        ("POST", f"/configurations/{UUID(int=3)}/analyze"),
        ("GET", "/analyses"),
        ("GET", f"/analyses/{UUID(int=3)}"),
        ("GET", f"/analyses/{UUID(int=3)}/findings"),
    ],
)
def test_every_persistent_route_requires_authentication(
    api: tuple[TestClient, Store], method: str, path: str
) -> None:
    client, _ = api
    response = client.request(method, f"/api/v1{path}", content=PRIVATE)
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
    assert PRIVATE not in response.text
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"


@pytest.mark.parametrize("token", ["Bearer wrong-token", f"Basic {TOKEN}", "Bearer тест"])
def test_invalid_auth_does_not_inspect_body(api: tuple[TestClient, Store], token: str) -> None:
    client, _ = api
    # HTTP header bytes allow an invalid non-ASCII credential without client encoding errors.
    response = client.post(
        "/api/v1/configurations",
        headers={b"authorization": token.encode("utf-8")},
        content=PRIVATE,
    )
    assert response.status_code == 401
    assert PRIVATE not in response.text


@pytest.mark.parametrize(
    "change",
    [
        {"filename": "../private.cfg"},
        {"filename": "C:\\private.cfg"},
        {"filename": "file.exe"},
        {"filename": "file\x00.cfg"},
        {"content": ""},
        {"content": "   \n"},
        {"content": "hostname edge\n\x00"},
        {"content": "unknown text"},
        {"device_id": PRIVATE},
        {"unexpected": PRIVATE},
        {"content": 123},
        {"content": "hostname edge\n" + "!\n" * 10_000},
        {"content": "hostname edge\n" + "я" * (1024 * 1024)},
    ],
)
def test_invalid_upload_is_bounded_and_does_not_leak_inputs(
    api: tuple[TestClient, Store], change: dict
) -> None:
    client, store = api
    body = {"device_id": DEVICE, "filename": "edge.cfg", "content": "hostname edge\n"} | change
    response = client.post("/api/v1/configurations", headers=HEADERS, json=body)
    assert response.status_code == 400
    assert PRIVATE not in response.text
    with store.engine.connect() as connection:
        assert connection.execute(text("SELECT count(*) FROM configurations")).scalar_one() == 0


@pytest.mark.parametrize("body", [b"{", b"\xff", b"[]", b'{"content":"a","content":"b"}'])
def test_malformed_json_is_generic(api: tuple[TestClient, Store], body: bytes) -> None:
    client, _ = api
    response = client.post(
        "/api/v1/configurations",
        content=body,
        headers=HEADERS | {"Content-Type": "application/json"},
    )
    assert response.status_code == 400
    assert response.json() == {"detail": "Invalid configuration upload."}


def test_transport_rejects_unsupported_and_oversized_requests(
    api: tuple[TestClient, Store], monkeypatch: pytest.MonkeyPatch
) -> None:
    client, _ = api
    for extra in ({"Content-Type": "text/plain"}, {"Content-Encoding": "gzip"}):
        response = client.post(
            "/api/v1/configurations",
            content="{}",
            headers=HEADERS | {"Content-Type": "application/json"} | extra,
        )
        assert response.status_code == 415
    for length, status in (("-1", 400), ("not-a-number", 400), ("999999999", 413)):
        response = client.post(
            "/api/v1/configurations",
            content="{}",
            headers=HEADERS | {"Content-Type": "application/json", "Content-Length": length},
        )
        assert response.status_code == status
    monkeypatch.setattr(configurations, "MAX_REQUEST_BYTES", 8)
    response = client.post(
        "/api/v1/configurations",
        content=iter([b"1234", b"56789"]),
        headers=HEADERS | {"Content-Type": "application/json"},
    )
    assert response.status_code == 413


def test_identity_conflict_does_not_create_snapshot_or_audit(api: tuple[TestClient, Store]) -> None:
    client, store = api
    upload(client)
    response = client.post(
        "/api/v1/configurations",
        headers=HEADERS,
        json={"device_id": DEVICE, "filename": "other.cfg", "content": "hostname other\n"},
    )
    assert response.status_code == 409
    with store.engine.connect() as connection:
        for table in ("devices", "configurations", "audit_events"):
            assert connection.execute(text(f"SELECT count(*) FROM {table}")).scalar_one() == 1


def test_openapi_describes_upload_and_bearer_security(api: tuple[TestClient, Store]) -> None:
    client, _ = api
    document = client.get("/openapi.json").json()
    operation = document["paths"]["/api/v1/configurations"]["post"]
    assert operation["security"] == [{"HTTPBearer": []}]
    schema = operation["requestBody"]["content"]["application/json"]["schema"]
    assert set(schema["required"]) == {"device_id", "filename", "content"}
    assert schema["additionalProperties"] is False


@pytest.mark.parametrize("target", ["configuration", "analysis", "device"])
def test_corrupt_payload_is_unavailable_not_a_success(
    api: tuple[TestClient, Store], target: str
) -> None:
    client, store = api
    snapshot = upload(client)
    cid = snapshot["configuration_id"]
    aid = client.post(f"/api/v1/configurations/{cid}/analyze", headers=HEADERS).json()[
        "analysis_id"
    ]
    table, column = {
        "configuration": ("configurations", "payload"),
        "analysis": ("analyses", "payload"),
        "device": ("devices", "identity_payload"),
    }[target]
    with store.engine.begin() as connection:
        connection.execute(text(f"UPDATE {table} SET {column}=:payload"), {"payload": PRIVATE})
    if target == "device":
        response = client.post(
            "/api/v1/configurations",
            headers=HEADERS,
            json={"device_id": DEVICE, "filename": "edge.cfg", "content": "hostname edge\n"},
        )
    else:
        path = f"configurations/{cid}" if target == "configuration" else f"analyses/{aid}"
        response = client.get(f"/api/v1/{path}", headers=HEADERS)
    assert response.status_code == 503
    assert response.json() == {"detail": "Stored data is unavailable."}
    assert PRIVATE not in response.text


def test_wrong_key_and_valid_ciphertext_swaps_are_rejected(
    api: tuple[TestClient, Store], settings: ApiSettings
) -> None:
    client, store = api
    one, two = upload(client), upload(client)
    wrong_key = ApiSettings(settings.database_url, TOKEN, Fernet.generate_key().decode("ascii"))
    with TestClient(create_app(wrong_key)) as wrong:
        assert wrong.get("/api/v1/configurations", headers=HEADERS).status_code == 503
    with store.engine.begin() as connection:
        payload = connection.execute(
            text("SELECT payload FROM configurations WHERE id=:id"),
            {"id": one["configuration_id"]},
        ).scalar_one()
        connection.execute(
            text("UPDATE configurations SET payload=:payload WHERE id=:id"),
            {"id": two["configuration_id"], "payload": payload},
        )
    assert (
        client.get(f"/api/v1/configurations/{two['configuration_id']}", headers=HEADERS).status_code
        == 503
    )


@pytest.mark.parametrize(
    "envelope_change",
    [
        {"kind": "analysis"},
        {"id": str(UUID(int=99))},
        {"contents": {}},
        {"contents": "private-invalid-contract"},
    ],
)
def test_authenticated_but_invalid_envelope_is_rejected(
    api: tuple[TestClient, Store], settings: ApiSettings, envelope_change: dict
) -> None:
    client, store = api
    snapshot = upload(client)
    cid = snapshot["configuration_id"]
    envelope = {
        "kind": "configuration",
        "id": cid,
        "contents": json.dumps(snapshot),
    } | envelope_change
    ciphertext = (
        Fernet(settings.encryption_key.encode("ascii"))
        .encrypt(json.dumps(envelope).encode("utf-8"))
        .decode("ascii")
    )
    with store.engine.begin() as connection:
        connection.execute(
            text("UPDATE configurations SET payload=:payload"), {"payload": ciphertext}
        )
    response = client.get(f"/api/v1/configurations/{cid}", headers=HEADERS)
    assert response.status_code == 503
    assert response.json() == {"detail": "Stored data is unavailable."}


def test_open_metadata_cannot_rebind_a_configuration(api: tuple[TestClient, Store]) -> None:
    client, store = api
    snapshot = upload(client)
    with store.engine.begin() as connection:
        connection.execute(
            text("UPDATE configurations SET source_sha256=:hash"), {"hash": "0" * 64}
        )
    assert (
        client.get(
            f"/api/v1/configurations/{snapshot['configuration_id']}", headers=HEADERS
        ).status_code
        == 503
    )


@pytest.mark.parametrize("path", ["/configurations", "/analyses"])
def test_query_validation_does_not_echo_input(api: tuple[TestClient, Store], path: str) -> None:
    client, _ = api
    for parameters in ({"limit": 101}, {"offset": -1}, {"limit": PRIVATE}):
        response = client.get(f"/api/v1{path}", params=parameters, headers=HEADERS)
        assert response.status_code == 422
        assert PRIVATE not in response.text


def test_missing_resources_and_disabled_or_unmigrated_service(settings: ApiSettings) -> None:
    with TestClient(create_app()) as disabled:
        assert disabled.get("/health").status_code == 200
        assert disabled.get("/api/v1/configurations", headers=HEADERS).status_code == 503
    application = create_app(settings)
    with TestClient(application) as client:
        assert client.get("/health").status_code == 200
        assert client.get("/ready").status_code == 503
        assert client.get("/api/v1/configurations", headers=HEADERS).status_code == 503
        upgrade_database(application.state.analysis_service.store.engine)
        assert client.get("/ready").status_code == 200
        for path in (
            f"/configurations/{UUID(int=4)}",
            f"/analyses/{UUID(int=4)}",
            f"/analyses/{UUID(int=4)}/findings",
        ):
            assert client.get(f"/api/v1{path}", headers=HEADERS).status_code == 404
        assert (
            client.post(
                f"/api/v1/configurations/{UUID(int=4)}/analyze", headers=HEADERS
            ).status_code
            == 404
        )


@pytest.mark.parametrize(
    "change",
    [
        {"device_id": str(UUID(int=8))},
        {"status": "partial"},
        {"explanations": []},
        {"source_sha256": "0" * 64},
        {"policy_catalog_version": "different"},
    ],
)
def test_analysis_contract_rejects_unbound_results(
    api: tuple[TestClient, Store], change: dict
) -> None:
    client, _ = api
    cid = upload(client)["configuration_id"]
    result = client.post(f"/api/v1/configurations/{cid}/analyze", headers=HEADERS).json()
    with pytest.raises(ValueError):
        AnalysisResult.model_validate(result | change)
