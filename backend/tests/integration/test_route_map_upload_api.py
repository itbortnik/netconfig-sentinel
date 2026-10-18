"""User-selected parser profile, version-bound coverage and unchanged old history."""

from uuid import UUID

import pytest
from app.api.contracts import ConfigurationSnapshot
from app.db.source_records import SourceRecords
from app.main import create_app
from app.parsers.coverage import ParserCoverage
from fastapi.testclient import TestClient
from test_persistent_api import HEADERS
from test_persistent_api import api as api
from test_persistent_api import settings as settings

SOURCE = (
    "hostname owned-route-map\nroute-map EXPORT permit 10\n"
    " match ip address prefix-list TRUSTED\n!\nroute-map EXPORT permit 20\n set metric 50\n!\n"
)
BODY = {"device_id": str(UUID(int=1)), "filename": "owned.cfg", "content": SOURCE}


def test_explicit_profile_upload_coverage_source_retention_and_restart_preserve_legacy(
    api, settings
):
    client, store = api
    old_response = client.post("/api/v1/configurations", headers=HEADERS, json=BODY)
    assert old_response.status_code == 201
    legacy = old_response.json()
    assert legacy["canonical"]["schema_version"] == "1.1"
    assert "route_maps" not in legacy["canonical"]
    response = client.post(
        "/api/v1/configurations",
        headers=HEADERS,
        json=BODY | {"parser_schema_version": "1.2", "retain_original_source": True},
    )
    assert response.status_code == 201
    current = response.json()
    assert current["canonical"]["schema_version"] == "1.2"
    assert current["canonical"]["route_maps"][0]["name"] == "EXPORT"
    assert current["canonical"]["parser_confidence"] == 1
    assert (
        current["parser_coverage"]["adapter_version"] == "cisco-ios-route-maps-source-lines-0.1.0"
    )
    assert current["parser_coverage"]["unparsed_units"] == 0
    assert legacy["parser_coverage"]["unparsed_units"] == 4
    assert current["canonical"]["source"]["sha256"] == legacy["canonical"]["source"]["sha256"]
    retained = SourceRecords(store).get(
        UUID(current["configuration_id"]),
        expected_source_sha256=current["canonical"]["source"]["sha256"],
        allow_local_read=True,
    )
    assert retained.content == SOURCE
    with TestClient(create_app(settings)) as restarted:
        for saved in (legacy, current):
            result = restarted.get(
                f"/api/v1/configurations/{saved['configuration_id']}", headers=HEADERS
            )
            assert result.status_code == 200 and result.json() == saved


@pytest.mark.parametrize("profile", [None, True, 1.2, "1.0", "1.3", "PRIVATE-PARSER-NAME"])
def test_unknown_or_coerced_parser_profile_refuses_before_persistence_without_echo(api, profile):
    client, _store = api
    response = client.post(
        "/api/v1/configurations",
        headers=HEADERS,
        json=BODY | {"parser_schema_version": profile},
    )
    assert response.status_code == 400
    assert "PRIVATE-PARSER-NAME" not in response.text
    assert client.get("/api/v1/configurations", headers=HEADERS).json() == []


def test_cisco_profile_does_not_accept_junos_or_exceed_selected_budget(api):
    client, _store = api
    for content in ("set system host-name owned\n", "hostname owned\n!" + "x" * 1048576):
        response = client.post(
            "/api/v1/configurations",
            headers=HEADERS,
            json=BODY | {"parser_schema_version": "1.2", "content": content},
        )
        assert response.status_code == 400
    assert client.get("/api/v1/configurations", headers=HEADERS).json() == []


def test_coverage_profile_cannot_be_relabelled_even_when_no_route_map_changes_counts(api):
    client, _store = api
    response = client.post(
        "/api/v1/configurations",
        headers=HEADERS,
        json=BODY | {"parser_schema_version": "1.2", "content": "hostname owned\n"},
    )
    assert response.status_code == 201
    snapshot = ConfigurationSnapshot.model_validate(response.json())
    coverage = snapshot.parser_coverage
    assert coverage is not None
    forged = coverage.model_dump() | {"adapter_version": "cisco-ios-source-lines-0.1.0"}
    with pytest.raises(ValueError, match="profile"):
        ParserCoverage.model_validate(forged).validate_binding(snapshot.canonical)
    with pytest.raises(ValueError):
        ConfigurationSnapshot.model_validate(snapshot.model_dump() | {"parser_coverage": forged})
