"""Actual HTTP native generation on authored inputs, not independent policy quality."""

from uuid import UUID, uuid4

import app.patching.native_patches as workflow_module
import pytest
from app.core.settings import ApiSettings
from app.db.migrate import upgrade_database
from app.db.native_patch_records import NativePatchRecords
from app.db.source_records import SourceRecords
from app.main import create_app
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import text

ADMIN = "owned-native-admin-service-token-00000000001"
ENGINEER = "owned-native-engineer-service-token-0000001"
ANALYST = "owned-native-analyst-service-token-00000001"
READER = "owned-native-reader-service-token-000000001"
MARKERS = ("owned-native-password-marker", "owned-native-community-marker")


def headers(token=ENGINEER):
    return {"Authorization": "Bearer " + token, "Content-Type": "application/json"}


def source(vendor):
    if vendor == "cisco":
        return (
            "hostname owned\nip ssh version 2\n"
            f"username operator privilege 15 secret 0 {MARKERS[0]}\n"
            f"snmp-server community {MARKERS[1]} RO\n"
            "line vty 0 4\n transport input ssh telnet\n!\n"
        )
    return (
        "set system host-name owned\nset system services ssh\n"
        f'set system login user operator authentication encrypted-password "{MARKERS[0]}"\n'
        f"set snmp community {MARKERS[1]} authorization read-only\n"
        "set system services telnet\n"
    )


@pytest.fixture
def native_api(tmp_path):
    settings = ApiSettings(
        f"sqlite:///{tmp_path / 'native.sqlite3'}",
        ADMIN,
        Fernet.generate_key().decode(),
        reader_token=READER,
        analyst_token=ANALYST,
        engineer_token=ENGINEER,
    )
    application = create_app(settings)
    store = application.state.analysis_service.store
    upgrade_database(store.engine)
    with TestClient(application) as client:
        yield client, application, settings


def prepare(client, vendor="cisco", *, retain=True, contents=None):
    response = client.post(
        "/api/v1/configurations",
        headers=headers(ANALYST),
        json={
            "device_id": str(uuid4()),
            "filename": "owned.cfg",
            "content": source(vendor) if contents is None else contents,
            "retain_original_source": retain,
        },
    )
    assert response.status_code == 201, response.text
    snapshot = response.json()
    configuration_id = snapshot["configuration_id"]
    response = client.post(
        f"/api/v1/configurations/{configuration_id}/analyze",
        headers=headers(ANALYST),
        json={},
    )
    assert response.status_code == 201, response.text
    analysis = response.json()
    response = client.get(
        f"/api/v2/configurations/{configuration_id}/native-patch-selection/{analysis['analysis_id']}",
        headers=headers(READER),
    )
    assert response.status_code == 200, response.text
    selection = response.json()
    pin = selection["finding_pins"][0]
    options = {
        "version": "native-patch-request-0.1.0",
        "candidate_id": str(uuid4()),
        "analysis_id": analysis["analysis_id"],
        "finding_id": pin["finding_id"],
        "analysis_sha256": selection["analysis_sha256"],
        "finding_sha256": pin["finding_sha256"],
        "source_sha256": selection["source"]["source_sha256"],
        "canonical_sha256": selection["canonical_sha256"],
        "policy_catalog_version": selection["policy_catalog_version"],
        "allow_local_native_generation": True,
        "allow_private_candidate_retention": True,
    }
    return snapshot, analysis, options


def url(snapshot):
    return f"/api/v2/configurations/{snapshot['configuration_id']}/native-patches"


def post(client, snapshot, options, token=ENGINEER):
    return client.post(url(snapshot), headers=headers(token), json=options)


def counts(application):
    with application.state.analysis_service.store.engine.connect() as connection:
        return (
            connection.execute(text("SELECT count(*) FROM native_patch_candidates")).scalar_one(),
            connection.execute(
                text("SELECT count(*) FROM audit_events WHERE action='native_patch.created'")
            ).scalar_one(),
        )


@pytest.mark.parametrize("vendor", ["cisco", "juniper"])
def test_actual_native_candidate_private_retention_and_restart_without_runtime(
    native_api, monkeypatch, vendor
):
    client, application, settings = native_api
    snapshot, _analysis, options = prepare(client, vendor)
    response = post(client, snapshot, options)
    assert response.status_code == 201, response.text
    public = response.json()
    assert public["status"] == "needs_review"
    assert public["formal_qualification"] == "not_proven"
    assert not any(public[name] for name in ("calibrated", "quality_proven", "approved", "applied"))
    assert public["service_role"] == "engineer"
    assert public["metadata"]["review"]["preflight"]["formal_verification"] == "not_run"
    assert public["metadata"]["review"]["preflight"]["after"]["complete"]
    assert public["native_commands"] == (
        ["line vty 0 4", "transport input ssh", "exit"]
        if vendor == "cisco"
        else ["delete system services telnet"]
    )
    store = application.state.analysis_service.store
    private = NativePatchRecords(store).get(UUID(options["candidate_id"]))
    assert private is not None
    assert private.before_text == source(vendor)
    for marker in MARKERS:
        assert marker in private.candidate_text
        assert marker not in response.text
        assert marker not in repr(private)
    with store.engine.connect() as connection:
        encrypted = connection.execute(
            text("SELECT payload FROM native_patch_candidates")
        ).scalar_one()
    assert all(marker not in encrypted for marker in MARKERS)
    operation = application.state.operation_journal.get(UUID(response.headers["X-Operation-Id"]))
    assert operation.receipt.operation == "generate_native_patch"
    assert operation.completion.result is not None
    assert all(marker not in operation.model_dump_json() for marker in MARKERS)
    with store.engine.begin() as connection:
        connection.execute(text("DELETE FROM configuration_sources"))

    def forbidden(*args, **kwargs):
        pytest.fail("immutable native history must not read originals or execute runtime checks")

    monkeypatch.setattr(SourceRecords, "get", forbidden)
    monkeypatch.setattr(workflow_module, "create_vendor_draft", forbidden)
    monkeypatch.setattr(workflow_module, "prepare_original_source", forbidden)
    monkeypatch.setattr(workflow_module, "evaluate_policies", forbidden)
    monkeypatch.setattr("app.patching.vendor_drafts.parse_configuration", forbidden)
    monkeypatch.setattr("app.detection.policy_engine.POLICY_CATALOGS", {})
    with TestClient(create_app(settings)) as restarted:
        loaded = restarted.get(
            url(snapshot) + "/" + options["candidate_id"], headers=headers(READER)
        )
        assert loaded.status_code == 200, loaded.text
        assert loaded.json() == public
        replay = post(restarted, snapshot, options, ADMIN)
        assert replay.status_code == 200, replay.text
        assert replay.json() == public
        listing = restarted.get(url(snapshot), headers=headers(READER))
        assert listing.status_code == 200, listing.text
        assert listing.json()[0]["review_sha256"] == public["review_sha256"]
        assert post(restarted, snapshot, options | {"finding_sha256": "0" * 64}).status_code == 409
    assert counts(application) == (1, 1)


@pytest.mark.parametrize("token,status", [(READER, 403), (ANALYST, 403), (ENGINEER, 400)])
def test_authorize_before_invalid_body(native_api, token, status):
    client, _application, _settings = native_api
    response = client.post(
        f"/api/v2/configurations/{uuid4()}/native-patches",
        headers=headers(token),
        content="not json",
    )
    assert response.status_code == status


@pytest.mark.parametrize(
    "field,value",
    [
        ("allow_local_native_generation", False),
        ("allow_local_native_generation", 1),
        ("allow_private_candidate_retention", False),
        ("allow_private_candidate_retention", "true"),
        ("allow_private_candidate_retention", None),
        ("version", "native-patch-request-9.0.0"),
        ("content", "untrusted client source"),
    ],
)
def test_strict_request_refusal_before_generation(native_api, monkeypatch, field, value):
    client, application, _settings = native_api
    snapshot, _analysis, options = prepare(client)

    def forbidden(*args, **kwargs):
        pytest.fail("invalid consent/request must not generate")

    monkeypatch.setattr(workflow_module, "create_vendor_draft", forbidden)
    assert post(client, snapshot, options | {field: value}).status_code == 400
    assert counts(application) == (0, 0)


@pytest.mark.parametrize(
    "field", ["analysis_sha256", "finding_sha256", "canonical_sha256", "source_sha256"]
)
def test_stale_pin_refused(native_api, field):
    client, application, _settings = native_api
    snapshot, _analysis, options = prepare(client)
    assert post(client, snapshot, options | {field: "0" * 64}).status_code == 409
    assert counts(application) == (0, 0)


def test_no_source_and_wrong_url_are_explicit_conflicts(native_api):
    client, application, _settings = native_api
    snapshot, _analysis, options = prepare(client, retain=False)
    assert post(client, snapshot, options).status_code == 409
    other, _analysis, body = prepare(client)
    assert post(client, other, body).status_code == 201
    assert post(client, snapshot, body).status_code == 409
    assert (
        client.get(url(snapshot) + "/" + body["candidate_id"], headers=headers()).status_code == 404
    )
    assert client.get(url({"configuration_id": uuid4()}), headers=headers()).status_code == 404
    assert counts(application) == (1, 1)


def test_duplicate_keys_budget_and_openapi(native_api):
    client, _application, _settings = native_api
    path = f"/api/v2/configurations/{uuid4()}/native-patches"
    assert client.post(path, headers=headers(), content='{"x":1,"x":2}').status_code == 400
    assert client.post(path, headers=headers(), content=" " * (16 * 1024 + 1)).status_code == 413
    schema = client.get("/openapi.json").json()
    post_schema = schema["paths"]["/api/v2/configurations/{configuration_id}/native-patches"][
        "post"
    ]
    request_schema = post_schema["requestBody"]["content"]["application/json"]["schema"]
    assert "version" in request_schema["required"]
    assert "allow_private_candidate_retention" in request_schema["required"]


def test_lost_operation_completion_reconciles_without_duplicate_generation(native_api, monkeypatch):
    client, application, _settings = native_api
    snapshot, _analysis, options = prepare(client)
    journal = application.state.operation_journal
    complete = journal.complete

    def fail(*args, **kwargs):
        raise RuntimeError("owned completion unavailable")

    monkeypatch.setattr(journal, "complete", fail)
    assert post(client, snapshot, options).status_code == 503
    assert counts(application) == (1, 1)
    monkeypatch.setattr(journal, "complete", complete)

    def forbidden(*args, **kwargs):
        pytest.fail("replay must return committed candidate")

    monkeypatch.setattr(workflow_module, "create_vendor_draft", forbidden)
    assert post(client, snapshot, options).status_code == 200
    assert counts(application) == (1, 1)


@pytest.mark.parametrize(
    "contents",
    [
        "hostname owned\nline vty 0 4\n transport input telnet\n!\n",
        "hostname owned\nline vty 0 4\n transport input ssh telnet\n!\n"
        "line vty 3 8\n transport input ssh telnet\n!\n",
        "hostname owned\nline vty 0 4\n transport input ssh telnet\n!\n"
        "unsupported-owned-command\n",
        "set system host-name owned\nset system services telnet\n",
    ],
    ids=["no-ssh-alternative", "overlapping-vty", "partial-parse", "no-junos-ssh"],
)
def test_native_generation_keeps_existing_refusals(native_api, contents):
    client, application, _settings = native_api
    snapshot, _analysis, options = prepare(client, contents=contents)
    assert post(client, snapshot, options).status_code == 409
    assert counts(application) == (0, 0)


def test_new_artifact_budget_is_413(native_api, monkeypatch):
    client, application, _settings = native_api
    snapshot, _analysis, options = prepare(client)
    monkeypatch.setattr("app.api.native_patch_contracts.MAX_NATIVE_PATCH_REVIEW_BYTES", 1)
    assert post(client, snapshot, options).status_code == 413
    assert counts(application) == (0, 0)
