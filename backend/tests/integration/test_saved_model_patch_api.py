"""Owned loopback responses test the workflow, not model execution or output quality."""

import json
import os
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from uuid import UUID, uuid4

import pytest
from app.core.local_model import LocalModelSettings
from app.core.settings import ApiSettings
from app.db.migrate import upgrade_database
from app.db.store import StorageIntegrityError, make_engine
from app.main import create_app
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import event, text
from sqlalchemy.engine import make_url

TOKEN = "saved-model-patch-owned-admin-token-001"
ENGINEER = "saved-model-patch-owned-engineer-token-001"
ANALYST = "saved-model-patch-owned-analyst-token-001"
READER = "saved-model-patch-owned-reader-token-001"
HEADERS = {"Authorization": f"Bearer {TOKEN}"}
SOURCE = "hostname private-edge\r\nip ssh version 1\r\nusername owned secret 0 private-password\r\n"


@pytest.fixture
def model_patch_api(tmp_path):
    state = {"requests": [], "damage": None, "delay": 0.0}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            wire = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            state["requests"].append(wire)
            context = json.loads(wire["messages"][1]["content"])
            answer = {
                "summary": "Owned synthetic answer; not a model measurement.",
                "technical_explanation": "The supplied source explicitly selects SSHv1.",
                "possible_impact": [],
                "recommendation": "Review the proposed change independently.",
                "patch_draft": {
                    "edits": [
                        {
                            "source_line": context["affected_block"][0]["source_line"],
                            "replacement": "ip ssh version 2"
                            if context["vendor"] == "cisco"
                            else "set system services ssh protocol-version v2",
                        }
                    ]
                },
                "assumptions": [],
                "missing_information": ["Device syntax, network access and engineer decision."],
                "citations": [context["documents"][0]["citation"]],
                "requires_human_review": True,
            }
            damage = state["damage"]
            if damage == "decline":
                answer["patch_draft"] = None
            elif damage == "command":
                answer["patch_draft"]["edits"][0]["replacement"] = "reload"
            elif damage == "anchor":
                answer["patch_draft"]["edits"][0]["source_line"] = 3
            elif damage == "citation":
                answer["citations"] = ["foreign#policy"]
            elif damage == "approval":
                answer["approved"] = True
            elif damage == "review":
                answer["requires_human_review"] = 1
            answer_text = json.dumps(answer)
            if damage == "duplicate":
                answer_text = answer_text.replace('"summary":', '"summary":"bad","summary":', 1)
            payload = json.dumps(
                {
                    "choices": [
                        {
                            "finish_reason": "stop",
                            "message": {"role": "assistant", "content": answer_text},
                        }
                    ]
                }
            ).encode()
            time.sleep(state["delay"])
            self.send_response(302 if damage == "redirect" else 200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            if damage == "redirect":
                self.send_header("Location", "http://outside.invalid/private")
            self.end_headers()
            self.wfile.write(payload)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=lambda: server.serve_forever(poll_interval=0.05), daemon=True)
    thread.start()
    database = f"sqlite:///{tmp_path / 'patch.sqlite3'}"
    configured = os.environ.get("NETCONFIG_TEST_DATABASE_URL", "")
    admin = None
    schema = f"sentinel_saved_patch_test_{uuid4().hex}"
    if configured:
        url = make_url(configured)
        if url.drivername != "postgresql+psycopg" or not (url.database or "").endswith("_test"):
            pytest.fail("saved patch tests require a postgresql+psycopg *_test database")
        admin = make_engine(configured)
        with admin.begin() as connection:
            connection.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
        database = url.update_query_dict({"options": f"-csearch_path={schema}"}).render_as_string(
            hide_password=False
        )
    settings = ApiSettings(
        database,
        TOKEN,
        Fernet.generate_key().decode(),
        reader_token=READER,
        analyst_token=ANALYST,
        engineer_token=ENGINEER,
    )
    model = LocalModelSettings(
        f"http://127.0.0.1:{server.server_port}/v1/chat/completions",
        "owned-synthetic-provider",
        allow_local_context=True,
        allow_patch_draft=True,
    )
    application = create_app(settings, local_model=model)
    service = application.state.analysis_service
    upgrade_database(service.store.engine)
    try:
        with TestClient(application) as client:
            yield client, service, state, settings, model
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        if admin is not None:
            # Only this test's freshly generated UUID-named schema is removed.
            with admin.begin() as connection:
                connection.exec_driver_sql(f'DROP SCHEMA "{schema}" CASCADE')
            admin.dispose()


def selected_request(client, *, source=SOURCE, retain=True, device_id=None):
    snapshot = client.post(
        "/api/v1/configurations",
        headers=HEADERS,
        json={
            "device_id": str(device_id or uuid4()),
            "filename": "private.cfg",
            "content": source,
            "retain_original_source": retain,
        },
    ).json()
    analysis = client.post(
        f"/api/v1/configurations/{snapshot['configuration_id']}/analyze", headers=HEADERS, json={}
    ).json()
    detected = next(
        item for item in analysis["findings"] if item["category"] == "management.ssh_version_1"
    )
    finding = next(
        item for item in analysis["explanations"] if item["finding_id"] == detected["finding_id"]
    )
    return (
        {
            "patch_id": str(uuid4()),
            "analysis_id": analysis["analysis_id"],
            "finding_id": finding["finding_id"],
            "finding_sha256": finding["finding_sha256"],
            "source_sha256": snapshot["canonical"]["source"]["sha256"],
            "allow_local_model_context": True,
        },
        snapshot,
        analysis,
    )


def generate(client, options):
    return client.post("/api/v1/model-patches", headers=HEADERS, json=options)


def test_saved_source_generation_is_bound_encrypted_restartable_and_not_promoted(model_patch_api):
    client, service, state, settings, _ = model_patch_api
    options, snapshot, analysis = selected_request(client)
    response = generate(client, options)
    assert response.status_code == 201, response.text
    saved = response.json()
    assert (
        saved["status"] == "draft"
        and saved["answer"]["patch_draft"]["edits"][0]["source_line"] == 2
    )
    assert saved["source"]["configuration_id"] == snapshot["configuration_id"]
    assert saved["finding_sha256"] == options["finding_sha256"]
    assert saved["candidate_sha256"] and saved["generation_attempt_limit"] == 1
    assert saved["formal_verification"] == saved["ml_verification"] == "not_run"
    assert saved["approved"] is saved["applied"] is saved["model_execution_authenticated"] is False
    assert saved["requires_human_review"] is True
    for serialized in (response.text, json.dumps(state["requests"])):
        assert "private-edge" not in serialized and "private-password" not in serialized
        assert "private.cfg" not in serialized
    assert len(state["requests"]) == 1
    assert generate(client, options).status_code == 200
    assert len(state["requests"]) == 1
    with TestClient(create_app(settings)) as restarted:
        assert (
            restarted.get(f"/api/v1/model-patches/{options['patch_id']}", headers=HEADERS).json()
            == saved
        )
        assert generate(restarted, options).json() == saved
        assert (
            restarted.get(f"/api/v1/analyses/{analysis['analysis_id']}", headers=HEADERS).json()
            == analysis
        )
        assert (
            restarted.get(
                f"/api/v1/configurations/{snapshot['configuration_id']}/source", headers=HEADERS
            ).status_code
            == 404
        )
    with service.store.engine.connect() as connection:
        for table in ("model_patch_intents", "model_patch_outcomes"):
            payload = connection.execute(text(f"SELECT payload FROM {table}")).scalar_one()
            assert "Owned synthetic" not in payload and "ip ssh version" not in payload
        actions = (
            connection.execute(
                text("SELECT action FROM audit_events WHERE action LIKE 'model_patch.%'")
            )
            .scalars()
            .all()
        )
        assert sorted(actions) == ["model_patch.completed", "model_patch.requested"]


@pytest.mark.parametrize(
    "damage", ["command", "anchor", "citation", "approval", "review", "duplicate", "redirect"]
)
def test_rejected_provider_attempt_is_terminal_and_is_not_retried(model_patch_api, damage):
    client, _, state, _, _ = model_patch_api
    options, _, _ = selected_request(client)
    state["damage"] = damage
    response = generate(client, options)
    assert response.status_code == 503 and "private" not in response.text
    failed = client.get(f"/api/v1/model-patches/{options['patch_id']}", headers=HEADERS).json()
    assert failed["status"] == "failed" and failed["answer"] is None
    assert failed["candidate_sha256"] is None
    state["damage"] = None
    replay = generate(client, options)
    assert replay.status_code == 200 and replay.json() == failed
    assert len(state["requests"]) == 1


def test_valid_null_patch_is_saved_as_declined_not_replaced(model_patch_api):
    client, _, state, _, _ = model_patch_api
    options, _, _ = selected_request(client)
    state["damage"] = "decline"
    result = generate(client, options)
    assert result.status_code == 201
    assert result.json()["status"] == "declined"
    assert result.json()["answer"]["patch_draft"] is None
    assert result.json()["candidate_sha256"] is None


@pytest.mark.parametrize("permission", [False, 1, "true", None])
def test_request_consent_is_explicit_strict_and_precedes_original_read(model_patch_api, permission):
    client, service, state, _, _ = model_patch_api
    options, _, _ = selected_request(client)
    options["allow_local_model_context"] = permission
    response = generate(client, options)
    assert response.status_code in {400, 403}
    assert not state["requests"]
    with service.store.engine.connect() as connection:
        assert (
            connection.execute(text("SELECT count(*) FROM model_patch_intents")).scalar_one() == 0
        )


@pytest.mark.parametrize(
    "token,expected", [(None, 401), (READER, 403), (ANALYST, 403), (ENGINEER, 201)]
)
def test_server_roles_gate_generation_before_body_and_provider(model_patch_api, token, expected):
    client, _, state, _, _ = model_patch_api
    options, _, _ = selected_request(client)
    result = client.post(
        "/api/v1/model-patches",
        json=options,
        headers={} if token is None else {"Authorization": f"Bearer {token}"},
    )
    assert result.status_code == expected, result.text
    assert len(state["requests"]) == (1 if expected == 201 else 0)


def test_missing_retained_source_cannot_be_reconstructed_from_ir(model_patch_api):
    client, _, state, _, _ = model_patch_api
    options, _, _ = selected_request(client, retain=False)
    response = generate(client, options)
    assert response.status_code == 409 and not state["requests"]


@pytest.mark.parametrize(
    "changed", ["analysis_id", "finding_id", "finding_sha256", "source_sha256"]
)
def test_selected_identity_must_match_before_generation(model_patch_api, changed):
    client, _, state, _, _ = model_patch_api
    options, _, _ = selected_request(client)
    options[changed] = "f" * 64 if changed.endswith("sha256") else str(uuid4())
    assert generate(client, options).status_code in {404, 409}
    assert not state["requests"]


def test_same_intent_cannot_be_rebound_to_another_finding(model_patch_api):
    client, _, state, _, _ = model_patch_api
    options, _, _ = selected_request(client)
    assert generate(client, options).status_code == 201
    changed = {**options, "finding_sha256": "f" * 64}
    assert generate(client, changed).status_code == 409 and len(state["requests"]) == 1


def test_operator_patch_switch_is_separate_from_explanations(model_patch_api):
    client, _, state, settings, model = model_patch_api
    options, _, _ = selected_request(client)
    disabled = LocalModelSettings(model.endpoint, model.model, allow_local_context=True)
    with TestClient(create_app(settings, local_model=disabled)) as other:
        assert generate(other, options).status_code == 503
    assert not state["requests"]


def test_saved_generation_can_be_listed_without_raw_configuration(model_patch_api):
    client, _, _, _, _ = model_patch_api
    options, _, _ = selected_request(client)
    saved = generate(client, options).json()
    response = client.get(
        "/api/v1/model-patches",
        params={"analysis_id": options["analysis_id"]},
        headers={"Authorization": f"Bearer {READER}"},
    )
    assert response.status_code == 200 and response.json() == [saved]


def test_new_model_patch_operations_have_safe_durable_audit_metadata(model_patch_api):
    client, _, _, _, _ = model_patch_api
    options, _, _ = selected_request(client)
    response = generate(client, options)
    receipt = client.get(
        f"/api/v1/operation-audit/{response.headers['X-Operation-Id']}", headers=HEADERS
    )
    assert receipt.status_code == 200, receipt.text
    result = receipt.json()
    assert result["receipt"]["operation"] == "generate_model_patch"
    assert result["completion"]["result"]["finding_sha256"] == options["finding_sha256"]
    assert str(UUID(options["patch_id"])) in result["completion"]["result"]["resource_ids"]
    assert "ip ssh version" not in receipt.text and "Owned synthetic" not in receipt.text


def test_junos_saved_source_uses_its_own_vendor_command(model_patch_api):
    client, _, state, _, _ = model_patch_api
    options, _, _ = selected_request(
        client,
        source=("set system host-name private-edge\nset system services ssh protocol-version v1\n"),
    )
    response = generate(client, options)
    assert response.status_code == 201, response.text
    assert (
        response.json()["answer"]["patch_draft"]["edits"][0]["replacement"]
        == "set system services ssh protocol-version v2"
    )
    assert json.loads(state["requests"][0]["messages"][1]["content"])["vendor"] == "juniper"


def test_explicit_retained_baseline_is_bound_and_not_treated_as_approved(model_patch_api):
    client, _, state, _, _ = model_patch_api
    device_id = uuid4()
    baseline = client.post(
        "/api/v1/configurations",
        headers=HEADERS,
        json={
            "device_id": str(device_id),
            "filename": "baseline.cfg",
            "content": SOURCE.replace("version 1", "version 2"),
            "retain_original_source": True,
        },
    ).json()
    options, _, _ = selected_request(client, device_id=device_id)
    options.update(
        baseline_configuration_id=baseline["configuration_id"],
        baseline_source_sha256=baseline["canonical"]["source"]["sha256"],
    )
    response = generate(client, options)
    assert response.status_code == 201, response.text
    assert response.json()["baseline"]["configuration_id"] == baseline["configuration_id"]
    context = json.loads(state["requests"][0]["messages"][1]["content"])
    assert context["baseline"]["approval"] == "not_proven"
    assert context["safe_diff"]["changes"] == [
        {"baseline": "2", "observed": "1", "property": "ssh_version"}
    ]


@pytest.mark.parametrize("damage", ["missing_pin", "foreign_device", "future", "missing_original"])
def test_invalid_baseline_is_refused_before_provider(model_patch_api, damage):
    client, _, state, _, _ = model_patch_api
    device_id = uuid4()
    if damage == "future":
        options, _, _ = selected_request(client, device_id=device_id)
    baseline = client.post(
        "/api/v1/configurations",
        headers=HEADERS,
        json={
            "device_id": str(uuid4() if damage == "foreign_device" else device_id),
            "filename": "baseline.cfg",
            "content": SOURCE.replace("version 1", "version 2"),
            "retain_original_source": damage != "missing_original",
        },
    ).json()
    if damage != "future":
        options, _, _ = selected_request(client, device_id=device_id)
    options["baseline_configuration_id"] = baseline["configuration_id"]
    if damage != "missing_pin":
        options["baseline_source_sha256"] = baseline["canonical"]["source"]["sha256"]
    assert generate(client, options).status_code in {400, 409}
    assert not state["requests"]


def test_multiple_api_processes_reserve_one_attempt_only(model_patch_api):
    client, _, state, settings, model = model_patch_api
    options, _, _ = selected_request(client)
    state["delay"] = 0.2
    applications = [create_app(settings, local_model=model) for _ in range(4)]

    def invoke(application):
        with TestClient(application) as other:
            return generate(other, options)

    with ThreadPoolExecutor(max_workers=4) as executor:
        responses = list(executor.map(invoke, applications))
    assert sorted(item.status_code for item in responses) == [200, 200, 200, 201]
    assert len(state["requests"]) == 1
    final = client.get(f"/api/v1/model-patches/{options['patch_id']}", headers=HEADERS)
    assert final.json()["status"] == "draft"


def test_busy_runtime_does_not_reserve_an_intent(model_patch_api):
    client, service, state, _, _ = model_patch_api
    options, _, _ = selected_request(client)
    runtime = client.app.state.local_model
    with runtime.patch_provider():
        response = generate(client, options)
    assert response.status_code == 429 and not state["requests"]
    with service.store.engine.connect() as connection:
        assert (
            connection.execute(text("SELECT count(*) FROM model_patch_intents")).scalar_one() == 0
        )


def test_lost_completion_remains_generating_and_is_not_retried(model_patch_api, monkeypatch):
    from app.db.model_patch_records import ModelPatchRecords

    client, _, state, _, _ = model_patch_api
    options, _, _ = selected_request(client)

    def fail(*args):
        raise StorageIntegrityError("Stored data is unavailable.")

    monkeypatch.setattr(ModelPatchRecords, "complete", fail)
    assert generate(client, options).status_code == 503
    saved = client.get(f"/api/v1/model-patches/{options['patch_id']}", headers=HEADERS).json()
    assert saved["status"] == "generating" and saved["completed_at"] is None
    assert saved["answer"] is None and saved["candidate_sha256"] is None
    assert generate(client, options).json() == saved and len(state["requests"]) == 1


def test_failed_reservation_audit_rolls_back_intent_and_never_calls_provider(model_patch_api):
    client, service, state, _, _ = model_patch_api
    options, _, _ = selected_request(client)

    def fail_audit(connection, cursor, statement, parameters, context, executemany):
        if statement.lower().startswith("insert into audit_events"):
            raise StorageIntegrityError("Stored data is unavailable.")

    event.listen(service.store.engine, "before_cursor_execute", fail_audit)
    try:
        assert generate(client, options).status_code == 503
    finally:
        event.remove(service.store.engine, "before_cursor_execute", fail_audit)
    assert not state["requests"]
    with service.store.engine.connect() as connection:
        assert (
            connection.execute(text("SELECT count(*) FROM model_patch_intents")).scalar_one() == 0
        )


@pytest.mark.parametrize(
    "target", ["intent_ciphertext", "outcome_ciphertext", "context_sha256", "candidate_sha256"]
)
def test_corrupt_saved_model_patch_is_not_exposed_or_regenerated(model_patch_api, target):
    client, service, state, _, _ = model_patch_api
    options, _, _ = selected_request(client)
    assert generate(client, options).status_code == 201
    is_intent = target in {"intent_ciphertext", "context_sha256"}
    table, column, kind = (
        ("model_patch_intents", "id", "model_patch_intent")
        if is_intent
        else ("model_patch_outcomes", "patch_id", "model_patch_outcome")
    )
    with service.store.engine.begin() as connection:
        payload = connection.execute(
            text(f"SELECT payload FROM {table} WHERE {column}=:id"), {"id": options["patch_id"]}
        ).scalar_one()
        changed = "invalid-private-ciphertext"
        if target.endswith("sha256"):
            plain = json.loads(
                service.store._decode(payload, kind=kind, row_id=options["patch_id"])
            )
            plain[target] = "f" * 64
            changed = service.store._encode(
                json.dumps(plain), kind=kind, row_id=options["patch_id"]
            )
        connection.execute(
            text(f"UPDATE {table} SET payload=:payload WHERE {column}=:id"),
            {"id": options["patch_id"], "payload": changed},
        )
    response = client.get(f"/api/v1/model-patches/{options['patch_id']}", headers=HEADERS)
    assert response.status_code == 503 and "private" not in response.text
    assert generate(client, options).status_code == 503 and len(state["requests"]) == 1
