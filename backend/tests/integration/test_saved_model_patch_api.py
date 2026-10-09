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
                            "replacement": (
                                "transport input ssh"
                                if context["finding"]["category"] == "management.telnet_enabled"
                                else "ip ssh version 2"
                            )
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


def selected_request(
    client,
    *,
    source=SOURCE,
    retain=True,
    device_id=None,
    category="management.ssh_version_1",
    inventory=None,
):
    snapshot = client.post(
        "/api/v1/configurations",
        headers=HEADERS,
        json={
            "device_id": str(device_id or uuid4()),
            "filename": "private.cfg",
            "content": source,
            "retain_original_source": retain,
            "inventory": inventory,
        },
    ).json()
    analysis = client.post(
        f"/api/v1/configurations/{snapshot['configuration_id']}/analyze", headers=HEADERS, json={}
    ).json()
    detected = next(item for item in analysis["findings"] if item["category"] == category)
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


def test_model_patch_capabilities_are_read_only_minimized_and_operator_bound(model_patch_api):
    client, _, state, settings, _ = model_patch_api
    result = client.get(
        "/api/v1/model-patches/capabilities", headers={"Authorization": f"Bearer {READER}"}
    )
    assert result.status_code == 200, result.text
    assert result.json() == {
        "version": "model-patch-capabilities-0.1.0",
        "generation": "configured",
        "network_engine": "disabled",
        "transformer": "disabled",
        "transformer_sha256": None,
        "individual_identity_verified": False,
        "application_supported": False,
    }
    assert not state["requests"] and "127.0.0.1" not in result.text
    with TestClient(create_app(settings)) as disabled:
        value = disabled.get("/api/v1/model-patches/capabilities", headers=HEADERS).json()
        assert value["generation"] == "disabled" and value["network_engine"] == "disabled"


def test_configured_capabilities_are_not_readiness_and_do_not_expose_operator_paths(
    model_patch_api, tmp_path
):
    from app.core.patch_verification import PatchVerificationSettings

    client, _, state, settings, _ = model_patch_api
    pin = "c" * 64
    options = PatchVerificationSettings(
        allow_engine_upload=True,
        registry_root=tmp_path / "private-nonexistent-registry",
        transformer_sha256=pin,
        foundation_source=tmp_path / "private-nonexistent-foundation",
    )
    with TestClient(create_app(settings, patch_verification=options)) as configured:
        response = configured.get("/api/v1/model-patches/capabilities", headers=HEADERS)
        assert response.status_code == 200, response.text
        assert response.json()["generation"] == "disabled"
        assert response.json()["network_engine"] == "configured"
        assert response.json()["transformer"] == "configured"
        assert response.json()["transformer_sha256"] == pin
        receipt = client.get(
            f"/api/v1/operation-audit/{response.headers['X-Operation-Id']}", headers=HEADERS
        )
        assert receipt.status_code == 200, receipt.text
        assert receipt.json()["receipt"]["operation"] == "model_patch_capabilities"
        for value in (response.text, receipt.text):
            assert "private-nonexistent" not in value
            assert "127.0.0.1" not in value
            assert "endpoint" not in value and "api_key" not in value
        assert not state["requests"]


@pytest.mark.parametrize(
    "changed",
    [
        {"application_supported": True},
        {"application_supported": 0},
        {"individual_identity_verified": 0},
        {"transformer": "configured"},
        {"transformer_sha256": "d" * 64},
        {"generation": "validated"},
        {"endpoint": "http://127.0.0.1:1234"},
    ],
)
def test_capability_contract_refuses_inferred_results_and_implicit_flags(changed):
    from app.api.model_patch_contracts import ModelPatchCapabilities

    with pytest.raises(ValueError):
        ModelPatchCapabilities.model_validate(
            {
                "generation": "disabled",
                "network_engine": "disabled",
                "transformer": "disabled",
                **changed,
            }
        )


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


def selected_review(client):
    options, snapshot, analysis = selected_request(client)
    generated = generate(client, options)
    assert generated.status_code == 201
    proposal = generated.json()
    review = {
        "verification_id": str(uuid4()),
        "proposal_sha256": proposal["proposal_sha256"],
        "mode": "local_preflight",
        "network": [
            {
                "configuration_id": snapshot["configuration_id"],
                "source_sha256": options["source_sha256"],
            }
        ],
        "scope": {"start_node": "private-edge", "destination": "203.0.113.1/32"},
    }
    return options, proposal, review, analysis


def test_saved_model_candidate_has_immutable_separate_local_review_and_restart(model_patch_api):
    client, _, state, settings, _ = model_patch_api
    options, proposal, body, analysis = selected_review(client)
    path = f"/api/v1/model-patches/{options['patch_id']}/verify"
    response = client.post(path, headers=HEADERS, json=body)
    assert response.status_code == 201, response.text
    run = response.json()
    assert run["status"] == "needs_review" and run["execution_status"] == "completed"
    assert run["report"]["candidate_sha256"] == proposal["candidate_sha256"]
    assert run["report"]["network_result"] is None
    assert run["ml_execution"] == "not_requested" and run["statistical_recheck"] is None
    assert "formal_report_not_supplied" in run["report"]["missing_checks"]
    assert run["report"]["approved"] is run["report"]["applied"] is False
    assert "private-password" not in response.text
    assert client.post(path, headers=HEADERS, json=body).json() == run
    with TestClient(create_app(settings)) as restarted:
        assert (
            restarted.get(
                f"/api/v1/model-patches/{options['patch_id']}/verifications/{body['verification_id']}",
                headers=HEADERS,
            ).json()
            == run
        )
        assert restarted.get(
            f"/api/v1/model-patches/{options['patch_id']}/verifications", headers=HEADERS
        ).json() == [run]
        assert (
            restarted.get(f"/api/v1/model-patches/{options['patch_id']}", headers=HEADERS).json()
            == proposal
        )
        assert (
            restarted.get(f"/api/v1/analyses/{analysis['analysis_id']}", headers=HEADERS).json()
            == analysis
        )
    assert len(state["requests"]) == 1


def test_engineer_rejection_is_source_bound_append_only_and_idempotent(model_patch_api):
    client, _, _, settings, _ = model_patch_api
    options, proposal, body, _ = selected_review(client)
    run = client.post(
        f"/api/v1/model-patches/{options['patch_id']}/verify", headers=HEADERS, json=body
    ).json()
    decision = {
        "decision_id": str(uuid4()),
        "verification_id": body["verification_id"],
        "proposal_sha256": proposal["proposal_sha256"],
        "review_sha256": run["review_sha256"],
        "verdict": "rejected",
        "comment": "Owned private engineer review, not device execution.",
    }
    path = f"/api/v1/model-patches/{options['patch_id']}/decisions"
    response = client.post(path, headers={"Authorization": f"Bearer {ENGINEER}"}, json=decision)
    assert response.status_code == 201, response.text
    saved = response.json()
    assert saved["individual_identity_verified"] is False and saved["applied"] is False
    assert saved["service_role"] == "engineer"
    assert client.post(path, headers=HEADERS, json=decision).json() == saved
    assert (
        client.post(
            path, headers=HEADERS, json=decision | {"comment": "Changed intent"}
        ).status_code
        == 409
    )
    with TestClient(create_app(settings)) as restarted:
        assert restarted.get(path, headers=HEADERS).json() == [saved]
        assert (
            restarted.get(f"/api/v1/model-patches/{options['patch_id']}", headers=HEADERS).json()
            == proposal
        )


def test_local_only_report_cannot_be_approved_by_role_or_acknowledgement(model_patch_api):
    client, _, _, _, _ = model_patch_api
    options, proposal, body, _ = selected_review(client)
    run = client.post(
        f"/api/v1/model-patches/{options['patch_id']}/verify", headers=HEADERS, json=body
    ).json()
    decision = {
        "decision_id": str(uuid4()),
        "verification_id": body["verification_id"],
        "proposal_sha256": proposal["proposal_sha256"],
        "review_sha256": run["review_sha256"],
        "verdict": "approved",
        "comment": "Owned attempted approval.",
        "acknowledged_limitations": run["report"]["missing_checks"],
        "device_syntax_checked": True,
        "management_access_checked": True,
        "rollback_ready": True,
    }
    response = client.post(
        f"/api/v1/model-patches/{options['patch_id']}/decisions", headers=HEADERS, json=decision
    )
    assert response.status_code == 409, response.text


@pytest.mark.parametrize(
    "change", ["source_pin", "scope", "proposal_pin", "missing_source", "future_network"]
)
def test_review_selection_conflicts_never_start_verification(model_patch_api, change):
    client, _, _, _, _ = model_patch_api
    options, _proposal, body, _ = selected_review(client)
    if change == "source_pin":
        body["network"][0]["source_sha256"] = "f" * 64
    elif change == "scope":
        body["scope"]["start_node"] = "foreign-node"
    elif change == "proposal_pin":
        body["proposal_sha256"] = "f" * 64
    else:
        other = client.post(
            "/api/v1/configurations",
            headers=HEADERS,
            json={
                "device_id": str(uuid4()),
                "filename": "neighbor.cfg",
                "content": "hostname neighbor\n",
                "retain_original_source": change == "future_network",
            },
        ).json()
        body["network"].append(
            {
                "configuration_id": other["configuration_id"],
                "source_sha256": other["canonical"]["source"]["sha256"],
            }
        )
    result = client.post(
        f"/api/v1/model-patches/{options['patch_id']}/verify", headers=HEADERS, json=body
    )
    assert result.status_code == 409, result.text


def test_http_batfish_requires_both_operator_and_request_permission(model_patch_api):
    client, _, _, _, _ = model_patch_api
    options, _, body, _ = selected_review(client)
    body["mode"] = "batfish"
    path = f"/api/v1/model-patches/{options['patch_id']}/verify"
    assert client.post(path, headers=HEADERS, json=body).status_code == 403
    body["allow_local_engine_upload"] = True
    assert client.post(path, headers=HEADERS, json=body).status_code == 503


@pytest.mark.parametrize("token, expected", [(None, 401), (READER, 403), (ANALYST, 403)])
@pytest.mark.parametrize("operation", ["verify", "decisions"])
def test_review_writes_authorize_before_parsing(model_patch_api, token, expected, operation):
    client, service, state, _, _ = model_patch_api
    result = client.post(
        f"/api/v1/model-patches/{uuid4()}/{operation}",
        headers={"Authorization": f"Bearer {token}"} if token else {},
        content="not-json",
    )
    assert result.status_code == expected and not state["requests"]
    with service.store.engine.connect() as connection:
        for table in ("model_patch_review_intents", "model_patch_decisions"):
            assert connection.execute(text(f"SELECT count(*) FROM {table}")).scalar_one() == 0


@pytest.mark.parametrize("value", [0, 1, "true", None])
def test_review_worker_consent_is_exact_boolean(model_patch_api, value):
    client, _, _, _, _ = model_patch_api
    options, _, body, _ = selected_review(client)
    body.update(mode="batfish", allow_local_engine_upload=value)
    assert (
        client.post(
            f"/api/v1/model-patches/{options['patch_id']}/verify", headers=HEADERS, json=body
        ).status_code
        == 400
    )


def test_review_duplicate_json_and_unknown_path_fields_are_refused(model_patch_api):
    client, _, _, _, _ = model_patch_api
    options, _, body, _ = selected_review(client)
    path = f"/api/v1/model-patches/{options['patch_id']}/verify"
    duplicate = json.dumps(body).replace('"mode":', '"mode":"batfish","mode":')
    assert (
        client.post(
            path, headers=HEADERS | {"Content-Type": "application/json"}, content=duplicate
        ).status_code
        == 400
    )
    assert (
        client.post(path, headers=HEADERS, json=body | {"model_path": "private"}).status_code == 400
    )


def test_review_id_cannot_be_rebound_and_different_ids_preserve_each_run(model_patch_api):
    client, _, state, _, _ = model_patch_api
    options, _, body, _ = selected_review(client)
    path = f"/api/v1/model-patches/{options['patch_id']}/verify"
    first = client.post(path, headers=HEADERS, json=body)
    assert first.status_code == 201
    changed = body | {"scope": {"start_node": "private-edge", "destination": "198.51.100.1/32"}}
    assert client.post(path, headers=HEADERS, json=changed).status_code == 409
    second = client.post(path, headers=HEADERS, json=changed | {"verification_id": str(uuid4())})
    assert (
        second.status_code == 201
        and second.json()["review_sha256"] != first.json()["review_sha256"]
    )
    rows = client.get(
        f"/api/v1/model-patches/{options['patch_id']}/verifications", headers=HEADERS
    ).json()
    assert rows == [second.json(), first.json()] and len(state["requests"]) == 1


def test_lost_review_completion_remains_running_and_never_reexecutes(model_patch_api, monkeypatch):
    from app.db.model_patch_review_records import ModelPatchReviewRecords

    client, _, state, _, _ = model_patch_api
    options, _, body, _ = selected_review(client)
    calls = []

    def fail(*args):
        calls.append(True)
        raise StorageIntegrityError("Stored data is unavailable.")

    monkeypatch.setattr(ModelPatchReviewRecords, "complete", fail)
    path = f"/api/v1/model-patches/{options['patch_id']}/verify"
    assert client.post(path, headers=HEADERS, json=body).status_code == 503
    replay = client.post(path, headers=HEADERS, json=body)
    assert replay.status_code == 200 and replay.json()["execution_status"] == "running"
    assert replay.json()["report"] is None and len(calls) == 1 and len(state["requests"]) == 1


def test_review_reservation_audit_failure_rolls_back_before_checks(model_patch_api, monkeypatch):
    client, service, _, _, _ = model_patch_api
    options, _, body, _ = selected_review(client)
    monkeypatch.setattr(
        "app.patching.saved_review.build_candidate_review",
        lambda *args, **kwargs: pytest.fail("check started"),
    )

    def fail(connection, cursor, statement, parameters, context, executemany):
        if statement.lower().startswith("insert into audit_events"):
            raise StorageIntegrityError("Stored data is unavailable.")

    event.listen(service.store.engine, "before_cursor_execute", fail)
    try:
        assert (
            client.post(
                f"/api/v1/model-patches/{options['patch_id']}/verify", headers=HEADERS, json=body
            ).status_code
            == 503
        )
    finally:
        event.remove(service.store.engine, "before_cursor_execute", fail)
    with service.store.engine.connect() as connection:
        assert (
            connection.execute(text("SELECT count(*) FROM model_patch_review_intents")).scalar_one()
            == 0
        )


def test_review_failure_is_terminal_without_automatic_repair(model_patch_api, monkeypatch):
    from app.patching.candidate_review import CandidateReviewUnavailable

    client, _, _, _, _ = model_patch_api
    options, _, body, _ = selected_review(client)
    calls = []

    def fail(*args, **kwargs):
        calls.append(True)
        raise CandidateReviewUnavailable("Candidate review is unavailable.")

    monkeypatch.setattr("app.patching.saved_review.build_candidate_review", fail)
    path = f"/api/v1/model-patches/{options['patch_id']}/verify"
    assert client.post(path, headers=HEADERS, json=body).status_code == 503
    replay = client.post(path, headers=HEADERS, json=body)
    assert replay.status_code == 200 and replay.json()["execution_status"] == "failed"
    assert replay.json()["approval_blockers"] == ["verification_not_completed"] and len(calls) == 1


def test_concurrent_review_in_four_api_processes_reserves_once(model_patch_api):
    client, service, _, settings, _ = model_patch_api
    options, _, body, _ = selected_review(client)

    def post(_):
        with TestClient(create_app(settings)) as other:
            return other.post(
                f"/api/v1/model-patches/{options['patch_id']}/verify", headers=HEADERS, json=body
            )

    with ThreadPoolExecutor(max_workers=4) as executor:
        responses = list(executor.map(post, range(4)))
    assert sorted(item.status_code for item in responses) == [200, 200, 200, 201]
    final = client.get(
        f"/api/v1/model-patches/{options['patch_id']}/verifications/{body['verification_id']}",
        headers=HEADERS,
    )
    assert final.json()["execution_status"] == "completed"
    with service.store.engine.connect() as connection:
        for table in ("model_patch_review_intents", "model_patch_review_outcomes"):
            assert connection.execute(text(f"SELECT count(*) FROM {table}")).scalar_one() == 1


@pytest.mark.parametrize(
    "target", ["intent_ciphertext", "outcome_ciphertext", "candidate_sha256", "network_result"]
)
def test_tampered_review_is_not_exposed_or_reexecuted(model_patch_api, target):
    client, service, state, _, _ = model_patch_api
    options, _, body, _ = selected_review(client)
    path = f"/api/v1/model-patches/{options['patch_id']}/verify"
    assert client.post(path, headers=HEADERS, json=body).status_code == 201
    is_intent = target == "intent_ciphertext"
    table, column, kind = (
        ("model_patch_review_intents", "id", "model_patch_review_intent")
        if is_intent
        else ("model_patch_review_outcomes", "verification_id", "model_patch_review_outcome")
    )
    with service.store.engine.begin() as connection:
        payload = connection.execute(
            text(f"SELECT payload FROM {table} WHERE {column}=:id"), {"id": body["verification_id"]}
        ).scalar_one()
        changed = "invalid-private-ciphertext"
        if not target.endswith("ciphertext"):
            plain = json.loads(
                service.store._decode(payload, kind=kind, row_id=body["verification_id"])
            )
            if target == "candidate_sha256":
                plain["report"]["candidate_sha256"] = "f" * 64
            else:
                plain["report"]["scope"]["destination"] = "198.51.100.1/32"
            changed = service.store._encode(
                json.dumps(plain), kind=kind, row_id=body["verification_id"]
            )
        connection.execute(
            text(f"UPDATE {table} SET payload=:value WHERE {column}=:id"),
            {"id": body["verification_id"], "value": changed},
        )
    result = client.post(path, headers=HEADERS, json=body)
    assert (
        result.status_code == 503 and "private" not in result.text and len(state["requests"]) == 1
    )


@pytest.mark.parametrize(
    "status",
    [
        "unavailable",
        "error",
        "incomplete",
        "inconclusive",
        "differences_found",
        "no_differences_in_scope",
    ],
)
def test_synthetic_engine_outcomes_remain_review_only_and_replay_without_engine(
    model_patch_api, monkeypatch, status
):
    from app.core.patch_verification import PatchVerificationSettings
    from app.verification.batfish import BatfishResult
    from app.verification.patch_runtime import PatchVerificationRuntime

    client, _, _, settings, _ = model_patch_api
    options, _, body, _ = selected_review(client)
    calls = []

    def check(before, after, scope, **kwargs):
        calls.append(True)
        values = dict(
            before_sha256=before.digest, after_sha256=after.digest, scope=scope, status=status
        )
        values["reason"] = {
            "unavailable": "sdk_missing",
            "error": "timeout",
            "incomplete": "initialization_issues",
            "inconclusive": "empty_reachable_scope",
            "differences_found": "query_completed",
            "no_differences_in_scope": "query_completed",
        }[status]
        if status in {"inconclusive", "differences_found", "no_differences_in_scope"}:
            values.update(
                engine_version="synthetic-not-engine-measurement",
                cleanup_complete=True,
                difference_count=1 if status == "differences_found" else 0,
                before_reachable_count=0 if status == "inconclusive" else 1,
                after_reachable_count=0 if status == "inconclusive" else 1,
            )
        return BatfishResult.model_validate(values)

    monkeypatch.setattr("app.verification.model_patch.check_with_batfish", check)
    client.app.state.patch_verification = PatchVerificationRuntime(
        PatchVerificationSettings(allow_engine_upload=True)
    )
    body.update(mode="batfish", allow_local_engine_upload=True)
    path = f"/api/v1/model-patches/{options['patch_id']}/verify"
    result = client.post(path, headers=HEADERS, json=body)
    assert result.status_code == 201, result.text
    run = result.json()
    assert run["report"]["network_result"]["batfish"]["status"] == status
    assert run["status"] == "needs_review" and run["applied"] is False
    assert "selected_ml_not_completed" in run["approval_blockers"]
    with TestClient(create_app(settings)) as restarted:
        assert restarted.post(path, headers=HEADERS, json=body).json() == run
    assert len(calls) == 1


def test_operator_model_failure_keeps_local_report_but_blocks_approval(model_patch_api, tmp_path):
    from app.core.patch_verification import PatchVerificationSettings
    from app.verification.patch_runtime import PatchVerificationRuntime

    client, _, _, _, _ = model_patch_api
    options, _, body, _ = selected_review(client)
    pin = "f" * 64
    client.app.state.patch_verification = PatchVerificationRuntime(
        PatchVerificationSettings(
            registry_root=tmp_path / "absent-registry", transformer_sha256=pin
        )
    )
    body.update(transformer_sha256=pin, allow_local_model_context=True)
    result = client.post(
        f"/api/v1/model-patches/{options['patch_id']}/verify", headers=HEADERS, json=body
    )
    assert result.status_code == 201, result.text
    assert result.json()["ml_execution"] == "unavailable"
    assert result.json()["report"]["ml_reviews"] == []
    assert "selected_ml_not_completed" in result.json()["approval_blockers"]
    assert "absent-registry" not in result.text


def test_selected_original_isolation_forest_is_reexecuted_without_refit(
    model_patch_api, monkeypatch
):
    from app.domain.fingerprints import finding_fingerprint

    client, _, _, _, _ = model_patch_api
    ids = []
    for index in range(16):
        response = client.post(
            "/api/v1/configurations",
            headers=HEADERS,
            json={
                "filename": "training.cfg",
                "device_id": str(uuid4()),
                "inventory": {
                    "device_role": "edge",
                    "site_class": "branch",
                    "service_profile": "control",
                },
                "content": f"hostname training-{index}\nip ssh version 2\n",
            },
        )
        assert response.status_code == 201
        ids.append(response.json()["configuration_id"])
    trained = client.post(
        "/api/v1/models/isolation-forest", headers=HEADERS, json={"configuration_ids": ids}
    )
    assert trained.status_code == 201, trained.text
    options, snapshot, _ = selected_request(
        client,
        inventory={"device_role": "edge", "site_class": "branch", "service_profile": "control"},
    )
    analysis = client.post(
        f"/api/v1/configurations/{snapshot['configuration_id']}/analyze",
        headers=HEADERS,
        json={"statistical_model_id": trained.json()["model_id"]},
    ).json()
    from app.domain import Finding

    finding = next(
        row for row in analysis["findings"] if row["category"] == "management.ssh_version_1"
    )
    options.update(
        analysis_id=analysis["analysis_id"],
        finding_id=finding["finding_id"],
        finding_sha256=finding_fingerprint(Finding.model_validate(finding)),
    )
    monkeypatch.setattr("sklearn.ensemble.IsolationForest.fit", lambda *args: pytest.fail("refit"))
    proposal = generate(client, options).json()
    body = {
        "verification_id": str(uuid4()),
        "proposal_sha256": proposal["proposal_sha256"],
        "network": [
            {
                "configuration_id": snapshot["configuration_id"],
                "source_sha256": options["source_sha256"],
            }
        ],
        "scope": {"start_node": "private-edge", "destination": "203.0.113.1/32"},
    }
    result = client.post(
        f"/api/v1/model-patches/{options['patch_id']}/verify", headers=HEADERS, json=body
    )
    assert result.status_code == 201, result.text
    scores = result.json()["statistical_recheck"]
    assert scores["before_score_samples"] == analysis["statistical"]["score_samples"]
    assert scores["artifact_sha256"] == trained.json()["artifact_sha256"]
    assert scores["quality_proven"] is scores["calibrated"] is False


@pytest.mark.skipif(
    os.environ.get("NETCONFIG_LIVE_BATFISH") != "1",
    reason="requires explicit owned loopback engine",
)
@pytest.mark.parametrize("scenario", ["reachable", "empty_scope"])
def test_saved_http_candidate_with_actual_engine_and_restart(model_patch_api, scenario):
    from app.core.patch_verification import PatchVerificationSettings
    from app.verification.patch_runtime import PatchVerificationRuntime

    from ml.instruct.network_cases import authored_network_patch_cases

    client, _, _, settings, _ = model_patch_api
    case = authored_network_patch_cases()[0]
    selections = []
    for config in case.before.configs:
        snapshot = client.post(
            "/api/v1/configurations",
            headers=HEADERS,
            json={
                "device_id": str(config.device_id),
                "filename": "owned-network.cfg",
                "content": config.text,
                "retain_original_source": True,
            },
        ).json()
        selections.append(
            {
                "configuration_id": snapshot["configuration_id"],
                "source_sha256": snapshot["canonical"]["source"]["sha256"],
            }
        )
    edge = selections[0]
    analysis = client.post(
        f"/api/v1/configurations/{edge['configuration_id']}/analyze", headers=HEADERS, json={}
    ).json()
    finding_id = next(
        item["finding_id"]
        for item in analysis["findings"]
        if item["category"] == "management.ssh_version_1"
    )
    finding = next(row for row in analysis["explanations"] if row["finding_id"] == finding_id)
    options = {
        "patch_id": str(uuid4()),
        "analysis_id": analysis["analysis_id"],
        "finding_id": finding["finding_id"],
        "finding_sha256": finding["finding_sha256"],
        "source_sha256": edge["source_sha256"],
        "allow_local_model_context": True,
    }
    proposal = generate(client, options).json()
    client.app.state.patch_verification = PatchVerificationRuntime(
        PatchVerificationSettings(allow_engine_upload=True, engine_timeout_seconds=120)
    )
    body = {
        "verification_id": str(uuid4()),
        "proposal_sha256": proposal["proposal_sha256"],
        "mode": "batfish",
        "allow_local_engine_upload": True,
        "network": selections,
        "scope": {
            "start_node": "edge",
            "destination": "198.51.100.1/32" if scenario == "reachable" else "203.0.113.1/32",
        },
    }
    path = f"/api/v1/model-patches/{options['patch_id']}/verify"
    result = client.post(path, headers=HEADERS, json=body)
    assert result.status_code == 201, result.text
    run = result.json()
    actual = run["report"]["network_result"]["batfish"]
    assert actual["cleanup_complete"] is True and actual["difference_count"] == 0
    assert actual["status"] == (
        "no_differences_in_scope" if scenario == "reachable" else "inconclusive"
    )
    assert (
        actual["before_reachable_count"]
        == actual["after_reachable_count"]
        == (1 if scenario == "reachable" else 0)
    )
    with TestClient(create_app(settings)) as restarted:
        assert restarted.post(path, headers=HEADERS, json=body).json() == run
    print(
        "OWNED_SAVED_MODEL_PATCH_BATFISH_RESULT="
        + json.dumps(
            {
                "scenario": scenario,
                "engine_version": actual["engine_version"],
                "status": actual["status"],
                "before_reachable_count": actual["before_reachable_count"],
                "after_reachable_count": actual["after_reachable_count"],
                "difference_count": actual["difference_count"],
                "cleanup_complete": actual["cleanup_complete"],
                "new_llm_generations": 0,
                "synthetic_provider": True,
                "status_promoted": False,
            },
            sort_keys=True,
        )
    )


@pytest.fixture(scope="module")
def owned_patch_native_registry(tmp_path_factory):
    # Actual tiny authored training/inference; not an independent quality evaluation.
    from ml.mutation import MutationType
    from ml.preprocessing.tokenization import TokenizerPolicy, train_config_tokenizer
    from ml.registry.store import initialize_registry, register_model
    from ml.training.classification_smoke import classification_fixtures
    from ml.training.multitask import HeadPolicy, LossWeights
    from ml.training.multitask_smoke import authored_supervision
    from ml.training.multitask_training import FineTunePolicy, multitask_identity, train_multitask
    from ml.training.transformer import EncoderPolicy, TrainingPolicy, train_masked_language_model

    splits = classification_fixtures()
    tokenizer = train_config_tokenizer(
        splits, policy=TokenizerPolicy(vocab_size=300, context_length=16)
    )
    encoder = train_masked_language_model(
        splits,
        tokenizer,
        encoder_policy=EncoderPolicy(hidden_size=16, heads=2, layers=1, feedforward_size=32),
        training_policy=TrainingPolicy(epochs=1),
    )
    examples = authored_supervision(splits, (MutationType.TELNET_ENABLED,))
    model = train_multitask(
        splits,
        encoder,
        examples,
        head_policy=HeadPolicy(classes=("telnet_enabled",), embedding_size=8),
        training_policy=FineTunePolicy(epochs=1),
        loss_weights=LossWeights(severity=0),
    )
    root = tmp_path_factory.mktemp("owned-native-patch-model") / "registry"
    initialize_registry(root)
    pin = multitask_identity(model)
    register_model(root, model, expected_identity=pin)
    return root, pin


@pytest.mark.parametrize("category", ["management.ssh_version_1", "management.telnet_enabled"])
def test_actual_isolated_native_inference_and_explicit_approval_gates(
    model_patch_api, owned_patch_native_registry, monkeypatch, category
):
    from app.core.patch_verification import PatchVerificationSettings
    from app.verification.batfish import BatfishResult
    from app.verification.patch_runtime import PatchVerificationRuntime

    client, service, _, settings, _ = model_patch_api
    source = (
        SOURCE
        if category.endswith("ssh_version_1")
        else (
            "hostname private-edge\nip ssh version 2\nline vty 0 4\n"
            " transport input ssh telnet\n!\n"
        )
    )
    options, snapshot, analysis = selected_request(client, source=source, category=category)
    proposal = generate(client, options).json()
    root, pin = owned_patch_native_registry
    client.app.state.patch_verification = PatchVerificationRuntime(
        PatchVerificationSettings(
            allow_engine_upload=True, registry_root=root, transformer_sha256=pin
        )
    )

    def synthetic_engine(before, after, scope, **kwargs):
        return BatfishResult(
            before_sha256=before.digest,
            after_sha256=after.digest,
            scope=scope,
            status="no_differences_in_scope",
            reason="query_completed",
            engine_version="synthetic-not-engine-measurement",
            cleanup_complete=True,
            difference_count=0,
            before_reachable_count=1,
            after_reachable_count=1,
        )

    monkeypatch.setattr("app.verification.model_patch.check_with_batfish", synthetic_engine)
    body = {
        "verification_id": str(uuid4()),
        "proposal_sha256": proposal["proposal_sha256"],
        "mode": "batfish",
        "allow_local_engine_upload": True,
        "transformer_sha256": pin,
        "allow_local_model_context": True,
        "network": [
            {
                "configuration_id": snapshot["configuration_id"],
                "source_sha256": options["source_sha256"],
            }
        ],
        "scope": {"start_node": "private-edge", "destination": "203.0.113.1/32"},
    }
    path = f"/api/v1/model-patches/{options['patch_id']}"
    result = client.post(path + "/verify", headers=HEADERS, json=body)
    assert result.status_code == 201, result.text
    run = result.json()
    assert run["ml_execution"] == "completed"
    transformer = run["report"]["ml_reviews"][0]["transformer"]
    assert transformer["status"] == "completed" and transformer["model_sha256"] == pin
    assert transformer["before"]["raw_source_sha256"] == options["source_sha256"]
    assert transformer["after"]["raw_source_sha256"] == proposal["candidate_sha256"]
    assert transformer["before"]["anomaly_score"] is not None
    assert run["topology_pinned_at_generation"] is False
    decision = {
        "decision_id": str(uuid4()),
        "verification_id": body["verification_id"],
        "proposal_sha256": proposal["proposal_sha256"],
        "review_sha256": run["review_sha256"],
        "verdict": "approved",
        "comment": "Owned simulated approval; no individual identity or device execution.",
        "acknowledged_limitations": run["report"]["missing_checks"],
        "device_syntax_checked": True,
        "management_access_checked": True,
        "rollback_ready": True,
    }
    if category.endswith("ssh_version_1"):
        assert run["approval_blockers"] == ["selected_ml_category_not_supported"]
        assert client.post(path + "/decisions", headers=HEADERS, json=decision).status_code == 409
    else:
        assert run["approval_blockers"] == []
        for changed in (
            {"acknowledged_limitations": []},
            {"device_syntax_checked": False},
            {"management_access_checked": False},
            {"rollback_ready": False},
            {"review_sha256": "f" * 64},
        ):
            assert (
                client.post(
                    path + "/decisions", headers=HEADERS, json=decision | changed
                ).status_code
                == 409
            )
        approved = client.post(
            path + "/decisions", headers={"Authorization": f"Bearer {ENGINEER}"}, json=decision
        )
        assert approved.status_code == 201, approved.text
        assert approved.json()["request"]["verdict"] == "approved"
        assert (
            approved.json()["applied"] is approved.json()["individual_identity_verified"] is False
        )
        with service.store.engine.connect() as connection:
            payload = connection.execute(
                text("SELECT payload FROM model_patch_decisions")
            ).scalar_one()
            assert "simulated approval" not in payload
    with TestClient(create_app(settings)) as restarted:
        assert restarted.post(path + "/verify", headers=HEADERS, json=body).json() == run
        assert restarted.get(path, headers=HEADERS).json() == proposal
        assert (
            restarted.get(f"/api/v1/analyses/{analysis['analysis_id']}", headers=HEADERS).json()
            == analysis
        )
    print(
        "OWNED_SAVED_PATCH_NATIVE_RESULT="
        + json.dumps(
            {
                "category": category,
                "model_sha256": pin,
                "ml_execution": run["ml_execution"],
                "before_score": transformer["before"]["anomaly_score"],
                "after_score": transformer["after"]["anomaly_score"],
                "approval_blockers": run["approval_blockers"],
                "synthetic_engine": True,
                "new_llm_generations": 0,
                "quality_proven": False,
            },
            sort_keys=True,
        )
    )
