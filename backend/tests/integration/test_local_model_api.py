"""Real loopback wire with synthetic responses, not a real model or quality evaluation."""

import json
import os
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from uuid import UUID, uuid4

import pytest
from app.audit.contracts import metadata_hash
from app.core.local_model import LocalModelSettings
from app.core.settings import ApiSettings
from app.db.migrate import upgrade_database
from app.db.store import make_engine
from app.main import create_app
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.engine import make_url

TOKEN = "local-model-api-synthetic-token-000001"
MODEL_KEY = "local-model-separate-private-key"
HEADERS = {"Authorization": f"Bearer {TOKEN}"}


class ModelServer:
    def __init__(self) -> None:
        self.requests: list[tuple[dict, dict]] = []
        self.status = 200
        self.content_type = "application/json"
        self.encoding: str | None = None
        self.delay = 0.0
        self.damage: str | None = None

    def response(self, request: dict) -> bytes:
        context = json.loads(request["messages"][1]["content"])
        answer = {
            "summary": "Synthetic model draft: inspect the supplied policy fact.",
            "technical_explanation": "Only the retrieved internal rule was considered.",
            "possible_impact": ["Hypothesis requiring independent review."],
            "recommendation": "Review the approved operational policy.",
            "patch_draft": None,
            "assumptions": [],
            "missing_information": ["Operational context."],
            "citations": [context["documents"][0]["citation"]],
            "requires_human_review": True,
        }
        if self.damage == "approval":
            answer["approved"] = True
        elif self.damage == "citation":
            answer["citations"] = ["unretrieved#section"]
        elif self.damage == "patch":
            answer["patch_draft"] = "configure terminal"
        elif self.damage == "review":
            answer["requires_human_review"] = False
        elif self.damage == "review-number":
            answer["requires_human_review"] = 1
        elif self.damage == "huge-answer":
            answer["summary"] = "x" * 33000
        answer_text = json.dumps(answer)
        if self.damage == "duplicate-answer":
            answer_text = answer_text.replace('"summary":', '"summary":"injected","summary":', 1)
        elif self.damage == "markdown":
            answer_text = "```json\n" + answer_text + "\n```"
        message = {"role": "assistant", "content": answer_text}
        if self.damage == "tool":
            message["tool_calls"] = [{"function": {"name": "private-command"}}]
        if self.damage == "refusal":
            message["refusal"] = "private-model-error"
        if self.damage == "content-list":
            message["content"] = []
        choice = {
            "message": message,
            "finish_reason": "length" if self.damage == "truncated" else "stop",
        }
        choices = [choice, choice] if self.damage == "multiple" else [choice]
        if self.damage == "empty":
            choices = []
        payload = json.dumps({"choices": choices}).encode()
        if self.damage == "huge-wire":
            return b"x" * 65537
        if self.damage == "invalid-json":
            return b"private-model-error"
        if self.damage == "duplicate-envelope":
            return b'{"choices":[],"choices":' + json.dumps(choices).encode() + b"}"
        return payload


@pytest.fixture
def model_server() -> Iterator[tuple[ModelServer, str]]:
    state = ModelServer()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args) -> None:
            pass

        def do_POST(self) -> None:
            assert self.path == "/v1/chat/completions"
            request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            state.requests.append((request, dict(self.headers)))
            payload = state.response(request)
            time.sleep(state.delay)
            try:
                self.send_response(state.status)
                self.send_header("Content-Type", state.content_type)
                self.send_header("Content-Length", str(len(payload)))
                if state.encoding is not None:
                    self.send_header("Content-Encoding", state.encoding)
                if state.status == 302:
                    self.send_header("Location", "http://outside.invalid/private-path")
                self.end_headers()
                self.wfile.write(payload)
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=lambda: server.serve_forever(poll_interval=0.05), daemon=True)
    thread.start()
    try:
        yield state, f"http://127.0.0.1:{server.server_port}/v1/chat/completions"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.fixture
def model_api(tmp_path: Path, model_server) -> Iterator[tuple]:
    state, endpoint = model_server
    database = f"sqlite:///{tmp_path / 'model.sqlite3'}"
    configured = os.environ.get("NETCONFIG_TEST_DATABASE_URL", "")
    admin = None
    schema = f"sentinel_model_test_{uuid4().hex}"
    if configured:
        url = make_url(configured)
        if url.drivername != "postgresql+psycopg" or not (url.database or "").endswith("_test"):
            pytest.fail("local model tests require a postgresql+psycopg *_test database")
        admin = make_engine(configured)
        with admin.begin() as connection:
            connection.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
        database = url.update_query_dict({"options": f"-csearch_path={schema}"}).render_as_string(
            hide_password=False
        )
    settings = ApiSettings(database, TOKEN, Fernet.generate_key().decode())
    model = LocalModelSettings(
        endpoint, "synthetic-test-model", allow_local_context=True, api_key=MODEL_KEY
    )
    try:
        application = create_app(settings, local_model=model)
        service = application.state.analysis_service
        upgrade_database(service.store.engine)
        with TestClient(application) as client:
            yield client, service, state, settings, model
    finally:
        if admin is not None:
            # Cleanup is limited to this freshly created, UUID-named test schema.
            with admin.begin() as connection:
                connection.exec_driver_sql(f'DROP SCHEMA "{schema}" CASCADE')
            admin.dispose()


def analyze(client, vendor="cisco", partial=False):
    contents = (
        "hostname private-hostname\n"
        if vendor == "cisco"
        else "set system host-name private-hostname\n"
    )
    if partial:
        contents += "unsupported raw private-secret\n"
    snapshot = client.post(
        "/api/v1/configurations",
        headers=HEADERS,
        json={
            "device_id": str(uuid4()),
            "filename": "private-input.cfg",
            "content": contents,
        },
    ).json()
    return client.post(
        f"/api/v1/configurations/{snapshot['configuration_id']}/analyze", headers=HEADERS
    ).json()


def explain(client, result, **updates):
    return client.post(
        f"/api/v1/findings/{result['findings'][0]['finding_id']}/explain",
        headers=HEADERS,
        json={
            "analysis_id": result["analysis_id"],
            "finding_sha256": result["explanations"][0]["finding_sha256"],
            "provider": "llm",
            "allow_local_model_context": True,
        }
        | updates,
    )


@pytest.mark.parametrize("vendor", ["cisco", "juniper"])
@pytest.mark.parametrize("partial", [False, True])
def test_model_draft_uses_redacted_wire_and_never_changes_saved_scores(model_api, vendor, partial):
    client, service, server, settings, model = model_api
    assert server.requests == []
    capabilities = client.get("/api/v1/explanation-capabilities", headers=HEADERS).json()
    assert capabilities["local_model"] == "configured" and not capabilities["model_health_checked"]
    assert server.requests == []
    result = analyze(client, vendor, partial)
    response = explain(client, result)
    assert response.status_code == 200, response.text
    bundle = response.json()
    operation = client.app.state.operation_journal.get(UUID(response.headers["X-Operation-Id"]))
    audit = operation.completion.result
    assert audit.context_sha256 == bundle["context_sha256"]
    assert audit.model_alias_sha256 == metadata_hash(model.model)
    assert bundle["privacy_version"] in audit.versions
    assert {item.permission for item in operation.completion.permissions} == {
        "read",
        "model_explanation",
    }
    assert MODEL_KEY not in operation.model_dump_json()
    assert "Synthetic model draft" not in operation.model_dump_json()
    assert bundle["llm_status"] == "draft"
    assert bundle["explanation"] == result["explanations"][0]
    assert bundle["answer"]["requires_human_review"] is True
    assert bundle["answer"]["patch_draft"] is None
    request, headers = server.requests[0]
    assert headers["Authorization"] == "Bearer " + MODEL_KEY
    assert TOKEN not in json.dumps(headers)
    assert request["stream"] is False and request["response_format"] == {"type": "json_object"}
    wire = json.dumps(request)
    for private in (
        "private-hostname",
        "private-secret",
        "private-input.cfg",
        settings.encryption_key,
        TOKEN,
    ):
        assert private not in wire
    context = json.loads(request["messages"][1]["content"])
    assert context["privacy"]["version"] == bundle["privacy_version"]
    assert context["documents"] == bundle["documents"]
    assert context["parser"]["unparsed_count"] == int(partial)
    assert "risk" not in context and "severity" not in context
    assert client.get(f"/api/v1/analyses/{result['analysis_id']}", headers=HEADERS).json() == result
    with service.store.engine.connect() as connection:
        assert connection.execute(text("SELECT count(*) FROM audit_events")).scalar_one() == 2
        assert connection.execute(text("SELECT count(*) FROM analyses")).scalar_one() == 1
    with TestClient(create_app(settings, local_model=model)) as restarted:
        assert explain(restarted, result).status_code == 200
        assert (
            restarted.get(f"/api/v1/analyses/{result['analysis_id']}", headers=HEADERS).json()
            == result
        )


def test_missing_consent_wrong_scope_and_auth_never_contact_model(model_api):
    client, _, server, _, _ = model_api
    result = analyze(client)
    assert explain(client, result, allow_local_model_context=False).status_code == 403
    assert explain(client, result, allow_local_model_context=1).status_code == 400
    assert explain(client, result, provider="local").status_code == 400
    assert explain(client, result, finding_sha256="f" * 64).status_code == 409
    assert explain(client, result, analysis_id=str(uuid4())).status_code == 404
    assert client.get("/api/v1/explanation-capabilities").status_code == 401
    assert (
        client.post(f"/api/v1/findings/{uuid4()}/explain", content=b"x" * 20000).status_code == 401
    )
    assert server.requests == []


@pytest.mark.parametrize(
    "damage",
    [
        "approval",
        "citation",
        "patch",
        "review",
        "review-number",
        "huge-answer",
        "duplicate-answer",
        "markdown",
        "tool",
        "refusal",
        "content-list",
        "truncated",
        "multiple",
        "empty",
        "huge-wire",
        "invalid-json",
        "duplicate-envelope",
    ],
)
def test_bad_model_output_is_rejected_without_fallback_or_private_text(model_api, damage):
    client, _, server, _, _ = model_api
    result = analyze(client)
    server.damage = damage
    response = explain(client, result)
    assert response.status_code == 503
    assert response.json() == {"detail": "Language model answer is unavailable or rejected."}
    assert "private-model-error" not in response.text
    assert client.get(f"/api/v1/analyses/{result['analysis_id']}", headers=HEADERS).json() == result


@pytest.mark.parametrize(
    "status,content_type,encoding",
    [
        (302, "application/json", None),
        (500, "application/json", None),
        (200, "text/html", None),
        (200, "application/json", "gzip"),
    ],
)
def test_redirect_errors_compression_and_non_json_are_not_followed(
    model_api, status, content_type, encoding
):
    client, _, server, _, _ = model_api
    result = analyze(client)
    server.status, server.content_type, server.encoding = status, content_type, encoding
    assert explain(client, result).status_code == 503
    assert len(server.requests) == 1


def test_hard_deadline_reaps_worker_and_releases_concurrency_slot(model_api, monkeypatch):
    client, _, server, _, model = model_api
    result = analyze(client)
    import subprocess

    from app.explanation.local_model import LocalModelRuntime

    processes = []
    original_popen = subprocess.Popen

    def capture_process(*args, **kwargs):
        process = original_popen(*args, **kwargs)
        processes.append(process)
        return process

    monkeypatch.setattr("app.explanation.local_model.subprocess.Popen", capture_process)

    timed = LocalModelSettings(
        model.endpoint, model.model, allow_local_context=True, timeout_seconds=1
    )
    client.app.state.local_model = LocalModelRuntime(timed)
    server.delay = 2
    start = time.monotonic()
    assert explain(client, result).status_code == 503
    assert time.monotonic() - start < 2.5
    assert len(processes) == 1 and processes[0].poll() is not None
    assert processes[0].stdin.closed and processes[0].stdout.closed
    server.delay = 0
    assert explain(client, result).status_code == 200
    runtime = client.app.state.local_model
    assert runtime._lock.acquire(blocking=False)
    try:
        assert explain(client, result).status_code == 429
    finally:
        runtime._lock.release()


def test_environment_proxies_are_not_used_for_loopback_transport(model_api, monkeypatch):
    client, _, server, _, _ = model_api
    monkeypatch.setenv("HTTP_PROXY", "http://outside.invalid:9999")
    monkeypatch.setenv("HTTPS_PROXY", "http://outside.invalid:9999")
    monkeypatch.setenv("ALL_PROXY", "http://outside.invalid:9999")
    result = analyze(client)
    assert explain(client, result).status_code == 200
    assert len(server.requests) == 1
