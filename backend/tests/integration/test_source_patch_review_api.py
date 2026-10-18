"""Real saved-source API flow with an explicit synthetic network worker, never live evidence."""

import json
from contextlib import contextmanager
from uuid import uuid4

import app.patching.source_review as workflow_module
import pytest
from app.api.source_patch_contracts import SourcePatchVerification
from app.core.patch_verification import PatchVerificationSettings
from app.core.settings import ApiSettings
from app.db.migrate import upgrade_database
from app.main import create_app
from app.verification.batfish import BatfishResult
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import text

TOKEN = "owned-source-patch-api-service-token-000001"
HEADERS = {"Authorization": f"Bearer {TOKEN}"}
READER = "owned-source-patch-reader-service-token-000001"
ANALYST = "owned-source-patch-analyst-service-token-00001"
ENGINEER = "owned-source-patch-engineer-service-token-0001"
BEFORE = "hostname edge\nip route 203.0.113.0 255.255.255.0 192.0.2.2\n"
AFTER = "hostname edge\nip route 203.0.113.0 255.255.255.0 192.0.2.3\n"


@pytest.fixture
def source_api(tmp_path, monkeypatch):
    settings = ApiSettings(
        f"sqlite:///{tmp_path / 'source-pair.sqlite3'}",
        TOKEN,
        Fernet.generate_key().decode(),
        reader_token=READER,
        analyst_token=ANALYST,
        engineer_token=ENGINEER,
    )
    application = create_app(
        settings, patch_verification=PatchVerificationSettings(allow_engine_upload=True)
    )
    store = application.state.analysis_service.store
    upgrade_database(store.engine)
    calls = []

    def worker(before, after, scope, **options):
        calls.append((before, after, scope, options))
        return BatfishResult(
            before_sha256=before.digest,
            after_sha256=after.digest,
            scope=scope,
            status="no_differences_in_scope",
            reason="query_completed",
            engine_version="owned-synthetic-worker",
            difference_count=0,
            before_reachable_count=1,
            after_reachable_count=1,
            cleanup_complete=True,
        )

    monkeypatch.setattr(workflow_module, "check_with_batfish", worker)
    with TestClient(application) as client:
        yield client, application, settings, calls


def upload(client, contents, device=None, *, retain=True, profile=None):
    body = {
        "device_id": device or str(uuid4()),
        "filename": "owned.cfg",
        "content": contents,
        "retain_original_source": retain,
    }
    if profile:
        body["parser_schema_version"] = profile
    response = client.post("/api/v1/configurations", headers=HEADERS, json=body)
    assert response.status_code == 201, response.text
    return response.json()


def draft_pair(client, *, before=BEFORE, after=AFTER, retain=True, profile=None):
    first = upload(client, before, retain=retain, profile=profile)
    second = upload(client, after, first["device_id"], retain=retain, profile=profile)
    response = client.post(
        "/api/v1/patches",
        headers=HEADERS,
        json={
            "patch_id": str(uuid4()),
            "before_configuration_id": first["configuration_id"],
            "after_configuration_id": second["configuration_id"],
            "before_source_sha256": first["canonical"]["source"]["sha256"],
            "after_source_sha256": second["canonical"]["source"]["sha256"],
        },
    )
    assert response.status_code == 201, response.text
    return response.json(), first, second


def options(draft, **updates):
    return {
        "verification_id": str(uuid4()),
        "draft_sha256": draft["draft_sha256"],
        "scope": {"start_node": "edge", "destination": "203.0.113.0/24"},
        "allow_local_engine_upload": True,
        "companions": [],
    } | updates


def post(client, draft, body, *, headers=HEADERS):
    return client.post(f"/api/v2/patches/{draft['patch_id']}/verify", headers=headers, json=body)


def get(client, draft, body, *, headers=HEADERS):
    return client.get(
        f"/api/v2/patches/{draft['patch_id']}/verifications/{body['verification_id']}",
        headers=headers,
    )


def counts(application):
    with application.state.analysis_service.store.engine.connect() as connection:
        return tuple(
            connection.execute(text(f"SELECT count(*) FROM {name}")).scalar_one()
            for name in ("patch_network_review_intents", "patch_network_review_outcomes")
        )


def test_real_sources_restart_and_identical_replay_preserve_history_and_do_not_rerun(
    source_api, monkeypatch
):
    client, application, settings, calls = source_api
    draft, before, after = draft_pair(client)
    companion = upload(client, "hostname peer\n")
    body = options(
        draft,
        companions=[
            {
                "configuration_id": companion["configuration_id"],
                "source_sha256": companion["canonical"]["source"]["sha256"],
            }
        ],
    )
    result = post(client, draft, body)
    assert result.status_code == 201, result.text
    saved = result.json()
    view = SourcePatchVerification.model_validate(saved)
    assert view.status == "needs_review" and view.approved is view.applied is False
    assert view.intent.preflight.formal_verification == view.ml_status == "not_run"
    assert "device_syntax_not_verified" in view.validation_blockers
    assert "individual_engineer_review_required" in view.validation_blockers
    assert view.outcome.network_result.status == "no_differences_in_scope"
    assert view.intent.before.source_sha256 != view.intent.before_network_sha256
    assert (
        json.loads(view.review_json)["intent"]["before"]["configuration_id"]
        == before["configuration_id"]
    )
    old_network, new_network, _scope, consent = calls[0]
    assert consent["allow_local_upload"] is True
    assert (
        next(row.text for row in old_network.configs if str(row.device_id) == before["device_id"])
        == BEFORE
    )
    assert (
        next(row.text for row in new_network.configs if str(row.device_id) == after["device_id"])
        == AFTER
    )
    assert (
        next(
            row.text for row in old_network.configs if str(row.device_id) == companion["device_id"]
        )
        == "hostname peer\n"
    )
    assert counts(application) == (1, 1)
    assert get(client, draft, body).json() == saved
    listed = client.get(
        f"/api/v2/patches/{draft['patch_id']}/verifications", headers=HEADERS
    ).json()
    assert listed[0]["review_sha256"] == saved["review_sha256"] and len(listed) == 1

    def forbidden(*args, **kwargs):
        raise AssertionError("replay must not read source, re-evaluate policy or invoke worker")

    monkeypatch.setattr(workflow_module, "prepare_original_source", forbidden)
    monkeypatch.setattr(workflow_module, "review_configuration_change", forbidden)
    monkeypatch.setattr(workflow_module, "check_with_batfish", forbidden)
    with TestClient(create_app(settings)) as restarted:
        assert post(restarted, draft, body).status_code == 200
        assert post(restarted, draft, body).json() == saved
        assert get(restarted, draft, body).json() == saved
    assert len(calls) == 1
    for snapshot in (before, after, companion):
        assert (
            client.get(
                f"/api/v1/configurations/{snapshot['configuration_id']}", headers=HEADERS
            ).json()
            == snapshot
        )
    with application.state.analysis_service.store.engine.connect() as connection:
        payloads = (
            connection.execute(text("SELECT payload FROM patch_network_review_intents"))
            .scalars()
            .all()
        )
        assert all("203.0.113" not in raw and "hostname" not in raw for raw in payloads)
        actions = (
            connection.execute(
                text("SELECT action FROM audit_events WHERE action LIKE 'patch.network%'")
            )
            .scalars()
            .all()
        )
        assert sorted(actions) == [
            "patch.network_verification_completed",
            "patch.network_verification_requested",
        ]


@pytest.mark.parametrize(
    "change",
    [
        {"allow_local_engine_upload": False},
        {"draft_sha256": "0" * 64},
        {"scope": {"start_node": "edge", "destination": "198.51.100.0/24"}},
    ],
)
def test_existing_id_with_changed_intent_conflicts_without_sdk(source_api, change):
    client, _application, _settings, calls = source_api
    draft, *_ = draft_pair(client)
    body = options(draft)
    assert post(client, draft, body).status_code == 201
    assert post(client, draft, body | change).status_code == 409
    assert len(calls) == 1


@pytest.mark.parametrize("role,allowed", [(READER, False), (ANALYST, False), (ENGINEER, True)])
def test_rbac_on_fresh_and_replayed_id_precedes_body_and_engine(source_api, role, allowed):
    client, _app, _settings, calls = source_api
    draft, *_ = draft_pair(client)
    body = options(draft)
    assert post(client, draft, body).status_code == 201
    headers = {"Authorization": f"Bearer {role}"}
    assert post(client, draft, body, headers=headers).status_code == (200 if allowed else 403)
    assert get(client, draft, body, headers=headers).status_code == 200
    if not allowed:
        response = client.post(
            f"/api/v2/patches/{draft['patch_id']}/verify",
            headers=headers,
            content=b"{" + b"x" * 20000,
        )
        assert response.status_code == 403
    assert len(calls) == 1


@pytest.mark.parametrize("failure", ["consent", "disabled", "busy"])
def test_preconditions_fail_before_source_read_and_reservation(source_api, monkeypatch, failure):
    client, app, _settings, calls = source_api
    draft, *_ = draft_pair(client)
    body = options(draft)
    if failure == "consent":
        body["allow_local_engine_upload"] = False
    if failure == "disabled":
        app.state.patch_verification = workflow_module.PatchVerificationRuntime(
            PatchVerificationSettings()
        )

    @contextmanager
    def busy():
        from app.verification.patch_runtime import PatchVerificationBusy

        raise PatchVerificationBusy()
        yield

    if failure == "busy":
        monkeypatch.setattr(app.state.patch_verification, "selected_worker", busy)
    monkeypatch.setattr(
        workflow_module, "prepare_original_source", lambda *a, **k: pytest.fail("source read")
    )
    response = post(client, draft, body)
    assert response.status_code == {"consent": 403, "disabled": 503, "busy": 429}[failure]
    assert counts(app) == (0, 0) and calls == []


@pytest.mark.parametrize(
    "change",
    [
        {"allow_local_engine_upload": 1},
        {"allow_local_engine_upload": "true"},
        {"endpoint": "PRIVATE-ENDPOINT"},
        {"scope": {"start_node": "edge", "destination": "2001:db8::/64"}},
        {"scope": {"start_node": "edge", "destination": "203.0.113.7/24"}},
        {"scope": {"start_node": "../PRIVATE", "destination": "203.0.113.0/24"}},
    ],
)
def test_invalid_selection_is_generic_and_does_not_start_an_attempt(source_api, change):
    client, app, _settings, calls = source_api
    draft, *_ = draft_pair(client)
    response = post(client, draft, options(draft, **change))
    assert response.status_code == 400
    assert "PRIVATE" not in response.text
    assert counts(app) == (0, 0) and calls == []


@pytest.mark.parametrize(
    "fault",
    [
        "missing",
        "duplicate_device",
        "duplicate_hostname",
        "hash",
        "startnode",
        "partial",
        "route_map",
    ],
)
def test_retained_sources_and_network_preparation_fail_before_upload(source_api, fault):
    client, app, _settings, calls = source_api
    kwargs = {"retain": fault != "missing"}
    if fault == "partial":
        kwargs["after"] = AFTER + "unsupported PRIVATE-RAW\n"
    if fault == "route_map":
        kwargs.update(
            profile="1.2",
            before=BEFORE + "route-map A permit 10\n set metric 50\n!\n",
            after=AFTER + "route-map A permit 10\n set metric 50\n!\n",
        )
    draft, before, _after = draft_pair(client, **kwargs)
    body = options(draft)
    if fault in {"duplicate_device", "duplicate_hostname", "hash"}:
        companion = (
            before
            if fault == "duplicate_device"
            else upload(
                client, "hostname edge\n" if fault == "duplicate_hostname" else "hostname peer\n"
            )
        )
        body["companions"] = [
            {
                "configuration_id": companion["configuration_id"],
                "source_sha256": "0" * 64
                if fault == "hash"
                else companion["canonical"]["source"]["sha256"],
            }
        ]
    if fault == "startnode":
        body["scope"]["start_node"] = "PRIVATE-NO-NODE"
    response = post(client, draft, body)
    assert response.status_code == 409, response.text
    assert "PRIVATE" not in response.text
    assert counts(app) == (0, 0) and calls == []


@pytest.mark.parametrize(
    "status,reason,cleanup",
    [
        ("unavailable", "sdk_missing", None),
        ("error", "timeout", None),
        ("incomplete", "initialization_issues", False),
        ("inconclusive", "empty_reachable_scope", True),
        ("differences_found", "query_completed", True),
        ("no_differences_in_scope", "query_completed", False),
    ],
)
def test_worker_outcomes_preserve_local_preflight_and_cleanup_without_promotion(
    source_api, monkeypatch, status, reason, cleanup
):
    client, _app, _settings, _calls = source_api
    draft, *_ = draft_pair(client)

    def worker(before, after, scope, **kwargs):
        queried = status in {"inconclusive", "differences_found", "no_differences_in_scope"}
        return BatfishResult(
            before_sha256=before.digest,
            after_sha256=after.digest,
            scope=scope,
            status=status,
            reason=reason,
            engine_version="owned-synthetic-worker" if queried else None,
            cleanup_complete=cleanup,
            difference_count=(1 if status == "differences_found" else 0) if queried else None,
            before_reachable_count=1 if queried else None,
            after_reachable_count=(0 if status == "inconclusive" else 1) if queried else None,
        )

    monkeypatch.setattr(workflow_module, "check_with_batfish", worker)
    response = post(client, draft, options(draft))
    assert response.status_code == 201, response.text
    view = response.json()
    assert view["outcome"]["network_result"]["status"] == status
    assert view["outcome"]["network_result"]["cleanup_complete"] is cleanup
    assert view["intent"]["preflight"]["formal_verification"] == "not_run"
    assert view["status"] == "needs_review" and view["approved"] is view["applied"] is False
    if cleanup is not True:
        assert "engine_cleanup_not_confirmed" in view["validation_blockers"]


@pytest.mark.parametrize("fault", ["exception", "network_hash", "scope"])
def test_untrusted_worker_failure_is_generic_persisted_and_replayable(
    source_api, monkeypatch, fault
):
    client, app, _settings, _calls = source_api
    draft, *_ = draft_pair(client)
    body = options(draft)

    def worker(before, after, scope, **kwargs):
        if fault == "exception":
            raise RuntimeError("PRIVATE-SDK-ERROR")
        return BatfishResult(
            before_sha256="0" * 64 if fault == "network_hash" else before.digest,
            after_sha256=after.digest,
            scope=scope if fault != "scope" else scope.model_copy(update={"start_node": "OTHER"}),
            status="error",
            reason="worker_failed",
        )

    monkeypatch.setattr(workflow_module, "check_with_batfish", worker)
    response = post(client, draft, body)
    assert response.status_code == 201, response.text
    assert "PRIVATE" not in response.text
    assert response.json()["outcome"]["network_result"]["reason"] == "worker_failed"
    assert counts(app) == (1, 1)
    assert post(client, draft, body).json() == response.json()


def test_duplicate_json_keys_and_oversized_body_are_refused_without_echo(source_api):
    client, app, _settings, calls = source_api
    draft, *_ = draft_pair(client)
    raw = json.dumps(options(draft))
    duplicated = raw.replace('"verification_id":', '"verification_id":"PRIVATE","verification_id":')
    for contents, status in ((duplicated, 400), ("PRIVATE" * 4000, 413)):
        response = client.post(
            f"/api/v2/patches/{draft['patch_id']}/verify",
            headers=HEADERS | {"Content-Type": "application/json"},
            content=contents,
        )
        assert response.status_code == status
        assert "PRIVATE" not in response.text
    assert counts(app) == (0, 0) and calls == []


@pytest.mark.parametrize("user_count,expected", [(800, 201), (889, 413)])
def test_preflight_budget_reserves_space_for_outcome_before_any_sdk_call(
    source_api, user_count, expected
):
    client, app, _settings, calls = source_api
    names = [f"u{i}" + "x" * min(60, max(0, 750 - 60 * i)) for i in range(user_count)]
    before = "hostname edge\n" + "".join(f"username {name} password 0 x\n" for name in names)
    draft, *_ = draft_pair(client, before=before, after=before + "ntp server 192.0.2.1\n")
    response = post(
        client,
        draft,
        options(
            draft,
            scope={
                "start_node": "edge",
                "destination": "198.51.100.0/24",
            },
        ),
    )
    assert response.status_code == expected
    assert len(calls) == (1 if expected == 201 else 0)
    assert counts(app) == ((1, 1) if expected == 201 else (0, 0))
    if expected == 201:
        assert response.json()["execution_status"] == "completed"


def test_oversized_untrusted_worker_result_is_generic_and_remains_replayable(
    source_api, monkeypatch
):
    client, _app, _settings, _calls = source_api
    draft, *_ = draft_pair(client)
    body = options(draft)

    def worker(before, after, scope, **kwargs):
        return BatfishResult(
            before_sha256=before.digest,
            after_sha256=after.digest,
            scope=scope,
            status="error",
            reason="engine_error",
            limitations=("PRIVATE" * 40000,),
        )

    monkeypatch.setattr(workflow_module, "check_with_batfish", worker)
    response = post(client, draft, body)
    assert response.status_code == 201 and "PRIVATE" not in response.text
    assert response.json()["execution_status"] == "completed"
    assert response.json()["outcome"]["network_result"]["reason"] == "worker_failed"
    assert post(client, draft, body).json() == response.json()
