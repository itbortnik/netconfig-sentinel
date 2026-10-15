"""Synthetic owned provider tests persistence/replay, never actual model quality."""

import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from hashlib import sha256
from uuid import UUID, uuid4

import pytest
from app.audit.journal import OperationJournal
from app.db.model_patch_records import ModelPatchRecords
from app.db.store import StorageIntegrityError
from app.explanation.local_model import LocalModelRuntime
from app.main import create_app
from fastapi.testclient import TestClient
from sqlalchemy import event, text
from test_saved_model_patch_api import (
    ANALYST,
    HEADERS,
    READER,
    selected_request,
)
from test_saved_model_patch_api import (
    model_patch_api as model_patch_api,
)

V1 = "/api/v1/model-patches"
V2 = "/api/v2/model-patches"


@pytest.fixture
def grounded_api(model_patch_api):
    client, service, state, settings, old_model = model_patch_api
    model = replace(old_model, allow_grounded_patch_draft=True)
    client.app.state.local_model = LocalModelRuntime(model)
    return client, service, state, settings, model


@pytest.mark.parametrize("decline", [False, True])
def test_saved_grounded_candidate_or_null_round_trip_and_provider_free_restart(
    grounded_api, decline
):
    client, service, state, settings, _ = grounded_api
    request, _, _ = selected_request(client)
    state["damage"] = "decline" if decline else None
    created = client.post(V2, headers=HEADERS, json=request)
    assert created.status_code == 201, created.text
    result = created.json()
    assert result["version"] == "grounded-source-bound-patch-proposal-0.1.0"
    assert result["presentation_kind"] == "server_derived"
    projected = result["projection"]
    assert projected["status"] == ("declined" if decline else "draft")
    assert (result["model_answer"]["patch_draft"] is None) is decline
    assert result["model_answer"]["patch_draft"] == projected["answer"]["patch_draft"]
    assert result["context_sha256"] != result["edit_context_sha256"]
    assert projected["context_sha256"] == result["edit_context_sha256"]
    assert "BEFORE" in projected["answer"]["technical_explanation"]
    assert result["source_facts"]["baseline_approval"] == "not_proven"
    assert projected["formal_verification"] == "not_run"
    assert projected["approved"] is False and projected["applied"] is False
    assert len(state["requests"]) == 1
    assert "private-password" not in str(state["requests"])
    assert client.get(V1 + "/" + request["patch_id"], headers=HEADERS).status_code == 404
    assert (
        client.get(V1, params={"analysis_id": request["analysis_id"]}, headers=HEADERS).json() == []
    )
    assert client.get(
        V2, params={"analysis_id": request["analysis_id"]}, headers=HEADERS
    ).json() == [result]
    client.app.state.local_model = None
    assert client.post(V2, headers=HEADERS, json=request).json() == result
    with TestClient(create_app(settings)) as restarted:
        read = restarted.get(V2 + "/" + request["patch_id"], headers=HEADERS)
        assert read.status_code == 200 and read.json() == result
        assert restarted.post(V2, headers=HEADERS, json=request).json() == result
    assert len(state["requests"]) == 1
    assert service.store.get_analysis(UUID(request["analysis_id"])) is not None


@pytest.mark.parametrize(
    "damage",
    [
        "command",
        "anchor",
        "citation",
        "approval",
        "review",
        "duplicate",
        "facts",
        "prose",
        "redirect",
    ],
)
def test_rejected_grounded_attempt_is_terminal_without_raw_output_or_retry(grounded_api, damage):
    client, _, state, _, _ = grounded_api
    request, _, _ = selected_request(client)
    state["damage"] = damage
    attempted = client.post(V2, headers=HEADERS, json=request)
    assert attempted.status_code == 503
    saved = client.get(V2 + "/" + request["patch_id"], headers=HEADERS)
    assert saved.status_code == 200, saved.text
    value = saved.json()
    assert value["projection"]["status"] == "failed"
    assert value["model_answer"] is None and value["projection"]["answer"] is None
    assert value["projection_sha256"] is None
    assert client.post(V2, headers=HEADERS, json=request).json() == value
    assert len(state["requests"]) == 1


@pytest.mark.parametrize("first,second", [(V1, V2), (V2, V1)])
def test_idempotency_identity_includes_protocol_before_provider(grounded_api, first, second):
    client, _, state, _, _ = grounded_api
    request, _, _ = selected_request(client)
    initial = client.post(first, headers=HEADERS, json=request)
    assert initial.status_code == 201
    assert client.post(second, headers=HEADERS, json=request).status_code == 409
    assert len(state["requests"]) == 1
    assert client.post(first, headers=HEADERS, json=request).status_code == 200
    assert len(state["requests"]) == 1


def test_mixed_pagination_and_legacy_filter_before_limit_offset(grounded_api):
    client, _, _, _, _ = grounded_api
    request, _, _ = selected_request(client)
    ids, legacy = [], []
    for index in range(6):
        request = request | {"patch_id": str(uuid4())}
        path = V1 if index % 2 == 0 else V2
        assert client.post(path, headers=HEADERS, json=request).status_code == 201
        ids.insert(0, request["patch_id"])
        if path == V1:
            legacy.insert(0, request["patch_id"])
    query = {"analysis_id": request["analysis_id"], "limit": 2, "offset": 1}
    old_rows = client.get(V1, headers=HEADERS, params=query).json()
    assert [row["patch_id"] for row in old_rows] == legacy[1:3]
    rows = client.get(V2, headers=HEADERS, params=query).json()
    assert [row.get("projection", row)["patch_id"] for row in rows] == ids[1:3]


@pytest.mark.parametrize("old,new", [(False, False), (True, False), (False, True), (True, True)])
def test_operator_modes_are_independent_and_capability_defaults_do_not_activate(
    grounded_api, old, new
):
    client, _, state, _, model = grounded_api
    client.app.state.local_model = LocalModelRuntime(
        replace(
            model,
            allow_patch_draft=old,
            allow_grounded_patch_draft=new,
        )
    )
    caps = client.get(V2 + "/capabilities", headers=HEADERS)
    assert caps.status_code == 200, caps.text
    value = caps.json()
    assert value["grounded_generation"] == ("configured" if new else "disabled")
    assert value["legacy"]["generation"] == ("configured" if old else "disabled")
    for path, allowed in ((V1, old), (V2, new)):
        request, _, _ = selected_request(client)
        result = client.post(path, headers=HEADERS, json=request)
        assert result.status_code == (201 if allowed else 503), result.text
    assert len(state["requests"]) == int(old) + int(new)


@pytest.mark.parametrize("token", [READER, ANALYST])
def test_v2_authorizes_before_body_and_generation(grounded_api, token):
    client, _, state, _, _ = grounded_api
    result = client.post(
        V2, headers={"Authorization": "Bearer " + token}, content=b"invalid-private"
    )
    assert result.status_code == 403
    assert not state["requests"]


@pytest.mark.parametrize("change", ["consent", "source_pin", "finding_pin", "missing_source"])
def test_v2_selection_or_consent_fails_before_provider(grounded_api, change):
    client, _, state, _, _ = grounded_api
    request, _, _ = selected_request(client, retain=change != "missing_source")
    if change == "consent":
        request["allow_local_model_context"] = False
    elif change == "source_pin":
        request["source_sha256"] = "f" * 64
    elif change == "finding_pin":
        request["finding_sha256"] = "f" * 64
    result = client.post(V2, headers=HEADERS, json=request)
    assert result.status_code == (403 if change == "consent" else 409), result.text
    assert not state["requests"]


@pytest.mark.parametrize("verdict", ["rejected", "needs_more_information"])
def test_grounded_candidate_local_review_and_decision_replay_preserve_context_and_gates(
    grounded_api,
    verdict,
):
    client, _, state, settings, _ = grounded_api
    request, _, _ = selected_request(client)
    generated = client.post(V2, headers=HEADERS, json=request)
    assert generated.status_code == 201, generated.text
    wrapper = generated.json()
    projected = wrapper["projection"]
    body = {
        "verification_id": str(uuid4()),
        "proposal_sha256": projected["proposal_sha256"],
        "mode": "local_preflight",
        "network": [
            {
                "configuration_id": projected["source"]["configuration_id"],
                "source_sha256": projected["source_sha256"],
            }
        ],
        "scope": {"start_node": "private-edge", "destination": "203.0.113.1/32"},
    }
    path = V1 + "/" + request["patch_id"]
    response = client.post(path + "/verify", headers=HEADERS, json=body)
    assert response.status_code == 201, response.text
    result = response.json()
    assert result["report"]["context_sha256"] == wrapper["edit_context_sha256"]
    assert result["report"]["context_sha256"] != wrapper["context_sha256"]
    assert result["report"]["status"] == "needs_review"
    assert len(client.get(path + "/verifications", headers=HEADERS).json()) == 1
    decision = {
        "decision_id": str(uuid4()),
        "verification_id": body["verification_id"],
        "proposal_sha256": projected["proposal_sha256"],
        "review_sha256": result["review_sha256"],
        "verdict": verdict,
        "comment": "Owned synthetic service-role review; no individual identity.",
    }
    attempted_approval = decision | {
        "verdict": "approved",
        "acknowledged_limitations": result["report"]["missing_checks"],
        "device_syntax_checked": True,
        "management_access_checked": True,
        "rollback_ready": True,
    }
    assert (
        client.post(path + "/decisions", headers=HEADERS, json=attempted_approval).status_code
        == 409
    )
    saved_decision = client.post(path + "/decisions", headers=HEADERS, json=decision)
    assert saved_decision.status_code == 201, saved_decision.text
    saved = saved_decision.json()
    assert saved["request"]["verdict"] == verdict
    assert saved["applied"] is saved["individual_identity_verified"] is False
    with TestClient(create_app(settings)) as restarted:
        history = restarted.get(path + "/verifications", headers=HEADERS)
        assert history.status_code == 200 and history.json() == [result]
        assert restarted.post(path + "/verify", headers=HEADERS, json=body).json() == result
        assert restarted.get(V2 + "/" + request["patch_id"], headers=HEADERS).json() == wrapper
        assert restarted.get(path + "/decisions", headers=HEADERS).json() == [saved]
        assert restarted.post(path + "/decisions", headers=HEADERS, json=decision).json() == saved
    assert len(state["requests"]) == 1


@pytest.mark.parametrize("index", range(4))
def test_both_vendors_and_both_supported_categories_use_exact_source_bound_edits(
    grounded_api, index
):
    from ml.instruct.patch_smoke import authored_patch_cases

    client, _, state, _, _ = grounded_api
    case = authored_patch_cases()[index].prepared
    request, _, _ = selected_request(client, source=case.before, category=case.finding.category)
    reply = client.post(V2, headers=HEADERS, json=request)
    assert reply.status_code == 201, reply.text
    assert reply.json()["projection"]["status"] == "draft"
    assert (
        reply.json()["projection"]["candidate_sha256"] == sha256(case.baseline.encode()).hexdigest()
    )
    assert len(state["requests"]) == 1


@pytest.mark.parametrize(
    "change",
    [
        "actual_context",
        "edit_context",
        "renderer",
        "facts",
        "projection",
        "missing_version",
        "duplicate_version",
        "unknown_version",
        "outcome_protocol",
        "row_protocol",
    ],
)
def test_key_holder_tamper_or_rehashed_context_never_becomes_new_history(grounded_api, change):
    client, service, state, _, _ = grounded_api
    request, _, _ = selected_request(client)
    assert client.post(V2, headers=HEADERS, json=request).status_code == 201
    key = request["patch_id"]
    with service.store.engine.begin() as connection:
        old_intent = connection.execute(
            text("SELECT payload FROM model_patch_intents WHERE id=:id"), {"id": key}
        ).scalar_one()
        old_outcome = connection.execute(
            text("SELECT payload FROM model_patch_outcomes WHERE patch_id=:id"), {"id": key}
        ).scalar_one()
        intent = json.loads(
            service.store._decode(old_intent, kind="model_patch_intent", row_id=key)
        )
        outcome = json.loads(
            service.store._decode(old_outcome, kind="model_patch_outcome", row_id=key)
        )
        if change == "actual_context":
            intent["context_sha256"] = intent["edit_context_sha256"]
        elif change == "edit_context":
            intent["edit_context_sha256"] = intent["context_sha256"]
        elif change == "renderer":
            intent["renderer_policy_sha256"] = "0" * 64
        elif change == "facts":
            current = intent["source_facts"]["observed_ssh_enabled"]
            intent["source_facts"]["observed_ssh_enabled"] = current is False
            intent["facts_binding_sha256"] = sha256(
                json.dumps(
                    intent["source_facts"],
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
            ).hexdigest()
            outcome["model_answer"]["facts_binding_sha256"] = intent["facts_binding_sha256"]
        elif change == "projection":
            outcome["answer"]["summary"] = "Approved and safe; formal passed."
            outcome["projection_sha256"] = sha256(
                json.dumps(
                    outcome["answer"], ensure_ascii=False, sort_keys=True, separators=(",", ":")
                ).encode()
            ).hexdigest()
        elif change == "missing_version":
            intent.pop("version")
        elif change == "unknown_version":
            intent["version"] = "grounded-model-patch-intent-9.0.0"
        elif change == "outcome_protocol":
            outcome["version"] = "model-patch-outcome-0.1.0"
        elif change == "row_protocol":
            connection.execute(
                text(
                    "UPDATE model_patch_intents SET protocol='legacy-model-patch-0.1.0' "
                    "WHERE id=:id"
                ),
                {"id": key},
            )
        # Rehash the whole parent binding too, not merely an obvious stale SHA.
        outcome["intent_sha256"] = sha256(
            json.dumps(intent, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        raw_intent = json.dumps(intent)
        if change == "duplicate_version":
            raw_intent = '{"version":"fake",' + raw_intent[1:]
        connection.execute(
            text("UPDATE model_patch_intents SET payload=:payload WHERE id=:id"),
            {
                "id": key,
                "payload": service.store._encode(raw_intent, kind="model_patch_intent", row_id=key),
            },
        )
        connection.execute(
            text("UPDATE model_patch_outcomes SET payload=:payload WHERE patch_id=:id"),
            {
                "id": key,
                "payload": service.store._encode(
                    json.dumps(outcome), kind="model_patch_outcome", row_id=key
                ),
            },
        )
    assert client.get(V2 + "/" + key, headers=HEADERS).status_code == 503
    assert client.post(V2, headers=HEADERS, json=request).status_code == 503
    assert len(state["requests"]) == 1


def test_lost_completion_remains_generating_and_never_repeats_provider(grounded_api, monkeypatch):
    client, _, state, settings, _ = grounded_api
    request, _, _ = selected_request(client)

    def lost(*args, **kwargs):
        raise StorageIntegrityError("simulated owned lost completion")

    monkeypatch.setattr(ModelPatchRecords, "complete", lost)
    assert client.post(V2, headers=HEADERS, json=request).status_code == 503
    monkeypatch.undo()
    with TestClient(create_app(settings)) as restarted:
        result = restarted.post(V2, headers=HEADERS, json=request)
        assert result.status_code == 200, result.text
        assert result.json()["projection"]["status"] == "generating"
        assert result.json()["model_answer"] is None
    assert len(state["requests"]) == 1


def test_v2_receipt_failure_prevents_dispatch_and_domain_reservation(grounded_api, monkeypatch):
    client, service, state, _, _ = grounded_api
    request, _, _ = selected_request(client)

    def unavailable(*args, **kwargs):
        raise StorageIntegrityError("owned receipt failure")

    monkeypatch.setattr(OperationJournal, "start", unavailable)
    reply = client.post(V2, headers=HEADERS, json=request)
    assert reply.status_code == 503
    assert not state["requests"]
    assert ModelPatchRecords(service.store).get(UUID(request["patch_id"])) is None


def test_simultaneous_cross_protocol_reservation_uses_one_global_identity(grounded_api):
    client, _, state, settings, model = grounded_api
    request, _, _ = selected_request(client)
    state["delay"] = 0.1
    with TestClient(create_app(settings, local_model=model)) as another:
        with ThreadPoolExecutor(max_workers=2) as workers:
            first = workers.submit(client.post, V1, headers=HEADERS, json=request)
            second = workers.submit(another.post, V2, headers=HEADERS, json=request)
            replies = [first.result(), second.result()]
    assert sorted(reply.status_code for reply in replies) == [201, 409]
    assert len(state["requests"]) == 1


@pytest.mark.parametrize("stage", ["requested", "completed"])
def test_grounded_domain_audit_is_atomic_with_each_durable_write(grounded_api, stage):
    client, service, state, _, _ = grounded_api
    request, _, _ = selected_request(client)
    action = "model_patch." + stage

    def unavailable(connection, cursor, statement, parameters, context, executemany):
        if statement.lower().startswith("insert into audit_events") and action in str(parameters):
            raise StorageIntegrityError("owned domain audit failure")

    event.listen(service.store.engine, "before_cursor_execute", unavailable)
    try:
        assert client.post(V2, headers=HEADERS, json=request).status_code == 503
    finally:
        event.remove(service.store.engine, "before_cursor_execute", unavailable)
    with service.store.engine.connect() as connection:
        assert (
            connection.execute(text("SELECT count(*) FROM model_patch_outcomes")).scalar_one() == 0
        )
        assert (
            connection.execute(
                text("SELECT count(*) FROM audit_events WHERE action=:action"), {"action": action}
            ).scalar_one()
            == 0
        )
    stored = ModelPatchRecords(service.store).get(UUID(request["patch_id"]))
    if stage == "requested":
        assert stored is None and not state["requests"]
        assert client.post(V2, headers=HEADERS, json=request).status_code == 201
    else:
        assert stored is not None and stored[1] is None
        replay = client.post(V2, headers=HEADERS, json=request)
        assert replay.status_code == 200
        assert replay.json()["projection"]["status"] == "generating"
    assert len(state["requests"]) == 1


def test_grounded_operation_journal_binds_visible_ids_without_raw_choices(grounded_api):
    client, _, state, _, _ = grounded_api
    request, _, _ = selected_request(client)
    created = client.post(V2, headers=HEADERS, json=request)
    assert created.status_code == 201, created.text
    wrapper = created.json()
    for response in (created, client.get(V2 + "/" + request["patch_id"], headers=HEADERS)):
        record = client.get(
            "/api/v1/operation-audit/" + response.headers["X-Operation-Id"], headers=HEADERS
        )
        assert record.status_code == 200, record.text
        metadata = record.json()["completion"]["result"]
        assert set(metadata["resource_ids"]) >= {
            request["patch_id"],
            request["analysis_id"],
            request["finding_id"],
        }
        assert metadata["source_sha256"] == request["source_sha256"]
        assert metadata["finding_sha256"] == request["finding_sha256"]
        assert metadata["context_sha256"] == wrapper["context_sha256"]
        assert metadata["context_sha256"] != wrapper["edit_context_sha256"]
        assert "grounded-before-presentation-0.1.0" in metadata["versions"]
        for private in (
            "private-password",
            "ip ssh version",
            "source_facts",
            "model_answer",
            "technical_explanation",
            "fact_refs",
            "Owned synthetic",
        ):
            assert private not in record.text
    assert len(state["requests"]) == 1


def test_v2_stale_schema_fails_before_dispatch_or_provider(grounded_api):
    client, service, state, _, _ = grounded_api
    request, _, _ = selected_request(client)
    with service.store.engine.begin() as connection:
        connection.execute(
            text("UPDATE alembic_version SET version_num='0009_configuration_model_runs'")
        )
    try:
        assert client.post(V2, headers=HEADERS, json=request).status_code == 503
        assert client.get(V2 + "/capabilities", headers=HEADERS).status_code == 503
        assert not state["requests"]
        with service.store.engine.connect() as connection:
            assert (
                connection.execute(text("SELECT count(*) FROM model_patch_intents")).scalar_one()
                == 0
            )
    finally:
        with service.store.engine.begin() as connection:
            connection.execute(
                text("UPDATE alembic_version SET version_num='0010_model_patch_protocols'")
            )
