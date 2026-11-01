"""Real HTTP native-to-ordinary creation; authored inputs do not measure quality."""

import json
from hashlib import sha256
from uuid import UUID, uuid4

import pytest
from app.db.native_patch_records import NativePatchRecords
from app.db.source_records import SourceRecords
from app.main import create_app
from fastapi.testclient import TestClient
from sqlalchemy import text
from test_native_patch_api import (
    ADMIN,
    ANALYST,
    ENGINEER,
    MARKERS,
    READER,
    headers,
    post,
    prepare,
)
from test_native_patch_api import native_api as native_api


def candidate(client, vendor="cisco"):
    before, analysis, request = prepare(client, vendor)
    response = post(client, before, request)
    assert response.status_code == 201, response.text
    return before, analysis, response.json()


def request_for(native):
    return {
        "version": "native-materialization-request-0.1.0",
        "after_configuration_id": str(uuid4()),
        "patch_id": str(uuid4()),
        "native_review_sha256": native["review_sha256"],
        "allow_local_source_materialization": True,
        "allow_private_candidate_source_retention": True,
    }


def path(before, native):
    return (
        f"/api/v2/configurations/{before['configuration_id']}"
        f"/native-patches/{native['candidate_id']}/materialization"
    )


def materialize(client, before, native, options, token=ENGINEER):
    return client.post(path(before, native), headers=headers(token), json=options)


def counts(application):
    with application.state.analysis_service.store.engine.connect() as connection:
        return {
            table: connection.execute(text(f"SELECT count(*) FROM {table}")).scalar_one()
            for table in (
                "configurations",
                "configuration_sources",
                "patch_proposals",
                "native_materializations",
            )
        }


@pytest.mark.parametrize("vendor", ["cisco", "juniper"])
def test_actual_atomic_creation_then_separate_existing_deterministic_review(
    native_api, monkeypatch, vendor
):
    client, application, _settings = native_api
    before, analysis, native = candidate(client, vendor)
    options = request_for(native)

    def forbidden(*args, **kwargs):
        pytest.fail("materialization must not run policy, native generator, model or engine")

    with monkeypatch.context() as guard:
        for name in (
            "app.patching.native_patches.create_vendor_draft",
            "app.patching.native_patches.evaluate_policies",
            "app.patching.vendor_drafts.evaluate_policies",
        ):
            guard.setattr(name, forbidden)
        response = materialize(client, before, native, options)
    assert response.status_code == 201, response.text
    saved = response.json()
    assert saved["origin"] == "generated_native_candidate" and saved["status"] == "draft_created"
    assert saved["formal_qualification"] == "not_proven"
    assert all(
        saved[field] is False
        for field in (
            "fresh_policy_recheck_performed",
            "model_recheck_performed",
            "network_verification_performed",
            "individual_identity_verified",
            "approved",
            "applied",
        )
    )
    proof = {
        key: value for key, value in saved.items() if key not in {"review_json", "review_sha256"}
    }
    assert saved["review_json"] == json.dumps(
        proof, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    assert sha256(saved["review_json"].encode()).hexdigest() == saved["review_sha256"]
    assert all(marker not in response.text for marker in MARKERS)
    store = application.state.analysis_service.store
    private = NativePatchRecords(store).get(UUID(native["candidate_id"]))
    retained = SourceRecords(store).get(
        UUID(options["after_configuration_id"]),
        expected_source_sha256=saved["after"]["source_sha256"],
        allow_local_read=True,
    )
    assert retained.content == private.candidate_text
    assert all(marker in retained.content for marker in MARKERS)
    assert counts(application) == {
        "configurations": 2,
        "configuration_sources": 2,
        "patch_proposals": 1,
        "native_materializations": 1,
    }
    operation = application.state.operation_journal.get(UUID(response.headers["X-Operation-Id"]))
    assert operation.receipt.operation == "materialize_native_patch"
    assert operation.completion.result is not None
    assert all(marker not in operation.model_dump_json() for marker in MARKERS)
    with store.engine.connect() as connection:
        actions = connection.execute(text("SELECT action FROM audit_events")).scalars().all()
        assert actions.count("native_patch.materialized") == 1
        assert actions.count("patch.draft_created") == 1
        assert actions.count("configuration.source_retained") == 2
        assert actions.count("configuration.created") == 2
    draft = client.get(f"/api/v1/patches/{options['patch_id']}", headers=headers(READER))
    assert draft.status_code == 200, draft.text
    assert (
        draft.json()["status"] == "draft" and draft.json()["draft_sha256"] == saved["draft_sha256"]
    )
    base = f"/api/v2/patches/{options['patch_id']}"
    selection = client.get(
        base + "/deterministic-selection/" + analysis["analysis_id"], headers=headers(READER)
    )
    assert selection.status_code == 200, selection.text
    recheck = client.post(
        base + "/deterministic-rechecks",
        headers=headers(),
        json={
            "recheck_id": str(uuid4()),
            "draft_sha256": saved["draft_sha256"],
            "before_analysis_id": analysis["analysis_id"],
            "before_analysis_sha256": selection.json()["before_analysis_sha256"],
            "reference_canonical_sha256": None,
            "allow_local_analysis_context": True,
        },
    )
    assert recheck.status_code == 201, recheck.text
    assert recheck.json()["execution_status"] == "completed"
    assert client.get(path(before, native), headers=headers(READER)).json() == saved
    assert (
        client.get(
            f"/api/v2/configurations/{options['after_configuration_id']}/native-origin",
            headers=headers(READER),
        ).json()
        == saved
    )


@pytest.mark.parametrize("vendor", ["cisco", "juniper"])
def test_restart_history_and_replay_after_source_removal_without_runtime(
    native_api, monkeypatch, vendor
):
    client, application, settings = native_api
    before, _analysis, native = candidate(client, vendor)
    options = request_for(native)
    response = materialize(client, before, native, options)
    assert response.status_code == 201, response.text
    saved = response.json()
    with application.state.analysis_service.store.engine.begin() as connection:
        connection.execute(text("DELETE FROM configuration_sources"))

    def forbidden(*args, **kwargs):
        pytest.fail("materialized history/replay must not execute runtime or access sources")

    for name in (
        "app.db.source_records.SourceRecords.get",
        "app.patching.native_materialization.prepare_native_materialization",
        "app.patching.native_materialization_preparation.parse_configuration_with_coverage",
        "app.patching.native_materialization_preparation.prepare_original_source",
        "app.patching.native_patches.create_vendor_draft",
        "app.patching.native_patches.evaluate_policies",
    ):
        monkeypatch.setattr(name, forbidden)
    with TestClient(create_app(settings)) as restarted:
        assert restarted.get(path(before, native), headers=headers(READER)).json() == saved
        origin = restarted.get(
            f"/api/v2/configurations/{options['after_configuration_id']}/native-origin",
            headers=headers(READER),
        )
        assert origin.status_code == 200 and origin.json() == saved
        replay = materialize(restarted, before, native, options, ADMIN)
        assert replay.status_code == 200 and replay.json() == saved
        assert (
            materialize(restarted, before, native, options | {"patch_id": str(uuid4())}).status_code
            == 409
        )
    assert counts(application)["native_materializations"] == 1


def test_fresh_creation_requires_original_row_without_restoring_private_copy(native_api):
    client, application, _settings = native_api
    before, _analysis, native = candidate(client)
    options = request_for(native)
    with application.state.analysis_service.store.engine.begin() as connection:
        connection.execute(text("DELETE FROM configuration_sources"))
    assert materialize(client, before, native, options).status_code == 409
    assert counts(application) == {
        "configurations": 1,
        "configuration_sources": 0,
        "patch_proposals": 0,
        "native_materializations": 0,
    }
    assert (
        NativePatchRecords(application.state.analysis_service.store).get(
            UUID(native["candidate_id"])
        )
        is not None
    )


@pytest.mark.parametrize(
    "field", ["allow_local_source_materialization", "allow_private_candidate_source_retention"]
)
@pytest.mark.parametrize("value", [False, 0, 1, "true"])
def test_http_requires_two_exact_true_consents(native_api, field, value):
    client, application, _settings = native_api
    before, _analysis, native = candidate(client)
    assert (
        materialize(client, before, native, request_for(native) | {field: value}).status_code == 400
    )
    assert counts(application)["native_materializations"] == 0


@pytest.mark.parametrize("token", [READER, ANALYST])
def test_read_roles_cannot_materialize(native_api, token):
    client, application, _settings = native_api
    before, _analysis, native = candidate(client)
    assert materialize(client, before, native, request_for(native), token).status_code == 403
    assert client.get(path(before, native), headers=headers(token)).status_code == 404
    assert counts(application)["native_materializations"] == 0


def test_wrong_urls_stale_proof_and_request_bounds(native_api):
    client, application, _settings = native_api
    before, _analysis, native = candidate(client)
    options = request_for(native)
    assert (
        materialize(
            client, before, native, options | {"native_review_sha256": "0" * 64}
        ).status_code
        == 409
    )
    other = {"configuration_id": str(uuid4())}
    assert materialize(client, other, native, options).status_code == 409
    assert client.get(path(other, native), headers=headers(READER)).status_code == 404
    assert (
        client.get(
            f"/api/v2/configurations/{before['configuration_id']}/native-origin",
            headers=headers(READER),
        ).status_code
        == 404
    )
    assert (
        client.post(path(before, native), headers=headers(), content='{"x":1,"x":2}').status_code
        == 400
    )
    assert (
        client.post(
            path(before, native), headers=headers(), content=" " * (16 * 1024 + 1)
        ).status_code
        == 413
    )
    assert (
        materialize(client, before, native, options | {"candidate_text": "untrusted"}).status_code
        == 400
    )
    assert counts(application)["native_materializations"] == 0
    schema = client.get("/openapi.json").json()["paths"][
        "/api/v2/configurations/{configuration_id}/native-patches/{candidate_id}/materialization"
    ]["post"]["requestBody"]["content"]["application/json"]["schema"]
    assert set(options) <= set(schema["required"])


def test_lost_operation_completion_reconciles_committed_outputs(native_api, monkeypatch):
    client, application, _settings = native_api
    before, _analysis, native = candidate(client)
    options = request_for(native)
    journal = application.state.operation_journal
    original = journal.complete

    def failed(*args, **kwargs):
        raise RuntimeError("owned completion unavailable")

    monkeypatch.setattr(journal, "complete", failed)
    assert materialize(client, before, native, options).status_code == 503
    assert counts(application)["native_materializations"] == 1
    monkeypatch.setattr(journal, "complete", original)

    def forbidden(*args, **kwargs):
        pytest.fail("replay must reconcile committed outputs without preparation")

    monkeypatch.setattr(
        "app.patching.native_materialization.prepare_native_materialization", forbidden
    )
    loaded = client.get(path(before, native), headers=headers(READER))
    assert loaded.status_code == 200
    replay = materialize(client, before, native, options)
    assert replay.status_code == 200 and replay.json() == loaded.json()
    assert counts(application)["native_materializations"] == 1
