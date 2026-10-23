"""Synthetic SDK-aware HTTP controls; no real engine or SDK observation is claimed."""

from datetime import timedelta, timezone
from uuid import UUID, uuid4

import app.patching.source_review as workflow
import pytest
from app.api.source_patch_sdk_contracts import (
    SourcePatchIntentV2,
    SourcePatchVerificationV2,
    parse_source_patch_request,
)
from app.core.patch_verification import PatchVerificationSettings
from app.main import create_app
from app.verification.batfish import BatfishExecution
from fastapi.testclient import TestClient
from test_source_evidence_api import evidence_api as evidence_api
from test_source_evidence_api import options as evidence_options
from test_source_evidence_api import post as evidence_post
from test_source_evidence_api import prepare as prepare_evidence
from test_source_ml_recheck_api import source_ml_api as source_ml_api
from test_source_patch_review_api import (
    HEADERS,
    READER,
    draft_pair,
    get,
    options,
    post,
)
from test_source_patch_review_api import (
    source_api as source_api,
)


@pytest.fixture
def sdk_api(source_api, monkeypatch):
    legacy_worker = workflow.check_with_batfish

    def worker(*args, **kwargs):
        return BatfishExecution(
            result=legacy_worker(*args, **kwargs),
            sdk_version="0.36.0",
            sdk_observation="observed",
        )

    monkeypatch.setattr(workflow, "check_with_batfish_evidence", worker)
    return source_api


def test_saved_sdk_protocol_replays_exact_proof_without_sources_or_worker(sdk_api, monkeypatch):
    client, _, _, calls = sdk_api
    draft, _, _ = draft_pair(client)
    body = options(draft, version="source-patch-request-0.2.0")
    created = post(client, draft, body)
    assert created.status_code == 201, created.text
    view = SourcePatchVerificationV2.model_validate(created.json())
    assert view.outcome is not None
    assert view.outcome.network_execution.sdk_version == "0.36.0"
    assert view.outcome.network_execution.sdk_observation == "observed"
    assert view.ml_status == "not_run" and view.status == "needs_review"
    assert view.approved is view.applied is False and len(calls) == 1

    def forbidden(*args, **kwargs):
        pytest.fail("history must not read original source or execute a worker")

    monkeypatch.setattr(workflow, "check_with_batfish_evidence", forbidden)
    monkeypatch.setattr(workflow, "check_with_batfish", forbidden)
    monkeypatch.setattr(workflow.SourcePatchWorkflow, "_source", forbidden)
    assert get(client, draft, body).json() == created.json()
    replay = post(client, draft, body)
    assert replay.status_code == 200 and replay.json() == created.json()
    listed = client.get(f"/api/v2/patches/{draft['patch_id']}/verifications", headers=HEADERS)
    assert listed.status_code == 200
    assert listed.json()[0]["version"] == "source-patch-verification-summary-0.2.0"
    reader = client.get(
        f"/api/v2/patches/{draft['patch_id']}/verifications/{body['verification_id']}",
        headers={"Authorization": f"Bearer {READER}"},
    )
    assert reader.status_code == 200 and reader.json() == created.json()


@pytest.mark.parametrize("first_new", [False, True])
def test_same_uuid_cannot_switch_protocol_and_legacy_default_stays_byte_equal(sdk_api, first_new):
    client, _, _, calls = sdk_api
    draft, _, _ = draft_pair(client)
    body = options(draft)
    if first_new:
        body["version"] = "source-patch-request-0.2.0"
    created = post(client, draft, body)
    assert created.status_code == 201
    alternate = body | {
        "version": "source-patch-request-0.1.0" if first_new else "source-patch-request-0.2.0"
    }
    assert post(client, draft, alternate).status_code == 409
    assert len(calls) == 1
    replay = body | {"version": created.json()["intent"]["request"]["version"]}
    assert post(client, draft, replay).json() == created.json()
    assert get(client, draft, body).json() == created.json()


@pytest.mark.parametrize("fault", ["exception", "wrong_source", "wrong_type"])
def test_invalid_sdk_worker_cannot_save_unbound_observation(sdk_api, monkeypatch, fault):
    client, _, _, _ = sdk_api
    draft, _, _ = draft_pair(client)
    original = workflow.check_with_batfish_evidence

    def invalid(*args, **kwargs):
        if fault == "exception":
            raise RuntimeError("private engine detail")
        result = original(*args, **kwargs)
        if fault == "wrong_type":
            return result.result
        return result.model_copy(
            update={"result": result.result.model_copy(update={"before_sha256": "f" * 64})}
        )

    monkeypatch.setattr(workflow, "check_with_batfish_evidence", invalid)
    body = options(draft, version="source-patch-request-0.2.0")
    response = post(client, draft, body)
    assert response.status_code == 201
    view = SourcePatchVerificationV2.model_validate(response.json())
    assert view.outcome is not None
    assert view.outcome.network_result.reason == "worker_failed"
    assert view.outcome.network_execution.sdk_version is None
    assert view.outcome.network_execution.sdk_observation == "not_observed"
    assert "private engine detail" not in response.text
    assert get(client, draft, body).json() == response.json()


@pytest.mark.parametrize(
    "field,value,status",
    [
        ("version", "source-patch-request-0.4.0", 400),
        ("allow_local_engine_upload", False, 403),
    ],
)
def test_protocol_and_consent_refusals_start_no_worker(sdk_api, field, value, status):
    client, _, _, calls = sdk_api
    draft, _, _ = draft_pair(client)
    body = options(draft, version="source-patch-request-0.2.0") | {field: value}
    assert post(client, draft, body).status_code == status
    assert calls == []
    fresh = body | {"verification_id": str(uuid4())}
    response = client.post(
        f"/api/v2/patches/{draft['patch_id']}/verify",
        headers={"Authorization": f"Bearer {READER}"},
        json=fresh,
    )
    assert response.status_code == 403 and calls == []


def test_new_network_requires_new_joint_protocol_without_claiming_storage_corruption(
    evidence_api, monkeypatch
):
    client, *_ = evidence_api
    selected = prepare_evidence(client, include=())
    draft, records, before, _ = selected
    legacy_worker = workflow.check_with_batfish

    def worker(*args, **kwargs):
        return BatfishExecution(
            result=legacy_worker(*args, **kwargs),
            sdk_version="0.36.0",
            sdk_observation="observed",
        )

    monkeypatch.setattr(workflow, "check_with_batfish_evidence", worker)
    request = options(
        draft,
        version="source-patch-request-0.2.0",
        scope={
            "start_node": before["canonical"]["device"]["hostname"],
            "destination": "192.0.2.1/32",
        },
    )
    response = post(client, draft, request)
    assert response.status_code == 201, response.text
    records["network"] = response.json()
    report = evidence_post(client, selected, evidence_options(selected))
    assert report.status_code == 409, report.text
    assert get(client, draft, request).json() == response.json()


def test_restart_reads_and_replays_new_record_with_engine_disabled(sdk_api, monkeypatch):
    client, _, settings, calls = sdk_api
    draft, _, _ = draft_pair(client)
    request = options(draft, version="source-patch-request-0.2.0")
    saved = post(client, draft, request)
    assert saved.status_code == 201

    def forbidden(*args, **kwargs):
        pytest.fail("restart history cannot read sources or run SDK")

    monkeypatch.setattr(workflow.SourcePatchWorkflow, "_source", forbidden)
    monkeypatch.setattr(workflow, "check_with_batfish_evidence", forbidden)
    application = create_app(
        settings, patch_verification=PatchVerificationSettings(allow_engine_upload=False)
    )
    with TestClient(application) as restarted:
        assert get(restarted, draft, request).json() == saved.json()
        replay = post(restarted, draft, request)
        assert replay.status_code == 200 and replay.json() == saved.json()
    assert len(calls) == 1


@pytest.mark.parametrize("engine_error", [False, True])
def test_saved_metadata_observation_is_separate_from_engine_success(
    sdk_api, monkeypatch, engine_error
):
    client, _, _, _ = sdk_api
    draft, _, _ = draft_pair(client)
    original = workflow.check_with_batfish_evidence

    def worker(*args, **kwargs):
        execution = original(*args, **kwargs)
        if engine_error:
            result = execution.result.model_dump() | {
                "status": "error",
                "reason": "engine_error",
                "difference_count": None,
                "before_reachable_count": None,
                "after_reachable_count": None,
            }
            return BatfishExecution.model_validate(execution.model_dump() | {"result": result})
        return BatfishExecution(
            result=execution.result, sdk_version=None, sdk_observation="metadata_unavailable"
        )

    monkeypatch.setattr(workflow, "check_with_batfish_evidence", worker)
    request = options(draft, version="source-patch-request-0.2.0")
    response = post(client, draft, request)
    assert response.status_code == 201, response.text
    view = SourcePatchVerificationV2.model_validate(response.json())
    assert view.outcome is not None
    execution = view.outcome.network_execution
    assert execution.sdk_observation == ("observed" if engine_error else "metadata_unavailable")
    assert execution.sdk_version == ("0.36.0" if engine_error else None)
    assert execution.result.status == ("error" if engine_error else "no_differences_in_scope")
    assert view.status == "needs_review" and view.approved is view.applied is False
    assert get(client, draft, request).json() == response.json()


@pytest.mark.parametrize("offset", [-3, 3])
def test_direct_source_reservation_preserves_aware_offset_in_payload(sdk_api, offset):
    client, application, _, calls = sdk_api
    draft, _, _ = draft_pair(client)
    selected = workflow.SourcePatchWorkflow(application.state.analysis_service.store)
    request = parse_source_patch_request(options(draft, version="source-patch-request-0.2.0"))
    _, _, intent = selected._prepare(UUID(draft["patch_id"]), request)
    intent = SourcePatchIntentV2.model_validate(
        intent.model_dump()
        | {"created_at": intent.created_at.astimezone(timezone(timedelta(hours=offset)))}
    )
    assert selected.records.reserve(intent) is True
    saved = selected.records.get(request.verification_id)
    assert saved is not None and saved[0].model_dump_json() == intent.model_dump_json()
    assert selected.records.reserve(intent) is False
    assert calls == []
