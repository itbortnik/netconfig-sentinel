"""Versioned source record controls; numeric fixtures prove no actual SDK observation."""

import json
from hashlib import sha256

import pytest
from app.api.source_patch_contracts import SourcePatchVerification, source_review_fingerprint
from app.api.source_patch_sdk_contracts import (
    SourcePatchIntentV2,
    SourcePatchOutcomeV2,
    SourcePatchVerificationV2,
    VerifySourcePatchV2,
    parse_source_patch_intent_json,
    parse_source_patch_outcome_json,
    parse_source_patch_request,
    source_patch_summary,
    source_patch_view,
)
from app.verification.batfish import BatfishExecution
from test_original_deterministic_pair import prepared as prepared
from test_source_evidence_contracts import joint_fixture


def records(prepared):
    legacy = joint_fixture(prepared, network_status="no_differences_in_scope")[-1]
    assert legacy is not None and legacy.outcome is not None
    request = VerifySourcePatchV2.model_validate(
        legacy.intent.request.model_dump() | {"version": "source-patch-request-0.2.0"}
    )
    intent = SourcePatchIntentV2.model_validate(
        legacy.intent.model_dump()
        | {"version": "source-patch-intent-0.2.0", "request": request.model_dump()}
    )
    outcome = SourcePatchOutcomeV2(
        verification_id=request.verification_id,
        intent_sha256=source_review_fingerprint(intent),
        completed_at=legacy.outcome.completed_at,
        network_execution=BatfishExecution(
            result=legacy.outcome.network_result,
            sdk_version="0.36.0",
            sdk_observation="observed",
        ),
    )
    return legacy, intent, outcome


def reseal(value):
    value["review_json"] = json.dumps(
        {key: item for key, item in value.items() if key not in {"review_json", "review_sha256"}},
        sort_keys=True,
        separators=(",", ":"),
    )
    value["review_sha256"] = sha256(value["review_json"].encode()).hexdigest()
    return value


def test_legacy_dispatch_retains_exact_serialization_and_does_no_metadata_lookup(
    prepared, monkeypatch
):
    import importlib.metadata

    monkeypatch.setattr(
        importlib.metadata,
        "version",
        lambda *args: pytest.fail("history cannot query SDK metadata"),
    )
    legacy, _, _ = records(prepared)
    assert legacy.outcome is not None
    intent = parse_source_patch_intent_json(legacy.intent.model_dump_json())
    outcome = parse_source_patch_outcome_json(legacy.outcome.model_dump_json())
    view = source_patch_view(intent, outcome)
    assert type(view) is SourcePatchVerification
    assert view.model_dump_json() == legacy.model_dump_json()
    assert view.review_json == legacy.review_json
    assert view.review_sha256 == legacy.review_sha256
    request = legacy.intent.request.model_dump(mode="json", exclude={"version"})
    assert parse_source_patch_request(request) == legacy.intent.request
    assert source_patch_summary(view).version == "source-patch-verification-summary-0.1.0"


def test_new_records_bind_protocol_and_sdk_envelope_without_promoting_status(prepared):
    legacy, intent, outcome = records(prepared)
    parsed_intent = parse_source_patch_intent_json(intent.model_dump_json())
    parsed_outcome = parse_source_patch_outcome_json(outcome.model_dump_json())
    view = source_patch_view(parsed_intent, parsed_outcome)
    assert isinstance(view, SourcePatchVerificationV2)
    assert view.outcome is not None
    assert view.outcome.network_execution.sdk_version == "0.36.0"
    assert view.outcome.network_result == legacy.outcome.network_result
    assert view.execution_status == "completed" and view.status == "needs_review"
    assert view.ml_status == "not_run" and view.approved is view.applied is False
    assert view.validation_blockers == legacy.validation_blockers
    assert view.review_sha256 != legacy.review_sha256
    assert "network_execution" in json.loads(view.review_json)["outcome"]
    assert "network_result" not in json.loads(view.review_json)["outcome"]
    assert parse_source_patch_request(intent.request.model_dump()) == intent.request
    assert source_patch_summary(view).version == "source-patch-verification-summary-0.2.0"
    pending = source_patch_view(intent, None)
    assert pending.execution_status == "pending_unknown"
    assert "network_execution_unknown" in pending.validation_blockers


@pytest.mark.parametrize("new_intent", [False, True])
def test_mixed_record_versions_cannot_be_resealed_into_one_review(prepared, new_intent):
    legacy, intent, outcome = records(prepared)
    with pytest.raises(ValueError, match="protocols differ"):
        source_patch_view(
            intent if new_intent else legacy.intent, legacy.outcome if new_intent else outcome
        )


@pytest.mark.parametrize(
    "fault",
    [
        "request_version",
        "draft",
        "intent_hash",
        "scope",
        "before",
        "chronology",
        "blockers",
        "proof",
    ],
)
def test_resealed_new_projection_rejects_mismatched_bindings(prepared, fault):
    _, intent, outcome = records(prepared)
    body = source_patch_view(intent, outcome).model_dump(mode="json")
    if fault == "request_version":
        body["intent"]["request"]["version"] = "source-patch-request-0.1.0"
    elif fault == "draft":
        body["draft_sha256"] = "f" * 64
    elif fault == "intent_hash":
        body["outcome"]["intent_sha256"] = "f" * 64
    elif fault == "scope":
        body["outcome"]["network_execution"]["result"]["scope"]["start_node"] = "different-node"
    elif fault == "before":
        body["outcome"]["network_execution"]["result"]["before_sha256"] = "f" * 64
    elif fault == "chronology":
        body["outcome"]["completed_at"] = "2000-01-01T00:00:00Z"
    elif fault == "blockers":
        body["validation_blockers"] = []
    if fault != "proof":
        reseal(body)
    else:
        body["outcome"]["network_execution"]["sdk_version"] = "0.37.0"
    with pytest.raises(ValueError):
        SourcePatchVerificationV2.model_validate(body)


@pytest.mark.parametrize("flag", ["approved", "applied"])
@pytest.mark.parametrize("value", [True, 0, "false"])
def test_new_review_flags_require_exact_false(prepared, flag, value):
    _, intent, outcome = records(prepared)
    body = source_patch_view(intent, outcome).model_dump(mode="json")
    body[flag] = value
    with pytest.raises(ValueError):
        SourcePatchVerificationV2.model_validate(reseal(body))


def test_unknown_or_extra_request_versions_do_not_fall_back(prepared):
    _, intent, _ = records(prepared)
    request = intent.request.model_dump()
    with pytest.raises(ValueError):
        parse_source_patch_request(request | {"version": "source-patch-request-0.3.0"})
    with pytest.raises(ValueError):
        parse_source_patch_request(request | {"sdk_version": "invented"})
