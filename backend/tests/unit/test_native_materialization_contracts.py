"""Strict bounded generated-origin DTO and pure saved-parent checks."""

import json
from datetime import timedelta
from hashlib import sha256
from uuid import uuid4

import pytest
from app.api.native_materialization_contracts import (
    CreateNativeMaterialization,
    NativeMaterialization,
    native_materialization_record,
    validate_native_materialization_parent,
)
from test_native_materialization_preparation import AFTER, PATCH, TIME, inputs, prepare


def options(native, **updates):
    return CreateNativeMaterialization.model_validate(
        {
            "version": "native-materialization-request-0.1.0",
            "after_configuration_id": AFTER,
            "patch_id": PATCH,
            "native_review_sha256": native.public.review_sha256,
            "allow_local_source_materialization": True,
            "allow_private_candidate_source_retention": True,
            **updates,
        }
    )


def record_case():
    native, before, analysis, retained = inputs()
    prepared = prepare((native, before, analysis, retained))
    record = native_materialization_record(
        before.configuration_id,
        native.public.candidate_id,
        options(native),
        native,
        before,
        prepared,
        created_at=TIME,
        service_role="engineer",
    )
    return record, native, before, prepared


def reproof(body):
    body = dict(body)
    body.pop("review_json", None)
    body.pop("review_sha256", None)
    encoded = json.dumps(body, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return {**body, "review_json": encoded, "review_sha256": sha256(encoded.encode()).hexdigest()}


def test_exact_canonical_proof_contains_no_raw_candidate_or_approval():
    record, native, before, prepared = record_case()
    body = record.model_dump(mode="json")
    assert body == reproof(body)
    assert record.after.configuration_id == AFTER and record.patch_id == PATCH
    assert record.origin == "generated_native_candidate" and record.status == "draft_created"
    assert record.formal_qualification == "not_proven"
    assert "private-password" not in record.model_dump_json()
    validate_native_materialization_parent(record, native, before, prepared.after, prepared.draft)


@pytest.mark.parametrize(
    "name", ["allow_local_source_materialization", "allow_private_candidate_source_retention"]
)
@pytest.mark.parametrize("value", [False, 0, 1, "true", "false", None])
def test_exact_consents_including_typed_request_shortcuts(name, value):
    native = inputs()[0]
    with pytest.raises(ValueError):
        options(native, **{name: value})
    poisoned = options(native).model_copy(update={name: value})
    with pytest.raises(ValueError):
        CreateNativeMaterialization.model_validate(poisoned)


@pytest.mark.parametrize(
    "name",
    [
        "fresh_policy_recheck_performed",
        "model_recheck_performed",
        "network_verification_performed",
        "individual_identity_verified",
        "approved",
        "applied",
    ],
)
@pytest.mark.parametrize("value", [0, "false", True])
def test_exact_false_assurances_reject_even_recomputed_proof(name, value):
    record = record_case()[0]
    body = reproof({**record.model_dump(mode="json"), name: value})
    with pytest.raises(ValueError):
        NativeMaterialization.model_validate(body)


@pytest.mark.parametrize("mutation", ["url", "candidate", "after", "draft", "native", "time"])
def test_real_parent_bindings_reject_typed_mutation(mutation):
    record, native, before, prepared = record_case()
    after, draft = prepared.after, prepared.draft
    if mutation == "url":
        record = record.model_copy(update={"configuration_id": uuid4()})
    elif mutation == "candidate":
        record = NativeMaterialization.model_validate(
            reproof({**record.model_dump(mode="json"), "candidate_id": str(uuid4())})
        )
    elif mutation == "after":
        after = after.model_copy(update={"device_id": uuid4()})
    elif mutation == "draft":
        draft = draft.model_copy(update={"requires_human_review": 1})
    elif mutation == "native":
        native = native.model_copy(update={"candidate_text": native.candidate_text + "!\n"})
    else:
        after = after.model_copy(update={"created_at": TIME + timedelta(seconds=1)})
    with pytest.raises(ValueError):
        validate_native_materialization_parent(record, native, before, after, draft)


def test_nested_typed_consent_bypass_and_noncanonical_proof_rejected():
    record = record_case()[0]
    for poisoned in (
        record.model_copy(
            update={
                "request": record.request.model_copy(
                    update={"allow_local_source_materialization": 1}
                )
            }
        ),
        record.model_copy(update={"review_json": record.review_json + " "}),
    ):
        with pytest.raises(ValueError):
            NativeMaterialization.model_validate(poisoned)


@pytest.mark.parametrize(
    "constant,field",
    [
        ("MAX_NATIVE_MATERIALIZATION_REVIEW_BYTES", "review_json"),
        ("MAX_NATIVE_MATERIALIZATION_PUBLIC_BYTES", None),
    ],
)
def test_proof_and_public_budget_exact_boundary(monkeypatch, constant, field):
    import app.api.native_materialization_contracts as contracts

    record = record_case()[0]
    size = len((getattr(record, field) if field else record.model_dump_json()).encode())
    monkeypatch.setattr(contracts, constant, size)
    assert NativeMaterialization.model_validate_json(record.model_dump_json()) == record
    monkeypatch.setattr(contracts, constant, size - 1)
    with pytest.raises(ValueError):
        NativeMaterialization.model_validate_json(record.model_dump_json())
