"""New encrypted protocol cannot be downgraded, rehashed or replayed on stale facts."""

import json
import warnings
from dataclasses import replace

import pytest
from app.explanation import grounded_receipts
from app.explanation.grounded_patch import projection_sha256, validate_grounded_patch_answer
from app.explanation.grounded_receipts import (
    GroundedPatchReceiptUnavailable,
    create_grounded_patch_receipt,
    load_grounded_patch_receipt,
    save_grounded_patch_receipt,
)
from app.explanation.knowledge import text_sha256
from app.explanation.patch_receipts import ModelPatchReceiptUnavailable, load_patch_receipt
from cryptography.fernet import Fernet
from test_grounded_patch import prepared_answer
from test_model_patch_receipts import inputs as legacy_inputs

from ml.instruct.runtime import GenerationObservation, InstructIdentity
from ml.instruct.source import inventory_sha256


def inputs(null=False):
    prepared, answer = prepared_answer(null=null)
    generated = validate_grounded_patch_answer(json.dumps(answer).encode(), prepared)
    identity = InstructIdentity(
        source_inventory_sha256=inventory_sha256(),
        parameter_count=4022468096,
        device_name="explicit-unit-fake",
        runtime_versions=("test=fake",),
    )
    observation = GenerationObservation(1900, 200, 1.0, prepared.prompt.context_sha256)
    receipt = create_grounded_patch_receipt(
        generated,
        prepared=prepared,
        identity=identity,
        observation=observation,
        expected_inventory_sha256=inventory_sha256(),
    )
    return prepared, generated, identity, observation, receipt


def save(path, receipt, prepared, key):
    save_grounded_patch_receipt(
        receipt, path, prepared=prepared, key=key, expected_inventory_sha256=inventory_sha256()
    )


def load(path, prepared, key, pin=None):
    return load_grounded_patch_receipt(
        path, prepared=prepared, key=key, expected_inventory_sha256=pin or inventory_sha256()
    )


@pytest.mark.parametrize("null", [False, True])
def test_encrypted_round_trip_bind_raw_typed_answer_new_prompt_and_derived_presentation(
    tmp_path, monkeypatch, null
):
    prepared, generated, _, _, receipt = inputs(null)
    path, key = tmp_path / "private.ncp", Fernet.generate_key()
    save(path, receipt, prepared, key)
    ciphertext = path.read_bytes()
    assert ciphertext.startswith(b"NCS-MODEL-PATCH-2\n")
    assert key not in ciphertext
    assert b"owned-host" not in ciphertext
    assert "owned-host" not in repr(receipt)
    # Replay has no provider/GPU invocation, even if all generation APIs are unusable.
    from app.explanation import grounded_patch

    from ml.instruct import runtime

    monkeypatch.setattr(runtime.LocalInstructProvider, "generate", lambda *a: pytest.fail("model"))
    monkeypatch.setattr(runtime, "_load_gpu_model", lambda *a: pytest.fail("GPU"))
    monkeypatch.setattr(
        grounded_patch, "generate_grounded_patch_draft", lambda *a: pytest.fail("gen")
    )
    recovered = load(path, prepared, key)
    assert recovered == receipt
    assert recovered.model_answer == generated.model_answer
    assert recovered.answer == generated.generated.answer
    assert recovered.projection_sha256 == projection_sha256(generated.generated)
    assert recovered.generation.context_sha256 == prepared.prompt.context_sha256
    assert recovered.context_sha256 != prepared.legacy.prompt.context_sha256
    assert recovered.status == ("no_candidate" if null else "needs_review")
    assert recovered.formal_verification == "not_run"
    for flag in (
        "application_supported",
        "automatic_activation",
        "semantic_truth_proven",
        "model_identity_authenticated",
    ):
        assert getattr(recovered, flag) is False
    with pytest.raises(GroundedPatchReceiptUnavailable):
        save(path, receipt, prepared, key)
    assert path.read_bytes() == ciphertext


@pytest.mark.parametrize("change", ["source", "baseline", "facts", "chunks", "prompt", "pin"])
def test_retained_input_change_or_wrong_pin_rejected(tmp_path, change):
    prepared, _, _, _, receipt = inputs()
    path, key = tmp_path / "PRIVATE-PATH.ncp", Fernet.generate_key()
    save(path, receipt, prepared, key)
    pin = None
    if change == "source":
        prepared = replace(prepared, legacy=replace(prepared.legacy, before="changed"))
    elif change == "baseline":
        prepared = replace(prepared, legacy=replace(prepared.legacy, baseline=None))
    elif change == "facts":
        prepared = replace(
            prepared,
            source_facts=prepared.source_facts.model_copy(update={"baseline_approval": "approved"}),
        )
    elif change == "chunks":
        chunk = prepared.legacy.chunks[0].model_copy(
            update={"content": "untrusted injected instruction"}
        )
        prepared = replace(prepared, legacy=replace(prepared.legacy, chunks=(chunk,)))
    elif change == "prompt":
        prepared = replace(prepared, prompt=replace(prepared.prompt, context_sha256="0" * 64))
    else:
        pin = "0" * 64
    with pytest.raises(GroundedPatchReceiptUnavailable) as caught:
        load(path, prepared, key, pin)
    assert str(caught.value) == "Grounded patch receipt is unavailable."


@pytest.mark.parametrize(
    "change",
    [
        "renderer",
        "projection",
        "candidate",
        "approval",
        "fact_binding",
        "model_answer",
        "version",
        "duplicate_json",
        "false_coercion",
    ],
)
def test_key_holder_rehashed_forgery_still_rejected_by_replay(tmp_path, change):
    prepared, _, _, _, receipt = inputs()
    path, key = tmp_path / "forged.ncp", Fernet.generate_key()
    value = receipt.model_dump(mode="json")
    if change == "renderer":
        value["renderer_policy_sha256"] = "0" * 64
    elif change == "projection":
        value["answer"]["summary"] = "The candidate is safe and approved."
        value["projection_sha256"] = text_sha256(
            json.dumps(value["answer"], ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        )
    elif change == "candidate":
        value["candidate_text"] += "reload\n"
    elif change == "approval":
        value["source_facts"]["baseline_approval"] = "approved"
    elif change == "fact_binding":
        value["facts_binding_sha256"] = "0" * 64
        value["model_answer"]["facts_binding_sha256"] = "0" * 64
    elif change == "model_answer":
        value["model_answer"]["recommendation_code"] = "apply"
        value["model_answer_sha256"] = text_sha256(
            json.dumps(value["model_answer"], sort_keys=True, separators=(",", ":"))
        )
    elif change == "version":
        value["version"] = "private-model-patch-receipt-0.1.0"
    elif change == "false_coercion":
        value["semantic_truth_proven"] = 0
    raw = json.dumps(value).encode()
    if change == "duplicate_json":
        raw = b'{"version":"fake",' + raw[1:]
    path.write_bytes(b"NCS-MODEL-PATCH-2\n" + Fernet(key).encrypt(raw))
    with pytest.raises(GroundedPatchReceiptUnavailable):
        load(path, prepared, key)


def test_old_and_new_loaders_do_not_downgrade_or_fallback(tmp_path):
    prepared, _, _, _, receipt = inputs()
    old, _, _, _, old_receipt = legacy_inputs()
    path, key = tmp_path / "new.ncp", Fernet.generate_key()
    save(path, receipt, prepared, key)
    with pytest.raises(ModelPatchReceiptUnavailable):
        load_patch_receipt(
            path, key=key, prepared=old, expected_inventory_sha256=inventory_sha256()
        )
    for magic in (b"NCS-MODEL-PATCH-1\n", b"NCS-MODEL-PATCH-3\n", b""):
        path.write_bytes(magic + Fernet(key).encrypt(old_receipt.model_dump_json().encode()))
        with pytest.raises(GroundedPatchReceiptUnavailable):
            load(path, prepared, key)


@pytest.mark.parametrize(
    "change", ["legacy_context", "incomplete", "late", "identity", "projection"]
)
def test_receipt_creation_requires_new_actual_observation_and_unmodified_generation(change):
    prepared, generated, identity, observation, _ = inputs()
    if change == "legacy_context":
        observation = replace(observation, context_sha256=prepared.legacy.prompt.context_sha256)
    elif change == "incomplete":
        observation = replace(observation, completed=False, rejection="deadline")
    elif change == "late":
        observation = replace(observation, seconds=20.01)
    elif change == "identity":
        identity = identity.model_copy(update={"parameter_count": 4000000000})
    else:
        generated = replace(
            generated, generated=replace(generated.generated, candidate_text="fake")
        )
    with pytest.raises(GroundedPatchReceiptUnavailable):
        create_grounded_patch_receipt(
            generated,
            prepared=prepared,
            identity=identity,
            observation=observation,
            expected_inventory_sha256=inventory_sha256(),
        )


def test_wrong_key_plaintext_budget_and_missing_parent_do_not_fallback(tmp_path, monkeypatch):
    prepared, _, _, _, receipt = inputs()
    path, key = tmp_path / "owned.ncp", Fernet.generate_key()
    save(path, receipt, prepared, key)
    with pytest.raises(GroundedPatchReceiptUnavailable):
        load(path, prepared, Fernet.generate_key())
    monkeypatch.setattr(grounded_receipts, "MAX_ENCRYPTED_BYTES", 3)
    with pytest.raises(GroundedPatchReceiptUnavailable):
        load(path, prepared, key)
    monkeypatch.setattr(grounded_receipts, "MAX_PLAIN_BYTES", 3)
    with pytest.raises(GroundedPatchReceiptUnavailable):
        save(tmp_path / "no.ncp", receipt, prepared, key)
    assert not (tmp_path / "no.ncp").exists()
    monkeypatch.undo()
    with pytest.raises(GroundedPatchReceiptUnavailable):
        save(tmp_path / "absent" / "no.ncp", receipt, prepared, key)
    path.write_bytes(receipt.model_dump_json().encode())
    with pytest.raises(GroundedPatchReceiptUnavailable):
        load(path, prepared, key)


@pytest.mark.parametrize("mode", ["create", "save"])
def test_unvalidated_private_model_answer_not_printed_before_receipt_revalidation(
    tmp_path, capsys, mode
):
    prepared, generated, identity, observation, receipt = inputs()
    malformed = generated.model_answer.model_copy(update={"patch_draft": "PRIVATE-ANSWER-MARKER"})
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        with pytest.raises(GroundedPatchReceiptUnavailable):
            if mode == "create":
                create_grounded_patch_receipt(
                    replace(generated, model_answer=malformed),
                    prepared=prepared,
                    identity=identity,
                    observation=observation,
                    expected_inventory_sha256=inventory_sha256(),
                )
            else:
                save(
                    tmp_path / "no.ncp",
                    receipt.model_copy(update={"model_answer": malformed}),
                    prepared,
                    Fernet.generate_key(),
                )
    assert not caught
    captured = capsys.readouterr()
    assert "PRIVATE-ANSWER-MARKER" not in captured.out + captured.err
    assert not (tmp_path / "no.ncp").exists()
