"""Private receipts authenticate bytes, not model truth, source consent or approval."""

import json
from dataclasses import replace
from uuid import UUID

import pytest
from app.detection.policy_engine import evaluate_policies
from app.explanation import patch_receipts
from app.explanation.knowledge import text_sha256
from app.explanation.patch_provider import build_patch_prompt, generate_patch_draft
from app.explanation.patch_receipts import (
    ModelPatchReceiptUnavailable,
    create_patch_receipt,
    load_patch_receipt,
    save_patch_receipt,
)
from app.parsers import parse_configuration
from cryptography.fernet import Fernet

from ml.instruct.runtime import GenerationObservation, InstructIdentity
from ml.instruct.source import inventory_sha256


def inputs(null=False):
    before = (
        "hostname PRIVATE-HOST\nusername PRIVATE-USER secret 9 PRIVATE-HASH\nip ssh version 1\n"
    )
    parsed = parse_configuration(before, filename="private.cfg")
    finding = next(
        row
        for row in evaluate_policies(parsed, device_id=UUID(int=1))
        if row.category == "management.ssh_version_1"
    )
    prepared = build_patch_prompt(
        before,
        finding=finding,
        source_sha256=text_sha256(before),
        reference_id="PRIVATE-REFERENCE",
        allow_local_context=True,
    )
    answer = {
        "summary": "Explicit unit fake, not actual inference.",
        "technical_explanation": "Review source.",
        "possible_impact": [],
        "recommendation": "Review syntax, access and rollback.",
        "patch_draft": None
        if null
        else {"edits": [{"source_line": 3, "replacement": "ip ssh version 2"}]},
        "assumptions": [],
        "missing_information": ["Actual formal and human approval."],
        "citations": [prepared.chunks[0].citation],
        "requires_human_review": True,
    }

    class Fake:
        def generate(self, prompt):
            return json.dumps(answer).encode()

    generated = generate_patch_draft(Fake(), prepared, allow_local_context=True)
    identity = InstructIdentity(
        source_inventory_sha256=inventory_sha256(),
        parameter_count=4022468096,
        device_name="fake-unit-device",
        runtime_versions=("test=fake",),
    )
    observation = GenerationObservation(1800, 250, 1.0, prepared.prompt.context_sha256)
    receipt = create_patch_receipt(
        generated,
        prepared=prepared,
        identity=identity,
        observation=observation,
        expected_inventory_sha256=inventory_sha256(),
    )
    return prepared, generated, identity, observation, receipt


@pytest.mark.parametrize("null", [False, True])
def test_encrypted_round_trip_replays_exact_source_and_preserves_null_refusal(tmp_path, null):
    prepared, generated, _, _, receipt = inputs(null)
    key = Fernet.generate_key()
    path = tmp_path / "owned.ncp"
    save_patch_receipt(
        receipt, path, key=key, prepared=prepared, expected_inventory_sha256=inventory_sha256()
    )
    ciphertext = path.read_bytes()
    for private in (b"PRIVATE-HOST", b"PRIVATE-USER", b"PRIVATE-HASH", b"PRIVATE-REFERENCE", key):
        assert private not in ciphertext
        assert private.decode() not in repr(receipt)
    loaded = load_patch_receipt(
        path, key=key, prepared=prepared, expected_inventory_sha256=inventory_sha256()
    )
    assert loaded == receipt
    assert loaded.candidate_text == generated.candidate_text
    assert loaded.status == ("no_candidate" if null else "needs_review")
    assert loaded.formal_verification == "not_run"
    assert loaded.application_supported is False
    assert loaded.automatic_activation is False
    assert loaded.semantic_truth_proven is False


def test_existing_artifact_is_not_overwritten(tmp_path):
    prepared, _, _, _, receipt = inputs()
    key = Fernet.generate_key()
    path = tmp_path / "owned.ncp"
    save_patch_receipt(
        receipt, path, key=key, prepared=prepared, expected_inventory_sha256=inventory_sha256()
    )
    original = path.read_bytes()
    with pytest.raises(ModelPatchReceiptUnavailable):
        save_patch_receipt(
            receipt, path, key=key, prepared=prepared, expected_inventory_sha256=inventory_sha256()
        )
    assert path.read_bytes() == original


@pytest.mark.parametrize(
    "mode", ["wrong_key", "corrupt", "plaintext", "source", "context", "model_pin"]
)
def test_untrusted_or_stale_input_fails_with_no_private_diagnostic(tmp_path, mode):
    prepared, _, _, _, receipt = inputs()
    key = Fernet.generate_key()
    path = tmp_path / "PRIVATE-PATH.ncp"
    save_patch_receipt(
        receipt, path, key=key, prepared=prepared, expected_inventory_sha256=inventory_sha256()
    )
    pin = inventory_sha256()
    if mode == "wrong_key":
        key = Fernet.generate_key()
    elif mode == "corrupt":
        path.write_bytes(path.read_bytes()[:-3] + b"bad")
    elif mode == "plaintext":
        path.write_bytes(receipt.model_dump_json().encode())
    elif mode == "source":
        prepared = replace(prepared, before=prepared.before + "!\n")
    elif mode == "context":
        prepared = replace(prepared, prompt=replace(prepared.prompt, context_sha256="0" * 64))
    else:
        pin = "f" * 64
    with pytest.raises(ModelPatchReceiptUnavailable) as error:
        load_patch_receipt(path, key=key, prepared=prepared, expected_inventory_sha256=pin)
    assert str(error.value) == "Model patch receipt is unavailable."


@pytest.mark.parametrize(
    "change", ["context", "incomplete", "nan", "negative", "late", "tokens", "identity"]
)
def test_generation_proof_and_identity_are_not_assumed(tmp_path, change):
    prepared, generated, identity, observation, _ = inputs()
    if change == "context":
        observation = replace(observation, context_sha256="f" * 64)
    elif change == "incomplete":
        observation = replace(observation, completed=False, rejection="deadline")
    elif change in {"nan", "negative", "late"}:
        observation = replace(
            observation, seconds={"nan": float("nan"), "negative": -1, "late": 20.1}[change]
        )
    elif change == "tokens":
        observation = replace(observation, generated_tokens=2049)
    else:
        identity = identity.model_copy(update={"source_inventory_sha256": "f" * 64})
    with pytest.raises(ModelPatchReceiptUnavailable):
        create_patch_receipt(
            generated,
            prepared=prepared,
            identity=identity,
            observation=observation,
            expected_inventory_sha256=inventory_sha256(),
        )


def test_changed_candidate_and_metadata_cannot_be_saved_as_original_generation(tmp_path):
    prepared, generated, identity, observation, receipt = inputs()
    changed = replace(generated, candidate_text=generated.candidate_text + "ip ssh version 1\n")
    with pytest.raises(ModelPatchReceiptUnavailable):
        create_patch_receipt(
            changed,
            prepared=prepared,
            identity=identity,
            observation=observation,
            expected_inventory_sha256=inventory_sha256(),
        )
    changed_receipt = receipt.model_copy(
        update={"candidate_text": receipt.candidate_text + "reload\n"}
    )
    with pytest.raises(ModelPatchReceiptUnavailable):
        save_patch_receipt(
            changed_receipt,
            tmp_path / "owned.ncp",
            key=Fernet.generate_key(),
            prepared=prepared,
            expected_inventory_sha256=inventory_sha256(),
        )
    assert not (tmp_path / "owned.ncp").exists()


def test_missing_parent_and_invalid_key_do_not_create_artifacts(tmp_path):
    prepared, _, _, _, receipt = inputs()
    for path, key in (
        (tmp_path / "absent" / "owned.ncp", Fernet.generate_key()),
        (tmp_path / "owned.ncp", b"invalid-private-key"),
    ):
        with pytest.raises(ModelPatchReceiptUnavailable):
            save_patch_receipt(
                receipt,
                path,
                key=key,
                prepared=prepared,
                expected_inventory_sha256=inventory_sha256(),
            )
        assert not path.exists()


@pytest.mark.parametrize("change", ["claim", "candidate", "duplicate", "budget", "linked"])
def test_authenticated_but_invalid_payload_still_rejected(tmp_path, monkeypatch, change):
    prepared, _, _, _, receipt = inputs()
    key = Fernet.generate_key()
    path = tmp_path / "owned.ncp"
    save_patch_receipt(
        receipt, path, key=key, prepared=prepared, expected_inventory_sha256=inventory_sha256()
    )
    if change in {"claim", "candidate", "duplicate"}:
        data = receipt.model_dump(mode="json")
        if change == "claim":
            data["formal_verification"] = "passed"
        elif change == "candidate":
            data["answer"]["patch_draft"]["edits"][0]["replacement"] = "reload"
        raw = json.dumps(data).encode()
        if change == "duplicate":
            raw = raw.replace(b'{"version":', b'{"version":"injected","version":', 1)
        path.write_bytes(patch_receipts._MAGIC + Fernet(key).encrypt(raw))
    elif change == "budget":
        monkeypatch.setattr(patch_receipts, "MAX_ENCRYPTED_BYTES", 1)
    else:

        def refuse_path(path):
            raise ValueError("linked-private-path")

        monkeypatch.setattr(patch_receipts, "safe_path", refuse_path)
    with pytest.raises(ModelPatchReceiptUnavailable) as error:
        load_patch_receipt(
            path, key=key, prepared=prepared, expected_inventory_sha256=inventory_sha256()
        )
    assert str(error.value) == "Model patch receipt is unavailable."
