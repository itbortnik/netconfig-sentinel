"""Prompt guidance changes preserve old bytes and never confer source authenticity."""

import json
from dataclasses import replace

import pytest
from app.explanation.grounded_patch import (
    GROUND_PATCH_INSTRUCTIONS,
    SCOPED_GROUND_PATCH_INSTRUCTIONS,
    GroundedPatchAnswer,
    generate_grounded_patch_draft,
    grounded_patch_policy_for_instructions,
    recheck_scoped_grounded_patch_prompt,
    validate_grounded_patch_answer,
)
from app.explanation.grounded_receipts import (
    GroundedPatchReceiptUnavailable,
    create_grounded_patch_receipt,
)
from app.explanation.knowledge import text_sha256
from app.explanation.provider import InvalidProviderAnswer
from test_grounded_patch import Fake, prepared_answer
from test_grounded_receipts import inputs, load, save
from test_instruct_patch_mode import provider

OLD = "grounded-patch-prompt-0.1.0"
NEW = "grounded-patch-prompt-0.2.0"


@pytest.mark.parametrize(
    "index,pin",
    enumerate(
        (
            "e0dc1c83e5d3eba51bb75b2c8279517680a9baba5febf20286e3a4106ece59af",
            "a14622e27807a9a3db7cbb0dbeded1f67e9a98e2e05a7e713b9c3f94567ccc79",
            "6ae680e299d947ff91f054839a0de0128788bb25a613ab6f5f40205c91ef14ac",
            "c3e314bb84fefa433452616d54ae4a736d7c083e33a50dbc7fb59996531bec2c",
        )
    ),
)
def test_library_default_preserves_historical_prompt_bytes(index, pin):
    prepared, _ = prepared_answer(index)
    assert prepared.prompt_policy == OLD
    assert prepared.prompt.context_sha256 == pin
    assert prepared.prompt.instructions == GROUND_PATCH_INSTRUCTIONS
    assert prepared.prompt.answer_schema_json == json.dumps(
        GroundedPatchAnswer.model_json_schema(), sort_keys=True
    )
    assert grounded_patch_policy_for_instructions(text_sha256(prepared.prompt.instructions)) == OLD


@pytest.mark.parametrize("index", range(4))
@pytest.mark.parametrize("baseline", [False, True])
@pytest.mark.parametrize("null", [False, True])
def test_new_policy_keeps_answer_projection_source_replay_and_null(index, baseline, null):
    old, old_wire = prepared_answer(index, baseline=baseline, null=null)
    prepared, wire = prepared_answer(index, baseline=baseline, null=null, prompt_policy=NEW)
    assert old.source_facts == prepared.source_facts
    assert old_wire == wire
    assert prepared.prompt.instructions == SCOPED_GROUND_PATCH_INSTRUCTIONS
    assert grounded_patch_policy_for_instructions(text_sha256(prepared.prompt.instructions)) == NEW
    recheck_scoped_grounded_patch_prompt(prepared.prompt)
    context = json.loads(prepared.prompt.context_json)
    schema = json.loads(prepared.prompt.answer_schema_json)
    assert context["required_answer_fields"] == schema["required"]
    assert schema["$defs"]["ModelLineEdit"]["properties"]["source_line"]["enum"] == [
        item["source_line"] for item in context["supplied_patch_context"]["affected_block"]
    ]
    assert schema["properties"]["citations"]["items"]["enum"] == [
        item["citation"] for item in context["supplied_patch_context"]["documents"]
    ]
    # The answer still has the same nine keys and source-enforced edit semantics.
    fake = Fake(wire)
    result = generate_grounded_patch_draft(fake, prepared, allow_local_context=True)
    previous = validate_grounded_patch_answer(json.dumps(old_wire).encode(), old)
    assert result == previous
    assert fake.calls == 1
    assert (result.generated.candidate_text is None) is null


@pytest.mark.parametrize("pin", ["0" * 64, "", "grounded-patch-prompt-0.2.0"])
def test_unrecognized_instruction_pin_has_no_latest_default(pin):
    with pytest.raises(ValueError, match="unknown grounded patch prompt policy"):
        grounded_patch_policy_for_instructions(pin)


@pytest.mark.parametrize("policy", [OLD, NEW])
def test_policy_only_mutation_cannot_bypass_full_source_replay(policy):
    prepared, wire = prepared_answer(prompt_policy=policy)
    changed = replace(prepared, prompt_policy=NEW if policy == OLD else OLD)
    fake = Fake(wire)
    with pytest.raises(ValueError):
        generate_grounded_patch_draft(fake, changed, allow_local_context=True)
    assert fake.calls == 0


@pytest.mark.parametrize("enabled", [False, True])
def test_native_scoped_patch_requires_independent_opt_in(tmp_path, monkeypatch, enabled):
    selected = provider(
        tmp_path,
        monkeypatch,
        allow_patch_draft=True,
        allow_candidate_review=True,
        allow_grounded_explanation=True,
        allow_grounded_patch_draft=enabled,
    )
    prompt = prepared_answer(prompt_policy=NEW)[0].prompt
    if enabled:
        assert selected.generate(prompt) == b"actual-model-output"
    else:
        with pytest.raises(InvalidProviderAnswer):
            selected.generate(prompt)
        assert selected.last_generation is None


@pytest.mark.parametrize(
    "change",
    ["scalar", "duplicate", "extra", "component", "facts", "schema", "anchor", "pin", "old"],
)
def test_native_rebuild_refuses_mutated_scoped_context_before_generation(
    tmp_path, monkeypatch, change
):
    prepared, _ = prepared_answer(prompt_policy=NEW)
    prompt = prepared.prompt
    data = json.loads(prompt.context_json)
    schema = json.loads(prompt.answer_schema_json)
    if change == "scalar":
        data = None
    elif change == "extra":
        data["permission_to_apply"] = True
    elif change == "component":
        data["supplied_patch_context"]["formal_verification"]["status"] = "passed"
    elif change == "facts":
        data["source_facts"]["observed_ssh_version"] = "2"
    elif change == "schema":
        schema["properties"]["citations"]["items"].pop("enum")
    elif change == "anchor":
        schema["$defs"]["ModelLineEdit"]["properties"]["source_line"]["enum"] = [9999]
    elif change == "old":
        prompt = replace(prompt, instructions=GROUND_PATCH_INSTRUCTIONS)
    raw = json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    if change == "duplicate":
        raw = '{"version":"PRIVATE-MARKER",' + raw[1:]
    prompt = replace(
        prompt,
        context_json=raw,
        context_sha256="0" * 64 if change == "pin" else text_sha256(raw),
        answer_schema_json=json.dumps(schema, sort_keys=True),
    )
    selected = provider(tmp_path, monkeypatch, allow_grounded_patch_draft=True)
    with pytest.raises(InvalidProviderAnswer) as caught:
        selected.generate(prompt)
    assert "PRIVATE-MARKER" not in str(caught.value)
    assert selected.last_generation is None


@pytest.mark.parametrize("policy", [OLD, NEW])
@pytest.mark.parametrize("null", [False, True])
def test_receipt_replays_exact_supplied_policy_and_refuses_other_policy(tmp_path, policy, null):
    from cryptography.fernet import Fernet

    _, _, identity, _, _ = inputs(null)
    prepared, wire = prepared_answer(null=null, prompt_policy=policy)
    generated = validate_grounded_patch_answer(json.dumps(wire).encode(), prepared)
    from ml.instruct.runtime import GenerationObservation
    from ml.instruct.source import inventory_sha256

    receipt = create_grounded_patch_receipt(
        generated,
        prepared=prepared,
        identity=identity,
        observation=GenerationObservation(2000, 200, 1.0, prepared.prompt.context_sha256),
        expected_inventory_sha256=inventory_sha256(),
    )
    path, key = tmp_path / "private.ncp", Fernet.generate_key()
    save(path, receipt, prepared, key)
    assert load(path, prepared, key) == receipt
    other = prepared_answer(null=null, prompt_policy=NEW if policy == OLD else OLD)[0]
    with pytest.raises(GroundedPatchReceiptUnavailable):
        load(path, other, key)
