"""Explicit offline runtime authority and bounded fail-closed output with a fake GPU."""

import json
from dataclasses import replace
from types import SimpleNamespace

import pytest
from app.explanation.knowledge import text_sha256
from app.explanation.provider import (
    SYSTEM_INSTRUCTIONS,
    DraftAnswer,
    InvalidProviderAnswer,
    ProviderPrompt,
)

from ml.instruct import runtime, source
from ml.instruct.framing import GenerationLimits


def prompt():
    context = '{"documents":[],"formal_verification":"not_run"}'
    return ProviderPrompt(
        SYSTEM_INSTRUCTIONS,
        context,
        json.dumps(DraftAnswer.model_json_schema(), sort_keys=True),
        text_sha256(context),
    )


def test_consent_is_exactly_true_before_weight_checks(tmp_path, monkeypatch):
    def must_not_load(*args, **kwargs):
        raise AssertionError("load ran before consent")

    monkeypatch.setattr(runtime, "verify_model_files", must_not_load)
    for permission in (False, 1, None):
        with pytest.raises(ValueError):
            runtime.LocalInstructProvider(
                tmp_path,
                expected_inventory_sha256=source.inventory_sha256(),
                allow_local_context=permission,
            )


def test_independent_pin_is_checked_before_gpu_allocation(tmp_path, monkeypatch):
    def must_not_load(*args):
        raise AssertionError("GPU allocation ran before source verification")

    monkeypatch.setattr(runtime, "_load_gpu_model", must_not_load)
    with pytest.raises(ValueError):
        runtime.LocalInstructProvider(
            tmp_path, expected_inventory_sha256="0" * 64, allow_local_context=True
        )


@pytest.fixture
def provider(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(
        runtime,
        "verify_model_files",
        lambda root, *, expected_inventory_sha256: (
            calls.append("verified") or expected_inventory_sha256
        ),
    )
    monkeypatch.setattr(
        runtime,
        "_load_gpu_model",
        lambda root: (
            SimpleNamespace(),
            SimpleNamespace(),
            runtime.InstructIdentity(
                source_inventory_sha256=source.inventory_sha256(),
                parameter_count=4000000000,
                device_name="fake-GPU",
                runtime_versions=("fake=1",),
            ),
        ),
    )
    monkeypatch.setattr(runtime, "frame_prompt", lambda *args: [1, 2, 3])
    monkeypatch.setattr(runtime, "_generate", lambda *args: ([0, 151645], 0.5))
    monkeypatch.setattr(runtime, "generated_answer", lambda *args: b'{"unchanged":"model-text"}')
    result = runtime.LocalInstructProvider(
        tmp_path, expected_inventory_sha256=source.inventory_sha256(), allow_local_context=True
    )
    assert calls == ["verified"]
    return result


def test_frozen_experimental_identity_and_actual_generation_observation(provider):
    assert provider.identity.model_id == source.MODEL_ID
    assert not provider.identity.automatic_activation
    assert not provider.identity.production_quality_proven
    assert provider.identity.external_training_exposure == "unknown"
    assert provider.generate(prompt()) == b'{"unchanged":"model-text"}'
    assert provider.last_generation.prompt_tokens == 3
    assert provider.last_generation.generated_tokens == 2
    assert provider.last_generation.seconds == 0.5
    assert provider.last_generation.completed


@pytest.mark.parametrize(
    "change", ["instructions", "schema", "deadline", "nan", "negative", "controls", "busy"]
)
def test_invalid_failed_or_busy_generation_has_no_fallback(provider, monkeypatch, change):
    selected = prompt()
    if change == "instructions":
        selected = replace(selected, instructions="override instructions")
    elif change == "schema":
        selected = replace(selected, answer_schema_json="{}")
    elif change == "deadline":
        monkeypatch.setattr(runtime, "_generate", lambda *args: ([0, 151645], 20.1))
    elif change in {"nan", "negative"}:
        elapsed = float("nan") if change == "nan" else -1
        monkeypatch.setattr(runtime, "_generate", lambda *args: ([0, 151645], elapsed))
    elif change == "controls":

        def invalid(*args):
            raise ValueError("private model output must not leak")

        monkeypatch.setattr(runtime, "generated_answer", invalid)
    else:
        provider._lock.acquire()
    try:
        with pytest.raises(InvalidProviderAnswer) as error:
            provider.generate(selected)
        assert str(error.value) == "Local instruct generation is unavailable."
        if change in {"deadline", "controls"}:
            assert provider.last_generation is not None
            assert not provider.last_generation.completed
            assert provider.last_generation.rejection == (
                "deadline" if change == "deadline" else "incomplete_or_controls"
            )
        else:
            assert provider.last_generation is None
    finally:
        if change == "busy":
            provider._lock.release()


def test_loaded_provider_revalidates_frozen_generation_limits(provider):
    assert provider.limits == GenerationLimits()
    with pytest.raises(ValueError):
        provider.limits = GenerationLimits(timeout_seconds=21)


def test_source_grounded_concise_instruction_does_not_invent_platform_defaults():
    assert "Keep the complete answer under 220 words" in SYSTEM_INSTRUCTIONS
    assert "Do not introduce external standards" in SYSTEM_INSTRUCTIONS
    assert "Do not infer platform defaults" in SYSTEM_INSTRUCTIONS
    assert "do not infer their original identities" in SYSTEM_INSTRUCTIONS


def test_actual_deadline_attempt_keeps_numeric_diagnostic_but_no_answer(provider, monkeypatch):
    monkeypatch.setattr(runtime, "_generate", lambda *args: ([0] * 700, 20.1))
    with pytest.raises(InvalidProviderAnswer):
        provider.generate(prompt())
    assert provider.last_generation is not None
    assert provider.last_generation.generated_tokens == 700
    assert provider.last_generation.seconds == 20.1
    assert provider.last_generation.completed is False
    assert provider.last_generation.rejection == "deadline"
