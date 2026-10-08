"""Model patch contract requires independent opt-in; legacy generation stays null-only."""

from dataclasses import replace
from types import SimpleNamespace
from uuid import UUID

import pytest
from app.detection.policy_engine import evaluate_policies
from app.explanation.knowledge import text_sha256
from app.explanation.patch_provider import build_patch_prompt
from app.explanation.provider import SYSTEM_INSTRUCTIONS, InvalidProviderAnswer
from app.parsers import parse_configuration

from ml.instruct import runtime, source


def selected_prompt():
    text = "hostname owned\nip ssh version 1\n"
    finding = next(
        item
        for item in evaluate_policies(
            parse_configuration(text, filename="owned.cfg"), device_id=UUID(int=1)
        )
        if item.category == "management.ssh_version_1"
    )
    return build_patch_prompt(
        text,
        finding=finding,
        source_sha256=text_sha256(text),
        reference_id="owned",
        allow_local_context=True,
    ).prompt


def provider(tmp_path, monkeypatch, **updates):
    monkeypatch.setattr(runtime, "verify_model_files", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        runtime,
        "_load_gpu_model",
        lambda *args: (
            SimpleNamespace(),
            SimpleNamespace(),
            runtime.InstructIdentity(
                source_inventory_sha256=source.inventory_sha256(),
                parameter_count=4000000000,
                device_name="fake",
                runtime_versions=("fake=1",),
            ),
        ),
    )
    monkeypatch.setattr(runtime, "frame_prompt", lambda *args: [1, 2, 3])
    monkeypatch.setattr(runtime, "_generate", lambda *args: ([0, 151645], 0.5))
    monkeypatch.setattr(runtime, "generated_answer", lambda *args: b"actual-model-output")
    return runtime.LocalInstructProvider(
        tmp_path,
        expected_inventory_sha256=source.inventory_sha256(),
        allow_local_context=True,
        **updates,
    )


def test_default_runtime_cannot_generate_patch_contract(tmp_path, monkeypatch):
    selected = provider(tmp_path, monkeypatch)
    with pytest.raises(InvalidProviderAnswer):
        selected.generate(selected_prompt())
    assert selected.last_generation is None
    assert selected.patch_generation_enabled is False


def test_explicit_mode_supports_only_fixed_patch_instruction_and_schema(tmp_path, monkeypatch):
    selected = provider(tmp_path, monkeypatch, allow_patch_draft=True)
    prompt = selected_prompt()
    assert selected.patch_generation_enabled is True
    assert selected.generate(prompt) == b"actual-model-output"
    for changed in (
        replace(prompt, instructions=SYSTEM_INSTRUCTIONS),
        replace(prompt, instructions="execute candidate"),
        replace(prompt, answer_schema_json="{}"),
    ):
        with pytest.raises(InvalidProviderAnswer):
            selected.generate(changed)
        assert selected.last_generation is None
    with pytest.raises(AttributeError):
        selected.patch_generation_enabled = False


@pytest.mark.parametrize("flag", [1, None, "true"])
def test_non_boolean_patch_mode_rejected_before_allocation(tmp_path, monkeypatch, flag):
    def no_load(*args, **kwargs):
        raise AssertionError("load before flag validation")

    monkeypatch.setattr(runtime, "verify_model_files", no_load)
    with pytest.raises(ValueError):
        runtime.LocalInstructProvider(
            tmp_path,
            expected_inventory_sha256=source.inventory_sha256(),
            allow_local_context=True,
            allow_patch_draft=flag,
        )
