"""Independent local operator opt-in and a shared worker slot, with zero model calls."""

import os

import pytest
from app.core.local_model import LocalModelSettings
from app.explanation.local_model import LocalModelRuntime, ModelBusy, ModelPatchDisabled


def settings(**updates):
    return LocalModelSettings(
        "http://127.0.0.1:9000/v1/chat/completions",
        "explicit-unit-fake",
        allow_local_context=True,
        **updates,
    )


@pytest.mark.parametrize("value", [None, 0, 1, "true"])
def test_new_operator_flag_requires_exact_boolean(value):
    with pytest.raises(ValueError):
        settings(allow_grounded_patch_draft=value)


@pytest.mark.parametrize("old", [False, True])
@pytest.mark.parametrize("new", [False, True])
def test_runtime_policy_permissions_independent_without_network_or_model(old, new):
    runtime = LocalModelRuntime(settings(allow_patch_draft=old, allow_grounded_patch_draft=new))
    for manager, allowed in ((runtime.patch_provider, old), (runtime.grounded_patch_provider, new)):
        if allowed:
            with manager() as selected:
                assert selected is runtime.provider
        else:
            with pytest.raises(ModelPatchDisabled), manager():
                pytest.fail("disabled provider yielded")


def test_same_nonblocking_slot_is_used_in_both_directions():
    runtime = LocalModelRuntime(settings(allow_patch_draft=True, allow_grounded_patch_draft=True))
    for first, second in (
        (runtime.patch_provider, runtime.grounded_patch_provider),
        (runtime.grounded_patch_provider, runtime.patch_provider),
    ):
        with first(), pytest.raises(ModelBusy), second():
            pytest.fail("simultaneous provider yielded")
        with second() as selected:
            assert selected is runtime.provider


@pytest.mark.parametrize("permission", ["true", "2", "01", "false"])
def test_invalid_environment_flag_is_not_treated_as_enabled(monkeypatch, permission):
    monkeypatch.setenv("NETCONFIG_LLM_ENDPOINT", "http://127.0.0.1:9000/v1/chat/completions")
    monkeypatch.setenv("NETCONFIG_LLM_MODEL", "explicit-unit-fake")
    monkeypatch.setenv("NETCONFIG_LLM_ALLOW_LOCAL_CONTEXT", "1")
    monkeypatch.setenv("NETCONFIG_LLM_ALLOW_GROUNDED_PATCH_DRAFT", permission)
    with pytest.raises(ValueError):
        LocalModelSettings.from_environment()


def test_grounded_environment_is_detected_and_old_flag_does_not_enable_it(monkeypatch):
    for name in tuple(os.environ):
        if name.startswith("NETCONFIG_LLM_"):
            monkeypatch.delenv(name, raising=False)
    assert LocalModelSettings.from_environment() is None
    monkeypatch.setenv("NETCONFIG_LLM_ALLOW_GROUNDED_PATCH_DRAFT", "1")
    with pytest.raises(ValueError):
        LocalModelSettings.from_environment()
    monkeypatch.setenv("NETCONFIG_LLM_ENDPOINT", "http://127.0.0.1:9000/v1/chat/completions")
    monkeypatch.setenv("NETCONFIG_LLM_MODEL", "explicit-unit-fake")
    monkeypatch.setenv("NETCONFIG_LLM_ALLOW_LOCAL_CONTEXT", "1")
    selected = LocalModelSettings.from_environment()
    assert selected.allow_grounded_patch_draft is True and selected.allow_patch_draft is False
    monkeypatch.setenv("NETCONFIG_LLM_ALLOW_GROUNDED_PATCH_DRAFT", "0")
    monkeypatch.setenv("NETCONFIG_LLM_ALLOW_PATCH_DRAFT", "1")
    selected = LocalModelSettings.from_environment()
    assert selected.allow_grounded_patch_draft is False and selected.allow_patch_draft is True
