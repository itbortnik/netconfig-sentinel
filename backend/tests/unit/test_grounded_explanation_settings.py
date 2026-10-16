"""New explanation mode remains explicit and shares the existing nonblocking slot."""

import os
from itertools import permutations

import pytest
from app.core.local_model import LocalModelSettings
from app.explanation.local_model import (
    GroundedExplanationDisabled,
    LocalModelRuntime,
    ModelBusy,
    ModelPatchDisabled,
)


def settings(**updates):
    return LocalModelSettings(
        "http://127.0.0.1:9000/v1/chat/completions",
        "owned-settings-fixture",
        allow_local_context=True,
        **updates,
    )


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch):
    for name in tuple(os.environ):
        if name.startswith("NETCONFIG_LLM_"):
            monkeypatch.delenv(name, raising=False)


@pytest.mark.parametrize("value", [None, 0, 1, "true", [], {}])
def test_grounded_explanation_flag_is_exact_boolean(value):
    with pytest.raises(ValueError):
        settings(allow_grounded_explanation=value)


@pytest.mark.parametrize("patch", [False, True])
@pytest.mark.parametrize("grounded_patch", [False, True])
@pytest.mark.parametrize("grounded_explanation", [False, True])
def test_three_optional_modes_do_not_authorize_each_other(
    patch, grounded_patch, grounded_explanation
):
    runtime = LocalModelRuntime(
        settings(
            allow_patch_draft=patch,
            allow_grounded_patch_draft=grounded_patch,
            allow_grounded_explanation=grounded_explanation,
        )
    )
    for manager, allowed, error in (
        (runtime.patch_provider, patch, ModelPatchDisabled),
        (runtime.grounded_patch_provider, grounded_patch, ModelPatchDisabled),
        (runtime.grounded_explanation_provider, grounded_explanation, GroundedExplanationDisabled),
    ):
        if allowed:
            with manager() as selected:
                assert selected is runtime.provider
        else:
            with pytest.raises(error), manager():
                pytest.fail("disabled mode yielded a provider")


def test_all_modes_share_the_same_nonblocking_slot_and_release_after_error():
    runtime = LocalModelRuntime(
        settings(
            allow_patch_draft=True,
            allow_grounded_patch_draft=True,
            allow_grounded_explanation=True,
        )
    )
    for first, second in permutations(
        (
            runtime.patch_provider,
            runtime.grounded_patch_provider,
            runtime.grounded_explanation_provider,
        ),
        2,
    ):
        with first(), pytest.raises(ModelBusy), second():
            pytest.fail("simultaneous mode yielded")
        with second() as selected:
            assert selected is runtime.provider
    with pytest.raises(RuntimeError), runtime.grounded_explanation_provider():
        raise RuntimeError("owned failure")
    with runtime.patch_provider():
        pass


def test_disabled_flags_alone_do_not_create_an_incomplete_endpoint_configuration(monkeypatch):
    for flag in (
        "NETCONFIG_LLM_ALLOW_PATCH_DRAFT",
        "NETCONFIG_LLM_ALLOW_GROUNDED_PATCH_DRAFT",
        "NETCONFIG_LLM_ALLOW_GROUNDED_EXPLANATION",
    ):
        monkeypatch.setenv(flag, "0")
    assert LocalModelSettings.from_environment() is None


@pytest.mark.parametrize("flag", ["1", "true", "false", "01", "2"])
def test_non_disabled_flag_without_required_configuration_fails_closed(monkeypatch, flag):
    monkeypatch.setenv("NETCONFIG_LLM_ALLOW_GROUNDED_EXPLANATION", flag)
    with pytest.raises(ValueError):
        LocalModelSettings.from_environment()


def test_grounded_explanation_environment_is_independent_of_patch_modes(monkeypatch):
    monkeypatch.setenv("NETCONFIG_LLM_ENDPOINT", "http://127.0.0.1:9000/v1/chat/completions")
    monkeypatch.setenv("NETCONFIG_LLM_MODEL", "owned-settings-fixture")
    monkeypatch.setenv("NETCONFIG_LLM_ALLOW_LOCAL_CONTEXT", "1")
    monkeypatch.setenv("NETCONFIG_LLM_ALLOW_GROUNDED_EXPLANATION", "1")
    value = LocalModelSettings.from_environment()
    assert value.allow_grounded_explanation is True
    assert value.allow_patch_draft is value.allow_grounded_patch_draft is False
