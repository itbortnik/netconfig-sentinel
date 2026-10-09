"""Explicit operator opt-ins never accept truthy strings/numbers or HTTP paths."""

from pathlib import Path

import pytest
from app.core.patch_verification import PatchVerificationSettings


@pytest.mark.parametrize("value", [0, 1, "true", None])
def test_engine_operator_flag_requires_exact_boolean(value):
    with pytest.raises(ValueError):
        PatchVerificationSettings(allow_engine_upload=value)


@pytest.mark.parametrize(
    "updates",
    [
        {"registry_root": Path("relative")},
        {"transformer_sha256": "f" * 64},
        {"foundation_source": Path("relative")},
        {"engine_timeout_seconds": True},
        {"ml_timeout_seconds": 301},
        {"engine_timeout_seconds": 0},
    ],
)
def test_partial_unsafe_model_or_timeout_settings_are_refused(updates):
    with pytest.raises(ValueError):
        PatchVerificationSettings(**updates)


@pytest.mark.parametrize("value, enabled", [("", False), ("0", False), ("1", True)])
def test_environment_opt_in_is_explicit(monkeypatch, value, enabled):
    for name in (
        "NETCONFIG_PATCH_MODEL_REGISTRY",
        "NETCONFIG_PATCH_MODEL_SHA256",
        "NETCONFIG_PATCH_FOUNDATION_SOURCE",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("NETCONFIG_PATCH_ALLOW_ENGINE_UPLOAD", value)
    settings = PatchVerificationSettings.from_environment()
    assert (settings is not None and settings.allow_engine_upload) == enabled


def test_environment_invalid_flag_and_partial_registry_refused(monkeypatch):
    monkeypatch.setenv("NETCONFIG_PATCH_ALLOW_ENGINE_UPLOAD", "yes")
    with pytest.raises(ValueError):
        PatchVerificationSettings.from_environment()
    monkeypatch.setenv("NETCONFIG_PATCH_ALLOW_ENGINE_UPLOAD", "0")
    monkeypatch.setenv("NETCONFIG_PATCH_MODEL_REGISTRY", str(Path.cwd()))
    monkeypatch.delenv("NETCONFIG_PATCH_MODEL_SHA256", raising=False)
    with pytest.raises(ValueError):
        PatchVerificationSettings.from_environment()
