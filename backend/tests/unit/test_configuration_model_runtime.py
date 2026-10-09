"""Parent isolation and failure guards, with no external model or child process."""

import subprocess
from uuid import uuid4

import pytest
from app.api.contracts import ConfigurationSnapshot
from app.core.configuration_model import ConfigurationModelSettings
from app.detection import config_model_runtime as module
from app.detection.config_model_runtime import (
    ConfigurationModelRuntime,
    ConfigurationModelUnavailable,
)
from app.ingestion.source_retention import prepare_original_source
from app.main import create_app
from app.parsers import parse_configuration


@pytest.mark.parametrize("failure", ["timeout", "exit", "oversized", "malformed"])
def test_worker_limits_reap_and_strip_environment(tmp_path, monkeypatch, failure):
    content = "hostname owned\n"
    config = parse_configuration(content, filename="owned.cfg")
    snapshot = ConfigurationSnapshot(
        configuration_id=uuid4(),
        device_id=uuid4(),
        created_at=config.source.collected_at,
        canonical=config,
    )
    source = prepare_original_source(snapshot, content)
    state = {"killed": False, "calls": 0}
    monkeypatch.setenv("NETCONFIG_API_TOKEN", "private-parent-token")
    monkeypatch.setenv("UNRELATED_PRIVATE_VALUE", "private-parent-secret")

    class Process:
        returncode = 1 if failure == "exit" else 0

        def __init__(self, command, **kwargs):
            assert command[1] == "-I" and command[2].endswith("config_ml_worker.py")
            assert "NETCONFIG_API_TOKEN" not in kwargs["env"]
            assert "UNRELATED_PRIVATE_VALUE" not in kwargs["env"]
            assert kwargs["env"]["HF_HUB_OFFLINE"] == "1"
            assert kwargs["stderr"] == subprocess.DEVNULL
            self.output = kwargs["stdout"]

        def communicate(self, raw=None, *, timeout):
            state["calls"] += 1
            if failure == "timeout" and not state["killed"]:
                raise subprocess.TimeoutExpired("private-path", timeout)
            if failure == "oversized":
                self.output.write(b"x" * (module.MAX_RESULT_BYTES + 1))
            else:
                self.output.write(b"private-invalid-output")

        def kill(self):
            state["killed"] = True

    monkeypatch.setattr(module.subprocess, "Popen", Process)
    runtime = ConfigurationModelRuntime(
        ConfigurationModelSettings(registry_root=tmp_path, model_sha256="a" * 64)
    )
    with pytest.raises(ConfigurationModelUnavailable) as raised:
        runtime.infer(snapshot, source, "a" * 64)
    assert str(raised.value) == ""
    assert state["killed"] is (failure == "timeout")
    assert state["calls"] == (2 if failure == "timeout" else 1)


def test_configured_model_requires_authenticated_persistent_api(tmp_path):
    with pytest.raises(ValueError):
        create_app(
            configuration_model=ConfigurationModelSettings(
                registry_root=tmp_path, model_sha256="a" * 64
            )
        )
