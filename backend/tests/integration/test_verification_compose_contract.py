"""Standalone verifier configuration needs no application credentials or daemon."""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
IMAGE = "batfish/batfish@sha256:7909378197c5a3974f2e8180af58cef0ca17b74d1cd9ba39f2d1fddb64737e55"


def test_standalone_verifier_compiles_without_api_database_or_engine_activation(tmp_path):
    docker = shutil.which("docker")
    if docker is None:
        pytest.skip("requires the optional Docker Compose CLI, not a running engine")
    empty_env = tmp_path / "empty.env"
    empty_env.write_text("", encoding="utf-8")
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.upper().startswith(("NETCONFIG_", "COMPOSE_", "DOCKER_"))
    }
    capability = subprocess.run(
        [docker, "compose", "version", "--short"],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        encoding="utf-8",
        timeout=30,
        creationflags=int(getattr(subprocess, "CREATE_NO_WINDOW", 0)),
    )
    assert len(capability.stdout) < 32_768 and len(capability.stderr) < 32_768
    diagnostic = capability.stderr.lower()
    if capability.returncode != 0 and "compose" in diagnostic and (
        "is not a docker command" in diagnostic or "unknown command" in diagnostic
    ):
        pytest.skip("requires the optional Docker Compose plugin, not a running engine")
    assert capability.returncode == 0, "Installed Docker Compose capability probe failed"
    result = subprocess.run(
        [
            docker,
            "compose",
            "--env-file",
            str(empty_env),
            "--file",
            str(ROOT / "docker-compose.verification.yml"),
            "config",
            "--format",
            "json",
        ],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        encoding="utf-8",
        timeout=30,
        creationflags=int(getattr(subprocess, "CREATE_NO_WINDOW", 0)),
    )
    assert result.returncode == 0, "Standalone verification Compose configuration failed"
    assert len(result.stdout) < 32_768
    configured = json.loads(result.stdout)
    assert configured["name"] == "sentinel-verification"
    assert set(configured["services"]) == {"batfish"}
    service = configured["services"]["batfish"]
    assert service["image"] == IMAGE
    assert service["read_only"] is True
    assert int(service["mem_limit"]) == 4 * 1024**3
    assert float(service["cpus"]) == 2
    assert not service.get("environment")
    assert not service.get("depends_on")
    assert not service.get("build")
    assert not service.get("privileged", False)
    assert service.get("network_mode") != "host"
    ports = service["ports"]
    assert len(ports) == 1
    assert ports[0]["host_ip"] == "127.0.0.1"
    assert str(ports[0]["published"]) == "9996" and ports[0]["target"] == 9996
    assert ports[0]["protocol"] == "tcp"
    assert service["tmpfs"] == ["/tmp:size=1g"]
    mounts = service["volumes"]
    assert len(mounts) == 1 and mounts[0]["type"] == "volume"
    assert mounts[0]["source"] == "batfish_data" and mounts[0]["target"] == "/data"
    assert set(configured["volumes"]) == {"batfish_data"}


@pytest.mark.parametrize(
    "diagnostic",
    ["docker: 'compose' is not a docker command.", 'unknown command "compose" for "docker"'],
)
def test_missing_optional_compose_plugin_is_skipped(tmp_path, monkeypatch, diagnostic):
    monkeypatch.setattr(shutil, "which", lambda name: "docker")
    calls = []

    def missing_plugin(arguments, **kwargs):
        calls.append(arguments)
        return subprocess.CompletedProcess(arguments, 1, stdout="", stderr=diagnostic)

    monkeypatch.setattr(subprocess, "run", missing_plugin)
    with pytest.raises(pytest.skip.Exception, match="optional Docker Compose plugin"):
        test_standalone_verifier_compiles_without_api_database_or_engine_activation(tmp_path)
    assert calls == [["docker", "compose", "version", "--short"]]


def test_supported_compose_configuration_failure_is_not_skipped(tmp_path, monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: "docker")
    calls = []

    def broken_configuration(arguments, **kwargs):
        calls.append(arguments)
        if "version" in arguments:
            return subprocess.CompletedProcess(arguments, 0, stdout="v2.0.0", stderr="")
        return subprocess.CompletedProcess(arguments, 1, stdout="", stderr="invalid config")

    monkeypatch.setattr(subprocess, "run", broken_configuration)
    with pytest.raises(
        AssertionError, match="Standalone verification Compose configuration failed"
    ):
        test_standalone_verifier_compiles_without_api_database_or_engine_activation(tmp_path)
    assert len(calls) == 2 and calls[1][-3:] == ["config", "--format", "json"]
