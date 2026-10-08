"""Opt-in SDK process boundary: no network engine is used in these tests."""

import json
import subprocess
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
from app.verification import batfish
from app.verification.batfish import BatfishResult, ReachabilityScope, check_with_batfish
from app.verification.snapshots import prepare_snapshot


def test_upload_disabled_and_sdk_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    snapshot = prepare_snapshot({UUID(int=1): "hostname edge\n"})
    scope = ReachabilityScope(start_node="edge", destination="192.0.2.0/24")
    monkeypatch.setattr(batfish.importlib.util, "find_spec", lambda _: None)
    assert check_with_batfish(snapshot, snapshot, scope).reason == "upload_not_authorized"
    assert (
        check_with_batfish(snapshot, snapshot, scope, allow_local_upload=True).reason
        == "sdk_missing"
    )


@pytest.mark.parametrize("behavior", ["success", "timeout", "error", "malformed", "null", "list"])
def test_worker_is_bounded_and_temp_inputs_are_cleaned(
    monkeypatch: pytest.MonkeyPatch, behavior: str
) -> None:
    snapshot = prepare_snapshot({UUID(int=1): "hostname edge\n"})
    scope = ReachabilityScope(start_node="edge", destination="192.0.2.0/24")
    monkeypatch.setattr(batfish.importlib.util, "find_spec", lambda _: object())
    monkeypatch.setenv("HTTP_PROXY", "http://outside.invalid:8080")
    monkeypatch.setenv("NETCONFIG_API_TOKEN", "private-service-token")
    monkeypatch.setenv("HF_TOKEN", "private-model-token")
    monkeypatch.setenv("PYTHONPATH", "untrusted-import-directory")
    monkeypatch.setenv("PYTHONSTARTUP", "untrusted-startup-file")
    directories = []

    def run(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        assert args[0][1] == "-I"
        assert Path(args[0][2]).name == "batfish_worker.py"
        request = json.loads(kwargs["input"])
        directories.append(Path(request["before"]).parent)
        assert directories[-1].exists()
        assert kwargs["timeout"] == 7
        assert "HTTP_PROXY" not in kwargs["env"]
        assert "NETCONFIG_API_TOKEN" not in kwargs["env"]
        assert "HF_TOKEN" not in kwargs["env"]
        assert "PYTHONPATH" not in kwargs["env"]
        assert "PYTHONSTARTUP" not in kwargs["env"]
        assert kwargs["env"]["NO_PROXY"] == "*"
        assert request["scope"]["start_node"] == "edge"
        if behavior == "timeout":
            raise subprocess.TimeoutExpired("worker", 7)
        if behavior == "error":
            raise OSError("private-secret")
        output = (
            "private-secret"
            if behavior == "malformed"
            else json.dumps(
                {
                    "engine_version": "test-double",
                    "status": "no_differences_in_scope",
                    "reason": "query_completed",
                    "difference_count": 0,
                    "before_reachable_count": 1,
                    "after_reachable_count": 1,
                }
            )
        )
        if behavior in {"null", "list"}:
            output = "null" if behavior == "null" else "[]"
        return subprocess.CompletedProcess(args[0], 0, output, "private-secret")

    monkeypatch.setattr(batfish.subprocess, "run", run)
    result = check_with_batfish(
        snapshot, snapshot, scope, allow_local_upload=True, timeout_seconds=7
    )
    assert result.status == ("no_differences_in_scope" if behavior == "success" else "error")
    assert all(not directory.exists() for directory in directories)
    assert "private-secret" not in result.model_dump_json()


@pytest.mark.parametrize("consent", [None, 0, 1, "true", "false", object()])
def test_upload_permission_is_an_explicit_boolean(
    monkeypatch: pytest.MonkeyPatch, consent: Any
) -> None:
    snapshot = prepare_snapshot({UUID(int=1): "hostname edge\n"})
    scope = ReachabilityScope(start_node="edge", destination="192.0.2.0/24")

    def no_sdk_access(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("SDK lookup must not precede consent validation")

    monkeypatch.setattr(batfish.importlib.util, "find_spec", no_sdk_access)
    with pytest.raises(ValueError, match="permission must be a boolean"):
        check_with_batfish(snapshot, snapshot, scope, allow_local_upload=consent)


@pytest.mark.parametrize("timeout", [True, False, 1.0, "60", None, 0, 301])
def test_worker_timeout_is_a_bounded_integer(timeout: Any) -> None:
    snapshot = prepare_snapshot({UUID(int=1): "hostname edge\n"})
    scope = ReachabilityScope(start_node="edge", destination="192.0.2.0/24")
    with pytest.raises(ValueError, match="timeout must"):
        check_with_batfish(snapshot, snapshot, scope, timeout_seconds=timeout)


def test_empty_scope_cannot_claim_success() -> None:
    with pytest.raises(ValueError):
        BatfishResult(
            engine_version="test-double",
            before_sha256="a" * 64,
            after_sha256="b" * 64,
            scope=ReachabilityScope(start_node="edge", destination="192.0.2.0/24"),
            status="no_differences_in_scope",
            reason="query_completed",
            difference_count=0,
            before_reachable_count=0,
            after_reachable_count=0,
        )


@pytest.mark.parametrize("field,value", [("difference_count", True), ("engine_version", None)])
def test_query_results_require_real_counts_and_version(field: str, value: object) -> None:
    payload = {
        "before_sha256": "a" * 64,
        "after_sha256": "b" * 64,
        "scope": {"start_node": "edge", "destination": "192.0.2.0/24"},
        "status": "differences_found",
        "reason": "query_completed",
        "engine_version": "test-double",
        "difference_count": 1,
        "before_reachable_count": 1,
        "after_reachable_count": 1,
    }
    payload[field] = value
    with pytest.raises(ValueError):
        BatfishResult.model_validate(payload)
