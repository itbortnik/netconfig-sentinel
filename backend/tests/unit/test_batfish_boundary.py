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


@pytest.mark.parametrize("behavior", ["success", "timeout", "error", "malformed"])
def test_worker_is_bounded_and_temp_inputs_are_cleaned(
    monkeypatch: pytest.MonkeyPatch, behavior: str
) -> None:
    snapshot = prepare_snapshot({UUID(int=1): "hostname edge\n"})
    scope = ReachabilityScope(start_node="edge", destination="192.0.2.0/24")
    monkeypatch.setattr(batfish.importlib.util, "find_spec", lambda _: object())
    monkeypatch.setenv("HTTP_PROXY", "http://outside.invalid:8080")
    directories = []

    def run(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        request = json.loads(kwargs["input"])
        directories.append(Path(request["before"]).parent)
        assert directories[-1].exists()
        assert kwargs["timeout"] == 7
        assert "HTTP_PROXY" not in kwargs["env"]
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
                    "status": "no_differences_in_scope",
                    "reason": "query_completed",
                    "difference_count": 0,
                    "before_reachable_count": 1,
                    "after_reachable_count": 1,
                }
            )
        )
        return subprocess.CompletedProcess(args[0], 0, output, "private-secret")

    monkeypatch.setattr(batfish.subprocess, "run", run)
    result = check_with_batfish(
        snapshot, snapshot, scope, allow_local_upload=True, timeout_seconds=7
    )
    assert result.status == ("no_differences_in_scope" if behavior == "success" else "error")
    assert all(not directory.exists() for directory in directories)
    assert "private-secret" not in result.model_dump_json()


def test_empty_scope_cannot_claim_success() -> None:
    with pytest.raises(ValueError):
        BatfishResult(
            before_sha256="a" * 64,
            after_sha256="b" * 64,
            scope=ReachabilityScope(start_node="edge", destination="192.0.2.0/24"),
            status="no_differences_in_scope",
            reason="query_completed",
            difference_count=0,
            before_reachable_count=0,
            after_reachable_count=0,
        )
