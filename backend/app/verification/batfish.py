"""Opt-in loopback Batfish checks, with a bounded isolated SDK worker."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
from ipaddress import IPv4Network
from pathlib import Path
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.verification.snapshots import NetworkSnapshot, validate_snapshot_pair, write_snapshot


class ReachabilityScope(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    start_node: str = Field(pattern=r"^[A-Za-z0-9_-]{1,128}$")
    destination: IPv4Network


class BatfishResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["batfish-check-0.1.0"] = "batfish-check-0.1.0"
    before_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    after_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    scope: ReachabilityScope
    status: Literal[
        "unavailable",
        "error",
        "incomplete",
        "inconclusive",
        "differences_found",
        "no_differences_in_scope",
    ]
    reason: Literal[
        "upload_not_authorized",
        "sdk_missing",
        "worker_failed",
        "timeout",
        "engine_error",
        "initialization_issues",
        "empty_reachable_scope",
        "query_completed",
    ]
    engine_version: str | None = Field(default=None, min_length=1, max_length=2048)
    network_name: str | None = Field(default=None, pattern=r"^sentinel-[0-9a-f]{32}$")
    cleanup_complete: bool | None = None
    difference_count: int | None = Field(default=None, ge=0, strict=True)
    before_reachable_count: int | None = Field(default=None, ge=0, strict=True)
    after_reachable_count: int | None = Field(default=None, ge=0, strict=True)
    requires_human_review: Literal[True] = True
    limitations: tuple[str, ...] = (
        "Only the supplied snapshot and explicit IPv4 destination/start node are modeled.",
        "Differences may be reachability gains or losses; counts are not impact severity.",
        "No patch validation, approval or application is performed.",
        "External topology completeness and operational state are not established.",
    )

    @model_validator(mode="after")
    def consistent_result(self) -> BatfishResult:
        reasons = {
            "unavailable": {"upload_not_authorized", "sdk_missing"},
            "error": {"worker_failed", "timeout", "engine_error"},
            "incomplete": {"initialization_issues"},
            "inconclusive": {"empty_reachable_scope"},
            "differences_found": {"query_completed"},
            "no_differences_in_scope": {"query_completed"},
        }
        if self.reason not in reasons[self.status]:
            raise ValueError("reason does not match verification status")
        queried = self.status in {"inconclusive", "differences_found", "no_differences_in_scope"}
        if queried and (self.engine_version is None or not self.engine_version.strip()):
            raise ValueError("completed queries require engine version metadata")
        counts = (self.difference_count, self.before_reachable_count, self.after_reachable_count)
        if queried != all(value is not None for value in counts):
            raise ValueError("query counts conflict with result status")
        if not queried and any(value is not None for value in counts):
            raise ValueError("unperformed queries cannot have counts")
        if self.status == "no_differences_in_scope" and (
            self.difference_count != 0
            or not self.before_reachable_count
            or not self.after_reachable_count
        ):
            raise ValueError("empty or changed scope cannot claim no differences")
        if self.status == "differences_found" and not self.difference_count:
            raise ValueError("differences require nonzero count")
        if self.status == "inconclusive" and (
            self.difference_count != 0
            or (self.before_reachable_count and self.after_reachable_count)
        ):
            raise ValueError("inconclusive scope must be empty on at least one side")
        return self


def check_with_batfish(
    before: NetworkSnapshot,
    after: NetworkSnapshot,
    scope: ReachabilityScope,
    *,
    allow_local_upload: bool = False,
    timeout_seconds: int = 60,
) -> BatfishResult:
    validate_snapshot_pair(before, after)
    scope = ReachabilityScope.model_validate(scope.model_dump())
    if scope.start_node not in {config.hostname for config in before.configs}:
        raise ValueError("start node is absent from the supplied snapshots")
    if not 1 <= timeout_seconds <= 300:
        raise ValueError("timeout must be between 1 and 300 seconds")
    common = {"before_sha256": before.digest, "after_sha256": after.digest, "scope": scope}

    def failure(status: str, reason: str) -> BatfishResult:
        return BatfishResult.model_validate({**common, "status": status, "reason": reason})

    if not allow_local_upload:
        return failure("unavailable", "upload_not_authorized")
    if importlib.util.find_spec("pybatfish") is None:
        return failure("unavailable", "sdk_missing")
    network_name = f"sentinel-{uuid4().hex}"
    common["network_name"] = network_name
    with tempfile.TemporaryDirectory(prefix="network-verification-") as directory:
        root = Path(directory)
        write_snapshot(before, root / "before")
        write_snapshot(after, root / "after")
        request = {
            "network_name": network_name,
            "before": str(root / "before"),
            "after": str(root / "after"),
            "scope": scope.model_dump(mode="json"),
            "nodes": {f"configs/{item.filename}": item.hostname for item in before.configs},
        }
        try:
            environment = {
                key: value
                for key, value in os.environ.items()
                if key.upper() not in {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"}
            }
            environment["NO_PROXY"] = "*"
            run = subprocess.run(
                [sys.executable, "-m", "app.verification.batfish_worker"],
                input=json.dumps(request),
                capture_output=True,
                encoding="utf-8",
                timeout=timeout_seconds,
                check=False,
                env=environment,
            )
            if run.returncode != 0 or len(run.stdout) > 32_768:
                return failure("error", "worker_failed")
            response = json.loads(run.stdout)
            if not isinstance(response, dict):
                return failure("error", "worker_failed")
            result = BatfishResult.model_validate({**response, **common})
        except subprocess.TimeoutExpired:
            return failure("error", "timeout")
        except (OSError, ValueError):
            return failure("error", "worker_failed")
    return result
