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


class BatfishExecution(BaseModel):
    """Worker-observed SDK distribution metadata, without a binary identity claim."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["batfish-execution-0.2.0"] = "batfish-execution-0.2.0"
    result: BatfishResult
    sdk_version: str | None = Field(
        min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9.!+_-]{0,127}$"
    )
    sdk_observation: Literal["observed", "not_observed", "metadata_unavailable"]

    @model_validator(mode="after")
    def observed_metadata(self) -> BatfishExecution:
        if (self.sdk_observation == "observed") != (self.sdk_version is not None):
            raise ValueError("SDK observation differs from its recorded version")
        if (
            self.result.reason
            in {"upload_not_authorized", "sdk_missing", "worker_failed", "timeout"}
            and self.sdk_observation != "not_observed"
        ):
            raise ValueError("unobserved worker execution cannot record SDK metadata")
        if self.sdk_observation == "not_observed" and self.result.status not in {
            "unavailable",
            "error",
        }:
            raise ValueError("completed SDK calls require an observation or metadata failure")
        return self


def check_with_batfish(
    before: NetworkSnapshot,
    after: NetworkSnapshot,
    scope: ReachabilityScope,
    *,
    allow_local_upload: bool = False,
    timeout_seconds: int = 60,
) -> BatfishResult:
    result = _check_with_batfish(
        before,
        after,
        scope,
        allow_local_upload=allow_local_upload,
        timeout_seconds=timeout_seconds,
        protocol=None,
    )
    assert isinstance(result, BatfishResult)
    return result


def check_with_batfish_evidence(
    before: NetworkSnapshot,
    after: NetworkSnapshot,
    scope: ReachabilityScope,
    *,
    allow_local_upload: bool = False,
    timeout_seconds: int = 60,
) -> BatfishExecution:
    result = _check_with_batfish(
        before,
        after,
        scope,
        allow_local_upload=allow_local_upload,
        timeout_seconds=timeout_seconds,
        protocol="batfish-execution-0.2.0",
    )
    assert isinstance(result, BatfishExecution)
    return result


def _check_with_batfish(
    before: NetworkSnapshot,
    after: NetworkSnapshot,
    scope: ReachabilityScope,
    *,
    allow_local_upload: bool,
    timeout_seconds: int,
    protocol: Literal["batfish-execution-0.2.0"] | None,
) -> BatfishResult | BatfishExecution:
    validate_snapshot_pair(before, after)
    scope = ReachabilityScope.model_validate(scope.model_dump())
    if scope.start_node not in {config.hostname for config in before.configs}:
        raise ValueError("start node is absent from the supplied snapshots")
    if type(allow_local_upload) is not bool:
        raise ValueError("local upload permission must be a boolean")
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 300:
        raise ValueError("timeout must be between 1 and 300 seconds")
    common = {"before_sha256": before.digest, "after_sha256": after.digest, "scope": scope}

    def failure(status: str, reason: str) -> BatfishResult | BatfishExecution:
        result = BatfishResult.model_validate({**common, "status": status, "reason": reason})
        if protocol is None:
            return result
        return BatfishExecution(result=result, sdk_version=None, sdk_observation="not_observed")

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
        if protocol is not None:
            request.update(
                protocol=protocol, before_sha256=before.digest, after_sha256=after.digest
            )
        try:
            environment = {
                key: value
                for key, value in os.environ.items()
                if key.upper() in {"SYSTEMROOT", "WINDIR", "PATH", "TMP", "TEMP", "LANG", "LC_ALL"}
            }
            environment["NO_PROXY"] = "*"
            environment["PYTHONNOUSERSITE"] = "1"
            run = subprocess.run(
                [sys.executable, "-I", str(Path(__file__).with_name("batfish_worker.py"))],
                input=json.dumps(request),
                capture_output=True,
                encoding="utf-8",
                timeout=timeout_seconds,
                check=False,
                env=environment,
                creationflags=(
                    int(getattr(subprocess, "CREATE_NO_WINDOW", 0))
                    if sys.platform == "win32"
                    else 0
                ),
            )
            response_size = len(run.stdout) if protocol is None else len(run.stdout.encode("utf-8"))
            if run.returncode != 0 or response_size > 32_768:
                return failure("error", "worker_failed")
            response = json.loads(run.stdout)
            if not isinstance(response, dict):
                return failure("error", "worker_failed")
            if protocol is None:
                return BatfishResult.model_validate({**response, **common})
            execution = BatfishExecution.model_validate(response)
            result = execution.result
            if (result.before_sha256, result.after_sha256, result.scope, result.network_name) != (
                before.digest,
                after.digest,
                scope,
                network_name,
            ):
                return failure("error", "worker_failed")
            return execution
        except subprocess.TimeoutExpired:
            return failure("error", "timeout")
        except (OSError, ValueError):
            return failure("error", "worker_failed")
