"""Worker control tests use process doubles, never claimed inference measurements."""

import json
import subprocess
from pathlib import Path
from uuid import UUID

import pytest
from app.core.patch_verification import PatchVerificationSettings
from app.patching.proposal import create_patch_proposal
from app.patching.review import review_patch_proposal
from app.verification.patch_runtime import (
    PatchMLUnavailable,
    PatchVerificationBusy,
    PatchVerificationDisabled,
    PatchVerificationRuntime,
)

PIN = "f" * 64
BEFORE = "hostname owned\nip ssh version 1\n"
AFTER = "hostname owned\nip ssh version 2\n"


def review():
    proposal = create_patch_proposal(BEFORE, AFTER, device_id=UUID(int=1), reference_id="owned")
    return review_patch_proposal(proposal, BEFORE, AFTER, device_id=UUID(int=1))


def test_disabled_and_wrong_pin_never_spawn(tmp_path, monkeypatch):
    monkeypatch.setattr("subprocess.Popen", lambda *args, **kwargs: pytest.fail("spawned"))
    for settings, pin in (
        (PatchVerificationSettings(), PIN),
        (PatchVerificationSettings(registry_root=tmp_path, transformer_sha256=PIN), "0" * 64),
    ):
        with pytest.raises(PatchVerificationDisabled):
            PatchVerificationRuntime(settings).review_ml(review(), BEFORE, AFTER, pin)


def test_nonblocking_worker_slot_is_released_on_failure():
    runtime = PatchVerificationRuntime(PatchVerificationSettings())
    with pytest.raises(ValueError), runtime.selected_worker():
        with pytest.raises(PatchVerificationBusy), runtime.selected_worker():
            pytest.fail("acquired busy slot")
        raise ValueError("owned failure")
    with runtime.selected_worker():
        pass


@pytest.mark.parametrize("failure", ["timeout", "exit", "malformed", "oversized"])
def test_worker_deadline_reaping_environment_and_result_refusal(tmp_path, monkeypatch, failure):
    from app.verification.patch_ml_contracts import MAX_RESULT_BYTES

    calls = []
    monkeypatch.setenv("NETCONFIG_API_TOKEN", "owned-private-api-token")
    monkeypatch.setenv("NETCONFIG_ENCRYPTION_KEY", "owned-private-encryption-key")
    monkeypatch.setenv("PYTHONPATH", "untrusted-python-path")

    class Process:
        returncode = 1 if failure == "exit" else 0

        def __init__(self, command, **options):
            calls.append(("spawn", command, options))
            self.output = options["stdout"]

        def communicate(self, request=None, *, timeout):
            calls.append(("communicate", request, timeout))
            if request is not None:
                if failure == "timeout":
                    raise subprocess.TimeoutExpired("owned-worker", timeout)
                self.output.write(
                    b"x" * (MAX_RESULT_BYTES + 1) if failure == "oversized" else b"{}"
                )
            return None, None

        def kill(self):
            calls.append(("kill",))

    monkeypatch.setattr("subprocess.Popen", Process)
    settings = PatchVerificationSettings(
        registry_root=tmp_path, transformer_sha256=PIN, ml_timeout_seconds=1
    )
    with pytest.raises(PatchMLUnavailable):
        PatchVerificationRuntime(settings).review_ml(review(), BEFORE, AFTER, PIN)
    _, command, options = calls[0]
    assert command[1] == "-I" and Path(command[2]).name == "patch_ml_worker.py"
    assert Path(command[2]).is_absolute()
    assert all(
        name not in options["env"]
        for name in ("NETCONFIG_API_TOKEN", "NETCONFIG_ENCRYPTION_KEY", "PYTHONPATH")
    )
    assert options["env"]["HF_HUB_OFFLINE"] == options["env"]["TRANSFORMERS_OFFLINE"] == "1"
    job = json.loads(calls[1][1])
    assert job["registry_root"] == str(tmp_path) and job["model_sha256"] == PIN
    assert len(job["key_hex"]) == 64
    if failure == "timeout":
        assert calls[2] == ("kill",) and calls[3] == ("communicate", None, 5)
