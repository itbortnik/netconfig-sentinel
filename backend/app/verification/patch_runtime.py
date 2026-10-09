"""No operator endpoints from HTTP; bounded offline ML worker, killed/reaped on timeout."""

import json
import os
import secrets
import subprocess
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryFile
from threading import Lock

from app.api.configurations import _unique_keys
from app.core.patch_verification import PatchVerificationSettings
from app.patching.review import PatchReview
from app.verification.patch_ml_contracts import MAX_JOB_BYTES, MAX_RESULT_BYTES, PatchMLJob
from ml.inference.change_contracts import MLChangeReview


class PatchVerificationDisabled(Exception):
    pass


class PatchVerificationBusy(Exception):
    pass


class PatchMLUnavailable(Exception):
    pass


class PatchVerificationRuntime:
    def __init__(self, settings: PatchVerificationSettings) -> None:
        self.settings = settings
        self._lock = Lock()

    @contextmanager
    def selected_worker(self) -> Iterator[None]:
        if not self._lock.acquire(blocking=False):
            raise PatchVerificationBusy()
        try:
            yield
        finally:
            self._lock.release()

    def review_ml(self, review: PatchReview, before: str, after: str, pin: str) -> MLChangeReview:
        if self.settings.registry_root is None or self.settings.transformer_sha256 != pin:
            raise PatchVerificationDisabled()
        try:
            job = PatchMLJob(
                registry_root=str(self.settings.registry_root),
                model_sha256=pin,
                foundation_source=str(self.settings.foundation_source)
                if self.settings.foundation_source
                else None,
                key_hex=secrets.token_hex(32),
                local_review=review,
                before=before,
                after=after,
            )
            request = job.model_dump_json().encode()
            if len(request) > MAX_JOB_BYTES:
                raise ValueError("oversized job")
            environment = {
                key: value
                for key, value in os.environ.items()
                if key.upper() in {"SYSTEMROOT", "WINDIR", "PATH", "TMP", "TEMP", "LANG", "LC_ALL"}
            }
            environment.update(
                {
                    "HF_HUB_OFFLINE": "1",
                    "TRANSFORMERS_OFFLINE": "1",
                    "HF_DATASETS_OFFLINE": "1",
                    "HF_HUB_DISABLE_TELEMETRY": "1",
                    "TOKENIZERS_PARALLELISM": "false",
                }
            )
            with TemporaryFile() as output:
                process = subprocess.Popen(
                    [sys.executable, "-I", str(Path(__file__).with_name("patch_ml_worker.py"))],
                    stdin=subprocess.PIPE,
                    stdout=output,
                    stderr=subprocess.DEVNULL,
                    env=environment,
                    creationflags=int(getattr(subprocess, "CREATE_NO_WINDOW", 0))
                    if sys.platform == "win32"
                    else 0,
                )
                try:
                    process.communicate(request, timeout=self.settings.ml_timeout_seconds)
                except BaseException:
                    process.kill()
                    process.communicate(timeout=5)
                    raise
                if process.returncode != 0 or output.tell() > MAX_RESULT_BYTES:
                    raise ValueError("worker did not produce a bounded result")
                output.seek(0)
                result = MLChangeReview.model_validate(
                    json.loads(output.read(MAX_RESULT_BYTES + 1), object_pairs_hook=_unique_keys)
                )
            if result.local_review != review or result.transformer.model_sha256 != pin:
                raise ValueError("worker source or model identity differs")
            return result
        except (OSError, ValueError, TypeError, RecursionError, subprocess.SubprocessError):
            raise PatchMLUnavailable() from None
