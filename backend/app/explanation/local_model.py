"""Explicit redacted local-model invocation; isolated deadline and one worker per process."""

import json
import os
import subprocess
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from threading import Lock

from app.core.local_model import LocalModelSettings
from app.explanation.knowledge import DocumentChunk
from app.explanation.privacy import redact_prompt
from app.explanation.provider import (
    MAX_ANSWER_BYTES,
    DraftAnswer,
    ExplanationProvider,
    InvalidProviderAnswer,
    ProviderPrompt,
    generate_draft,
)


class ModelBusy(Exception):
    pass


class ModelPatchDisabled(Exception):
    pass


class LoopbackProvider:
    def __init__(self, settings: LocalModelSettings) -> None:
        self.settings = settings

    def generate(self, prompt: ProviderPrompt) -> bytes:
        request = json.dumps(
            {
                "endpoint": self.settings.endpoint,
                "model": self.settings.model,
                "api_key": self.settings.api_key,
                "timeout": self.settings.timeout_seconds,
                "instructions": prompt.instructions,
                "context_json": prompt.context_json,
                "answer_schema_json": prompt.answer_schema_json,
            },
            ensure_ascii=False,
            allow_nan=False,
        ).encode()
        if len(request) > 128 * 1024:
            raise InvalidProviderAnswer("Language model provider failed.")
        environment = {
            key: value
            for key, value in os.environ.items()
            if key.upper()
            in {
                "SYSTEMROOT",
                "WINDIR",
                "PATH",
                "TMP",
                "TEMP",
                "LANG",
                "LC_ALL",
            }
        }
        process = subprocess.Popen(
            [sys.executable, "-I", str(Path(__file__).with_name("http_worker.py"))],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=environment,
            creationflags=(
                int(getattr(subprocess, "CREATE_NO_WINDOW", 0)) if sys.platform == "win32" else 0
            ),
        )
        try:
            stdout, _ = process.communicate(request, timeout=self.settings.timeout_seconds)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            raise InvalidProviderAnswer("Language model provider failed.") from None
        except BaseException:
            process.kill()
            process.communicate()
            raise
        if process.returncode != 0 or len(stdout) > MAX_ANSWER_BYTES:
            raise InvalidProviderAnswer("Language model provider failed.")
        return stdout


class LocalModelRuntime:
    def __init__(self, settings: LocalModelSettings) -> None:
        self.settings = settings
        self.provider = LoopbackProvider(settings)
        self._lock = Lock()

    @contextmanager
    def patch_provider(self) -> Iterator[ExplanationProvider]:
        """Separate operator permission; shares the explanation concurrency limit."""
        if not self.settings.allow_patch_draft:
            raise ModelPatchDisabled()
        if not self._lock.acquire(blocking=False):
            raise ModelBusy()
        try:
            # The caller must build/revalidate the fixed whitelist-only patch prompt.
            yield self.provider
        finally:
            self._lock.release()

    def explain(
        self, prompt: ProviderPrompt, chunks: tuple[DocumentChunk, ...]
    ) -> tuple[DraftAnswer, str]:
        if not self._lock.acquire(blocking=False):
            raise ModelBusy()
        try:
            redacted = redact_prompt(prompt)
            return generate_draft(self.provider, redacted, chunks), redacted.context_sha256
        finally:
            self._lock.release()
