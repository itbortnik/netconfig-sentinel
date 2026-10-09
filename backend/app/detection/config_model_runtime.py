"""Optional offline worker with a hard deadline and one non-queued process slot."""

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
from app.api.contracts import ConfigurationSnapshot
from app.core.configuration_model import ConfigurationModelSettings
from app.detection.config_model_contracts import (
    MAX_JOB_BYTES,
    MAX_RESULT_BYTES,
    ConfigurationModelJob,
)
from app.ingestion.source_retention import StoredOriginalSource
from ml.inference.config_contracts import ConfigurationInferenceReport


class ConfigurationModelDisabled(Exception):
    pass


class ConfigurationModelBusy(Exception):
    pass


class ConfigurationModelUnavailable(Exception):
    pass


class ConfigurationModelRuntime:
    def __init__(self, settings: ConfigurationModelSettings) -> None:
        self.settings = settings
        self._lock = Lock()

    @contextmanager
    def selected_worker(self) -> Iterator[None]:
        if not self._lock.acquire(blocking=False):
            raise ConfigurationModelBusy()
        try:
            yield
        finally:
            self._lock.release()

    def infer(
        self, snapshot: ConfigurationSnapshot, source: StoredOriginalSource, pin: str
    ) -> ConfigurationInferenceReport:
        if self.settings.registry_root is None or self.settings.model_sha256 != pin:
            raise ConfigurationModelDisabled()
        try:
            job = ConfigurationModelJob(
                registry_root=str(self.settings.registry_root),
                model_sha256=pin,
                foundation_source=str(self.settings.foundation_source)
                if self.settings.foundation_source
                else None,
                key_hex=secrets.token_hex(32),
                snapshot=snapshot,
                source=source,
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
                    [sys.executable, "-I", str(Path(__file__).with_name("config_ml_worker.py"))],
                    stdin=subprocess.PIPE,
                    stdout=output,
                    stderr=subprocess.DEVNULL,
                    env=environment,
                    creationflags=int(getattr(subprocess, "CREATE_NO_WINDOW", 0))
                    if sys.platform == "win32"
                    else 0,
                )
                try:
                    process.communicate(request, timeout=self.settings.timeout_seconds)
                except BaseException:
                    process.kill()
                    process.communicate(timeout=5)
                    raise
                if process.returncode != 0 or output.tell() > MAX_RESULT_BYTES:
                    raise ValueError("worker did not produce a bounded result")
                output.seek(0)
                result = ConfigurationInferenceReport.model_validate(
                    json.loads(output.read(MAX_RESULT_BYTES + 1), object_pairs_hook=_unique_keys)
                )
            if (
                result.model.model_sha256 != pin
                or result.prediction.raw_source_sha256 != source.snapshot.source_sha256
                or result.prediction.total_lines != len(source.content.splitlines())
            ):
                raise ValueError("worker source/model binding differs")
            return result
        except (OSError, ValueError, TypeError, RecursionError, subprocess.SubprocessError):
            raise ConfigurationModelUnavailable() from None
