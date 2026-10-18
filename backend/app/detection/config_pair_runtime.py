"""A bounded offline pair worker; its caller shares ConfigurationModelRuntime's slot."""

import json
import os
import secrets
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryFile

from app.api.configurations import _unique_keys
from app.api.contracts import ConfigurationSnapshot
from app.core.configuration_model import ConfigurationModelSettings
from app.detection.config_model_runtime import (
    ConfigurationModelDisabled,
    ConfigurationModelUnavailable,
)
from app.detection.config_pair_contracts import (
    MAX_PAIR_JOB_BYTES,
    MAX_PAIR_RESULT_BYTES,
    ConfigurationPairJob,
)
from app.ingestion.source_retention import StoredOriginalSource
from ml.inference.pair_contracts import ConfigurationPairReport


class ConfigurationPairTooLarge(Exception):
    pass


def prepare_configuration_pair_job(
    settings: ConfigurationModelSettings,
    before: ConfigurationSnapshot,
    after: ConfigurationSnapshot,
    before_source: StoredOriginalSource,
    after_source: StoredOriginalSource,
    pin: str,
) -> ConfigurationPairJob:
    if settings.registry_root is None or settings.model_sha256 != pin:
        raise ConfigurationModelDisabled()
    job = ConfigurationPairJob(
        registry_root=str(settings.registry_root),
        model_sha256=pin,
        foundation_source=str(settings.foundation_source) if settings.foundation_source else None,
        key_hex=secrets.token_hex(32),
        before=before,
        after=after,
        before_source=before_source,
        after_source=after_source,
    )
    if len(job.model_dump_json().encode()) > MAX_PAIR_JOB_BYTES:
        raise ConfigurationPairTooLarge()
    return job


def run_configuration_pair_job(
    settings: ConfigurationModelSettings, job: ConfigurationPairJob
) -> ConfigurationPairReport:
    if (
        settings.registry_root is None
        or str(settings.registry_root) != job.registry_root
        or settings.model_sha256 != job.model_sha256
        or (str(settings.foundation_source) if settings.foundation_source else None)
        != job.foundation_source
    ):
        raise ConfigurationModelDisabled()
    try:
        job = ConfigurationPairJob.model_validate(job.model_dump(warnings=False))
        request = job.model_dump_json().encode()
        if len(request) > MAX_PAIR_JOB_BYTES:
            raise ValueError("oversized pair job")
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
                [sys.executable, "-I", str(Path(__file__).with_name("config_pair_worker.py"))],
                stdin=subprocess.PIPE,
                stdout=output,
                stderr=subprocess.DEVNULL,
                env=environment,
                creationflags=int(getattr(subprocess, "CREATE_NO_WINDOW", 0))
                if sys.platform == "win32"
                else 0,
            )
            try:
                process.communicate(request, timeout=settings.timeout_seconds)
            except BaseException:
                process.kill()
                process.communicate(timeout=5)
                raise
            if process.returncode != 0 or output.tell() > MAX_PAIR_RESULT_BYTES:
                raise ValueError("worker did not produce a bounded paired result")
            output.seek(0)
            result = ConfigurationPairReport.model_validate(
                json.loads(output.read(MAX_PAIR_RESULT_BYTES + 1), object_pairs_hook=_unique_keys)
            )
        if (
            len(
                json.dumps(
                    result.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
                ).encode()
            )
            > MAX_PAIR_RESULT_BYTES
        ):
            raise ValueError("canonical pair result exceeds budget")
        for report, snapshot, source in (
            (result.before, job.before, job.before_source),
            (result.after, job.after, job.after_source),
        ):
            if (
                report.model.model_sha256 != job.model_sha256
                or report.prediction.raw_source_sha256 != snapshot.canonical.source.sha256
                or report.prediction.total_lines != len(source.content.splitlines())
            ):
                raise ValueError("paired worker result binding differs")
        return result
    except (OSError, ValueError, TypeError, RecursionError, subprocess.SubprocessError):
        raise ConfigurationModelUnavailable() from None
