"""Pair process and key/model consistency with a numeric fixture, never model quality."""

import io
import json
import subprocess
from types import SimpleNamespace

import app.detection.config_pair_runtime as runtime
import pytest
from app.detection.config_model_runtime import ConfigurationModelUnavailable
from test_configuration_model_api import native_registry as native_registry
from test_source_ml_recheck_api import options, pair, post
from test_source_ml_recheck_api import source_ml_api as source_ml_api

from ml.inference.pair_contracts import ConfigurationPairReport


def job_and_report(source_ml_api):
    client, _app, _settings, calls = source_ml_api
    draft, *_ = pair(client)
    saved = post(client, draft, options(draft)).json()
    return calls[0], ConfigurationPairReport.model_validate(saved["outcome"]["report"])


def test_pair_primitive_calls_same_model_key_vendor_device_and_pin_twice(
    source_ml_api, monkeypatch
):
    import ml.inference.configuration_pair as pair_module

    job, report = job_and_report(source_ml_api)
    model, key, seen = object(), bytes.fromhex(job.key_hex), []

    def infer(content, **kwargs):
        seen.append((content, kwargs))
        return report.before if len(seen) == 1 else report.after

    monkeypatch.setattr(pair_module, "infer_configuration", infer)
    actual = pair_module.infer_configuration_pair(
        job.before_source.content,
        job.after_source.content,
        vendor=job.before.canonical.device.vendor,
        device_id=job.before.device_id,
        model=model,
        expected_model_sha256=job.model_sha256,
        pseudonymization_key=key,
    )
    assert actual == report and len(seen) == 2
    assert [item[0] for item in seen] == [job.before_source.content, job.after_source.content]
    assert seen[0][1] == seen[1][1]
    assert seen[0][1]["model"] is model and seen[1][1]["pseudonymization_key"] is key


@pytest.mark.parametrize(
    "fault", [None, "timeout", "oversized", "wrong_source", "duplicate", "exit"]
)
def test_bounded_offline_process_result_binding_and_timeout_reaping(
    source_ml_api, monkeypatch, fault
):
    job, report = job_and_report(source_ml_api)
    settings = source_ml_api[1].state.configuration_model.settings
    seen = {}

    class Process:
        returncode = 0

        def __init__(self, command, **kwargs):
            seen.update(command=command, options=kwargs, killed=False, communications=0)
            raw = report.model_dump_json().encode()
            if fault == "oversized":
                raw = b"x" * (runtime.MAX_PAIR_RESULT_BYTES + 1)
            if fault == "wrong_source":
                changed = report.model_dump(mode="json")
                changed["after"]["prediction"]["raw_source_sha256"] = "f" * 64
                raw = json.dumps(changed).encode()
            if fault == "duplicate":
                raw = b'{"before":null,"before":null}'
            kwargs["stdout"].write(raw)
            if fault == "exit":
                self.returncode = 1

        def communicate(self, data=None, *, timeout):
            seen["communications"] += 1
            if fault == "timeout" and not seen["killed"]:
                raise subprocess.TimeoutExpired("owned-worker", timeout)
            if data is not None:
                assert json.loads(data)["key_hex"] == job.key_hex

        def kill(self):
            seen["killed"] = True

    monkeypatch.setattr(runtime.subprocess, "Popen", Process)
    if fault:
        with pytest.raises(ConfigurationModelUnavailable):
            runtime.run_configuration_pair_job(settings, job)
    else:
        assert runtime.run_configuration_pair_job(settings, job) == report
    assert "-I" in seen["command"]
    assert seen["options"]["env"]["HF_HUB_OFFLINE"] == "1"
    assert all(not key.startswith("NETCONFIG_") for key in seen["options"]["env"])
    if fault == "timeout":
        assert seen["killed"] and seen["communications"] == 2


def test_worker_loads_once_and_passes_both_exact_sources_and_one_private_key(
    source_ml_api, monkeypatch
):
    import app.detection.config_pair_worker as worker

    import ml.inference.configuration_pair as pair_module
    import ml.registry.store as registry

    job, report = job_and_report(source_ml_api)
    loads, forwards, model = [], [], object()

    def load(*args, **kwargs):
        loads.append((args, kwargs))
        return model

    def infer(*args, **kwargs):
        forwards.append((args, kwargs))
        return report

    output = io.BytesIO()
    monkeypatch.setattr(registry, "load_registered_model", load)
    monkeypatch.setattr(pair_module, "infer_configuration_pair", infer)
    monkeypatch.setattr(
        worker.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(job.model_dump_json().encode()))
    )
    monkeypatch.setattr(worker.sys, "stdout", SimpleNamespace(buffer=output))
    worker.main()
    assert len(loads) == len(forwards) == 1
    assert forwards[0][0] == (job.before_source.content, job.after_source.content)
    assert forwards[0][1]["model"] is model
    assert forwards[0][1]["pseudonymization_key"] == bytes.fromhex(job.key_hex)
    assert ConfigurationPairReport.model_validate_json(output.getvalue()) == report


@pytest.mark.parametrize("vendor", ["cisco", "juniper"])
def test_actual_isolated_native_pair_on_authored_sources(
    source_ml_api, native_registry, monkeypatch, vendor
):
    import app.patching.source_ml as workflow
    from app.core.configuration_model import ConfigurationModelSettings
    from test_source_patch_review_api import draft_pair

    client, application, _settings, synthetic_calls = source_ml_api
    root, pin, _kind = native_registry
    application.state.configuration_model.settings = ConfigurationModelSettings(
        registry_root=root, model_sha256=pin
    )
    monkeypatch.setattr(workflow, "run_configuration_pair_job", runtime.run_configuration_pair_job)
    if vendor == "cisco":
        draft, before, after = pair(client)
    else:
        draft, before, after = draft_pair(
            client,
            before="set system host-name edge\nset system services telnet\n",
            after="set system host-name edge\nset system services ssh\n",
        )
    body = options(draft, model_sha256=pin)
    response = post(client, draft, body)
    assert response.status_code == 201, response.text
    result = response.json()
    assert result["execution_status"] == "completed" and not synthetic_calls
    reports = result["outcome"]["report"]
    for side, snapshot in (("before", before), ("after", after)):
        report = reports[side]
        assert report["runtime_torch_version"] != "synthetic-fixture"
        assert (
            report["prediction"]["raw_source_sha256"] == snapshot["canonical"]["source"]["sha256"]
        )
        assert report["prediction"]["embedding_dimensions"] == 8
        assert report["prediction"]["severity_scores"] is None
    assert result["formal_verification"] == "not_run" and result["quality_proven"] is False
    assert post(client, draft, body).json() == result
