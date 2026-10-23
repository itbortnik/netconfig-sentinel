"""Isolated SDK metadata protocol controls; fake sessions are not live engine evidence."""

import io
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

import pytest
from app.verification import batfish, batfish_worker
from app.verification.batfish import (
    BatfishExecution,
    BatfishResult,
    ReachabilityScope,
    check_with_batfish,
    check_with_batfish_evidence,
)
from app.verification.snapshots import prepare_snapshot
from test_batfish_session_contract import Session

PROTOCOL = "batfish-execution-0.2.0"
OBSERVED_VERSION = "2026.8.19.3660"


def request():
    return {
        "protocol": PROTOCOL,
        "before_sha256": "a" * 64,
        "after_sha256": "b" * 64,
        "network_name": "sentinel-" + "1" * 32,
        "before": "owned-before",
        "after": "owned-after",
        "nodes": {"configs/device.cfg": "edge"},
        "scope": {"start_node": "edge", "destination": "192.0.2.0/24"},
    }


def envelope(options, *, observed="observed", version=OBSERVED_VERSION):
    return {
        "version": PROTOCOL,
        "sdk_version": version,
        "sdk_observation": observed,
        "result": {
            "version": "batfish-check-0.1.0",
            "before_sha256": options["before_sha256"],
            "after_sha256": options["after_sha256"],
            "network_name": options["network_name"],
            "scope": options["scope"],
            "status": "no_differences_in_scope",
            "reason": "query_completed",
            "engine_version": "authored-session-fixture",
            "cleanup_complete": True,
            "difference_count": 0,
            "before_reachable_count": 1,
            "after_reachable_count": 1,
        },
    }


def pair():
    before = prepare_snapshot({UUID(int=1): "hostname edge\n"})
    after = prepare_snapshot({UUID(int=1): "hostname edge\n! authored candidate\n"})
    return before, after, ReachabilityScope(start_node="edge", destination="192.0.2.0/24")


def install_worker(monkeypatch, options, *, mode="unchanged", metadata_value=OBSERVED_VERSION):
    events = []
    session = Session(mode)
    monkeypatch.setattr(session, "set_network", lambda name: None)

    def sdk_import(name):
        assert name == "pybatfish.datamodel.flow"
        events.append("sdk_import")
        print("private-import-diagnostic")
        return SimpleNamespace(HeaderConstraints=dict, PathConstraints=dict)

    def lookup(name):
        assert name == "pybatfish" and events == ["sdk_import"]
        events.append("metadata")
        if isinstance(metadata_value, Exception):
            raise metadata_value
        return metadata_value

    def create_session():
        events.append("session")
        return session

    monkeypatch.setattr(batfish_worker.importlib, "import_module", sdk_import)
    monkeypatch.setattr(batfish_worker.metadata, "version", lookup)
    monkeypatch.setattr(batfish_worker, "_session", create_session)
    monkeypatch.setattr(batfish_worker.sys, "stdin", io.StringIO(json.dumps(options)))
    return events, session


@pytest.mark.parametrize(
    "mode,status",
    [
        ("unchanged", "no_differences_in_scope"),
        ("changed", "differences_found"),
        ("empty", "inconclusive"),
        ("parse_failed", "incomplete"),
        ("error", "error"),
        ("cleanup_failed", "no_differences_in_scope"),
    ],
)
def test_worker_observes_after_sdk_import_before_session_and_keeps_engine_status(
    monkeypatch, capsys, mode, status
):
    options = request()
    events, session = install_worker(monkeypatch, options, mode=mode)
    batfish_worker.main()
    captured = capsys.readouterr()
    assert "private" not in captured.out and captured.err == ""
    execution = BatfishExecution.model_validate_json(captured.out)
    assert events == ["sdk_import", "metadata", "session"]
    assert execution.sdk_observation == "observed" and execution.sdk_version == OBSERVED_VERSION
    assert execution.result.status == status
    assert execution.result.before_sha256 == options["before_sha256"]
    assert execution.result.after_sha256 == options["after_sha256"]
    assert execution.result.scope.model_dump(mode="json") == options["scope"]
    assert execution.result.network_name == options["network_name"]
    assert session.deleted == [options["network_name"]]


def test_session_creation_error_preserves_already_observed_metadata(monkeypatch, capsys):
    install_worker(monkeypatch, request())

    def fail():
        raise RuntimeError("private-session-diagnostic")

    monkeypatch.setattr(batfish_worker, "_session", fail)
    batfish_worker.main()
    captured = capsys.readouterr()
    execution = BatfishExecution.model_validate_json(captured.out)
    assert execution.result.status == "error" and execution.result.reason == "engine_error"
    assert execution.sdk_observation == "observed" and execution.sdk_version == OBSERVED_VERSION
    assert "private" not in captured.out


@pytest.mark.parametrize(
    "metadata_value",
    [
        RuntimeError("private-metadata-diagnostic"),
        batfish_worker.metadata.PackageNotFoundError("private-distribution"),
        "",
        " ",
        "1" * 129,
        "private/path",
        "2026\nprivate-diagnostic",
        "версия",
        None,
        2026,
    ],
)
def test_metadata_failure_never_erases_completed_query(monkeypatch, capsys, metadata_value):
    events, _session = install_worker(monkeypatch, request(), metadata_value=metadata_value)
    batfish_worker.main()
    captured = capsys.readouterr()
    execution = BatfishExecution.model_validate_json(captured.out)
    assert events == ["sdk_import", "metadata", "session"]
    assert execution.sdk_version is None and execution.sdk_observation == "metadata_unavailable"
    assert execution.result.status == "no_differences_in_scope"
    assert execution.result.difference_count == 0 and execution.result.cleanup_complete is True
    assert "private" not in captured.out


def test_worker_sdk_import_failure_does_not_observe_metadata_or_create_session(monkeypatch, capsys):
    options = request()
    install_worker(monkeypatch, options)

    def fail_import(name):
        raise ImportError("private-sdk-import")

    def forbidden(*args, **kwargs):
        pytest.fail("SDK import failure proceeded to metadata or session")

    monkeypatch.setattr(batfish_worker.importlib, "import_module", fail_import)
    monkeypatch.setattr(batfish_worker.metadata, "version", forbidden)
    monkeypatch.setattr(batfish_worker, "_session", forbidden)
    batfish_worker.main()
    captured = capsys.readouterr()
    execution = BatfishExecution.model_validate_json(captured.out)
    assert execution.result.reason == "engine_error"
    assert execution.sdk_version is None and execution.sdk_observation == "not_observed"
    assert "private" not in captured.out


def test_missing_protocol_is_exact_legacy_output_and_performs_no_metadata_lookup(
    monkeypatch, capsys
):
    options = request()
    del options["protocol"]
    install_worker(monkeypatch, options)

    def forbidden(*args, **kwargs):
        pytest.fail("legacy worker looked up SDK distribution metadata")

    monkeypatch.setattr(batfish_worker.metadata, "version", forbidden)
    batfish_worker.main()
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert result == {
        "engine_version": '{"Batfish": "test-double"}',
        "status": "no_differences_in_scope",
        "reason": "query_completed",
        "difference_count": 0,
        "before_reachable_count": 1,
        "after_reachable_count": 1,
        "cleanup_complete": True,
    }
    assert "sdk_version" not in result and "version" not in result
    assert "private" not in captured.out


@pytest.mark.parametrize("protocol", [None, "", "batfish-execution-9.0.0", 1, {}])
def test_unknown_worker_protocol_fails_before_sdk_and_metadata(monkeypatch, capsys, protocol):
    options = request() | {"protocol": protocol}
    install_worker(monkeypatch, options)

    def forbidden(*args, **kwargs):
        pytest.fail("unknown worker protocol touched SDK, metadata or session")

    monkeypatch.setattr(batfish_worker.importlib, "import_module", forbidden)
    monkeypatch.setattr(batfish_worker.metadata, "version", forbidden)
    monkeypatch.setattr(batfish_worker, "_session", forbidden)
    batfish_worker.main()
    assert json.loads(capsys.readouterr().out) == {"status": "error", "reason": "engine_error"}


@pytest.mark.parametrize(
    "state,version",
    [
        ("observed", None),
        ("observed", ""),
        ("observed", "bad/value"),
        ("not_observed", "1.0"),
        ("metadata_unavailable", "1.0"),
        ("not_observed", None),
    ],
)
def test_envelope_rejects_inconsistent_observation_or_unobserved_completed_query(state, version):
    with pytest.raises(ValueError):
        BatfishExecution.model_validate(envelope(request(), observed=state, version=version))


@pytest.mark.parametrize(
    "reason", ["upload_not_authorized", "sdk_missing", "worker_failed", "timeout"]
)
def test_parent_side_failures_cannot_claim_worker_observation(reason):
    data = envelope(request())
    data["result"] = {
        "before_sha256": "a" * 64,
        "after_sha256": "b" * 64,
        "scope": request()["scope"],
        "status": "unavailable" if reason in {"upload_not_authorized", "sdk_missing"} else "error",
        "reason": reason,
    }
    with pytest.raises(ValueError):
        BatfishExecution.model_validate(data)


def test_new_parent_path_accepts_only_worker_observed_metadata_and_isolated_transport(monkeypatch):
    before, after, scope = pair()
    directories = []
    monkeypatch.setattr(batfish.importlib.util, "find_spec", lambda _: object())
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "PYTHONPATH", "NETCONFIG_API_TOKEN"):
        monkeypatch.setenv(key, "private-inherited-value")

    def no_parent_metadata(*args, **kwargs):
        pytest.fail("parent guessed SDK version from its installation")

    def run(*args, **kwargs):
        options = json.loads(kwargs["input"])
        assert args[0][1] == "-I" and Path(args[0][2]).name == "batfish_worker.py"
        assert options["protocol"] == PROTOCOL
        assert options["before_sha256"] == before.digest
        assert options["after_sha256"] == after.digest
        assert kwargs["timeout"] == 7 and kwargs["env"]["NO_PROXY"] == "*"
        assert kwargs["env"]["PYTHONNOUSERSITE"] == "1"
        assert not {
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "PYTHONPATH",
            "NETCONFIG_API_TOKEN",
        } & set(kwargs["env"])
        directories.append(Path(options["before"]).parent)
        assert directories[-1].exists()
        return subprocess.CompletedProcess(
            args[0], 0, json.dumps(envelope(options)), "private-stderr"
        )

    monkeypatch.setattr(batfish_worker.metadata, "version", no_parent_metadata)
    monkeypatch.setattr(batfish.subprocess, "run", run)
    result = check_with_batfish_evidence(
        before, after, scope, allow_local_upload=True, timeout_seconds=7
    )
    assert result.sdk_version == OBSERVED_VERSION and result.sdk_observation == "observed"
    assert result.result.status == "no_differences_in_scope"
    assert (
        result.result.before_sha256 == before.digest and result.result.after_sha256 == after.digest
    )
    assert all(not directory.exists() for directory in directories)
    assert "private" not in result.model_dump_json()


@pytest.mark.parametrize(
    "fault",
    [
        "timeout",
        "oserror",
        "nonzero",
        "malformed",
        "null",
        "list",
        "oversized",
        "protocol",
        "legacy",
        "before",
        "after",
        "scope",
        "network",
    ],
)
def test_new_transport_failures_never_impute_sdk_and_keep_exact_parent_bindings(monkeypatch, fault):
    before, after, scope = pair()
    directories = []
    monkeypatch.setattr(batfish.importlib.util, "find_spec", lambda _: object())

    def forbidden(*args, **kwargs):
        pytest.fail("failed transport looked up parent SDK metadata")

    def run(*args, **kwargs):
        options = json.loads(kwargs["input"])
        directories.append(Path(options["before"]).parent)
        if fault == "timeout":
            raise subprocess.TimeoutExpired("private-worker", 7)
        if fault == "oserror":
            raise OSError("private-transport-diagnostic")
        response = envelope(options)
        if fault in {"before", "after"}:
            response["result"][fault + "_sha256"] = "f" * 64
        elif fault == "scope":
            response["result"]["scope"] = {
                "start_node": "another",
                "destination": "198.51.100.0/24",
            }
        elif fault == "network":
            response["result"]["network_name"] = "sentinel-" + "f" * 32
        elif fault == "protocol":
            response["version"] = "batfish-execution-9.0.0"
        elif fault == "legacy":
            response = response["result"]
        elif fault == "oversized":
            response["padding"] = "Ж" * 17000
        output = {"malformed": "private-diagnostic", "null": "null", "list": "[]"}.get(
            fault, json.dumps(response, ensure_ascii=False)
        )
        if fault == "oversized":
            assert len(output) < 32768 < len(output.encode())
        return subprocess.CompletedProcess(
            args[0], 2 if fault == "nonzero" else 0, output, "private-stderr"
        )

    monkeypatch.setattr(batfish_worker.metadata, "version", forbidden)
    monkeypatch.setattr(batfish.subprocess, "run", run)
    result = check_with_batfish_evidence(
        before, after, scope, allow_local_upload=True, timeout_seconds=7
    )
    assert result.sdk_version is None and result.sdk_observation == "not_observed"
    assert result.result.status == "error"
    assert result.result.reason == ("timeout" if fault == "timeout" else "worker_failed")
    assert (result.result.before_sha256, result.result.after_sha256, result.result.scope) == (
        before.digest,
        after.digest,
        scope,
    )
    assert all(not directory.exists() for directory in directories)
    assert "private" not in result.model_dump_json()


@pytest.mark.parametrize("consent", [False, True])
def test_pre_worker_refusals_never_observe_or_launch_worker(monkeypatch, consent):
    before, after, scope = pair()

    def forbidden(*args, **kwargs):
        pytest.fail("pre-worker refusal observed metadata or launched worker")

    monkeypatch.setattr(batfish_worker.metadata, "version", forbidden)
    monkeypatch.setattr(batfish.subprocess, "run", forbidden)
    monkeypatch.setattr(
        batfish.importlib.util, "find_spec", lambda _: None if consent else forbidden()
    )
    execution = check_with_batfish_evidence(before, after, scope, allow_local_upload=consent)
    assert execution.result.reason == ("sdk_missing" if consent else "upload_not_authorized")
    assert execution.sdk_version is None and execution.sdk_observation == "not_observed"


def test_legacy_parent_request_and_result_are_not_enveloped(monkeypatch):
    before, after, scope = pair()
    monkeypatch.setattr(batfish.importlib.util, "find_spec", lambda _: object())

    def run(*args, **kwargs):
        options = json.loads(kwargs["input"])
        assert "protocol" not in options
        assert "before_sha256" not in options and "after_sha256" not in options
        return subprocess.CompletedProcess(
            args[0], 0, json.dumps({"status": "error", "reason": "engine_error"}), ""
        )

    monkeypatch.setattr(batfish.subprocess, "run", run)
    result = check_with_batfish(before, after, scope, allow_local_upload=True)
    assert isinstance(result, BatfishResult) and result.reason == "engine_error"
    assert "sdk_version" not in result.model_dump() and "sdk_observation" not in result.model_dump()
