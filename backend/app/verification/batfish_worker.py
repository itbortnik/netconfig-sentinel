"""Isolated SDK worker. Its output is summaries only, never raw engine diagnostics."""

from __future__ import annotations

import contextlib
import importlib
import json
import os
import re
import sys
from importlib import metadata
from typing import Any


def evaluate_session(
    session: Any, request: dict[str, Any], header_type: Any, path_type: Any
) -> dict[str, Any]:
    """SDK boundary kept explicit for contract tests without a running engine."""
    result: dict[str, Any] = {"status": "error", "reason": "engine_error"}
    created = False
    network = request["network_name"]
    try:
        if network in session.list_networks():
            return result
        session.set_network(network)
        created = True
        versions = session.get_component_versions()
        if not isinstance(versions, dict) or not versions:
            raise ValueError("engine version unavailable")
        version = json.dumps(versions, sort_keys=True)
        if len(version) > 2048:
            raise ValueError("invalid engine version metadata")
        result["engine_version"] = version
        for side in ("before", "after"):
            session.init_snapshot(
                request[side],
                name=side,
                overwrite=False,
                extra_args={"ignoremanagementinterfaces": False},
            )
            frame = session.q.fileParseStatus().answer(snapshot=side).frame()
            rows = frame.to_dict(orient="records")
            if len(rows) != len(request["nodes"]):
                result.update(status="incomplete", reason="initialization_issues")
                return result
            observed = {}
            for row in rows:
                filename = row["File_Name"]
                if filename in observed or row["Status"] != "PASSED":
                    result.update(status="incomplete", reason="initialization_issues")
                    return result
                observed[filename] = row["Nodes"]
            expected = {filename: [hostname] for filename, hostname in request["nodes"].items()}
            if observed != expected:
                result.update(status="incomplete", reason="initialization_issues")
                return result
            if len(session.q.initIssues().answer(snapshot=side).frame()) or len(
                session.q.parseWarning().answer(snapshot=side).frame()
            ):
                result.update(status="incomplete", reason="initialization_issues")
                return result
        headers = header_type(dstIps=request["scope"]["destination"])
        paths = path_type(startLocation=request["scope"]["start_node"])
        params = {
            "headers": headers,
            "pathConstraints": paths,
            "actions": "success",
            "maxTraces": 1,
        }
        before_count = len(session.q.reachability(**params).answer(snapshot="before").frame())
        after_count = len(session.q.reachability(**params).answer(snapshot="after").frame())
        difference_count = len(
            session.q.differentialReachability(**params)
            .answer(snapshot="after", reference_snapshot="before")
            .frame()
        )
        status = (
            "differences_found"
            if difference_count
            else "no_differences_in_scope"
            if before_count and after_count
            else "inconclusive"
        )
        result.update(
            status=status,
            reason="empty_reachable_scope" if status == "inconclusive" else "query_completed",
            difference_count=difference_count,
            before_reachable_count=before_count,
            after_reachable_count=after_count,
        )
    except Exception:
        # SDK errors may contain configuration lines, paths or server responses.
        result = {"status": "error", "reason": "engine_error"}
    finally:
        if created:
            try:
                session.delete_network(network)
                result["cleanup_complete"] = True
            except Exception:
                result["cleanup_complete"] = False
    return result


class BatfishRedirectRefused(RuntimeError):
    """A local engine cannot delegate transport or acknowledge a redirect as cleanup."""


def _reject_redirect(response: Any, **kwargs: Any) -> Any:
    if 300 <= response.status_code < 400:
        raise BatfishRedirectRefused("Local Batfish redirect refused.")
    return response


def _session() -> Any:
    session_type = importlib.import_module("pybatfish.client.session").Session
    return session_type(
        host="127.0.0.1",
        port=9996,
        ssl=False,
        proxies={"http": None, "https": None},
        request_kwargs={"allow_redirects": False, "hooks": {"response": _reject_redirect}},
    )


def _sdk_metadata() -> tuple[str | None, str]:
    """Observe only the imported worker SDK's distribution metadata, never paths or errors."""
    try:
        version = metadata.version("pybatfish")
        if (
            not isinstance(version, str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.!+_-]{0,127}", version) is None
        ):
            raise ValueError("invalid SDK distribution metadata")
        return version, "observed"
    except Exception:
        return None, "metadata_unavailable"


def main() -> None:
    evidence = False
    sdk_version, sdk_observation = None, "not_observed"
    try:
        request = json.loads(sys.stdin.read(65_536))
        if "protocol" in request:
            if request["protocol"] != "batfish-execution-0.2.0":
                raise ValueError("unknown worker protocol")
            evidence = True
        with open(os.devnull, "w", encoding="utf-8") as quiet:
            with contextlib.redirect_stdout(quiet), contextlib.redirect_stderr(quiet):
                flow = importlib.import_module("pybatfish.datamodel.flow")
                if evidence:
                    sdk_version, sdk_observation = _sdk_metadata()
                result = evaluate_session(
                    _session(),
                    request,
                    flow.HeaderConstraints,
                    flow.PathConstraints,
                )
    except Exception:
        result = {"status": "error", "reason": "engine_error"}
    if evidence:
        try:
            # Echo the exact new protocol's bindings. The parent checks these rather than
            # overwriting a mismatched worker response with its own requested inputs.
            result.update(
                before_sha256=request["before_sha256"],
                after_sha256=request["after_sha256"],
                scope=request["scope"],
                network_name=request["network_name"],
            )
            result = {
                "version": "batfish-execution-0.2.0",
                "result": result,
                "sdk_version": sdk_version,
                "sdk_observation": sdk_observation,
            }
        except Exception:
            result = {"status": "error", "reason": "engine_error"}
    print(json.dumps(result))


if __name__ == "__main__":
    main()
