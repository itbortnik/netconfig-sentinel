"""Isolated SDK worker. Its output is summaries only, never raw engine diagnostics."""

from __future__ import annotations

import contextlib
import importlib
import json
import os
import sys
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


def main() -> None:
    try:
        request = json.loads(sys.stdin.read(65_536))
        with open(os.devnull, "w", encoding="utf-8") as quiet:
            with contextlib.redirect_stdout(quiet), contextlib.redirect_stderr(quiet):
                session_type = importlib.import_module("pybatfish.client.session").Session
                flow = importlib.import_module("pybatfish.datamodel.flow")
                result = evaluate_session(
                    session_type(host="127.0.0.1"),
                    request,
                    flow.HeaderConstraints,
                    flow.PathConstraints,
                )
    except Exception:
        result = {"status": "error", "reason": "engine_error"}
    print(json.dumps(result))


if __name__ == "__main__":
    main()
