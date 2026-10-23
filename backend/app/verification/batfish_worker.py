"""Isolated SDK worker. Its output is summaries only, never raw engine diagnostics."""

from __future__ import annotations

import contextlib
import importlib
import json
import os
import re
import sys
from collections.abc import Mapping, Sequence
from hashlib import sha256
from importlib import metadata
from ipaddress import IPv4Address, IPv4Network
from typing import Any


def _empty_impact(state: str, reason: str) -> dict[str, Any]:
    return dict(
        state=state,
        reason=reason,
        direction=None,
        lost_witness_count=None,
        gained_witness_count=None,
        witnesses=[],
    )


def _directional_impact(
    answer: Any, scope: dict[str, Any], flow_type: Any, trace_type: Any
) -> dict[str, Any]:
    """Interpret complete bounded example traces, never the difference of counters."""

    def unknown(reason: str) -> dict[str, Any]:
        return _empty_impact("unknown", reason)

    expected = {
        "Flow": "Flow",
        "Snapshot_Traces": "Set<Trace>",
        "Snapshot_TraceCount": "Integer",
        "Reference_Traces": "Set<Trace>",
        "Reference_TraceCount": "Integer",
    }
    success = {"ACCEPTED", "DELIVERED_TO_SUBNET", "EXITS_NETWORK"}
    known = success | {
        "DENIED_IN",
        "DENIED_OUT",
        "NO_ROUTE",
        "NULL_ROUTED",
        "NEIGHBOR_UNREACHABLE",
        "LOOP",
    }
    flow_fields = {
        "dscp",
        "dstIp",
        "dstPort",
        "ecn",
        "fragmentOffset",
        "icmpCode",
        "icmpVar",
        "ingressInterface",
        "ingressNode",
        "ingressVrf",
        "ipProtocol",
        "packetLength",
        "srcIp",
        "srcPort",
        "tcpFlagsAck",
        "tcpFlagsCwr",
        "tcpFlagsEce",
        "tcpFlagsFin",
        "tcpFlagsPsh",
        "tcpFlagsRst",
        "tcpFlagsSyn",
        "tcpFlagsUrg",
    }
    try:
        raw_rows = answer.rows
        if not isinstance(raw_rows, list):
            return unknown("unsupported_frame")
        if len(raw_rows) > 64:
            return unknown("witness_limit_exceeded")
        for raw_row in raw_rows:
            if not isinstance(raw_row, Mapping) or set(raw_row) != set(expected):
                return unknown("unsupported_frame")
            for prefix in ("Reference", "Snapshot"):
                raw_count = raw_row[prefix + "_TraceCount"]
                raw_traces = raw_row[prefix + "_Traces"]
                if (
                    type(raw_count) is not int
                    or not 1 <= raw_count <= 16
                    or not isinstance(raw_traces, list)
                    or len(raw_traces) != raw_count
                ):
                    return unknown("incomplete_traces")
            raw_flow = raw_row["Flow"]
            required = {
                "dscp",
                "dstIp",
                "ecn",
                "fragmentOffset",
                "ipProtocol",
                "packetLength",
                "srcIp",
            }
            if (
                not isinstance(raw_flow, Mapping)
                or not required.issubset(raw_flow)
                or not set(raw_flow).issubset(flow_fields | {"state", "tag"})
                or raw_flow.get("ingressNode") != scope["start_node"]
            ):
                return unknown("unsupported_frame")
            # The pinned engine emits these legacy fields, which Flow.from_dict drops.
            # Support only the observed pair and keep it in the witness identity.
            if ("state" in raw_flow or "tag" in raw_flow) and (
                raw_flow.get("state") != "NEW" or raw_flow.get("tag") != "tag"
            ):
                return unknown("unsupported_frame")
            ranges = {
                "dscp": (0, 63),
                "ecn": (0, 3),
                "fragmentOffset": (0, 8191),
                "packetLength": (20, 65535),
                "srcPort": (0, 65535),
                "dstPort": (0, 65535),
                "icmpCode": (0, 255),
                "icmpVar": (0, 255),
                **{key: (0, 1) for key in flow_fields if key.startswith("tcpFlags")},
            }
            for key, (low, high) in ranges.items():
                value = raw_flow.get(key)
                if value is None and key not in required:
                    continue
                if type(value) is not int or not low <= value <= high:
                    return unknown("unsupported_frame")
            for key in ("srcIp", "dstIp"):
                if type(raw_flow[key]) is not str:
                    return unknown("unsupported_frame")
                IPv4Address(raw_flow[key])
            if (
                type(raw_flow["ipProtocol"]) is not str
                or re.fullmatch(r"[A-Za-z0-9_]{1,64}", raw_flow["ipProtocol"]) is None
            ):
                return unknown("unsupported_frame")
            for key in ("ingressNode", "ingressInterface", "ingressVrf"):
                value = raw_flow.get(key)
                if value is not None and (
                    type(value) is not str or not 1 <= len(value) <= 128 or "\0" in value
                ):
                    return unknown("unsupported_frame")
        frame = answer.frame()
        columns = answer.metadata.column_metadata
        if (
            len(columns) != len(expected)
            or {c.name: c.schema for c in columns} != expected
            or len(frame.columns) != len(expected)
            or set(frame.columns) != set(expected)
        ):
            return unknown("unsupported_frame")
        if len(frame) != len(raw_rows):
            return unknown("unsupported_frame")
        records = frame.to_dict(orient="records")
        if len(records) != len(frame):
            return unknown("unsupported_frame")
        witnesses: list[dict[str, Any]] = []
        hashes = set()
        for row, raw_row in zip(records, raw_rows, strict=True):
            if not isinstance(row, Mapping) or set(row) != set(expected):
                return unknown("unsupported_frame")
            flow = row["Flow"]
            if not isinstance(flow, flow_type):
                return unknown("unsupported_frame")
            data = flow.dict()
            if (
                not isinstance(data, dict)
                or set(data) != flow_fields
                or data != {key: raw_row["Flow"].get(key) for key in flow_fields}
                or any(type(v) not in {str, int, type(None)} for v in data.values())
                or data["ingressNode"] != scope["start_node"]
                or IPv4Address(data["dstIp"]) not in IPv4Network(scope["destination"])
            ):
                return unknown("unsupported_frame")
            IPv4Address(data["srcIp"])
            identity = {"version": "reachability-flow-0.1.0", "flow": data}
            if "state" in raw_row["Flow"]:
                identity["legacy_engine_fields"] = {
                    key: raw_row["Flow"][key] for key in ("state", "tag")
                }
            raw = json.dumps(
                identity,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ).encode("ascii")
            if len(raw) > 4096:
                return unknown("witness_limit_exceeded")
            flow_hash = sha256(raw).hexdigest()
            if flow_hash in hashes:
                return unknown("ambiguous_witness")
            hashes.add(flow_hash)
            dispositions = {}
            for side, prefix in (("before", "Reference"), ("after", "Snapshot")):
                traces, count = row[prefix + "_Traces"], row[prefix + "_TraceCount"]
                if (
                    not isinstance(traces, Sequence)
                    or isinstance(traces, (str, bytes))
                    or type(count) is not int
                    or not 1 <= count <= 16
                    or count != len(traces)
                    or count != raw_row[prefix + "_TraceCount"]
                ):
                    return unknown("incomplete_traces")
                if any(not isinstance(t, trace_type) for t in traces):
                    return unknown("unsupported_frame")
                values = [t.disposition for t in traces]
                if any(
                    not isinstance(raw_trace, Mapping)
                    or raw_trace.get("disposition") != disposition
                    for raw_trace, disposition in zip(
                        raw_row[prefix + "_Traces"], values, strict=True
                    )
                ):
                    return unknown("unsupported_frame")
                if "INSUFFICIENT_INFO" in values:
                    return unknown("insufficient_information")
                if any(type(value) is not str or value not in known for value in values):
                    return unknown("unknown_disposition")
                dispositions[side] = sorted(values)
            before = bool(success.intersection(dispositions["before"]))
            after = bool(success.intersection(dispositions["after"]))
            if before == after:
                return unknown("ambiguous_witness")
            witnesses.append(
                dict(
                    flow_sha256=flow_hash,
                    before_dispositions=dispositions["before"],
                    after_dispositions=dispositions["after"],
                    before_trace_count=len(dispositions["before"]),
                    after_trace_count=len(dispositions["after"]),
                    direction="loss" if before else "gain",
                )
            )
        witnesses.sort(key=lambda row: row["flow_sha256"])
        losses = sum(row["direction"] == "loss" for row in witnesses)
        gains = len(witnesses) - losses
        return dict(
            state="observed",
            reason="query_completed",
            direction=(
                "loss_and_gain_found"
                if losses and gains
                else "loss_found"
                if losses
                else "gain_found"
                if gains
                else "no_witnesses_returned"
            ),
            lost_witness_count=losses,
            gained_witness_count=gains,
            witnesses=witnesses,
        )
    except Exception:
        return unknown("unsupported_frame")


def evaluate_session(
    session: Any,
    request: dict[str, Any],
    header_type: Any,
    path_type: Any,
    *,
    directional: bool = False,
    flow_type: Any = None,
    trace_type: Any = None,
) -> dict[str, Any]:
    """SDK boundary kept explicit for contract tests without a running engine."""
    result: dict[str, Any] = {"status": "error", "reason": "engine_error"}
    created = False
    network = request["network_name"]
    impact = _empty_impact("not_observed", "not_run")
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
            "maxTraces": 16 if directional else 1,
        }
        before_count = len(session.q.reachability(**params).answer(snapshot="before").frame())
        after_count = len(session.q.reachability(**params).answer(snapshot="after").frame())
        difference_answer = session.q.differentialReachability(**params).answer(
            snapshot="after", reference_snapshot="before"
        )
        difference_count = len(difference_answer.frame())
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
        if directional:
            impact = (
                _empty_impact("inconclusive", "empty_reachable_scope")
                if status == "inconclusive"
                else _directional_impact(difference_answer, request["scope"], flow_type, trace_type)
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
        if directional:
            if (
                result["status"] in {"differences_found", "no_differences_in_scope", "inconclusive"}
                and result.get("cleanup_complete") is not True
            ):
                impact = _empty_impact("unknown", "cleanup_unconfirmed")
            result["reachability_impact"] = impact
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
            if request["protocol"] not in {"batfish-execution-0.2.0", "batfish-execution-0.3.0"}:
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
                    **(
                        {"directional": True, "flow_type": flow.Flow, "trace_type": flow.Trace}
                        if request.get("protocol") == "batfish-execution-0.3.0"
                        else {}
                    ),
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
            impact = result.pop("reachability_impact", _empty_impact("not_observed", "not_run"))
            result = {
                "version": request["protocol"],
                "result": result,
                "sdk_version": sdk_version,
                "sdk_observation": sdk_observation,
            }
            if request["protocol"] == "batfish-execution-0.3.0":
                result["reachability_impact"] = impact
        except Exception:
            result = {"status": "error", "reason": "engine_error"}
    print(json.dumps(result))


if __name__ == "__main__":
    main()
