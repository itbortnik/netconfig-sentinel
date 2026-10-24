"""Trusted stdlib-only raw ingress extraction shared with the isolated SDK worker."""

from __future__ import annotations

import json
import re
from hashlib import sha256
from ipaddress import IPv4Interface
from typing import Any, Literal, cast

MAX_ROWS = 256
MAX_PREFIXES = 64
MAX_RAW_BYTES = 262_144
MAX_OBSERVATION_BYTES = 65_536
INGRESS_METHOD: Literal["selected-interface-concrete-ipv4-origination-0.1.0"] = (
    "selected-interface-concrete-ipv4-origination-0.1.0"
)
INGRESS_LIMITATIONS = (
    "Selection and concrete IPv4 origination eligibility are observed, "
    "not a complete ingress universe.",
    "Active is a modeled property, not operational link state; "
    "missing concrete IPv4 remains unknown.",
    "Source IP assignments are opaque engine renderings; "
    "equality and IP-set semantics are unverified.",
    "After-context assignments for common eligible identities do not prove complete flow coverage.",
    "Removed ingress, management access, external delivery, approval "
    "and safety are not established.",
    "Admission byte limits are post-download checks, not hard HTTP receive-memory bounds.",
)
_COLUMNS = {
    "resolveLocationSpecifier": {"Location": ("String", True, False)},
    "interfaceProperties": {
        "Interface": ("Interface", True, False),
        "Active": ("Boolean", False, True),
        "All_Prefixes": ("List<String>", False, True),
        "Interface_Type": ("String", False, True),
        "Switchport": ("Boolean", False, True),
    },
    "resolveIpsOfLocationSpecifier": {
        "Locations": ("String", True, False),
        "IP_Space": ("String", False, False),
    },
}


class IngressExtractionError(ValueError):
    """A closed reason code only; never include an engine diagnostic."""


def _fail(reason: str = "unsupported_answer") -> None:
    raise IngressExtractionError(reason)


def json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def canonical_id(node: str, interface: str) -> str:
    identity = dict(
        version="ingress-location-0.1.0", kind="interface", node=node, interface=interface
    )
    return sha256(
        json.dumps(identity, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    ).hexdigest()


def location_rendering(node: str, interface: str) -> str:
    if type(interface) is str and len(interface.encode("utf-8")) > 128:
        _fail("budget_exceeded")
    if (
        type(node) is not str
        or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", node) is None
        or type(interface) is not str
        or not 1 <= len(interface.encode("utf-8")) <= 128
        or re.fullmatch(r"[A-Za-z0-9_.:/-]+", interface) is None
    ):
        _fail("unsupported_location")
    return f"InterfaceLocation{{nodeName={node}, interfaceName={interface}}}"


def eligibility(active: bool, switchport: bool, prefixes: list[str]) -> tuple[bool | None, str]:
    if not active:
        return False, "inactive"
    if switchport:
        return False, "switchport"
    if prefixes:
        return True, "active_concrete_ipv4"
    return None, "no_concrete_ipv4"


def validate_interface(row: dict[str, Any]) -> None:
    """Validate saved observations too; resealing forged derived data cannot bypass this."""
    if set(row) != {
        "node",
        "interface",
        "canonical_id_sha256",
        "location_rendering",
        "active",
        "switchport",
        "interface_type",
        "concrete_ipv4_prefixes",
        "eligible",
        "eligibility_reason",
        "source_ip_rendering",
        "source_ip_sha256",
    }:
        _fail()
    rendered = location_rendering(row["node"], row["interface"])
    if (
        row["location_rendering"] != rendered
        or row["canonical_id_sha256"] != canonical_id(row["node"], row["interface"])
        or type(row["active"]) is not bool
        or type(row["switchport"]) is not bool
        or type(row["interface_type"]) is not str
        or re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", row["interface_type"]) is None
    ):
        _fail()
    prefixes = row["concrete_ipv4_prefixes"]
    if type(prefixes) is not list or len(prefixes) > MAX_PREFIXES:
        _fail("budget_exceeded" if isinstance(prefixes, list) else "unsupported_answer")
    if any(type(p) is not str or str(IPv4Interface(p)) != p for p in prefixes):
        _fail()
    if prefixes != sorted(set(prefixes)):
        _fail()
    eligible, reason = eligibility(row["active"], row["switchport"], prefixes)
    if type(row["eligible"]) is not type(eligible) or (
        row["eligible"],
        row["eligibility_reason"],
    ) != (eligible, reason):
        _fail()
    validate_assignment(
        {
            key: row[key]
            for key in ("canonical_id_sha256", "source_ip_rendering", "source_ip_sha256")
        }
    )


def validate_assignment(row: dict[str, Any]) -> None:
    if set(row) != {"canonical_id_sha256", "source_ip_rendering", "source_ip_sha256"}:
        _fail()
    text = row["source_ip_rendering"]
    if type(text) is not str or not text or any(ord(c) < 32 or ord(c) == 127 for c in text):
        _fail()
    if len(text.encode("utf-8")) > 4096:
        _fail("budget_exceeded")
    if row["source_ip_sha256"] != sha256(text.encode("utf-8")).hexdigest():
        _fail()


def _summary(summary: Any, count: int) -> bool:
    return (
        type(summary) is dict
        and set(summary) == {"notes", "numFailed", "numPassed", "numResults"}
        and type(summary["notes"]) is str
        and type(summary["numResults"]) is int
        and summary["numResults"] == count
        and type(summary["numFailed"]) is int
        and summary["numFailed"] == 0
        and type(summary["numPassed"]) is int
        and summary["numPassed"] == 0
    )


def raw_rows(raw: Any, question: str, expression: str) -> list[dict[str, Any]]:
    """Read the full answer.dict() envelope before any SDK DataFrame conversion."""
    if len(json_bytes(raw)) > MAX_RAW_BYTES:
        _fail("budget_exceeded")
    if (
        type(raw) is not dict
        or set(raw) != {"answerElements", "question", "status", "summary"}
        or raw["status"] != "SUCCESS"
        or type(raw["answerElements"]) is not list
        or len(raw["answerElements"]) != 1
    ):
        _fail()
    table = raw["answerElements"][0]
    if (
        type(table) is not dict
        or set(table) != {"class", "excludedRows", "metadata", "rows", "summary", "warnings"}
        or table["class"] != "org.batfish.datamodel.table.TableAnswerElement"
        or table["excludedRows"] != []
        or table["warnings"] != []
        or type(table["rows"]) is not list
    ):
        _fail()
    rows = table["rows"]
    if len(rows) > MAX_ROWS:
        _fail("budget_exceeded")
    metadata = table["metadata"]
    if (
        type(metadata) is not dict
        or set(metadata) != {"columnMetadata", "textDesc"}
        or type(metadata["textDesc"]) is not str
        or type(metadata["columnMetadata"]) is not list
    ):
        _fail()
    expected = _COLUMNS[question]
    columns = metadata["columnMetadata"]
    if len(columns) != len(expected):
        _fail()
    found = set()
    for col in columns:
        if (
            type(col) is not dict
            or set(col) != {"name", "schema", "isKey", "isValue", "description"}
            or type(col["name"]) is not str
            or col["name"] not in expected
            or col["name"] in found
            or type(col["isKey"]) is not bool
            or type(col["isValue"]) is not bool
            or type(col["description"]) is not str
            or (col["schema"], col["isKey"], col["isValue"]) != expected[col["name"]]
        ):
            _fail()
        found.add(col["name"])
    for row in rows:
        if type(row) is not dict or set(row) != set(expected):
            _fail()
    # The pinned resolver emits no table summary and this exact non-counting top sentinel.
    if table["summary"] is None and question != "interfaceProperties":
        if not _summary(raw["summary"], 0) or raw["summary"]["notes"] != "":
            _fail()
    elif not _summary(table["summary"], len(rows)) or not _summary(raw["summary"], len(rows)):
        _fail()
    q = raw["question"]
    if (
        type(q) is not dict
        or q.get("differential") is not False
        or q.get("assertion") is not None
        or q.get("exclusions") is not None
    ):
        _fail()
    if question == "interfaceProperties":
        if (
            q.get("class") != "org.batfish.question.interfaceproperties.InterfacePropertiesQuestion"
            or q.get("nodes") != expression
            or q.get("interfaces") is not None
            or q.get("excludeShutInterfaces") is not False
            or q.get("properties") != "Active,Switchport,All_Prefixes,Interface_Type"
        ):
            _fail()
    elif (
        q.get("class") != "org.batfish.question.specifiers.SpecifiersQuestion"
        or q.get("locationSpecifierInput") != expression
        or q.get("queryType")
        != ("LOCATION" if question == "resolveLocationSpecifier" else "IP_SPACE_OF_LOCATION")
        or q.get("specifierFactoryVersion") != "V2"
        or any(
            q.get(selector) is not None
            for selector in (
                "filterSpecifierInput",
                "interfaceSpecifierInput",
                "ipSpaceSpecifierInput",
                "nodeSpecifierInput",
            )
        )
    ):
        _fail()
    return cast(list[dict[str, Any]], rows)


def extract_side(answers: dict[str, Any], node: str) -> dict[str, Any]:
    expression = json.dumps(node)
    selected_rows = raw_rows(
        answers["resolveLocationSpecifier"], "resolveLocationSpecifier", expression
    )
    properties = raw_rows(answers["interfaceProperties"], "interfaceProperties", expression)
    assignments = raw_rows(
        answers["resolveIpsOfLocationSpecifier"], "resolveIpsOfLocationSpecifier", expression
    )
    selected: set[str] = set()
    for row in selected_rows:
        text = row["Location"]
        if type(text) is not str or text in selected:
            _fail("unsupported_location")
        selected.add(text)
    by_location: dict[str, dict[str, Any]] = {}
    for row in properties:
        identity = row["Interface"]
        if (
            type(identity) is not dict
            or set(identity) != {"hostname", "interface"}
            or identity["hostname"] != node
        ):
            _fail("unsupported_location")
        rendered = location_rendering(identity["hostname"], identity["interface"])
        if rendered in by_location:
            _fail("unsupported_location")
        prefixes = row["All_Prefixes"]
        if type(prefixes) is not list:
            _fail()
        if len(prefixes) > MAX_PREFIXES:
            _fail("budget_exceeded")
        if any(type(p) is not str for p in prefixes):
            _fail()
        prefixes = sorted({str(IPv4Interface(p)) for p in prefixes})
        if type(row["Active"]) is not bool or type(row["Switchport"]) is not bool:
            _fail()
        eligible, reason = eligibility(row["Active"], row["Switchport"], prefixes)
        by_location[rendered] = dict(
            node=node,
            interface=identity["interface"],
            canonical_id_sha256=canonical_id(node, identity["interface"]),
            location_rendering=rendered,
            active=row["Active"],
            switchport=row["Switchport"],
            interface_type=row["Interface_Type"],
            concrete_ipv4_prefixes=prefixes,
            eligible=eligible,
            eligibility_reason=reason,
        )
    if selected != set(by_location):
        _fail("unsupported_location")
    seen: set[str] = set()
    for row in assignments:
        rendered = row["Locations"]
        if type(rendered) is not str:
            _fail("incomplete_assignment")
        matches = [location for location in selected if rendered == f"[{location}]"]
        if len(matches) != 1 or matches[0] in seen:
            _fail("incomplete_assignment")
        location = matches[0]
        seen.add(location)
        text = row["IP_Space"]
        if type(text) is not str:
            _fail()
        by_location[location].update(
            source_ip_rendering=text, source_ip_sha256=sha256(text.encode("utf-8")).hexdigest()
        )
    if seen != selected:
        _fail("incomplete_assignment")
    interfaces = sorted(by_location.values(), key=lambda row: row["canonical_id_sha256"])
    for interface in interfaces:
        validate_interface(interface)
    return {"interfaces": interfaces}


def derived_fields(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    sides = []
    for side in (before, after):
        if type(side) is not dict or set(side) != {"interfaces"}:
            _fail()
        rows = side["interfaces"]
        if type(rows) is not list or len(rows) > MAX_ROWS:
            _fail()
        for row in rows:
            validate_interface(row)
        ids = [row["canonical_id_sha256"] for row in rows]
        if ids != sorted(set(ids)):
            _fail()
        sides.append({row["canonical_id_sha256"]: row for row in rows})
    left, right = sides
    complete = all(row["eligible"] is not None for side in sides for row in side.values())
    result: dict[str, Any] = dict(
        eligibility_complete=complete,
        selected_before_only=sorted(left.keys() - right.keys()),
        selected_after_only=sorted(right.keys() - left.keys()),
        common_eligible=None,
        before_eligible_only=None,
        after_eligible_only=None,
        after_common_assignments=None,
    )
    if complete:
        left_eligible = {key for key, row in left.items() if row["eligible"]}
        right_eligible = {key for key, row in right.items() if row["eligible"]}
        common = sorted(left_eligible & right_eligible)
        result.update(
            common_eligible=common,
            before_eligible_only=sorted(left_eligible - right_eligible),
            after_eligible_only=sorted(right_eligible - left_eligible),
            after_common_assignments=[
                {
                    key: right[item][key]
                    for key in ("canonical_id_sha256", "source_ip_rendering", "source_ip_sha256")
                }
                for item in common
            ],
        )
    return result


def empty_scope(request: dict[str, Any], state: str, reason: str) -> dict[str, Any]:
    return dict(
        version="ingress-scope-0.1.0",
        before_sha256=request["before_sha256"],
        after_sha256=request["after_sha256"],
        scope=request["scope"],
        network_name=request.get("network_name"),
        acquisition_state=state,
        reason=reason,
        before=None,
        after=None,
        eligibility_complete=None,
        selected_before_only=None,
        selected_after_only=None,
        common_eligible=None,
        before_eligible_only=None,
        after_eligible_only=None,
        after_common_assignments=None,
        semantic_ip_sets_verified=False,
        complete_flow_coverage=False,
        source_assignment_context="after",
        method=INGRESS_METHOD,
        limitations=list(INGRESS_LIMITATIONS),
    )


def observe_scope(session: Any, request: dict[str, Any]) -> dict[str, Any]:
    observation = empty_scope(request, "unknown", "query_failed")
    try:
        expression = json.dumps(request["scope"]["start_node"])
        sides = {}
        for side in ("before", "after"):
            answers = {}
            for name in _COLUMNS:
                params = (
                    dict(
                        nodes=expression,
                        properties="Active,Switchport,All_Prefixes,Interface_Type",
                        excludeShutInterfaces=False,
                    )
                    if name == "interfaceProperties"
                    else dict(locations=expression)
                )
                answer = getattr(session.q, name)(**params).answer(snapshot=side)
                answers[name] = answer.dict()
                # Reject an oversized answer before retaining subsequent responses.
                raw_rows(answers[name], name, expression)
            sides[side] = extract_side(answers, request["scope"]["start_node"])
        observation.update(
            acquisition_state="observed",
            reason="query_completed",
            **sides,
            **derived_fields(sides["before"], sides["after"]),
        )
        if len(json_bytes(observation)) > MAX_OBSERVATION_BYTES:
            _fail("budget_exceeded")
        return observation
    except IngressExtractionError as exc:
        return empty_scope(request, "unknown", str(exc))
    except (ValueError, TypeError, KeyError, UnicodeError):
        return empty_scope(request, "unknown", "unsupported_answer")
    except Exception:
        return (
            observation
            if observation["acquisition_state"] == "unknown"
            else empty_scope(request, "unknown", "unsupported_answer")
        )
