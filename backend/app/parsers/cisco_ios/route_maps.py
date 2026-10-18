"""Explicit IOS route-map configured facts; no route outcome or effective defaults."""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass

from app.domain import RouteMapClauseConfig, RouteMapConfig, UnparsedFragment
from app.parsers.base import source_location

_NAME = r"[A-Za-z0-9_.:/-]{1,128}"
_HEADER = re.compile(
    rf"route-map (?P<name>{_NAME}) (?P<action>permit|deny) (?P<sequence>[0-9]{{1,5}})",
    re.IGNORECASE,
)
_MATCH = re.compile(rf"match ip address prefix-list (?P<names>{_NAME}(?: {_NAME}){{0,63}})", re.I)
_METRIC = re.compile(r"set metric (?P<value>[0-9]{1,10})", re.I)


@dataclass
class RouteMapParse:
    route_maps: list[RouteMapConfig]
    handled_lines: set[int]
    unparsed: list[UnparsedFragment]
    warnings: list[str]


def parse_route_maps(text: str) -> RouteMapParse:
    """Only global explicit headers and their indented bounded child statements.

    Repeated keys/commands and unsupported children remain unparsed. Recognized
    sibling facts may survive with normalization_complete=false. No implicit
    sequence/action, deletion, continue/call, inherited or reference semantics.
    """
    if len(text.encode("utf-8")) > 1048576 or len(text.splitlines()) > 50000:
        raise ValueError("route-map parser input exceeds its byte/line budget")
    lines = list(enumerate(text.splitlines(), 1))
    if any(
        re.match(
            r"(?:banner(?:\s|$)|macro\s+name(?:\s|$)|tclsh(?:\s|$))",
            " ".join(raw.split()),
            re.I,
        )
        for _, raw in lines
    ):
        return RouteMapParse(
            [],
            set(),
            [],
            ["route-map normalization unavailable with an opaque configuration block"],
        )
    chunks: list[list[tuple[int, str]]] = []
    result = RouteMapParse([], set(), [], [])
    invalid_names: set[str] = set()
    invalidate_all = False
    cursor = 0
    while cursor < len(lines):
        number, raw = lines[cursor]
        command = " ".join(raw.split())
        if raw[:1].isspace() or not re.match(r"(?:no )?route-map(?: |$)", command, re.I):
            cursor += 1
            continue
        chunk = [(number, raw)]
        cursor += 1
        while cursor < len(lines):
            child_number, child_raw = lines[cursor]
            if not child_raw.strip():
                cursor += 1
                continue
            if child_raw.lstrip().startswith("!"):
                cursor += 1
                continue
            if not child_raw[:1].isspace():
                break
            chunk.append((child_number, child_raw))
            cursor += 1
            if child_raw.strip().lower() == "exit":
                break
        result.handled_lines.update(number for number, _ in chunk)
        match = _HEADER.fullmatch(command)
        if match is None or int(match["sequence"]) > 65535:
            tokens = command.split()
            offset = 2 if tokens[0].lower() == "no" else 1
            if len(tokens) > offset and re.fullmatch(_NAME, tokens[offset]):
                invalid_names.add(tokens[offset])
            else:
                invalidate_all = True
            _unknown(result, chunk)
            result.warnings.append(f"unsupported route-map header at line {number}")
        else:
            chunks.append(chunk)

    if len(chunks) > 1024:
        raise ValueError("route-map parser exceeds its clause budget")
    keys = Counter((_header(chunk)["name"], int(_header(chunk)["sequence"])) for chunk in chunks)
    maps: dict[str, list[RouteMapClauseConfig]] = defaultdict(list)
    headers: dict[str, list[tuple[int, str]]] = defaultdict(list)
    for chunk in chunks:
        match = _header(chunk)
        name, sequence = match["name"], int(match["sequence"])
        headers[name].append(chunk[0])
        if keys[(name, sequence)] > 1:
            invalid_names.add(name)
            _unknown(result, chunk)
            result.warnings.append(f"ambiguous route-map sequence at line {chunk[0][0]}")
            continue
        facts = {"header": source_location([chunk[0]])}
        matching: list[tuple[tuple[int, str], tuple[str, ...]]] = []
        metrics: list[tuple[tuple[int, str], int]] = []
        complete = True
        for number, raw in chunk[1:]:
            command = " ".join(raw.split())
            if command.lower() == "exit":
                continue
            child_match = _MATCH.fullmatch(command)
            child_metric = _METRIC.fullmatch(command)
            if child_match and len(set(child_match["names"].split())) == len(
                child_match["names"].split()
            ):
                matching.append(((number, raw), tuple(child_match["names"].split())))
            elif child_metric and int(child_metric["value"]) <= 4294967295:
                metrics.append(((number, raw), int(child_metric["value"])))
            else:
                complete = False
                _unknown(result, [(number, raw)])
        references: tuple[str, ...] = ()
        metric = None
        for key, rows in (("match_ipv4_prefix_lists", matching), ("set_metric", metrics)):
            if len(rows) == 1:
                facts[key] = source_location([rows[0][0]])
            elif len(rows) > 1:
                complete = False
                _unknown(result, [row[0] for row in rows])
                result.warnings.append(f"ambiguous route-map child at line {rows[0][0][0]}")
        if len(matching) == 1:
            references = matching[0][1]
        if len(metrics) == 1:
            metric = metrics[0][1]
        maps[name].append(
            RouteMapClauseConfig(
                sequence=sequence,
                action=match["action"].lower(),
                match_ipv4_prefix_lists=references,
                set_metric=metric,
                normalization_complete=complete,
                provenance=facts,
            )
        )
    for name in sorted(maps):
        clauses = sorted(maps[name], key=lambda item: item.sequence)
        result.route_maps.append(
            RouteMapConfig(
                name=name,
                clauses=clauses,
                normalization_complete=not invalidate_all
                and name not in invalid_names
                and all(item.normalization_complete for item in clauses),
                provenance={"name": source_location(headers[name])},
            )
        )
    return result


def _header(chunk: list[tuple[int, str]]) -> re.Match[str]:
    match = _HEADER.fullmatch(" ".join(chunk[0][1].split()))
    assert match is not None
    return match


def _unknown(result: RouteMapParse, lines: list[tuple[int, str]]) -> None:
    result.unparsed.extend(
        UnparsedFragment(raw_text=raw, location=source_location([(number, raw)], 0.0))
        for number, raw in lines
    )
