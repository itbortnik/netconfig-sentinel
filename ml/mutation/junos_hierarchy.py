"""Bounded, source-preserving edits of the parser's multiline JunOS subset.

This is an offline synthetic generator, not a vendor grammar or patch applier.
The caller reparses the entire result and checks each requested canonical effect.
"""

from __future__ import annotations

import hashlib
import shlex
from dataclasses import dataclass, field
from ipaddress import ip_address, ip_interface, ip_network
from itertools import pairwise

from app.domain import AclRule, CanonicalConfig, SourceLocation

from ml.mutation.engine import (
    MutationNotApplicableError,
    _changed_line_numbers,
    _different_area,
    _different_asn,
    _MutationSpec,
    _replace_span,
)
from ml.mutation.models import (
    STRUCTURAL_MUTATION_ENGINE_VERSION,
    MutationOperation,
    MutationType,
)


@dataclass
class _Node:
    tokens: tuple[str, ...]
    start: int
    end: int
    code_start: int
    code_end: int
    block: bool
    parent: _Node | None
    children: list[_Node] = field(default_factory=list)

    @property
    def path(self) -> tuple[tuple[str, ...], ...]:
        return (*self.parent.path, self.tokens) if self.parent else (self.tokens,)


@dataclass(frozen=True)
class _Edit:
    start: int
    end: int
    replacement: tuple[str, ...]


def _fail() -> MutationNotApplicableError:
    # Do not include input text, identifiers or credentials in diagnostics.
    return MutationNotApplicableError("hierarchical source is unsupported or ambiguous")


def _area(value: str) -> str:
    try:
        return str(ip_address(int(value) if value.isdigit() else value))
    except ValueError:
        raise _fail() from None


def _code(raw: str) -> tuple[int, int, str]:
    start = len(raw) - len(raw.lstrip())
    quote = ""
    escaped = False
    end = len(raw)
    structure: list[tuple[int, str]] = []
    for index in range(start, len(raw)):
        char = raw[index]
        if escaped:
            escaped = False
        elif quote:
            if char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
        elif char in {'"', "\u0027"}:
            quote = char
        elif raw[index : index + 2] == "//":
            end = index
            break
        elif char == "#" or raw[index : index + 2] in {"/*", "*/"}:
            raise _fail()
        elif char in "{};":
            structure.append((index, char))
    if quote:
        raise _fail()
    end = len(raw[:end].rstrip())
    code = raw[start:end]
    expected = (
        [(end - 2, "}"), (end - 1, ";")] if code == "};" else [(end - 1, code[-1])] if code else []
    )
    if structure != expected:
        raise _fail()
    return start, end, code


def _tree(lines: list[str]) -> list[_Node]:
    if len(lines) > 50_000 or len("\n".join(lines).encode("utf-8")) > 1_048_576:
        raise _fail()
    if any(any((ord(c) < 32 and c != "\t") or ord(c) == 127 for c in line) for line in lines):
        raise _fail()
    stack: list[_Node] = []
    nodes: list[_Node] = []
    roots: list[_Node] = []
    comment = False
    # Scalar repetitions and repeated keyed nodes can conceal overrides. Refuse
    # them instead of editing a value whose effective meaning is uncertain.
    keyed = {
        "address",
        "server",
        "host",
        "neighbor",
        "route",
        "radius-server",
        "tacplus-server",
        "family",
        "unit",
        "term",
        "filter",
        "group",
        "area",
        "community",
        "user",
        "prefix-list",
        "interface",
    }
    sibling_keys: dict[int, set[tuple[str, ...]]] = {}
    for index, raw in enumerate(lines):
        stripped = raw.strip()
        if comment or stripped.startswith("/*"):
            if "*/" in stripped:
                if stripped.split("*/", 1)[1].strip():
                    raise _fail()
                comment = False
            else:
                comment = True
            # The canonical adapter only treats these comment-only lines as
            # comments; arbitrary prose continuations cannot be hidden here.
            if not stripped.startswith(("/*", "*")):
                raise _fail()
            continue
        if not stripped or stripped.startswith(("#", "//")):
            continue
        start, _end, code = _code(raw)
        if code in {"}", "};"}:
            if not stack:
                raise _fail()
            stack.pop().end = index + 1
            continue
        block = code.endswith("{")
        if not block and not code.endswith(";"):
            raise _fail()
        body = code[:-1].rstrip()
        try:
            tokens = tuple(shlex.split(body))
        except ValueError:
            raise _fail() from None
        if not tokens:
            raise _fail()
        if tokens[0].casefold() in {
            "set",
            "inactive:",
            "replace:",
            "delete:",
            "groups",
            "apply-groups",
            "apply-groups-except",
            "apply-macro",
        }:
            raise _fail()
        parent = stack[-1] if stack else None
        siblings = parent.children if parent else roots
        key = (
            (tokens[0].casefold(), *tokens[1:2])
            if tokens[0].casefold() in keyed
            else (tokens[0].casefold(),)
        )
        if tokens[0] == "area" and len(tokens) == 2:
            key = ("area", _area(tokens[1]))
        seen = sibling_keys.setdefault(parent.start if parent else -1, set())
        if key in seen:
            raise _fail()
        seen.add(key)
        node = _Node(tokens, index, index + 1, start, start + len(body), block, parent)
        nodes.append(node)
        if len(nodes) > 4096:
            raise _fail()
        siblings.append(node)
        if block:
            stack.append(node)
            if len(stack) > 64:
                raise _fail()
    if stack or comment or not roots or any(not node.block for node in roots):
        raise _fail()
    return nodes


def validate_hierarchical_source(lines: list[str]) -> None:
    """Validate bounded source layout before invoking the canonical adapter."""
    _tree(lines)


def _rewrite(lines: list[str], node: _Node, body: str) -> _Edit:
    raw = lines[node.start]
    # Keep indentation, delimiter, whitespace and trailing comment byte-for-byte.
    return _Edit(
        node.start, node.start + 1, (raw[: node.code_start] + body + raw[node.code_end :],)
    )


def _remove(node: _Node) -> _Edit:
    return _Edit(node.start, node.end, ())


def _indent(lines: list[str], node: _Node) -> str:
    return lines[node.start][: node.code_start]


def _child_indent(lines: list[str], node: _Node) -> str:
    base = _indent(lines, node)
    if node.children:
        child = _indent(lines, node.children[0])
        if child.startswith(base) and len(child) > len(base):
            return child
    return base + ("\t" if "\t" in base else "    ")


def _clean(node: _Node, config: CanonicalConfig) -> bool:
    return not any(
        any(node.start < line <= node.end for line in fragment.location.source_lines)
        for fragment in config.unparsed_fragments
    )


def _fact_nodes(nodes: list[_Node], fact: SourceLocation | None) -> list[_Node]:
    if fact is None or len(fact.source_lines) != 1:
        return []
    return [node for node in nodes if node.start + 1 == fact.source_lines[0]]


def _terms(nodes: list[_Node], config: CanonicalConfig) -> list[tuple[_Node, AclRule]]:
    result: list[tuple[_Node, AclRule]] = []
    for acl in config.acls:
        family = "inet" if acl.family == "ipv4" else "inet6"
        for rule in acl.rules:
            path = (("firewall",), ("family", family), ("filter", acl.name), ("term", rule.term))
            result.extend((node, rule) for node in nodes if node.path == path)
    return result


def _plans(
    lines: list[str], nodes: list[_Node], config: CanonicalConfig, kind: MutationType
) -> list[list[_Edit]]:
    plans: list[list[_Edit]] = []
    if kind is MutationType.AAA_DISABLED and config.management.aaa_enabled:
        edits: list[_Edit] = []
        for node in nodes:
            if node.parent and node.parent.path == (("system",),):
                if node.tokens[0] in {"radius-server", "tacplus-server"}:
                    if not _clean(node, config):
                        raise _fail()
                    edits.append(_remove(node))
                elif node.tokens[0] == "authentication-order" and not node.block:
                    edits.append(_rewrite(lines, node, "authentication-order password"))
        if edits:
            plans.append(edits)
    elif kind is MutationType.TELNET_ENABLED and (
        config.management.ssh_enabled and not config.management.telnet_enabled
    ):
        for node in nodes:
            if node.path == (("system",), ("services",), ("ssh",)):
                for position in (node.start, node.end):
                    plans.append([_Edit(position, position, (_indent(lines, node) + "telnet;",))])
    elif kind is MutationType.SNMP_DOWNGRADE and (
        "v3" in config.management.snmp_versions
        and not {"v1", "v2c"}.intersection(config.management.snmp_versions)
    ):
        for node in nodes:
            if node.path == (("snmp",), ("v3",)) and node.parent:
                indent = _indent(lines, node)
                child = _child_indent(lines, node)
                replacement = (
                    indent + "community <redacted-community> {",
                    child + "authorization read-only;",
                    indent + "}",
                )
                for position in (node.start, node.end):
                    plans.append([_Edit(position, position, replacement)])
    elif kind in {
        MutationType.PERMISSIVE_ACL,
        MutationType.MISSING_ACL_ENTRY,
        MutationType.MANAGEMENT_EXPOSURE,
    }:
        for term, rule in _terms(nodes, config):
            if not _clean(term, config):
                continue
            if kind is MutationType.MISSING_ACL_ENTRY and rule.action == "permit":
                plans.append([_remove(term)])
            elif (
                kind is MutationType.PERMISSIVE_ACL
                and rule.action == "deny"
                and (
                    (not rule.source_addresses or "any" in rule.source_addresses)
                    and (not rule.destination_addresses or "any" in rule.destination_addresses)
                )
            ):
                for node in _fact_nodes(nodes, rule.provenance.get("action")):
                    body = "then accept" if node.tokens[0] == "then" else "accept"
                    plans.append([_rewrite(lines, node, body)])
            elif (
                kind is MutationType.MANAGEMENT_EXPOSURE
                and rule.action == "permit"
                and (
                    rule.source_addresses
                    and not {"any", "0.0.0.0/0", "::/0"}.intersection(rule.source_addresses)
                )
            ):
                for node in nodes:
                    if node.block or node.path[: len(term.path)] != term.path:
                        continue
                    parent = node.parent
                    if not parent:
                        continue
                    prefix = ""
                    if parent.tokens == ("from",) and node.tokens[0] == "source-address":
                        prefix = "source-address "
                    elif parent.tokens != ("source-address",):
                        continue
                    any_source = "::/0" if term.path[1] == ("family", "inet6") else "0.0.0.0/0"
                    plans.append([_rewrite(lines, node, prefix + any_source)])
    elif kind in {MutationType.VLAN_MISMATCH, MutationType.INCORRECT_ACCESS_TRUNK_MODE}:
        for interface in config.interfaces:
            if kind is MutationType.VLAN_MISMATCH and interface.access_vlan:
                for node in _fact_nodes(nodes, interface.access_vlan.provenance):
                    values = [token for token in node.tokens[1:] if token not in {"[", "]"}]
                    if node.tokens[0] != "members" or len(values) != 1 or node.block:
                        continue
                    value = values[0]
                    changed = (
                        str(1 if int(value) == 4094 else int(value) + 1)
                        if (value.isdigit())
                        else value + "-MISMATCH"
                    )
                    body = f"members [ {changed} ]" if "[" in node.tokens else f"members {changed}"
                    plans.append([_rewrite(lines, node, body)])
            elif kind is MutationType.INCORRECT_ACCESS_TRUNK_MODE and interface.switchport_mode:
                for node in _fact_nodes(nodes, interface.provenance.get("switchport_mode")):
                    mode = "trunk" if interface.switchport_mode == "access" else "access"
                    plans.append([_rewrite(lines, node, f"{node.tokens[0]} {mode}")])
    elif kind in {MutationType.BGP_REMOTE_AS_MISMATCH, MutationType.MISSING_BGP_NEIGHBOR}:
        if config.bgp:
            for neighbor in config.bgp.neighbors:
                path = (("protocols",), ("bgp",), ("group", neighbor.group))
                for node in nodes:
                    if not node.parent or node.parent.path != path:
                        continue
                    if len(node.tokens) < 2 or node.tokens[0] != "neighbor":
                        continue
                    try:
                        address_matches = str(ip_address(node.tokens[1])) == neighbor.address
                    except ValueError:
                        address_matches = False
                    if not address_matches or not _clean(node, config):
                        continue
                    if kind is MutationType.MISSING_BGP_NEIGHBOR:
                        plans.append([_remove(node)])
                    else:
                        asn = _different_asn(neighbor.remote_as)
                        if not node.block:
                            # Preserve a supported inline description/local-address/disable
                            # while adding an explicit peer override in a native block.
                            indent = _indent(lines, node)
                            child = indent + ("\t" if "\t" in indent else "    ")
                            raw = lines[node.start]
                            suffix = raw[node.code_end + 1 :]
                            parts = raw[node.code_start : node.code_end].split(maxsplit=2)
                            preserved = (
                                (child + parts[2] + ";",)
                                if len(parts) == 3 and node.tokens[2] != "peer-as"
                                else ()
                            )
                            plans.append(
                                [
                                    _Edit(
                                        node.start,
                                        node.end,
                                        (
                                            indent + f"neighbor {node.tokens[1]} {{" + suffix,
                                            *preserved,
                                            child + f"peer-as {asn};",
                                            indent + "}",
                                        ),
                                    )
                                ]
                            )
                        else:
                            explicit = [
                                child for child in node.children if child.tokens[0] == "peer-as"
                            ]
                            if explicit:
                                plans.append([_rewrite(lines, explicit[0], f"peer-as {asn}")])
                            else:
                                plans.append(
                                    [
                                        _Edit(
                                            node.end - 1,
                                            node.end - 1,
                                            (_child_indent(lines, node) + f"peer-as {asn};",),
                                        )
                                    ]
                                )
    elif kind is MutationType.OSPF_AREA_MISMATCH:
        for area in nodes:
            if not area.block or not area.parent or area.parent.path != (("protocols",), ("ospf",)):
                continue
            if len(area.tokens) != 2 or area.tokens[0] != "area":
                continue
            new_area = _different_area(_area(area.tokens[1]))
            target = next(
                (
                    item
                    for item in area.parent.children
                    if len(item.tokens) == 2
                    and item.tokens[0] == "area"
                    and _area(item.tokens[1]) == _area(new_area)
                ),
                None,
            )
            for ospf_node in area.children:
                if ospf_node.tokens[0] != "interface" or not _clean(ospf_node, config):
                    continue
                moved = tuple(lines[ospf_node.start : ospf_node.end])
                if target:
                    if any(item.tokens[:2] == ospf_node.tokens[:2] for item in target.children):
                        continue
                    old_indent = _indent(lines, ospf_node)
                    new_indent = _child_indent(lines, target)
                    moved = tuple(
                        new_indent + line[len(old_indent) :]
                        if line.startswith(old_indent)
                        else line
                        for line in moved
                    )
                    insert = _Edit(target.end - 1, target.end - 1, moved)
                else:
                    indent = _indent(lines, area)
                    insert = _Edit(
                        area.end,
                        area.end,
                        (
                            indent + f"area {new_area} {{",
                            *moved,
                            indent + "}",
                        ),
                    )
                plans.append([_remove(ospf_node), insert])
    elif kind is MutationType.REMOVED_STATIC_ROUTE:
        destinations = {route.destination for route in config.static_routes}
        for node in nodes:
            if (
                node.parent
                and node.parent.path == (("routing-options",), ("static",))
                and (
                    len(node.tokens) >= 2
                    and node.tokens[0] == "route"
                    and str(ip_network(node.tokens[1], strict=False)) in destinations
                    and _clean(node, config)
                )
            ):
                plans.append([_remove(node)])
    elif kind is MutationType.MISSING_NTP_SYSLOG:
        targets = [
            node
            for node in nodes
            if node.parent
            and (
                (node.parent.path == (("system",), ("ntp",)) and node.tokens[0] == "server")
                or (node.parent.path == (("system",), ("syslog",)) and node.tokens[0] == "host")
            )
        ]
        if any(not _clean(node, config) for node in targets):
            raise _fail()
        edits = [_remove(node) for node in targets]
        if edits:
            plans.append(edits)
    elif kind is MutationType.CONFLICTING_IP_ADDRESS:
        for destination in config.interfaces:
            for source in config.interfaces:
                if (destination.name, destination.unit) == (source.name, source.unit):
                    continue
                for address in destination.addresses:
                    for other in source.addresses:
                        if address.family != other.family or (
                            ip_interface(address.address).ip == ip_interface(other.address).ip
                        ):
                            continue
                        if any(
                            existing.address == other.address for existing in destination.addresses
                        ):
                            continue
                        for node in _fact_nodes(nodes, address.provenance):
                            if node.tokens[0] == "address" and _clean(node, config):
                                plans.append([_rewrite(lines, node, f"address {other.address}")])
    return plans


def mutate_hierarchy(
    lines: list[str],
    config: CanonicalConfig,
    seed: int,
    fingerprint: str,
    kind: MutationType,
    spec: _MutationSpec,
) -> tuple[list[str], MutationOperation]:
    nodes = _tree(lines)
    if sum(len(item.addresses) for item in config.interfaces) > 64:
        raise _fail()
    plans = _plans(lines, nodes, config, kind)
    if not plans:
        raise MutationNotApplicableError(f"precondition is not satisfied: {kind.value}")
    payload = f"{STRUCTURAL_MUTATION_ENGINE_VERSION}\0{fingerprint}\0{seed}\0{kind.value}"
    selected = plans[int(hashlib.sha256(payload.encode()).hexdigest(), 16) % len(plans)]
    edits = sorted(selected, key=lambda item: (item.start, item.end))
    if any(first.end > second.start for first, second in pairwise(edits)):
        raise _fail()
    start, end = min(item.start for item in edits), max(item.end for item in edits)
    replacement = list(lines[start:end])
    for edit in reversed(edits):
        replacement[edit.start - start : edit.end - start] = edit.replacement
    affected = tuple(start + line for line in _changed_line_numbers(lines[start:end], replacement))
    updated, operation = _replace_span(
        lines, start, end, replacement, kind, spec, affected_lines=affected
    )
    _tree(updated)
    return updated, operation
