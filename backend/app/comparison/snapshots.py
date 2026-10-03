"""Bounded normalized object changes with source anchors on their own side only."""

import json
from hashlib import sha256
from typing import Any

from pydantic import BaseModel, JsonValue

from app.api.contracts import ConfigurationSnapshot
from app.api.diff_contracts import DiffSection, DiffSnapshot, ObjectChange, SnapshotDiff
from app.domain import CanonicalConfig, SourceLocation

MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_OUTPUT_BYTES = 2 * 1024 * 1024
MAX_CHANGES = 500
type ObjectKey = tuple[DiffSection, tuple[str, ...]]
type ObjectIndex = dict[ObjectKey, tuple[dict[str, JsonValue], tuple[SourceLocation, ...]]]


class DiffConflict(ValueError):
    """Inputs do not identify an unambiguous older version of the same device."""


class DiffLimitExceeded(ValueError):
    """Comparison was refused, never silently truncated."""


def _dump(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )


def _strip_provenance(value: JsonValue) -> JsonValue:
    if isinstance(value, dict):
        return {key: _strip_provenance(item) for key, item in value.items() if key != "provenance"}
    if isinstance(value, list):
        return [_strip_provenance(item) for item in value]
    return value


def _normal(model: BaseModel) -> dict[str, JsonValue]:
    value = _strip_provenance(model.model_dump(mode="json"))
    assert isinstance(value, dict)
    return value


def _locations(value: Any) -> tuple[SourceLocation, ...]:
    found: dict[str, SourceLocation] = {}

    def visit(item: Any) -> None:
        if isinstance(item, SourceLocation):
            found[_dump(item.model_dump(mode="json"))] = item
        elif isinstance(item, BaseModel):
            for name in type(item).model_fields:
                visit(getattr(item, name))
        elif isinstance(item, dict):
            for nested in item.values():
                visit(nested)
        elif isinstance(item, (list, tuple)):
            for nested in item:
                visit(nested)

    visit(value)
    return tuple(found[key] for key in sorted(found))


def _objects(config: CanonicalConfig) -> ObjectIndex:
    index: ObjectIndex = {}

    def add(
        section: DiffSection,
        key: tuple[str, ...],
        model: BaseModel,
        values: dict[str, JsonValue] | None = None,
    ) -> None:
        identity = section, key
        if identity in index:
            raise DiffConflict("ambiguous duplicate object identity")
        index[identity] = (values if values is not None else _normal(model), _locations(model))

    add("device", ("metadata",), config.device)
    management = _normal(config.management)
    for name in ("snmp_versions", "ntp_servers", "syslog_servers"):
        items = management[name]
        assert isinstance(items, list)
        management[name] = sorted(items, key=_dump)
    add("management", ("global",), config.management, management)
    for interface in config.interfaces:
        values = _normal(interface)
        addresses = values["addresses"]
        assert isinstance(addresses, list)
        values["addresses"] = sorted(addresses, key=_dump)
        allowed = values["allowed_vlans"]
        if isinstance(allowed, dict):
            for name in ("vlan_names", "vlan_ids"):
                items = allowed[name]
                assert isinstance(items, list)
                allowed[name] = sorted(items, key=_dump)
        add("interfaces", (interface.name, interface.unit or ""), interface, values)
    for vlan in config.vlans:
        key = f"id:{vlan.vlan_id}" if vlan.vlan_id is not None else f"name:{vlan.name}"
        add("vlans", (key,), vlan)
    for acl in config.acls:
        # ACL/filter and prefix-list rule order remains intact.
        add("acls", (acl.family, acl.kind, acl.name), acl)
    for prefix in config.prefix_lists:
        add("prefix_lists", (prefix.family, prefix.name), prefix)
    routes: dict[tuple[str, str], list[BaseModel]] = {}
    for route in config.static_routes:
        routes.setdefault((route.family, route.destination), []).append(route)
    for route_key, group in routes.items():
        index[("static_routes", route_key)] = (
            {"routes": sorted([_normal(item) for item in group], key=_dump)},
            _locations(group),
        )
    if config.bgp is not None:
        values = _normal(config.bgp)
        del values["neighbors"]
        add("bgp", ("global",), config.bgp, values)
        # General BGP anchors do not borrow neighbor-only provenance.
        index[("bgp", ("global",))] = (values, _locations(config.bgp.provenance))
        for neighbor in config.bgp.neighbors:
            add("bgp_neighbors", (neighbor.address,), neighbor)
    for process in config.ospf:
        # Preserve network statement order: overlapping prefixes can be order-sensitive.
        add("ospf", (process.process_id,), process)
    return index


def _projection_hash(index: ObjectIndex) -> str:
    values = [[section, list(key), index[(section, key)][0]] for section, key in sorted(index)]
    return sha256(_dump(values).encode("utf-8")).hexdigest()


def _binding(snapshot: ConfigurationSnapshot, index: ObjectIndex) -> DiffSnapshot:
    config = snapshot.canonical
    return DiffSnapshot(
        configuration_id=snapshot.configuration_id,
        device_id=snapshot.device_id,
        created_at=snapshot.created_at,
        source_sha256=config.source.sha256,
        vendor=config.device.vendor,
        platform=config.device.platform,
        hostname=config.device.hostname,
        projection_sha256=_projection_hash(index),
        parser_confidence=config.parser_confidence,
        warning_count=len(config.parse_warnings),
        unparsed_count=len(config.unparsed_fragments),
    )


def compare_snapshots(before: ConfigurationSnapshot, after: ConfigurationSnapshot) -> SnapshotDiff:
    if (
        len(before.model_dump_json().encode("utf-8")) + len(after.model_dump_json().encode("utf-8"))
        > MAX_INPUT_BYTES
    ):
        raise DiffLimitExceeded("comparison input exceeds limits")
    before = ConfigurationSnapshot.model_validate_json(before.model_dump_json())
    after = ConfigurationSnapshot.model_validate_json(after.model_dump_json())
    if before.created_at.utcoffset() is None or after.created_at.utcoffset() is None:
        raise DiffConflict("comparison timestamps require a timezone")
    old, new = before.canonical.device, after.canonical.device
    if (
        before.configuration_id == after.configuration_id
        or before.created_at > after.created_at
        or (before.device_id, old.vendor, old.platform, old.hostname)
        != (after.device_id, new.vendor, new.platform, new.hostname)
    ):
        raise DiffConflict("incompatible comparison inputs")
    previous, current = _objects(before.canonical), _objects(after.canonical)
    changes: list[ObjectChange] = []
    for section, key in sorted(previous.keys() | current.keys()):
        old_object, new_object = previous.get((section, key)), current.get((section, key))
        if old_object is not None and new_object is not None and old_object[0] == new_object[0]:
            continue
        if len(changes) >= MAX_CHANGES:
            raise DiffLimitExceeded("too many object changes")
        changes.append(
            ObjectChange(
                section=section,
                object_key=key,
                kind="added"
                if old_object is None
                else ("removed" if new_object is None else "modified"),
                before_value=old_object[0] if old_object else None,
                after_value=new_object[0] if new_object else None,
                before_locations=old_object[1] if old_object else (),
                after_locations=new_object[1] if new_object else (),
            )
        )
    old_binding, new_binding = _binding(before, previous), _binding(after, current)
    report = SnapshotDiff(
        before=old_binding,
        after=new_binding,
        coverage="supported_complete"
        if old_binding.complete and new_binding.complete
        else "partial",
        source_changed=old_binding.source_sha256 != new_binding.source_sha256,
        added_count=sum(item.kind == "added" for item in changes),
        removed_count=sum(item.kind == "removed" for item in changes),
        modified_count=sum(item.kind == "modified" for item in changes),
        changes=tuple(changes),
        limitations=(
            "Normalized supported objects only; original files are not stored or reconstructed.",
            "Unsupported fragments, parser diagnostics, source metadata and "
            "provenance-only changes are excluded.",
            "Object source anchors belong to their own snapshot, not exact edited-line ranges.",
            "ACL/filter, prefix-list and OSPF network statement order is preserved; "
            "other selected memberships are normalized.",
            "A zero-change result is not raw equality, network equivalence, safety, "
            "approval or formal verification.",
            "Values may contain confidential information; "
            "this comparison is not a sanitization boundary.",
        ),
    )
    if len(report.model_dump_json().encode("utf-8")) > MAX_OUTPUT_BYTES:
        raise DiffLimitExceeded("comparison output exceeds limits")
    return report
