"""Normalized changes preserve ACL order, omit provenance noise and expose partial scope."""

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from app.api.contracts import ConfigurationSnapshot
from app.api.diff_contracts import ObjectChange, SnapshotDiff
from app.comparison.snapshots import DiffConflict, DiffLimitExceeded, compare_snapshots
from app.parsers import parse_configuration


def snapshot(text: str, *, seconds: int = 0, filename: str = "edge.cfg") -> ConfigurationSnapshot:
    return ConfigurationSnapshot(
        configuration_id=uuid4(),
        device_id=UUID(int=1),
        created_at=datetime(2026, 10, 3, tzinfo=UTC) + timedelta(seconds=seconds),
        canonical=parse_configuration(text, filename=filename),
    )


def test_changes_bind_both_sources_and_do_not_invent_current_lines_for_removal() -> None:
    before = snapshot(
        "hostname edge\ninterface Gi0/1\n description OLD\n!\ninterface Gi0/2\n shutdown\n!\n"
    )
    after = snapshot(
        "hostname edge\ninterface Gi0/1\n description NEW\n!\ninterface Gi0/3\n shutdown\n!\n",
        seconds=1,
    )
    report = compare_snapshots(before, after)
    assert report.coverage == "supported_complete"
    assert (report.added_count, report.removed_count, report.modified_count) == (1, 1, 1)
    assert report.before.source_sha256 == before.canonical.source.sha256
    assert report.after.source_sha256 == after.canonical.source.sha256
    removed = next(item for item in report.changes if item.kind == "removed")
    assert removed.after_value is None and not removed.after_locations
    assert removed.before_locations
    assert SnapshotDiff.model_validate_json(report.model_dump_json()) == report


def test_line_moves_filename_and_collection_metadata_are_not_object_changes() -> None:
    before = snapshot("hostname edge\nntp server 192.0.2.1\nlogging host 192.0.2.2\n")
    after = snapshot(
        "! shifted\nlogging host 192.0.2.2\n\nhostname edge\nntp server 192.0.2.1\n",
        seconds=1,
        filename="other.cfg",
    )
    report = compare_snapshots(before, after)
    assert report.source_changed and report.changes == ()
    assert report.before.projection_sha256 == report.after.projection_sha256


def test_acl_rule_order_is_not_sorted_away() -> None:
    first = " permit ip any any\n deny ip any any\n"
    second = " deny ip any any\n permit ip any any\n"
    before = snapshot("hostname edge\nip access-list extended FILTER\n" + first + "!\n")
    after = snapshot("hostname edge\nip access-list extended FILTER\n" + second + "!\n", seconds=1)
    report = compare_snapshots(before, after)
    assert len(report.changes) == 1 and report.changes[0].section == "acls"


def test_unknown_text_is_excluded_but_cannot_claim_full_coverage() -> None:
    before = snapshot("hostname edge\nunknown PRIVATE-BEFORE\n")
    after = snapshot("hostname edge\nunknown PRIVATE-AFTER\n", seconds=1)
    report = compare_snapshots(before, after)
    assert report.coverage == "partial" and report.source_changed
    assert report.changes == ()
    assert "PRIVATE" not in report.model_dump_json()
    assert report.before.unparsed_count == report.after.unparsed_count == 1


def test_distinct_device_current_reference_future_reference_and_ambiguous_objects_conflict() -> (
    None
):
    before, after = snapshot("hostname edge\n"), snapshot("hostname edge\n", seconds=1)
    for reference, current in (
        (before, before),
        (after, before),
        (before, after.model_copy(update={"device_id": uuid4()})),
        (before, snapshot("hostname other\n", seconds=1)),
    ):
        with pytest.raises(DiffConflict):
            compare_snapshots(reference, current)
    duplicate = parse_configuration(
        "hostname edge\ninterface Gi0/1\n shutdown\n!\n", filename="edge.cfg"
    )
    duplicate.interfaces.append(duplicate.interfaces[0])
    with pytest.raises(DiffConflict):
        compare_snapshots(before, after.model_copy(update={"canonical": duplicate}))


def test_budget_refuses_excess_changes_instead_of_returning_a_truncated_clean_result() -> None:
    before = snapshot("hostname edge\n")
    after = snapshot(
        "hostname edge\n" + "".join(f"interface Gi0/{n}\n shutdown\n!\n" for n in range(501)),
        seconds=1,
    )
    with pytest.raises(DiffLimitExceeded):
        compare_snapshots(before, after)


def test_all_supported_object_sections_and_nested_parameter_changes_are_compared() -> None:
    text = (
        "hostname edge\nversion 17.1\naaa new-model\nip ssh version 2\n"
        "interface Gi0/1\n description LAB\n ip address 192.0.2.1 255.255.255.0\n!\n"
        "vlan 10\n name LAB\n!\nip access-list extended FILTER\n permit ip any any\n!\n"
        "ip prefix-list PREFIX seq 10 permit 192.0.2.0/24\n"
        "ip route 0.0.0.0 0.0.0.0 192.0.2.254\n"
        "router bgp 65000\n bgp router-id 192.0.2.1\n neighbor 192.0.2.2 remote-as 65001\n!\n"
        "router ospf 1\n router-id 192.0.2.1\n network 192.0.2.0 0.0.0.255 area 0\n!\n"
    )
    before = snapshot("hostname edge\n")
    after = snapshot(text, seconds=1)
    report = compare_snapshots(before, after)
    assert report.coverage == "supported_complete"
    assert {item.section for item in report.changes} == {
        "device",
        "management",
        "interfaces",
        "vlans",
        "acls",
        "prefix_lists",
        "static_routes",
        "bgp",
        "bgp_neighbors",
        "ospf",
    }
    next_version = snapshot(
        text.replace("192.0.2.254", "192.0.2.253").replace("remote-as 65001", "remote-as 65002"),
        seconds=2,
    )
    changed = compare_snapshots(after, next_version)
    assert {item.section for item in changed.changes} == {"static_routes", "bgp_neighbors"}


@pytest.mark.parametrize(
    "change",
    [
        {"kind": "removed"},
        {"before_value": {"enabled": True}},
        {"after_value": None},
    ],
)
def test_contract_rejects_impossible_object_changes(change: dict) -> None:
    with pytest.raises(ValueError):
        ObjectChange.model_validate(
            {
                "section": "interfaces",
                "object_key": ["Gi0/1", ""],
                "kind": "added",
                "before_value": None,
                "after_value": {"enabled": True},
            }
            | change
        )
