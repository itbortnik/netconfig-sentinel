"""Conservative IOS numbered standard ACL facts, not packet-filter simulation."""

from datetime import UTC, datetime
from hashlib import sha256
from uuid import UUID

import pytest
from app.detection.policy_engine import evaluate_policies
from app.domain import CanonicalConfig
from app.parsers.coverage import parse_configuration_with_coverage
from app.policies import ACCESS_CONTROL_RULES

STAMP = datetime(2026, 10, 11, tzinfo=UTC)
ACL_RULES = ACCESS_CONTROL_RULES


def parse(source):
    return parse_configuration_with_coverage(source, filename="owned.cfg", collected_at=STAMP)


@pytest.mark.parametrize("identifier", [1, 99, 1300, 1999])
@pytest.mark.parametrize(
    "operand,expected",
    [
        ("any", "any"),
        ("host 192.0.2.7", "192.0.2.7/32"),
        ("192.0.2.7", "192.0.2.7/32"),
        ("192.0.2.7 0.0.0.255", "192.0.2.0/24"),
        ("192.0.2.7 0.0.0.0", "192.0.2.7/32"),
        ("192.0.2.7 255.255.255.255", "any"),
    ],
)
def test_complete_standard_rows_have_exact_canonical_and_hash_anchors(
    identifier, operand, expected
):
    row = f"access-list {identifier} permit {operand}"
    parsed = parse(f"hostname owned\n{row}\n")
    config = parsed.canonical
    assert not config.unparsed_fragments and not config.parse_warnings
    assert config.parser_confidence == 1
    assert parsed.coverage.accepted_units == 2 and parsed.coverage.unparsed_units == 0
    acl = config.acls[0]
    assert (acl.name, acl.kind, acl.family) == (str(identifier), "standard", "ipv4")
    rule = acl.rules[0]
    assert rule.source_addresses == [expected] and rule.action == "permit"
    assert rule.sequence is None and rule.protocol is None and rule.term is None
    assert (
        rule.destination_addresses
        == rule.source_ports
        == rule.destination_ports
        == rule.options
        == []
    )
    for anchor in (rule.provenance["rule"], acl.provenance["name"]):
        assert anchor.source_lines == [2]
        assert anchor.raw_text_hash == sha256(row.encode()).hexdigest()
    assert CanonicalConfig.model_validate_json(config.model_dump_json()) == config


def test_grouping_keeps_interleaved_acl_order_repeats_and_non_acl_context():
    rows = [
        "hostname owned",
        "access-list 7 deny host 192.0.2.7",
        "access-list 1300 permit 198.51.100.0 0.0.0.255",
        "interface Gi0/1",
        " description owned",
        "!",
        "ACCESS-LIST 7 PERMIT ANY",
        "access-list 7 deny host 192.0.2.7",
        "end",
    ]
    parsed = parse("\n".join(rows) + "\n")
    config = parsed.canonical
    assert not config.unparsed_fragments
    assert [acl.name for acl in config.acls] == ["7", "1300"]
    acl = config.acls[0]
    assert [rule.action for rule in acl.rules] == ["deny", "permit", "deny"]
    assert [rule.provenance["rule"].source_lines for rule in acl.rules] == [[2], [7], [8]]
    assert acl.provenance["name"].source_lines == [2, 7, 8]
    assert (
        acl.provenance["name"].raw_text_hash
        == sha256("\n".join(rows[index - 1] for index in (2, 7, 8)).encode()).hexdigest()
    )
    assert config.interfaces[0].description == "owned"
    assert parsed.coverage.command_units == 7 and parsed.coverage.structural_units == 1


@pytest.mark.parametrize(
    "row",
    [
        "access-list 0 permit any",
        "access-list 100 permit ip any any",
        "access-list 1299 permit any",
        "access-list 2000 permit ip any any",
        "access-list 2699 deny ip any any",
        "access-list 2700 permit any",
        "access-list 99999 permit any",
        "access-list 01 permit any",
        "access-list \u0661 permit any",
        "access-list NAME permit any",
        "access-list 1 permit",
        "access-list 1 permit host",
        "access-list 1 permit host 2001:db8::1",
        "access-list 1 permit 192.0.2.0/24",
        "access-list 1 permit 192.0.2.1 255.0.0.0",
        "access-list 1 permit 192.0.2.1 255.255.255.0",
        "access-list 1 permit 192.0.2.1 0.255.0.255",
        "access-list 1 permit any log",
        "access-list 1 permit any time-range OWNED",
        "access-list 1 permit object-group OWNED",
        "access-list 1 permit host 192.0.2.1 extra",
        "access-list 1 permit 192.0.2.1 garbage",
        "access-list 1 remark OWNED",
        "access-list 1 10 permit any",
        "no access-list 1",
        " access-list 1 permit any",
    ],
)
def test_unsupported_rows_remain_unknown_whole_without_empty_acl_or_policy(row):
    parsed = parse(f"hostname owned\n{row}\n")
    config = parsed.canonical
    assert config.acls == []
    assert len(config.unparsed_fragments) == 1
    fragment = config.unparsed_fragments[0]
    assert fragment.raw_text == row and fragment.location.source_lines == [2]
    assert fragment.location.raw_text_hash == sha256(row.encode()).hexdigest()
    assert fragment.location.parser_confidence == 0 and config.parser_confidence < 1
    assert parsed.coverage.unparsed_units == 1 and parsed.coverage.unparsed_fraction == 0.5
    assert parsed.coverage.proves_vendor_syntax is False
    assert evaluate_policies(config, device_id=UUID(int=1), rules=ACL_RULES) == []


@pytest.mark.parametrize(
    "kind", ["interface Gi0/1", "router bgp 65001", "ip access-list standard OWNED"]
)
def test_numbered_command_is_not_consumed_inside_submode(kind):
    parsed = parse(f"hostname owned\n{kind}\n access-list 1 permit any\n!\n")
    assert parsed.coverage.unparsed_units == 1
    assert parsed.canonical.unparsed_fragments[0].location.source_lines == [3]
    assert all(acl.name != "1" for acl in parsed.canonical.acls)


@pytest.mark.parametrize(
    "header",
    [
        "ip access-list standard 1",
        "ip access-list standard 01",
        "ip access-list standard 00001",
        "ip access-list standard " + "0" * 5000 + "1",
        "ip access-list extended 1",
    ],
)
@pytest.mark.parametrize("global_first", [True, False])
def test_mixed_numeric_submode_and_global_forms_refuse_global_rows_in_either_order(
    header, global_first
):
    named = (
        header + "\n deny host 192.0.2.1\n!\n"
        if "standard" in header
        else header + "\n deny ip any any\n!\n"
    )
    global_row = "access-list 1 permit any\n"
    source = "hostname owned\n" + (global_row + named if global_first else named + global_row)
    parsed = parse(source)
    assert len(parsed.canonical.unparsed_fragments) == 1
    assert parsed.canonical.unparsed_fragments[0].raw_text == global_row.rstrip()
    assert any("unsupported numbered ACL" in warning for warning in parsed.canonical.parse_warnings)
    assert len(parsed.canonical.acls) == 1
    assert parsed.canonical.acls[0].rules[0].action == "deny"
    assert evaluate_policies(parsed.canonical, device_id=UUID(int=1), rules=ACL_RULES) == []


@pytest.mark.parametrize(
    "operand,violation",
    [("any", True), ("192.0.2.1 255.255.255.255", True), ("host 192.0.2.1", False)],
)
def test_existing_policy_evaluates_configured_fact_with_exact_evidence_not_attachment(
    operand, violation
):
    config = parse(f"hostname owned\naccess-list 7 permit {operand}\n").canonical
    findings = evaluate_policies(config, device_id=UUID(int=1), rules=ACL_RULES)
    assert len(findings) == int(violation)
    if violation:
        finding = findings[0]
        assert finding.category == "acl.unrestricted_permit"
        assert finding.affected_lines == [2] and finding.anomaly_score == 0
        assert finding.observed["acl.unrestricted_permit"]["acl"] == "7"
        assert finding.evidence[0].source_location == config.acls[0].rules[0].provenance["rule"]


def test_unknown_sibling_does_not_disappear_or_create_a_partial_supported_rule():
    parsed = parse("hostname owned\naccess-list 1 deny any\naccess-list 1 permit any log\n")
    assert len(parsed.canonical.acls[0].rules) == 1
    assert parsed.canonical.acls[0].rules[0].action == "deny"
    assert parsed.coverage.accepted_units == 2 and parsed.coverage.unparsed_units == 1
    assert parsed.canonical.parser_confidence < 1
    assert evaluate_policies(parsed.canonical, device_id=UUID(int=1), rules=ACL_RULES) == []


def test_ipv6_numeric_name_does_not_collide_with_ipv4_numbered_namespace():
    parsed = parse(
        "hostname owned\nipv6 access-list 1\n deny ipv6 any any\n!\naccess-list 1 deny any\n"
    )
    assert not parsed.canonical.unparsed_fragments
    assert [(acl.name, acl.family) for acl in parsed.canonical.acls] == [
        ("1", "ipv6"),
        ("1", "ipv4"),
    ]


def test_global_statement_ends_submode_and_accepts_internal_whitespace():
    parsed = parse(
        "hostname owned\ninterface Gi0/1\n description owned\naccess-list\t1\tdeny\tany\n"
    )
    assert not parsed.canonical.unparsed_fragments
    assert parsed.canonical.interfaces[0].description == "owned"
    assert parsed.canonical.acls[0].rules[0].action == "deny"
