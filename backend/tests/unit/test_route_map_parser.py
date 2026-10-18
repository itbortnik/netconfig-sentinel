"""Configured clause facts are not evaluated routes, device syntax or network safety."""

import json
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path

import pytest
from app.domain import CanonicalConfig
from app.parsers import parse_configuration

AT = datetime(2020, 1, 1, tzinfo=UTC)
TEXT = """hostname owned-route-map
ip ssh version 2
route-map Export permit 20
 set metric 50
!
route-map Export deny 10
 match ip address prefix-list TRUSTED SECOND
!
"""


def parse(text=TEXT, *, schema_version="1.2"):
    return parse_configuration(
        text, filename="owned.cfg", collected_at=AT, schema_version=schema_version
    )


def test_explicit_profile_sorts_numeric_sequences_without_moving_body_or_source_anchors():
    result = parse()
    assert result.schema_version == "1.2"
    assert result.unparsed_fragments == result.parse_warnings == []
    assert result.parser_confidence == 1.0
    route_map = result.route_maps[0]
    assert route_map.name == "Export" and route_map.normalization_complete
    first, second = route_map.clauses
    assert (first.sequence, first.action, first.match_ipv4_prefix_lists, first.set_metric) == (
        10,
        "deny",
        ("TRUSTED", "SECOND"),
        None,
    )
    assert (second.sequence, second.action, second.set_metric) == (20, "permit", 50)
    assert first.provenance["header"].source_lines == [6]
    assert first.provenance["match_ipv4_prefix_lists"].source_lines == [7]
    assert second.provenance["header"].source_lines == [3]
    assert second.provenance["set_metric"].source_lines == [4]
    assert (
        first.provenance["header"].raw_text_hash
        == sha256(TEXT.splitlines()[5].encode()).hexdigest()
    )
    assert route_map.provenance["name"].source_lines == [3, 6]
    assert result.model_dump()["route_maps"][0]["clauses"][0]["sequence"] == 10


def test_default_profile_retains_released_unknowns_and_serialization():
    default = parse_configuration(TEXT, filename="owned.cfg", collected_at=AT)
    explicit_old = parse(schema_version="1.1")
    assert default == explicit_old
    assert default.schema_version == "1.1" and default.route_maps == []
    assert "route_maps" not in default.model_dump()
    assert [item.location.source_lines for item in default.unparsed_fragments] == [
        [3],
        [4],
        [6],
        [7],
    ]


@pytest.mark.parametrize("schema", ["1.0", "1.1"])
def test_historical_canonical_fields_do_not_acquire_empty_route_maps(schema):
    root = Path(__file__).resolve().parents[3]
    raw = json.loads(
        (root / "backend/tests/golden/expected/cisco_ios/edge-secure.cfg.json").read_text()
    )
    raw["schema_version"] = schema
    if schema == "1.0":
        raw.pop("local_users", None)
    assert CanonicalConfig.model_validate(raw).model_dump(mode="json") == raw


@pytest.mark.parametrize("sequence", [0, 65535])
@pytest.mark.parametrize("metric", [0, 4294967295])
def test_explicit_numeric_endpoints_and_empty_clause_are_configured_facts(sequence, metric):
    result = parse(f"hostname owned\nroute-map A permit {sequence}\n set metric {metric}\n!\n")
    clause = result.route_maps[0].clauses[0]
    assert (clause.sequence, clause.set_metric, clause.match_ipv4_prefix_lists) == (
        sequence,
        metric,
        (),
    )
    empty = parse(f"hostname owned\nroute-map A deny {sequence}\n!\n")
    assert empty.route_maps[0].clauses[0].normalization_complete
    assert empty.route_maps[0].clauses[0].set_metric is None


@pytest.mark.parametrize(
    "child",
    [
        "continue 30",
        "call OTHER",
        "set metric +1",
        "set metric -1",
        "set metric 4294967296",
        "set metric 10000 100 255 1 1500",
        "match ip address ACL",
        "match ipv6 address prefix-list V6",
        "match ip address prefix-list A A",
        "ip ssh version 1",
        "set metric 50 extra",
    ],
)
def test_unknown_children_remain_unparsed_and_cannot_make_complete_clause(child):
    source = "hostname owned\nip ssh version 2\nroute-map A permit 10\n " + child + "\n!\n"
    result = parse(source)
    assert result.management.ssh_version == "2"
    assert not result.route_maps[0].normalization_complete
    assert not result.route_maps[0].clauses[0].normalization_complete
    assert [item.raw_text for item in result.unparsed_fragments] == [" " + child]
    assert result.unparsed_fragments[0].location.source_lines == [4]
    assert result.parser_confidence < 1


@pytest.mark.parametrize(
    "headers",
    [
        ("route-map A permit 10", "route-map A permit 010"),
        ("route-map A permit 10", "route-map A deny 10"),
    ],
)
def test_repeated_sequence_is_ambiguous_not_merged_or_partially_claimed(headers):
    source = "hostname owned\n" + "\n!\n".join(h + "\n set metric 50" for h in headers) + "\n!\n"
    result = parse(source)
    assert result.route_maps == [] and len(result.unparsed_fragments) == 4
    assert len(result.parse_warnings) == 2


@pytest.mark.parametrize(
    "children,field",
    [
        (("set metric 1", "set metric 2"), "set_metric"),
        (
            ("match ip address prefix-list A", "match ip address prefix-list B"),
            "match_ipv4_prefix_lists",
        ),
    ],
)
def test_repeated_child_does_not_guess_last_value_or_merge_semantics(children, field):
    result = parse("hostname owned\nroute-map A permit 10\n " + "\n ".join(children) + "\n!\n")
    clause = result.route_maps[0].clauses[0]
    assert not clause.normalization_complete and field not in clause.provenance
    assert len(result.unparsed_fragments) == 2 and result.parse_warnings
    assert clause.set_metric is None and clause.match_ipv4_prefix_lists == ()


@pytest.mark.parametrize(
    "header", ["route-map A", "route-map A permit", "route-map A permit 65536", "no route-map A"]
)
def test_unsupported_global_route_map_command_prevents_complete_claim_for_same_name(header):
    result = parse("hostname owned\nroute-map A permit 10\n set metric 50\n!\n" + header + "\n")
    assert not result.route_maps[0].normalization_complete
    assert result.unparsed_fragments[-1].raw_text == header
    assert result.parse_warnings


def test_keyword_spacing_and_case_preserve_case_sensitive_names():
    result = parse(
        "hostname owned\nRoUtE-MaP\tExport\tpermit 10\n"
        "\tMaTcH ip address prefix-list Trusted\n exit\n"
    )
    assert result.route_maps[0].name == "Export"
    assert result.route_maps[0].clauses[0].match_ipv4_prefix_lists == ("Trusted",)
    assert result.unparsed_fragments == []


@pytest.mark.parametrize("schema", ["1.0", "1.3", None, True])
def test_unknown_explicit_profile_is_refused(schema):
    with pytest.raises(ValueError, match="profile"):
        parse(schema_version=schema)


def test_cisco_profile_is_not_declared_as_junos_policy_support():
    with pytest.raises(ValueError, match="requires Cisco"):
        parse("set system host-name owned\n")


def test_typed_route_map_cannot_be_injected_into_legacy_or_non_cisco_model():
    result = parse()
    value = result.model_dump()
    for schema in ("1.0", "1.1"):
        with pytest.raises(ValueError, match=r"schema 1\.2"):
            CanonicalConfig.model_validate(value | {"schema_version": schema})
    value["device"]["vendor"] = "juniper"
    with pytest.raises(ValueError, match="Cisco"):
        CanonicalConfig.model_validate(value)


def test_explicit_parser_byte_line_and_clause_budgets():
    for source in (
        "hostname owned\n!" + "x" * 1048576,
        "hostname owned\n" + "!\n" * 50000,
        "hostname owned\n" + "\n".join(f"route-map A permit {i}\n!" for i in range(1025)),
    ):
        with pytest.raises(ValueError, match="budget"):
            parse(source)


@pytest.mark.parametrize("opening", ["banner motd ^C", "macro name CUSTOM", "tclsh"])
@pytest.mark.parametrize("indent", ["", " ", "\t"])
def test_route_map_like_text_in_opaque_blocks_is_not_normalized_as_configuration(opening, indent):
    result = parse(
        "hostname owned\n" + indent + opening + "\nroute-map FAKE permit 10\n set metric 50\n"
    )
    assert result.route_maps == []
    assert result.parse_warnings
    assert any(item.raw_text == "route-map FAKE permit 10" for item in result.unparsed_fragments)


@pytest.mark.parametrize("comment", ["!", "! descriptive comment", " ! comment", "\t! comment"])
def test_comments_do_not_move_unsupported_children_out_of_the_selected_clause(comment):
    result = parse(
        "hostname owned\nroute-map A permit 10\n match ip address prefix-list X\n"
        + comment
        + "\n continue 20\n!\nroute-map A deny 20\n set metric 50\n!\n"
    )
    assert not result.route_maps[0].normalization_complete
    assert not result.route_maps[0].clauses[0].normalization_complete
    assert [item.raw_text for item in result.unparsed_fragments] == [" continue 20"]
