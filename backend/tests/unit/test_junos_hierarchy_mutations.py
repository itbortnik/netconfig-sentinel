"""Authored structural diagnostics, not independent vendor/ML qualification."""

import hashlib
import json
from datetime import UTC, datetime

import pytest
from app.domain import Vendor
from app.parsers import parse_configuration
from pydantic import ValidationError

from ml.datasets import ImportedDatasetRecord
from ml.mutation import (
    MUTATION_ENGINE_VERSION,
    STRUCTURAL_MUTATION_ENGINE_VERSION,
    MutationLocalization,
    MutationNotApplicableError,
    MutationType,
    MutationValidationError,
    MutationValidationStatus,
    SyntheticMutationSample,
    list_applicable_mutations,
    mutate_configuration,
    reverse_mutation,
)

HIERARCHY = """# Authored structural fixture, no real network or credentials.
system {
    host-name host-000000000002;
    authentication-order [ radius password ];
    services {
        ssh {
            protocol-version v2;
        }
    }
    ntp {
        server 198.51.100.10;
        server 198.51.100.11;
    }
    syslog {
        host 198.51.100.20 {
            any notice;
        }
    }
}
snmp {
    v3 {
        # Existing, bounded v3 indicator; no secret values.
    }
}
vlans {
    USERS {
        vlan-id 10;
    }
    SERVERS {
        vlan-id 20;
    }
}
interfaces {
    ge-0/0/1 {
        description "User link { braces }; literal";
        unit 0 {
            family inet {
                address 198.51.100.1/24;
            }
            family ethernet-switching {
                interface-mode access;
                vlan {
                    members USERS;
                }
            }
        }
    }
    ge-0/0/2 {
        unit 0 {
            family inet {
                address 198.51.101.1/24;
            }
            family ethernet-switching {
                port-mode access;
                vlan {
                    members [ SERVERS ];
                }
            }
        }
    }
}
firewall {
    family inet {
        filter MGMT-IN {
            term ALLOW-SSH {
                from {
                    source-address {
                        198.51.100.0/24;
                        198.51.101.0/24;
                    }
                    protocol tcp;
                    destination-port ssh;
                }
                then {
                    accept;
                }
            }
            # Preserve the position of the catch-all, not just its name.
            term DENY-REST {
                then discard; // preserve trailing comment
            }
        }
    }
}
routing-options {
    autonomous-system 65001;
    router-id 198.51.100.1;
    static {
        route 203.0.113.0/24 {
            next-hop 198.51.100.254;
            preference 10;
        }
        route 203.0.114.0/24 discard;
    }
}
protocols {
    bgp {
        group TRANSIT {
            type external;
            peer-as 65002;
            neighbor 198.51.100.2 {
                description "Transit neighbor";
            }
            neighbor 198.51.100.3;
        }
    }
    ospf {
        area 0 {
            interface ge-0/0/1.0 {
                metric 10;
            }
            interface ge-0/0/2.0;
        }
    }
}
"""

TYPES = tuple(kind for kind in MutationType if kind is not MutationType.ROUTE_MAP_ORDER_CHANGE)


def _record(text: str = HIERARCHY) -> ImportedDatasetRecord:
    digest = hashlib.sha256(text.encode()).hexdigest()
    return ImportedDatasetRecord(
        source_id="authored-structural",
        record_id="hierarchy-001",
        network_id="network-000000000001",
        site_id="site-000000000001",
        device_id="device-000000000001",
        captured_at=datetime(2026, 1, 1, tzinfo=UTC),
        vendor_hint=Vendor.JUNIPER,
        device_role="edge-router",
        raw_sha256=digest,
        sanitized_sha256=digest,
        sanitized_text=text,
        raw_byte_count=len(text.encode()),
        replacements={},
        sanitization_version="config-sanitizer-0.1.0",
    )


def _parse(text: str):
    return parse_configuration(
        text, filename="authored.conf", collected_at=datetime(2026, 1, 1, tzinfo=UTC)
    )


def _mutate(text: str, types: tuple[MutationType, ...], seed: int = 9) -> SyntheticMutationSample:
    return mutate_configuration(
        _record(text), types, seed=seed, engine_version=STRUCTURAL_MUTATION_ENGINE_VERSION
    )


@pytest.mark.parametrize("kind", TYPES)
@pytest.mark.parametrize(
    "newline,trailing", [("\n", True), ("\n", False), ("\r\n", True), ("\r\n", False)]
)
def test_all_fourteen_classes_reverse_exactly(
    kind: MutationType, newline: str, trailing: bool
) -> None:
    text = HIERARCHY.replace("\n", newline)
    if not trailing:
        text = text.removesuffix(newline)
    sample = _mutate(text, (kind,))
    assert sample.engine_version == STRUCTURAL_MUTATION_ENGINE_VERSION
    assert sample.labels[0].mutation_type == kind
    assert sample.labels[0].synthetic and not sample.labels[0].real_confirmed
    assert sample.syntax_validation.status == MutationValidationStatus.PASSED
    assert sample.syntax_validation.warning_count == 0
    assert sample.syntax_validation.unparsed_fragment_count == 0
    assert sample.formal_validation.status == MutationValidationStatus.NOT_RUN
    assert reverse_mutation(sample, sample.mutated_text) == text
    assert _parse(sample.mutated_text).unparsed_fragments == []
    assert sample.mutated_text.startswith(HIERARCHY.splitlines()[0])
    assert 'description "User link { braces }; literal";' in sample.mutated_text
    assert "# Preserve the position of the catch-all" in sample.mutated_text
    assert SyntheticMutationSample.model_validate_json(sample.model_dump_json()) == sample
    lines = sample.mutated_text.splitlines()
    assert all(1 <= line <= len(lines) for line in sample.affected_lines)
    assert sample.mutated_text.endswith(newline) == trailing


def test_old_entry_point_and_default_version_are_unchanged() -> None:
    assert MUTATION_ENGINE_VERSION == "config-mutation-0.1.0"
    with pytest.raises(MutationNotApplicableError, match="set syntax only"):
        mutate_configuration(_record(), (MutationType.TELNET_ENABLED,))
    assert list_applicable_mutations(_record()) == ()
    assert (
        list_applicable_mutations(_record(), engine_version=STRUCTURAL_MUTATION_ENGINE_VERSION)
        == TYPES
    )


@pytest.mark.parametrize(
    "types",
    [
        (
            MutationType.AAA_DISABLED,
            MutationType.TELNET_ENABLED,
            MutationType.SNMP_DOWNGRADE,
            MutationType.MANAGEMENT_EXPOSURE,
            MutationType.MISSING_NTP_SYSLOG,
        ),
        (
            MutationType.VLAN_MISMATCH,
            MutationType.BGP_REMOTE_AS_MISMATCH,
            MutationType.OSPF_AREA_MISMATCH,
            MutationType.REMOVED_STATIC_ROUTE,
            MutationType.CONFLICTING_IP_ADDRESS,
        ),
    ],
)
def test_linked_structural_edits_reverse_in_operation_order(
    types: tuple[MutationType, ...],
) -> None:
    sample = _mutate(HIERARCHY, types, seed=41)
    assert len(sample.operations) == 5
    assert tuple(label.mutation_type for label in sample.labels) == types
    assert reverse_mutation(sample, sample.mutated_text) == HIERARCHY
    with pytest.raises(MutationValidationError, match="does not match"):
        reverse_mutation(sample, sample.mutated_text + "# changed\n")


def test_seed_varies_positions_and_selected_nodes_without_changing_parent() -> None:
    record = _record()
    for kind in (
        MutationType.TELNET_ENABLED,
        MutationType.SNMP_DOWNGRADE,
        MutationType.MISSING_BGP_NEIGHBOR,
    ):
        samples = [
            mutate_configuration(
                record, (kind,), seed=seed, engine_version=STRUCTURAL_MUTATION_ENGINE_VERSION
            )
            for seed in range(12)
        ]
        assert len({sample.mutated_text for sample in samples}) >= 2
        assert samples[0] == _mutate(HIERARCHY, (kind,), 0)
        assert all(reverse_mutation(sample, sample.mutated_text) == HIERARCHY for sample in samples)
    assert record.sanitized_text == HIERARCHY


def test_bgp_override_changes_only_one_neighbor_and_preserves_inheritance() -> None:
    before = _parse(HIERARCHY)
    for seed in range(12):
        sample = _mutate(HIERARCHY, (MutationType.BGP_REMOTE_AS_MISMATCH,), seed)
        after = _parse(sample.mutated_text)
        assert "peer-as 65002;" in sample.mutated_text
        assert before.bgp and after.bgp
        assert len(after.bgp.neighbors) == 2
        assert sorted(neighbor.remote_as for neighbor in after.bgp.neighbors) == [65002, 65003]
        assert [neighbor.description for neighbor in after.bgp.neighbors] == [
            neighbor.description for neighbor in before.bgp.neighbors
        ]
        assert "neighbor 198.51.100.3 peer-as" not in sample.mutated_text
        assert any(
            "peer-as 65003;" in line and "neighbor" not in line
            for line in sample.mutated_text.splitlines()
        )


def test_ospf_moves_one_interface_with_its_metric_not_the_entire_area() -> None:
    for seed in range(12):
        sample = _mutate(HIERARCHY, (MutationType.OSPF_AREA_MISMATCH,), seed)
        after = _parse(sample.mutated_text)
        assert len(after.ospf[0].interfaces) == 2
        assert sorted(item.area_id for item in after.ospf[0].interfaces) == ["0.0.0.0", "0.0.0.1"]
        assert sorted((item.name, item.cost) for item in after.ospf[0].interfaces) == [
            ("ge-0/0/1.0", 10),
            ("ge-0/0/2.0", None),
        ]
        assert reverse_mutation(sample, sample.mutated_text) == HIERARCHY


def test_same_term_names_in_different_filters_do_not_remove_both() -> None:
    text = HIERARCHY.replace(
        "        filter MGMT-IN {",
        "        filter SECOND {\n            term ALLOW-SSH {\n"
        "                then accept;\n            }\n        }\n        filter MGMT-IN {",
    )
    sample = _mutate(text, (MutationType.MISSING_ACL_ENTRY,))
    assert sum(len(acl.rules) for acl in _parse(sample.mutated_text).acls) == 2
    assert sample.mutated_text.count("term ALLOW-SSH {") == 1
    assert reverse_mutation(sample, sample.mutated_text) == text


def test_external_aaa_nodes_are_removed_together_not_only_authentication_order() -> None:
    # Unknown credential syntax must not be swallowed by a subtree removal.
    text = HIERARCHY.replace(
        "    authentication-order",
        "    radius-server 198.51.100.44 {\n    }\n"
        "    tacplus-server 198.51.100.45 {\n    }\n    authentication-order",
    )
    sample = _mutate(text, (MutationType.AAA_DISABLED,))
    assert not _parse(sample.mutated_text).management.aaa_enabled
    assert "radius-server" not in sample.mutated_text
    assert "tacplus-server" not in sample.mutated_text
    assert reverse_mutation(sample, sample.mutated_text) == text


def test_unknown_sibling_is_preserved_but_unknown_target_is_refused() -> None:
    text = HIERARCHY.replace("    services {", "    future-setting bounded-value;\n    services {")
    before = _parse(text)
    sample = _mutate(text, (MutationType.TELNET_ENABLED,))
    assert [item.raw_text for item in _parse(sample.mutated_text).unparsed_fragments] == [
        item.raw_text for item in before.unparsed_fragments
    ]
    assert sample.syntax_validation.unparsed_fragment_count == 1
    assert sample.syntax_validation.status == MutationValidationStatus.PARTIAL
    assert reverse_mutation(sample, sample.mutated_text) == text
    unknown_target = HIERARCHY.replace(
        "            term ALLOW-SSH {",
        "            term ALLOW-SSH {\n                future-action arbitrary;",
    )
    with pytest.raises(MutationNotApplicableError, match="precondition"):
        _mutate(unknown_target, (MutationType.MISSING_ACL_ENTRY,))


@pytest.mark.parametrize(
    "change",
    [
        lambda text: text + "}\n",
        lambda text: text.removesuffix("}\n"),
        lambda text: text.replace("        ssh {", "        ssh { telnet; }"),
        lambda text: text.replace("    host-name", "    host-name duplicate;\n    host-name"),
        lambda text: text.replace("    services {", "    services {\n    }\n    services {"),
        lambda text: text.replace(
            "    services {", "    apply-groups hypothetical;\n    services {"
        ),
        lambda text: text.replace("    services {", "    inactive: services {"),
        lambda text: text.replace("    services {", "    services { /* inline */"),
        lambda text: text.replace(
            "    host-name host-000000000002;", "    host-name host-000000000002"
        ),
        lambda text: text.replace("    services {", "    future-setting \u0000;\n    services {"),
        lambda text: text.replace("\n", "\r\n", 1),
    ],
)
def test_ambiguous_and_unsupported_layouts_fail_closed(change) -> None:
    with pytest.raises((MutationNotApplicableError, MutationValidationError)):
        _mutate(change(HIERARCHY), (MutationType.TELNET_ENABLED,))


def test_schema_unknown_versions_and_unsupported_class_are_refused() -> None:
    with pytest.raises(ValueError, match="unsupported mutation engine"):
        mutate_configuration(
            _record(), (MutationType.TELNET_ENABLED,), engine_version="config-mutation-9.0.0"
        )
    with pytest.raises(MutationNotApplicableError, match="precondition"):
        _mutate(HIERARCHY, (MutationType.ROUTE_MAP_ORDER_CHANGE,))
    sample = _mutate(HIERARCHY, (MutationType.TELNET_ENABLED,))
    value = sample.model_dump()
    value["engine_version"] = "config-mutation-0.3.0"
    with pytest.raises(ValidationError):
        SyntheticMutationSample.model_validate(value)


@pytest.mark.parametrize("kind", TYPES)
def test_missing_canonical_preconditions_do_not_generate_a_label(kind: MutationType) -> None:
    text = "system {\n    host-name host-000000000003;\n}\n"
    with pytest.raises(MutationNotApplicableError, match="precondition"):
        _mutate(text, (kind,))


def test_all_released_flat_samples_keep_their_exact_serialization() -> None:
    from backend.tests.unit.test_mutation_engine import CISCO_TEXT, JUNOS_SET_TEXT
    from backend.tests.unit.test_mutation_engine import _record as released_record

    # Captured from the installed published 20c5b26 distribution, not recomputed
    # as the expected value by the implementation under test.
    rows = [
        mutate_configuration(
            released_record(CISCO_TEXT, Vendor.CISCO), (kind,), seed=17
        ).model_dump(mode="json")
        for kind in MutationType
    ]
    rows += [
        mutate_configuration(
            released_record(JUNOS_SET_TEXT, Vendor.JUNIPER), (kind,), seed=9
        ).model_dump(mode="json")
        for kind in TYPES
    ]
    digest = hashlib.sha256(
        json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    assert len(rows) == 29
    assert digest == "328152c2030b5b1817f8505942e3ea1fc1c244a1a1315876ac2a52b613f13010"


@pytest.mark.parametrize("kind", TYPES)
def test_tabs_comment_blocks_and_quoted_punctuation_are_not_reformatted(kind: MutationType) -> None:
    text = HIERARCHY.replace('"User link { braces }; literal"', '"{};"')
    text = text.replace("    ", "\t").replace(
        "system {", "/* outside block\n * } ; {\n */\nsystem {"
    )
    sample = _mutate(text, (kind,))
    assert 'description "{};";' in sample.mutated_text
    assert "/* outside block\n * } ; {\n */" in sample.mutated_text
    assert reverse_mutation(sample, sample.mutated_text) == text


def test_inline_neighbor_description_survives_peer_as_override() -> None:
    text = HIERARCHY.replace(
        "            neighbor 198.51.100.3;",
        '            neighbor 198.51.100.3 description "Inline uplink"; // keep-comment',
    )
    for seed in range(12):
        sample = _mutate(text, (MutationType.BGP_REMOTE_AS_MISMATCH,), seed)
        after = _parse(sample.mutated_text)
        assert after.bgp
        assert after.bgp.neighbors[1].description == "Inline uplink"
        assert "// keep-comment" in sample.mutated_text
        assert reverse_mutation(sample, sample.mutated_text) == text


def test_ospf_reuses_existing_normalized_destination_area() -> None:
    text = HIERARCHY.replace(
        "    ospf {",
        "    ospf {\n        area 0.0.0.1 {\n            interface lo0.0 {\n"
        "                passive;\n            }\n        }",
    )
    for seed in range(12):
        sample = _mutate(text, (MutationType.OSPF_AREA_MISMATCH,), seed)
        assert sample.mutated_text.count("area 0.0.0.1 {") == 1
        assert "area 0.0.0.0 {" not in sample.mutated_text
        assert len(_parse(sample.mutated_text).ospf[0].interfaces) == 3
        assert reverse_mutation(sample, sample.mutated_text) == text


def test_ipv6_sources_peers_and_address_conflicts_keep_the_family() -> None:
    text = HIERARCHY.replace("family inet {", "family inet6 {")
    for original, replacement in (
        ("198.51.100.1/24", "2001:db8:1::1/64"),
        ("198.51.101.1/24", "2001:db8:2::1/64"),
        ("198.51.100.0/24", "2001:db8:1::/64"),
        ("198.51.101.0/24", "2001:db8:2::/64"),
        ("neighbor 198.51.100.2", "neighbor 2001:DB8::2"),
        ("neighbor 198.51.100.3", "neighbor 2001:DB8::3"),
    ):
        text = text.replace(original, replacement)
    exposure = _mutate(text, (MutationType.MANAGEMENT_EXPOSURE,))
    assert "::/0;" in exposure.mutated_text and "0.0.0.0/0" not in exposure.mutated_text
    conflict = _mutate(text, (MutationType.CONFLICTING_IP_ADDRESS,))
    addresses = [
        item.address
        for interface in _parse(conflict.mutated_text).interfaces
        for item in interface.addresses
    ]
    assert len(addresses) == 2 and len(set(addresses)) == 1
    for kind in (MutationType.BGP_REMOTE_AS_MISMATCH, MutationType.MISSING_BGP_NEIGHBOR):
        sample = _mutate(text, (kind,))
        assert reverse_mutation(sample, sample.mutated_text) == text


def test_unknown_destination_children_cannot_be_swallowed() -> None:
    text = HIERARCHY.replace(
        "            any notice;",
        "            any notice;\n            future-log-setting arbitrary;",
    )
    with pytest.raises(MutationNotApplicableError):
        _mutate(text, (MutationType.MISSING_NTP_SYSLOG,))


@pytest.mark.parametrize(
    "text",
    [
        "#" * 1_048_577,
        "# comment\n" * 50_001,
        "system {\n"
        + "".join(f"    future-unique-{index} value;\n" for index in range(4097))
        + "}\n",
        "system {\n" + "    nested {\n" * 65 + "}\n" * 66,
    ],
    ids=["byte-bound", "line-bound", "node-bound", "depth-bound"],
)
def test_structural_budgets_are_checked_before_canonical_parsing(text: str, monkeypatch) -> None:
    from ml.mutation import engine

    def forbidden(*args, **kwargs):
        raise AssertionError("unbounded source reached canonical parser")

    monkeypatch.setattr(engine, "_parse", forbidden)
    with pytest.raises(MutationNotApplicableError):
        _mutate(text, (MutationType.TELNET_ENABLED,))


def test_crlf_byte_budget_counts_original_bytes_before_parsing(monkeypatch) -> None:
    from ml.mutation import engine

    text = HIERARCHY.replace("\n", "\r\n")
    padding = 1_048_576 - len(text.replace("\r\n", "\n").encode()) - 2
    text = "#" + "x" * padding + "\r\n" + text
    assert len(text.replace("\r\n", "\n").encode()) <= 1_048_576
    assert len(text.encode()) > 1_048_576

    def forbidden(*args, **kwargs):
        raise AssertionError("oversized CRLF source reached canonical parser")

    monkeypatch.setattr(engine, "_parse", forbidden)
    with pytest.raises(MutationNotApplicableError, match="byte budget"):
        _mutate(text, (MutationType.TELNET_ENABLED,))


def test_result_byte_budget_precedes_result_parsing(monkeypatch) -> None:
    from ml.mutation import engine

    text = HIERARCHY.replace("\n", "\r\n")
    text = "#" + "x" * (1_048_576 - len(text.encode()) - 3) + "\r\n" + text
    assert len(text.encode()) == 1_048_576
    original_parse = engine._parse

    def bounded_parse(record, candidate):
        assert len(candidate.encode()) <= 1_048_576
        return original_parse(record, candidate)

    monkeypatch.setattr(engine, "_parse", bounded_parse)
    with pytest.raises(MutationValidationError, match="byte budget"):
        _mutate(text, (MutationType.TELNET_ENABLED,))


def test_warning_and_equivalent_area_overrides_are_refused() -> None:
    text = HIERARCHY.replace(
        "        area 0 {", "        area 0.0.0.0 {\n        }\n        area 0 {"
    )
    with pytest.raises(MutationNotApplicableError):
        _mutate(text, (MutationType.OSPF_AREA_MISMATCH,))
    text = HIERARCHY.replace(
        "    bgp {",
        "    bgp {\n        group DUPLICATE {\n            peer-as 65004;\n"
        "            neighbor 198.51.100.2;\n        }",
    )
    with pytest.raises(MutationNotApplicableError, match="warning-free"):
        _mutate(text, (MutationType.MISSING_BGP_NEIGHBOR,))


@pytest.mark.parametrize(
    "kind",
    [
        MutationType.MISSING_ACL_ENTRY,
        MutationType.MISSING_BGP_NEIGHBOR,
        MutationType.REMOVED_STATIC_ROUTE,
        MutationType.MISSING_NTP_SYSLOG,
    ],
)
def test_deletions_do_not_label_a_surviving_neighboring_line(kind: MutationType) -> None:
    sample = _mutate(HIERARCHY, (kind,))
    assert sample.affected_lines == ()
    assert sample.localization is not None
    assert all(change.kind == "delete" for change in sample.localization.changes)
    assert all(change.mutated_line_count == 0 for change in sample.localization.changes)
    assert all(change.original_line_count > 0 for change in sample.localization.changes)
    assert sample.localization.original_line_count == len(HIERARCHY.splitlines())
    assert reverse_mutation(sample, sample.mutated_text) == HIERARCHY


def test_linked_localization_uses_final_parent_and_result_not_intermediate_offsets() -> None:
    sample = _mutate(
        HIERARCHY,
        (
            MutationType.MISSING_NTP_SYSLOG,
            MutationType.BGP_REMOTE_AS_MISMATCH,
            MutationType.TELNET_ENABLED,
        ),
    )
    assert sample.localization is not None
    assert any(change.kind == "delete" for change in sample.localization.changes)
    assert sample.affected_lines == sample.localization.changed_result_lines
    lines = sample.mutated_text.splitlines()
    assert any("telnet;" in lines[line - 1] for line in sample.affected_lines)
    assert any("peer-as 65003;" in lines[line - 1] for line in sample.affected_lines)
    assert reverse_mutation(sample, sample.mutated_text) == HIERARCHY


def test_localization_tampering_is_rejected_by_schema_and_exact_reverse() -> None:
    sample = _mutate(HIERARCHY, (MutationType.TELNET_ENABLED,))
    payload = sample.model_dump(mode="json")
    payload["localization"] = None
    with pytest.raises(ValidationError, match="localization"):
        SyntheticMutationSample.model_validate(payload)
    payload = sample.model_dump(mode="json")
    payload["affected_lines"] = []
    with pytest.raises(ValidationError, match="localization"):
        SyntheticMutationSample.model_validate(payload)
    assert sample.localization is not None
    change = sample.localization.changes[0]
    altered = change.model_copy(
        update={
            "original_start_line": change.original_start_line + 1,
            "mutated_start_line": change.mutated_start_line + 1,
        }
    )
    localization = sample.localization.model_copy(update={"changes": (altered,)})
    forged = sample.model_copy(
        update={"localization": localization, "affected_lines": localization.changed_result_lines}
    )
    with pytest.raises(MutationValidationError, match="localization"):
        reverse_mutation(forged, forged.mutated_text)


@pytest.mark.parametrize("seed", [True, 1.0, "1", None])
def test_new_version_refuses_coerced_seeds(seed) -> None:
    with pytest.raises(ValueError, match="seed must be an integer"):
        _mutate(HIERARCHY, (MutationType.TELNET_ENABLED,), seed)
    sample = _mutate(HIERARCHY, (MutationType.TELNET_ENABLED,))
    payload = sample.model_dump(mode="json")
    payload["seed"] = seed
    with pytest.raises(ValidationError, match="seed must be an integer"):
        SyntheticMutationSample.model_validate(payload)


@pytest.mark.parametrize("area", ["00", "0.0.0.0", "1", "0.0.0.1"])
def test_area_mutation_compares_normalized_identifiers(area: str) -> None:
    text = HIERARCHY.replace("        area 0 {", f"        area {area} {{")
    sample = _mutate(text, (MutationType.OSPF_AREA_MISMATCH,))
    before = [item.area_id for item in _parse(text).ospf[0].interfaces]
    after = [item.area_id for item in _parse(sample.mutated_text).ospf[0].interfaces]
    assert before != after
    assert reverse_mutation(sample, sample.mutated_text) == text


@pytest.mark.parametrize(
    "change",
    [
        {"kind": "delete"},
        {"original_start_line": True},
        {"original_start_line": 50_001},
        {"mutated_start_line": 50_001},
        {"original_start_line": 0},
        {"original_start_line": 2, "mutated_start_line": 3},
        {"mutated_line_count": 0},
        {"extra": "refused"},
    ],
)
def test_localization_refuses_inconsistent_or_coerced_spans(change) -> None:
    payload = {
        "original_line_count": 10,
        "mutated_line_count": 11,
        "changes": [
            {
                "kind": "insert",
                "original_start_line": 3,
                "original_line_count": 0,
                "mutated_start_line": 3,
                "mutated_line_count": 1,
                **change,
            }
        ],
    }
    with pytest.raises(ValidationError):
        MutationLocalization.model_validate(payload)
