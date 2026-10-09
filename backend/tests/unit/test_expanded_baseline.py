"""Contracts for the opt-in, source-bound second comparison generation."""

import json
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from uuid import UUID

import pytest
from app.detection.baseline.expanded import (
    ExpandedField,
    ExpandedReference,
    compare_expanded_reference,
    create_expanded_reference,
    project_expanded_facts,
)
from app.detection.baseline.peer_v2 import (
    ExpandedPeerBaseline,
    ExpandedPeerFeature,
    build_expanded_peer_baseline,
    evaluate_expanded_peer_baseline,
)
from app.domain import CanonicalConfig, Vendor
from app.parsers import parse_configuration
from pydantic import ValidationError

DEVICE_ID = UUID("f6156954-3f3b-4aa2-b693-5a710fe35d44")
COLLECTED_AT = datetime(2026, 1, 1, tzinfo=UTC)


def _owned_text(hostname: str = "edge", *, vendor: Vendor = Vendor.CISCO) -> str:
    if vendor is Vendor.CISCO:
        text = (
            "version 17.9\n"
            f"hostname {hostname}\n"
            "aaa new-model\n"
            "ip ssh version 2\n"
            "ntp server 192.0.2.10\n"
            "logging host 192.0.2.20\n"
            "snmp-server group SECURE v3 priv\n"
            "username reviewer privilege 15 secret 9 PRIVATE_HASH\n"
            "vlan 10\n name USERS\n!\n"
            "interface GigabitEthernet0/0\n"
            " no shutdown\n switchport mode trunk\n"
            " switchport trunk native vlan 10\n"
            " switchport trunk allowed vlan 10,20\n!\n"
            "ip access-list extended MGMT\n"
            " 10 permit tcp host 192.0.2.10 any eq 22 log\n"
            " 20 deny ip any any\n!\n"
            "ip prefix-list EXPORT seq 10 permit 203.0.113.0/24 le 28\n"
            "ip route 0.0.0.0 0.0.0.0 192.0.2.1 10\n"
            "router bgp 65001\n bgp router-id 192.0.2.2\n"
            " neighbor 192.0.2.1 remote-as 65002\n"
            " neighbor 192.0.2.1 update-source Loopback0\n!\n"
            "router ospf 10\n router-id 192.0.2.2\n"
            " passive-interface default\n"
            " no passive-interface GigabitEthernet0/0\n"
            " network 10.0.0.0 0.0.0.255 area 0\n!\n"
        )
    else:
        text = (
            f"set system host-name {hostname}\n"
            "set system services ssh protocol-version v2\n"
            "set system ntp server 192.0.2.10\n"
            "set system syslog host 192.0.2.20 any info\n"
            "set system login user reviewer class super-user\n"
            "set system login user reviewer authentication encrypted-password PRIVATE_HASH\n"
            "set vlans USERS vlan-id 10\n"
            "set interfaces ge-0/0/0 unit 0 family ethernet-switching interface-mode trunk\n"
            "set interfaces ge-0/0/0 unit 0 family ethernet-switching vlan members USERS\n"
            "set firewall family inet filter MGMT term ALLOW from protocol tcp\n"
            "set firewall family inet filter MGMT term ALLOW from source-address 192.0.2.10/32\n"
            "set firewall family inet filter MGMT term ALLOW from destination-port 22\n"
            "set firewall family inet filter MGMT term ALLOW then accept\n"
            "set firewall family inet filter MGMT term DENY then discard\n"
            "set policy-options prefix-list EXPORT 203.0.113.0/24\n"
            "set routing-options static route 0.0.0.0/0 next-hop 192.0.2.1\n"
            "set routing-options autonomous-system 65001\n"
            "set routing-options router-id 192.0.2.2\n"
            "set protocols bgp group TRANSIT type external\n"
            "set protocols bgp group TRANSIT peer-as 65002\n"
            "set protocols bgp group TRANSIT neighbor 192.0.2.1\n"
            "set protocols ospf area 0 interface ge-0/0/0.0\n"
            "set protocols ospf area 0 interface ge-0/0/0.0 metric 20\n"
        )
    return text


def _config(hostname: str = "edge", *, vendor: Vendor = Vendor.CISCO) -> CanonicalConfig:
    result = parse_configuration(
        _owned_text(hostname, vendor=vendor), filename="owned.cfg", collected_at=COLLECTED_AT
    )
    assert not result.parse_warnings and not result.unparsed_fragments
    assert result.parser_confidence == 1
    result.device.role = "edge-router"
    result.device.site_class = "lab"
    result.device.service_profile = "transit"
    return result


def _reference(config: CanonicalConfig) -> ExpandedReference:
    return create_expanded_reference(config, device_id=DEVICE_ID, reference_id="selected")


@pytest.mark.parametrize("vendor", list(Vendor))
def test_projection_and_reference_roundtrip_are_source_bound_and_secret_free(
    vendor: Vendor,
) -> None:
    config = _config(vendor=vendor)
    before = config.model_dump_json()
    facts = project_expanded_facts(config)
    reference = _reference(config)
    assert reference.version == "expected-config-0.2.0"
    assert reference.facts == facts
    assert reference.source_sha256 == config.source.sha256
    assert compare_expanded_reference(config, reference, device_id=DEVICE_ID) == []
    assert ExpandedReference.model_validate_json(reference.model_dump_json()) == reference
    encoded = reference.model_dump_json()
    assert "PRIVATE_HASH" not in encoded and "raw_text" not in encoded.replace("raw_text_hash", "")
    assert config.model_dump_json() == before
    assert {fact.field for fact in facts} >= {
        ExpandedField.NTP_SERVERS,
        ExpandedField.SYSLOG_SERVERS,
        ExpandedField.ACL_RULES,
        ExpandedField.PREFIX_RULES,
        ExpandedField.BGP_LOCAL_AS,
        ExpandedField.OSPF_INTERFACE_PASSIVE,
        ExpandedField.STATIC_TARGETS,
        ExpandedField.USER_AUTHENTICATION,
    }


def _change(config: CanonicalConfig, field: ExpandedField) -> None:
    if field is ExpandedField.NTP_SERVERS:
        config.management.ntp_servers = ["192.0.2.11"]
    elif field is ExpandedField.SYSLOG_SERVERS:
        config.management.syslog_servers = ["192.0.2.21"]
    elif field is ExpandedField.SNMP_VERSIONS:
        config.management.snmp_versions = ["v2c"]
    elif field is ExpandedField.INTERFACE_ENABLED:
        config.interfaces[0].enabled = False
    elif field is ExpandedField.INTERFACE_ALLOWED_VLANS:
        assert config.interfaces[0].allowed_vlans is not None
        config.interfaces[0].allowed_vlans.vlan_ids.append(30)
    elif field is ExpandedField.INTERFACE_NATIVE_VLAN:
        assert config.interfaces[0].native_vlan is not None
        config.interfaces[0].native_vlan.vlan_id = 20
    elif field is ExpandedField.ACL_RULES:
        config.acls[0].rules[0].options = ["established"]
    elif field is ExpandedField.PREFIX_RULES:
        config.prefix_lists[0].rules[0].le = 30
    elif field is ExpandedField.BGP_LOCAL_AS:
        assert config.bgp is not None
        config.bgp.local_as = 65100
    elif field is ExpandedField.BGP_ROUTER_ID:
        assert config.bgp is not None
        config.bgp.router_id = "192.0.2.3"
    elif field is ExpandedField.BGP_UPDATE_SOURCE:
        assert config.bgp is not None
        config.bgp.neighbors[0].update_source = "Loopback1"
    elif field is ExpandedField.BGP_ENABLED:
        assert config.bgp is not None
        config.bgp.neighbors[0].enabled = False
    elif field is ExpandedField.OSPF_PASSIVE_DEFAULT:
        config.ospf[0].passive_default = False
    elif field is ExpandedField.OSPF_INTERFACE_PASSIVE:
        config.ospf[0].interfaces[0].passive = True
    elif field is ExpandedField.STATIC_TARGETS:
        config.static_routes[0].next_hop = "192.0.2.254"
    elif field is ExpandedField.USER_PRIVILEGE:
        config.local_users[0].privilege = 1
    else:
        raise AssertionError("test mutation not implemented")
    config.source.sha256 = "f" * 64


@pytest.mark.parametrize(
    "field",
    [
        ExpandedField.NTP_SERVERS,
        ExpandedField.SYSLOG_SERVERS,
        ExpandedField.SNMP_VERSIONS,
        ExpandedField.INTERFACE_ENABLED,
        ExpandedField.INTERFACE_ALLOWED_VLANS,
        ExpandedField.INTERFACE_NATIVE_VLAN,
        ExpandedField.ACL_RULES,
        ExpandedField.PREFIX_RULES,
        ExpandedField.BGP_LOCAL_AS,
        ExpandedField.BGP_ROUTER_ID,
        ExpandedField.BGP_UPDATE_SOURCE,
        ExpandedField.BGP_ENABLED,
        ExpandedField.OSPF_PASSIVE_DEFAULT,
        ExpandedField.OSPF_INTERFACE_PASSIVE,
        ExpandedField.STATIC_TARGETS,
        ExpandedField.USER_PRIVILEGE,
    ],
)
def test_expanded_same_device_parameter_changes_are_reproducible(field: ExpandedField) -> None:
    config = _config()
    reference = _reference(config)
    original_reference = reference.model_dump_json()
    _change(config, field)
    first = compare_expanded_reference(config, reference, device_id=DEVICE_ID)
    assert len(first) == 1
    finding = first[0]
    assert finding.category == f"baseline.expected.{field.value}"
    assert finding.model_version == "expected-config-0.2.0"
    assert finding.observed["source_sha256"] == config.source.sha256
    assert finding.expected["source_sha256"] == reference.source_sha256
    assert finding.observed["present"] is True and finding.expected["present"] is True
    assert finding.expected["reference_facts_sha256"] == reference.fingerprint()
    assert finding == compare_expanded_reference(config, reference, device_id=DEVICE_ID)[0]
    assert reference.model_dump_json() == original_reference


@pytest.mark.parametrize(
    "collection", ["interfaces", "acls", "prefix_lists", "ospf", "local_users"]
)
def test_removed_objects_have_no_borrowed_current_line_anchors(collection: str) -> None:
    config = _config()
    reference = _reference(config)
    getattr(config, collection).clear()
    config.source.sha256 = "e" * 64
    findings = compare_expanded_reference(config, reference, device_id=DEVICE_ID)
    assert findings
    for finding in findings:
        if finding.observed["present"] is False:
            assert finding.affected_lines == []
            assert all(item.source_location is None for item in finding.evidence)
            assert finding.expected["present"] is True


def test_absent_object_is_not_confused_with_present_null_property() -> None:
    config = _config()
    assert config.bgp is not None
    config.bgp.neighbors[0].enabled = None
    reference = _reference(config)
    config.bgp.neighbors.clear()
    findings = compare_expanded_reference(config, reference, device_id=DEVICE_ID)
    enabled = next(item for item in findings if item.category.endswith("bgp.neighbor.enabled"))
    assert enabled.expected["value"] is None and enabled.expected["present"] is True
    assert enabled.observed["value"] is None and enabled.observed["present"] is False


def test_unordered_sets_ignore_input_order_but_ordered_acl_rules_do_not() -> None:
    config = _config()
    config.management.ntp_servers = ["192.0.2.10", "192.0.2.11"]
    reference = _reference(config)
    config.management.ntp_servers.reverse()
    config.management.ntp_servers.append("192.0.2.10")
    config.acls[0].rules[0].source_addresses = ["192.0.2.10/32", "192.0.2.11/32"]
    reference = _reference(config)
    config.acls[0].rules[0].source_addresses.reverse()
    assert compare_expanded_reference(config, reference, device_id=DEVICE_ID) == []
    config.acls[0].rules.reverse()
    findings = compare_expanded_reference(config, reference, device_id=DEVICE_ID)
    assert len(findings) == 1 and findings[0].category.endswith("acls.rules")


@pytest.mark.parametrize("collection", ["interfaces", "acls", "prefix_lists", "ospf", "vlans"])
def test_ambiguous_duplicate_objects_are_refused(collection: str) -> None:
    config = _config()
    items = getattr(config, collection)
    items.append(items[0].model_copy(deep=True))
    with pytest.raises(ValueError, match=r"duplicate|ambiguous"):
        _reference(config)


@pytest.mark.parametrize("partial", ["warning", "confidence", "unparsed"])
def test_reference_projection_rejects_partial_parsing(partial: str) -> None:
    config = _config()
    if partial == "warning":
        config.parse_warnings.append("private warning")
    elif partial == "confidence":
        config.parser_confidence = 0.9
    else:
        config = parse_configuration("hostname edge\nunsupported SECRET\n", filename="x.cfg")
    with pytest.raises(ValueError, match="complete parsing"):
        _reference(config)


def test_reference_revalidates_mutated_contracts_and_identity() -> None:
    config = _config()
    reference = _reference(config)
    config.device.hostname = "different"
    with pytest.raises(ValueError, match="identity"):
        compare_expanded_reference(config, reference, device_id=DEVICE_ID)
    data = json.loads(reference.model_dump_json())
    data["facts"].append(data["facts"][0])
    with pytest.raises(ValidationError, match="duplicate"):
        ExpandedReference.model_validate(data)
    data["facts"] = data["facts"][:1]
    data["facts"][0]["value"] = {"secret": "not supported"}
    with pytest.raises(ValidationError):
        ExpandedReference.model_validate(data)
    bad = reference.model_copy(update={"version": "expected-config-0.1.0"})
    with pytest.raises(ValueError):
        compare_expanded_reference(_config(), bad, device_id=DEVICE_ID)


def _peers(vendor: Vendor = Vendor.CISCO) -> list[CanonicalConfig]:
    return [_config(f"peer-{index}", vendor=vendor) for index in range(3)]


@pytest.mark.parametrize("vendor", list(Vendor))
def test_peer_profile_is_complete_roundtrippable_and_bound_to_independent_sources(
    vendor: Vendor,
) -> None:
    peers = _peers(vendor)
    baseline = build_expanded_peer_baseline(peers)
    assert baseline.model_version == "peer-baseline-0.2.0"
    assert baseline.sample_count == 3
    assert {item.field for item in baseline.features} == set(ExpandedPeerFeature)
    assert baseline.omitted_features == ()
    assert {item.source_sha256 for item in baseline.samples} == {
        config.source.sha256 for config in peers
    }
    assert ExpandedPeerBaseline.model_validate_json(baseline.model_dump_json()) == baseline
    target = _config("target", vendor=vendor)
    evaluation = evaluate_expanded_peer_baseline(target, baseline, device_id=DEVICE_ID)
    assert evaluation.status == "completed" and evaluation.findings == ()
    assert evaluation.compared_features == tuple(item.field for item in baseline.features)
    assert evaluation.skipped_features == ()
    assert evaluation.baseline_sha256 == baseline.fingerprint()


@pytest.mark.parametrize(
    ("field", "feature"),
    [
        (ExpandedField.NTP_SERVERS, ExpandedPeerFeature.NTP_SERVERS),
        (ExpandedField.SYSLOG_SERVERS, ExpandedPeerFeature.SYSLOG_SERVERS),
        (ExpandedField.ACL_RULES, ExpandedPeerFeature.ACL_PATTERNS),
        (ExpandedField.BGP_UPDATE_SOURCE, ExpandedPeerFeature.BGP_NEIGHBOR_PATTERNS),
        (ExpandedField.OSPF_PASSIVE_DEFAULT, ExpandedPeerFeature.OSPF_PROCESS_PATTERNS),
        (ExpandedField.STATIC_TARGETS, ExpandedPeerFeature.STATIC_TARGETS),
    ],
)
def test_peer_values_and_templates_are_not_presence_only(
    field: ExpandedField, feature: ExpandedPeerFeature
) -> None:
    baseline = build_expanded_peer_baseline(_peers())
    target = _config("target")
    _change(target, field)
    first = evaluate_expanded_peer_baseline(target, baseline, device_id=DEVICE_ID)
    assert len(first.findings) == 1
    finding = first.findings[0]
    assert finding.category == f"baseline.{feature.value}_deviation"
    assert finding.observed["source_sha256"] == target.source.sha256
    assert finding.expected["baseline_sha256"] == baseline.fingerprint()
    assert finding.expected["peer_sample_count"] == 3
    assert finding.confidence == 1 and finding.anomaly_score == 1
    assert first == evaluate_expanded_peer_baseline(target, baseline, device_id=DEVICE_ID)


def test_peer_consensus_support_and_omitted_fields_are_explicit() -> None:
    peers = _peers()
    fourth = _config("peer-4")
    fourth.management.ntp_servers = ["192.0.2.99"]
    fourth.source.sha256 = "d" * 64
    baseline = build_expanded_peer_baseline([*peers, fourth])
    ntp = next(item for item in baseline.features if item.field is ExpandedPeerFeature.NTP_SERVERS)
    assert ntp.support_count == 3 and ntp.support_ratio == 0.75
    target = _config("target")
    target.management.ntp_servers = ["192.0.2.99"]
    finding = evaluate_expanded_peer_baseline(target, baseline, device_id=DEVICE_ID).findings[0]
    assert finding.confidence == 0.75
    strict = build_expanded_peer_baseline([*peers, fourth], consensus_threshold=1)
    assert ExpandedPeerFeature.NTP_SERVERS in strict.omitted_features
    assert all(item.field is not ExpandedPeerFeature.NTP_SERVERS for item in strict.features)


def test_peer_templates_do_not_require_individual_router_ids_addresses_or_object_labels() -> None:
    target = _config("target")
    baseline = build_expanded_peer_baseline(_peers())
    assert target.bgp is not None
    target.bgp.router_id = "198.51.100.2"
    target.bgp.neighbors[0].address = "198.51.100.1"
    target.bgp.neighbors[0].group = "OTHER-LABEL"
    target.ospf[0].router_id = "198.51.100.2"
    target.ospf[0].process_id = "99"
    target.ospf[0].networks[0].prefix = "172.16.0.0/24"
    target.ospf[0].interfaces[0].name = "Ethernet99"
    target.interfaces[0].name = "Ethernet99"
    target.acls[0].name = "OTHER-ACL"
    target.acls[0].rules[0].sequence = 100
    target.prefix_lists[0].name = "OTHER-PREFIX"
    target.prefix_lists[0].rules[0].sequence = 100
    target.local_users[0].name = "other-user"
    assert evaluate_expanded_peer_baseline(target, baseline, device_id=DEVICE_ID).findings == ()
    reference = _reference(_config("target"))
    assert compare_expanded_reference(target, reference, device_id=DEVICE_ID)


def test_partial_target_skips_property_comparisons_without_inventing_absences() -> None:
    baseline = build_expanded_peer_baseline(_peers())
    target = _config("target")
    target.management.ntp_servers.clear()
    target.parser_confidence = 0.9
    evaluation = evaluate_expanded_peer_baseline(target, baseline, device_id=DEVICE_ID)
    assert evaluation.status == "partial"
    assert not evaluation.compared_features
    assert evaluation.skipped_features == tuple(item.field for item in baseline.features)
    assert len(evaluation.findings) == 1
    assert evaluation.findings[0].category == "baseline.parser.unsupported_ratio_high"
    assert evaluation.findings[0].affected_lines == []
    assert evaluation.findings[0].limitations
    target.parser_confidence = 0.99
    evaluation = evaluate_expanded_peer_baseline(target, baseline, device_id=DEVICE_ID)
    assert evaluation.status == "partial" and evaluation.findings == ()
    assert evaluation.skipped_features


@pytest.mark.parametrize("case", ["count", "source", "hostname", "group", "partial", "future"])
def test_peer_inputs_and_target_leakage_are_refused(case: str) -> None:
    peers = _peers()
    if case == "count":
        peers = peers[:2]
    elif case == "source":
        peers[1].source.sha256 = peers[0].source.sha256
    elif case == "hostname":
        peers[1].device.hostname = peers[0].device.hostname.upper()
    elif case == "group":
        peers[1].device.role = "different"
    elif case == "partial":
        peers[1].parse_warnings.append("unsupported")
    else:
        peers[1].source.collected_at += timedelta(days=1)
        baseline = build_expanded_peer_baseline(peers)
        with pytest.raises(ValueError, match="future"):
            evaluate_expanded_peer_baseline(_config("target"), baseline, device_id=DEVICE_ID)
        return
    with pytest.raises(ValueError):
        build_expanded_peer_baseline(peers)


def test_target_cannot_be_in_selected_peer_population() -> None:
    peers = _peers()
    baseline = build_expanded_peer_baseline(peers)
    with pytest.raises(ValueError, match="population"):
        evaluate_expanded_peer_baseline(peers[0], baseline, device_id=DEVICE_ID)


def test_profiles_reject_invalid_thresholds_inventory_and_versions() -> None:
    for threshold in [float("nan"), float("inf"), 0.5, 1.01]:
        with pytest.raises(ValueError):
            build_expanded_peer_baseline(_peers(), consensus_threshold=threshold)
    baseline = build_expanded_peer_baseline(_peers())
    data = baseline.model_dump(mode="json")
    data["features"].append(data["features"][0])
    with pytest.raises(ValidationError):
        ExpandedPeerBaseline.model_validate(data)
    data = baseline.model_dump(mode="json")
    data["features"].pop()
    with pytest.raises(ValidationError):
        ExpandedPeerBaseline.model_validate(data)
    bad = baseline.model_copy(update={"model_version": "peer-baseline-0.1.0"})
    with pytest.raises(ValueError):
        evaluate_expanded_peer_baseline(_config("target"), bad, device_id=DEVICE_ID)


def test_finding_identity_includes_version_source_and_exact_profile_not_only_line_numbers() -> None:
    target = _config("target")
    _change(target, ExpandedField.NTP_SERVERS)
    baseline = build_expanded_peer_baseline(_peers())
    first = evaluate_expanded_peer_baseline(target, baseline, device_id=DEVICE_ID).findings[0]
    different = build_expanded_peer_baseline(_peers(), unsupported_ratio_tolerance=0.1)
    second = evaluate_expanded_peer_baseline(target, different, device_id=DEVICE_ID).findings[0]
    assert first.finding_id != second.finding_id
    target.source.sha256 = "b" * 64
    third = evaluate_expanded_peer_baseline(target, baseline, device_id=DEVICE_ID).findings[0]
    assert first.finding_id != third.finding_id


@pytest.mark.parametrize(
    ("vendor", "old", "new", "fields"),
    [
        (
            Vendor.CISCO,
            "ntp server 192.0.2.10",
            "ntp server 192.0.2.11",
            {ExpandedField.NTP_SERVERS},
        ),
        (
            Vendor.JUNIPER,
            "ntp server 192.0.2.10",
            "ntp server 192.0.2.11",
            {ExpandedField.NTP_SERVERS},
        ),
        (
            Vendor.CISCO,
            "logging host 192.0.2.20",
            "logging host 192.0.2.21",
            {ExpandedField.SYSLOG_SERVERS},
        ),
        (
            Vendor.JUNIPER,
            "syslog host 192.0.2.20",
            "syslog host 192.0.2.21",
            {ExpandedField.SYSLOG_SERVERS},
        ),
        (Vendor.CISCO, "ip ssh version 2", "ip ssh version 1", {ExpandedField.SSH_VERSION}),
        (
            Vendor.JUNIPER,
            "ssh protocol-version v2",
            "ssh protocol-version v1",
            {ExpandedField.SSH_VERSION},
        ),
        (Vendor.CISCO, "native vlan 10", "native vlan 20", {ExpandedField.INTERFACE_NATIVE_VLAN}),
        (
            Vendor.CISCO,
            "allowed vlan 10,20",
            "allowed vlan 10,20,30",
            {ExpandedField.INTERFACE_ALLOWED_VLANS},
        ),
        (Vendor.CISCO, "eq 22 log", "eq 22 established", {ExpandedField.ACL_RULES}),
        (Vendor.JUNIPER, "ALLOW then accept", "ALLOW then discard", {ExpandedField.ACL_RULES}),
        (Vendor.CISCO, "/24 le 28", "/24 le 30", {ExpandedField.PREFIX_RULES}),
        (Vendor.CISCO, "remote-as 65002", "remote-as 65003", {ExpandedField.BGP_REMOTE_AS}),
        (Vendor.JUNIPER, "peer-as 65002", "peer-as 65003", {ExpandedField.BGP_REMOTE_AS}),
        (
            Vendor.CISCO,
            "update-source Loopback0",
            "update-source Loopback1",
            {ExpandedField.BGP_UPDATE_SOURCE},
        ),
        (
            Vendor.CISCO,
            "0.0.0.0 0.0.0.0 192.0.2.1 10",
            "0.0.0.0 0.0.0.0 192.0.2.254 10",
            {ExpandedField.STATIC_TARGETS},
        ),
        (
            Vendor.JUNIPER,
            "next-hop 192.0.2.1",
            "next-hop 192.0.2.254",
            {ExpandedField.STATIC_TARGETS},
        ),
        (
            Vendor.JUNIPER,
            "ge-0/0/0.0 metric 20",
            "ge-0/0/0.0 metric 30",
            {ExpandedField.OSPF_INTERFACE_COST},
        ),
        (Vendor.CISCO, "privilege 15", "privilege 1", {ExpandedField.USER_PRIVILEGE}),
        (Vendor.JUNIPER, "class super-user", "class read-only", {ExpandedField.USER_LOGIN_CLASS}),
    ],
)
def test_actual_owned_source_changes_have_exact_current_and_reference_anchors(
    vendor: Vendor, old: str, new: str, fields: set[ExpandedField]
) -> None:
    original = _owned_text(vendor=vendor)
    assert original.count(old) == 1
    current_text = original.replace(old, new)
    current = parse_configuration(current_text, filename="current.cfg", collected_at=COLLECTED_AT)
    reference = _reference(
        parse_configuration(original, filename="reference.cfg", collected_at=COLLECTED_AT)
    )
    findings = compare_expanded_reference(current, reference, device_id=DEVICE_ID)
    assert {item.category for item in findings} == {
        f"baseline.expected.{field.value}" for field in fields
    }
    assert current.source.sha256 == sha256(current_text.encode()).hexdigest()
    changed_line = next(
        index for index, line in enumerate(current_text.splitlines(), 1) if new in line
    )
    for finding in findings:
        assert changed_line in finding.affected_lines
        assert changed_line in finding.expected["reference_lines"]
        for evidence in finding.evidence:
            if evidence.source_location is not None:
                location = evidence.source_location
                selected = "\n".join(
                    current_text.splitlines()[index - 1] for index in location.source_lines
                )
                assert location.raw_text_hash == sha256(selected.encode()).hexdigest()
    assert "PRIVATE_HASH" not in json.dumps([item.model_dump(mode="json") for item in findings])


def test_peer_source_order_and_formatting_do_not_change_the_computed_profile() -> None:
    peers = _peers()
    first = build_expanded_peer_baseline(peers)
    assert first == build_expanded_peer_baseline(list(reversed(peers)))
    assert first.fingerprint() == build_expanded_peer_baseline(list(reversed(peers))).fingerprint()
    target = _config("target")
    target.acls.reverse()
    target.management.ntp_servers.append(target.management.ntp_servers[0])
    assert evaluate_expanded_peer_baseline(target, first, device_id=DEVICE_ID).findings == ()


def test_expanded_facts_and_saved_reference_do_not_alias_the_input_locations() -> None:
    config = _config()
    reference = _reference(config)
    encoded = reference.model_dump_json()
    config.management.provenance["ntp_servers"].source_lines.append(999)
    assert reference.model_dump_json() == encoded


@pytest.mark.parametrize(
    "case", ["roots", "object", "presence", "type", "range", "global_key", "enum"]
)
def test_incomplete_or_semantically_invalid_reference_facts_are_refused(case: str) -> None:
    data = _reference(_config()).model_dump(mode="json")
    if case in {"roots", "object"}:
        selected = ExpandedField.NTP_SERVERS if case == "roots" else ExpandedField.INTERFACE_MODE
        data["facts"] = [item for item in data["facts"] if item["field"] != selected.value]
    else:
        selected = {
            "presence": ExpandedField.INTERFACE_PRESENT,
            "type": ExpandedField.USER_PRIVILEGE,
            "range": ExpandedField.USER_PRIVILEGE,
            "global_key": ExpandedField.NTP_SERVERS,
            "enum": ExpandedField.SSH_VERSION,
        }[case]
        item = next(item for item in data["facts"] if item["field"] == selected.value)
        if case == "global_key":
            item["object_key"] = ["not-device"]
        else:
            item["value"] = {"presence": False, "type": True, "range": 100, "enum": "3"}[case]
    with pytest.raises(ValidationError):
        ExpandedReference.model_validate(data)


def test_individual_junos_update_source_ip_is_not_a_peer_consensus_requirement() -> None:
    peers = _peers(Vendor.JUNIPER)
    for index, config in enumerate(peers, 1):
        assert config.bgp is not None
        config.bgp.neighbors[0].update_source = f"192.0.2.{index}"
    baseline = build_expanded_peer_baseline(peers)
    target = _config("target", vendor=Vendor.JUNIPER)
    assert target.bgp is not None
    target.bgp.neighbors[0].update_source = "198.51.100.10"
    assert evaluate_expanded_peer_baseline(target, baseline, device_id=DEVICE_ID).findings == ()
    target.bgp.neighbors[0].update_source = "2001:db8::1"
    assert evaluate_expanded_peer_baseline(target, baseline, device_id=DEVICE_ID).findings
