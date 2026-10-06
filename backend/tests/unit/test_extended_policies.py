"""Every new requirement has counterexamples, exact anchors and versioned evidence."""

from uuid import UUID

import pytest
from app.detection.policy_engine import evaluate_policies
from app.domain import CanonicalConfig
from app.explanation.knowledge import KnowledgeUnavailable, load_knowledge_catalog
from app.explanation.local import explain_finding
from app.parsers import parse_configuration
from app.policies import ACCOUNT_RULES, POLICY_CATALOG_VERSION, POLICY_CATALOGS, POLICY_RULES

DEVICE = UUID(int=1)
CASES = (
    (
        "account.passwordless",
        "hostname edge\nusername test nopassword\n",
        "hostname edge\nusername test secret 9 PRIVATE\n",
        [2],
    ),
    (
        "account.cleartext_credential",
        "hostname edge\nusername test secret 0 PRIVATE\n",
        "hostname edge\nusername test secret 9 PRIVATE\n",
        [2],
    ),
    (
        "account.reversible_password",
        "hostname edge\nusername test password 7 PRIVATE\n",
        "hostname edge\nusername test secret 9 PRIVATE\n",
        [2],
    ),
    (
        "account.legacy_secret",
        "hostname edge\nusername test secret 5 PRIVATE\n",
        "hostname edge\nusername test secret 8 PRIVATE\n",
        [2],
    ),
    (
        "account.duplicate_uid",
        (
            "set system host-name edge\n"
            "set system login user a uid 1001\n"
            "set system login user b uid 1001\n"
        ),
        (
            "set system host-name edge\n"
            "set system login user a uid 1001\n"
            "set system login user b uid 1002\n"
        ),
        [2, 3],
    ),
    (
        "routing.static_next_hop_is_local",
        (
            "hostname edge\n"
            "interface Gi0/1\n"
            " ip address 192.0.2.1 255.255.255.0\n"
            "!\n"
            "ip route 198.51.100.0 255.255.255.0 192.0.2.1\n"
        ),
        (
            "hostname edge\n"
            "interface Gi0/1\n"
            " ip address 192.0.2.1 255.255.255.0\n"
            "!\n"
            "ip route 198.51.100.0 255.255.255.0 192.0.2.2\n"
        ),
        [3, 5],
    ),
    (
        "routing.static_next_hop_non_unicast",
        "hostname edge\nip route 198.51.100.0 255.255.255.0 224.0.0.1\n",
        "hostname edge\nip route 198.51.100.0 255.255.255.0 192.0.2.2\n",
        [2],
    ),
    (
        "interface.vlan_reference_undefined",
        "hostname edge\ninterface Gi0/1\n switchport mode access\n switchport access vlan 10\n",
        (
            "hostname edge\n"
            "vlan 10\n"
            " name USERS\n"
            "!\n"
            "interface Gi0/1\n"
            " switchport mode access\n"
            " switchport access vlan 10\n"
        ),
        [4],
    ),
    (
        "interface.native_vlan_excluded",
        (
            "hostname edge\n"
            "interface Gi0/1\n"
            " switchport mode trunk\n"
            " switchport trunk native vlan 10\n"
            " switchport trunk allowed vlan 20\n"
        ),
        (
            "hostname edge\n"
            "interface Gi0/1\n"
            " switchport mode trunk\n"
            " switchport trunk native vlan 10\n"
            " switchport trunk allowed vlan 10,20\n"
        ),
        [4, 5],
    ),
    (
        "interface.duplicate_address",
        (
            "hostname edge\n"
            "interface Gi0/1\n"
            " ip address 192.0.2.1 255.255.255.0\n"
            "!\n"
            "interface Gi0/2\n"
            " ip address 192.0.2.1 255.255.255.252\n"
        ),
        (
            "hostname edge\n"
            "interface Gi0/1\n"
            " ip address 192.0.2.1 255.255.255.0\n"
            "!\n"
            "interface Gi0/2\n"
            " ip address 192.0.2.2 255.255.255.252\n"
        ),
        [3, 6],
    ),
)


def selected(text, rule_id, *, version=POLICY_CATALOG_VERSION):
    config = parse_configuration(text, filename="synthetic.cfg")
    rule = next(rule for rule in POLICY_CATALOGS[version] if rule.rule_id == rule_id)
    return (
        config,
        rule,
        evaluate_policies(config, device_id=DEVICE, rules=(rule,), catalog_version=version),
    )


@pytest.mark.parametrize("rule_id,positive,negative,lines", CASES)
def test_each_new_policy_has_positive_negative_stable_evidence_and_resolved_explanation(
    rule_id, positive, negative, lines
):
    config, rule, findings = selected(positive, rule_id)
    assert not config.unparsed_fragments
    assert len(findings) == 1
    finding = findings[0]
    assert finding.affected_lines == lines and finding.evidence
    assert finding.model_version == POLICY_CATALOG_VERSION
    assert finding.remediation == rule.remediation and finding.references == list(rule.references)
    assert finding.severity == rule.severity and finding.anomaly_score == 0
    assert selected(positive, rule_id)[2] == findings
    assert selected(negative, rule_id)[2] == []
    explanation = explain_finding(finding, config)
    assert explanation.anchors and explanation.requires_human_review
    assert explanation.formal_verification == "not_run" and explanation.patch_draft is None
    assert (
        tuple(chunk.citation for chunk in load_knowledge_catalog().retrieve(finding))
        == rule.references
    )
    assert "PRIVATE" not in finding.model_dump_json() + explanation.model_dump_json()


@pytest.mark.parametrize(
    "rule_id,text",
    [
        ("account.cleartext_credential", "hostname edge\nusername test password 0 PRIVATE\n"),
        ("account.legacy_secret", "hostname edge\nusername test secret 4 PRIVATE\n"),
        (
            "routing.static_next_hop_is_local",
            (
                "set system host-name edge\n"
                "set interfaces ge-0/0/0 unit 0 family inet6 address 2001:db8::1/64\n"
                "set routing-options static route 2001:db8:2::/64 next-hop 2001:db8::1\n"
            ),
        ),
        (
            "routing.static_next_hop_non_unicast",
            (
                "set system host-name edge\n"
                "set routing-options static route 2001:db8:2::/64 next-hop ff02::1\n"
            ),
        ),
        (
            "routing.static_next_hop_non_unicast",
            "hostname edge\nip route 198.51.100.0 255.255.255.0 0.0.0.0\n",
        ),
        (
            "routing.static_next_hop_non_unicast",
            "hostname edge\nip route 198.51.100.0 255.255.255.0 255.255.255.255\n",
        ),
        (
            "interface.vlan_reference_undefined",
            (
                "set system host-name edge\n"
                "set interfaces ge-0/0/1 unit 0 family ethernet-switching interface-mode access\n"
                "set interfaces ge-0/0/1 unit 0 family ethernet-switching vlan members UNKNOWN\n"
            ),
        ),
        (
            "interface.vlan_reference_undefined",
            (
                "hostname edge\n"
                "interface Gi0/1\n"
                " switchport mode trunk\n"
                " switchport trunk allowed vlan 10,20\n"
            ),
        ),
        (
            "interface.native_vlan_excluded",
            (
                "hostname edge\n"
                "interface Gi0/1\n"
                " switchport mode trunk\n"
                " switchport trunk native vlan 10\n"
                " switchport trunk allowed vlan none\n"
            ),
        ),
        (
            "interface.duplicate_address",
            (
                "set system host-name edge\n"
                "set interfaces ge-0/0/0 unit 0 family inet6 address 2001:db8::1/64\n"
                "set interfaces ge-0/0/1 unit 0 family inet6 address 2001:db8::1/128\n"
            ),
        ),
    ],
)
def test_new_rules_cover_supported_encodings_vendors_and_ipv6(rule_id, text):
    config, _, findings = selected(text, rule_id)
    assert not config.unparsed_fragments and len(findings) == 1


@pytest.mark.parametrize(
    "rule_id,text",
    [
        ("account.passwordless", "hostname edge\nusername test privilege 1\n"),
        (
            "account.passwordless",
            "set system host-name edge\nset system login user remote class read-only\n",
        ),
        ("account.cleartext_credential", "hostname edge\nusername test secret PRIVATE\n"),
        (
            "account.legacy_secret",
            (
                "set system host-name edge\n"
                'set system login user test authentication encrypted-password "PRIVATE"\n'
            ),
        ),
        (
            "account.duplicate_uid",
            (
                "set system host-name edge\n"
                "set system login user a class operator\n"
                "set system login user b class operator\n"
            ),
        ),
        (
            "account.duplicate_uid",
            (
                "set system host-name edge\n"
                "set system login user a uid 1001\n"
                "set system login user a uid 1001\n"
            ),
        ),
        (
            "routing.static_next_hop_non_unicast",
            "hostname edge\nip route 198.51.100.0 255.255.255.0 Null0\n",
        ),
        (
            "routing.static_next_hop_non_unicast",
            (
                "set system host-name edge\n"
                "set routing-options static route 2001:db8:2::/64 next-hop fe80::1\n"
            ),
        ),
        (
            "interface.vlan_reference_undefined",
            (
                "hostname edge\n"
                "interface Gi0/1\n"
                " switchport mode trunk\n"
                " switchport trunk allowed vlan all\n"
            ),
        ),
        (
            "interface.vlan_reference_undefined",
            (
                "set system host-name edge\n"
                "set vlans USERS vlan-id 10\n"
                "set interfaces ge-0/0/1 unit 0 family ethernet-switching interface-mode access\n"
                "set interfaces ge-0/0/1 unit 0 family ethernet-switching vlan members USERS\n"
            ),
        ),
        (
            "interface.native_vlan_excluded",
            (
                "hostname edge\n"
                "interface Gi0/1\n"
                " switchport mode trunk\n"
                " switchport trunk native vlan 10\n"
                " switchport trunk allowed vlan all\n"
            ),
        ),
        (
            "interface.native_vlan_excluded",
            (
                "set system host-name edge\n"
                "set interfaces ge-0/0/1 native-vlan-id 10\n"
                "set interfaces ge-0/0/1 unit 0 family ethernet-switching interface-mode trunk\n"
                "set interfaces ge-0/0/1 unit 0 family ethernet-switching vlan members 20\n"
            ),
        ),
        (
            "interface.duplicate_address",
            (
                "hostname edge\n"
                "interface Gi0/1\n"
                " ip address 192.0.2.1 255.255.255.0\n"
                " ip address 192.0.2.1 255.255.255.0\n"
            ),
        ),
        (
            "interface.duplicate_address",
            (
                "hostname edge\n"
                "interface Gi0/1\n"
                " ip address 192.0.2.1 255.255.255.0\n"
                "!\n"
                "interface Gi0/2\n"
                " ip address 192.0.2.1 255.255.255.0\n"
                " shutdown\n"
            ),
        ),
    ],
)
def test_absent_implicit_other_vendor_and_legitimate_scope_are_not_guessed(rule_id, text):
    _, rule, findings = selected(text, rule_id)
    assert findings == []
    assert rule.references


def test_malformed_credential_options_cannot_produce_new_account_findings():
    config = parse_configuration(
        "hostname edge\nusername test secret 0 PRIVATE unknown\n", filename="synthetic.cfg"
    )
    assert config.unparsed_fragments and not config.local_users
    assert evaluate_policies(config, device_id=DEVICE, rules=ACCOUNT_RULES) == []


def test_uid_collision_is_detected_even_when_canonical_source_anchor_is_unavailable():
    config = parse_configuration("set system host-name edge\n", filename="synthetic.conf")
    data = config.model_dump()
    data["local_users"] = [{"name": "a", "uid": 1001}, {"name": "b", "uid": 1001}]
    restored = CanonicalConfig.model_validate(data)
    rule = next(rule for rule in POLICY_RULES if rule.rule_id == "account.duplicate_uid")
    finding = evaluate_policies(restored, device_id=DEVICE, rules=(rule,))[0]
    assert finding.affected_lines == [] and finding.evidence[0].source_location is None


def test_catalog_version_is_bound_and_old_findings_explain_without_new_rules():
    config = parse_configuration(
        "hostname edge\nusername test nopassword\n", filename="synthetic.cfg"
    )
    legacy = evaluate_policies(config, device_id=DEVICE, catalog_version="policy-rules-0.6.0")
    assert len(POLICY_CATALOGS["policy-rules-0.6.0"]) == 20
    assert not any(item.category.startswith("account.") for item in legacy)
    assert all(item.model_version == "policy-rules-0.6.0" for item in legacy)
    for finding in legacy:
        assert explain_finding(finding, config).detector_version == "policy-rules-0.6.0"
        assert load_knowledge_catalog().retrieve(finding)
    with pytest.raises(ValueError, match="catalog"):
        evaluate_policies(config, device_id=DEVICE, catalog_version="unknown")
    with pytest.raises(ValueError, match="catalog"):
        evaluate_policies(
            config, device_id=DEVICE, rules=ACCOUNT_RULES, catalog_version="policy-rules-0.6.0"
        )
    with pytest.raises(ValueError, match="catalog"):
        evaluate_policies(config, device_id=DEVICE, rules=(POLICY_RULES[0], POLICY_RULES[0]))
    new = next(
        item
        for item in evaluate_policies(config, device_id=DEVICE)
        if item.category == "account.passwordless"
    )
    mislabeled = new.model_copy(update={"model_version": "policy-rules-0.6.0"})
    with pytest.raises(ValueError):
        explain_finding(mislabeled, config)
    with pytest.raises(KnowledgeUnavailable):
        load_knowledge_catalog().retrieve(mislabeled)
    with pytest.raises(TypeError):
        POLICY_CATALOGS["invented"] = POLICY_RULES
