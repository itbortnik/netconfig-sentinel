"""Authored synthetic network scenarios, not captures or real anomaly labels."""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from app.domain import Vendor
from app.parsers.registry import parse_configuration

from ml.datasets import ImportedDatasetRecord, deduplicate_dataset, split_deduplicated_dataset
from ml.mutation import list_applicable_mutations
from ml.preprocessing import sanitize_configuration
from ml.preprocessing.blocks import digest

LAB_VERSION = "authored-laboratory-0.1.0"

# Each pair is one synthetic scenario. Cisco/JunOS are kept together when splitting.
# These structural differences are deliberate, not random identifier perturbations.
SCENARIOS: tuple[tuple[str, str, str], ...] = (
    (
        "static-branch",
        "interface GigabitEthernet0/0\n ip address 192.0.2.1 255.255.255.252\n!\n"
        "ip route 0.0.0.0 0.0.0.0 192.0.2.2\n",
        "set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/30\n"
        "set routing-options static route 0.0.0.0/0 next-hop 192.0.2.2\n",
    ),
    (
        "bgp-edge",
        "interface GigabitEthernet0/1\n ip address 198.51.100.1 255.255.255.252\n!\n"
        "router bgp 65001\n bgp router-id 198.51.100.1\n"
        " neighbor 198.51.100.2 remote-as 65002\n neighbor 198.51.100.2 description Transit\n!\n",
        "set interfaces ge-0/0/1 unit 0 family inet address 198.51.100.1/30\n"
        "set routing-options autonomous-system 65001\nset routing-options router-id 198.51.100.1\n"
        "set protocols bgp group TRANSIT type external\n"
        "set protocols bgp group TRANSIT peer-as 65002\n"
        "set protocols bgp group TRANSIT neighbor 198.51.100.2\n",
    ),
    (
        "ospf-core",
        "interface Loopback0\n ip address 192.0.2.10 255.255.255.255\n!\n"
        "interface GigabitEthernet0/2\n ip address 203.0.113.1 255.255.255.252\n!\n"
        "router ospf 10\n router-id 192.0.2.10\n passive-interface default\n"
        " no passive-interface GigabitEthernet0/2\n network 203.0.113.0 0.0.0.3 area 0\n!\n",
        "set interfaces lo0 unit 0 family inet address 192.0.2.10/32\n"
        "set interfaces ge-0/0/2 unit 0 family inet address 203.0.113.1/30\n"
        "set protocols ospf area 0 interface ge-0/0/2.0 metric 10\n"
        "set protocols ospf area 0 interface lo0.0 passive\n",
    ),
    (
        "access-switch",
        "vlan 10\n name USERS\n!\nvlan 20\n name VOICE\n!\n"
        "interface GigabitEthernet0/3\n switchport mode access\n switchport access vlan 10\n!\n"
        "interface GigabitEthernet0/4\n switchport mode access\n switchport access vlan 20\n!\n",
        "set vlans USERS vlan-id 10\nset vlans VOICE vlan-id 20\n"
        "set interfaces ge-0/0/3 unit 0 family ethernet-switching interface-mode access\n"
        "set interfaces ge-0/0/3 unit 0 family ethernet-switching vlan members USERS\n"
        "set interfaces ge-0/0/4 unit 0 family ethernet-switching interface-mode access\n"
        "set interfaces ge-0/0/4 unit 0 family ethernet-switching vlan members VOICE\n",
    ),
    (
        "distribution-trunk",
        "vlan 30\n name APPS\n!\nvlan 40\n name DATABASES\n!\nvlan 99\n name NATIVE\n!\n"
        "interface GigabitEthernet0/5\n switchport mode trunk\n switchport trunk native vlan 99\n"
        " switchport trunk allowed vlan 30,40,99\n!\n",
        "set vlans APPS vlan-id 30\nset vlans DATABASES vlan-id 40\nset vlans NATIVE vlan-id 99\n"
        "set interfaces ge-0/0/5 unit 0 family ethernet-switching interface-mode trunk\n"
        "set interfaces ge-0/0/5 unit 0 family ethernet-switching vlan members "
        "[ APPS DATABASES NATIVE ]\n",
    ),
    (
        "filtered-router",
        "interface GigabitEthernet0/6\n ip address 192.0.2.65 255.255.255.192\n!\n"
        "ip access-list extended MGMT-IN\n"
        " 10 permit tcp 192.0.2.64 0.0.0.63 host 192.0.2.65 eq ssh log\n"
        " 20 deny ip any any log\n!\n"
        "ip prefix-list TRUSTED seq 10 permit 192.0.2.64/26 le 32\n"
        "ip route 203.0.113.0 255.255.255.0 Null0 250\n",
        "set interfaces ge-0/0/6 unit 0 family inet address 192.0.2.65/26\n"
        "set firewall family inet filter MGMT-IN term SSH from source-address 192.0.2.64/26\n"
        "set firewall family inet filter MGMT-IN term SSH from protocol tcp\n"
        "set firewall family inet filter MGMT-IN term SSH from destination-port ssh\n"
        "set firewall family inet filter MGMT-IN term SSH then accept\n"
        "set firewall family inet filter MGMT-IN term DENY then discard\n"
        "set policy-options prefix-list TRUSTED 192.0.2.64/26\n"
        "set routing-options static route 203.0.113.0/24 discard\n",
    ),
)


def laboratory_records() -> tuple[ImportedDatasetRecord, ...]:
    """Twelve authored references, six hypothetical paired network scenarios."""
    records = []
    for index, (role, cisco, junos) in enumerate(SCENARIOS):
        for vendor, body in ((Vendor.CISCO, cisco), (Vendor.JUNIPER, junos)):
            network = f"lab-network-{index + 1}"
            if vendor is Vendor.CISCO:
                management = (
                    "aaa new-model\nip ssh version 2\nline vty 0 4\n transport input ssh\n!\n"
                )
                observability = "ntp server 192.0.2.123\nlogging host 192.0.2.124\n"
                text = f"hostname lab-{role}-cisco\n" + (
                    management + body + observability
                    if index % 2
                    else body + observability + management
                )
            else:
                management = (
                    "set system services ssh\nset system authentication-order [ radius password ]\n"
                )
                observability = (
                    "set system ntp server 192.0.2.123\n"
                    "set system syslog host 192.0.2.124 any notice\n"
                )
                text = f"set system host-name lab-{role}-junos\n" + (
                    body + observability + management
                    if index % 2
                    else management + body + observability
                )
            sanitized = sanitize_configuration(
                text,
                topology_id=network,
                pseudonymization_key=b"public-synthetic-lab-key-v1",
            )
            records.append(
                ImportedDatasetRecord(
                    source_id="authored-laboratory",
                    record_id=f"{role}-{vendor.value}",
                    network_id=network,
                    site_id=f"lab-site-{index + 1}",
                    device_id=f"{network}-{vendor.value}",
                    captured_at=datetime(2026, 1, 1, tzinfo=UTC) + timedelta(days=index),
                    vendor_hint=vendor,
                    device_role=role,
                    raw_sha256=digest(text),
                    sanitized_sha256=digest(sanitized.text),
                    sanitized_text=sanitized.text,
                    raw_byte_count=len(text.encode()),
                    replacements=sanitized.replacements,
                    sanitization_version=sanitized.version,
                )
            )
    return tuple(records)


def write_laboratory_bundle(path: Path) -> dict[str, object]:
    """Audit and save a new local bundle; no automatic training or external imports."""
    records = laboratory_records()
    dedup = deduplicate_dataset(records)
    splits = split_deduplicated_dataset(records, dedup)
    audits = []
    for record in records:
        parsed = parse_configuration(
            record.sanitized_text, filename=record.record_id, collected_at=record.captured_at
        )
        audits.append(
            {
                "record_id": record.record_id,
                "scenario": record.device_role,
                "vendor": record.vendor_hint,
                "source_sha256": record.sanitized_sha256,
                "warnings": len(parsed.parse_warnings),
                "unparsed": len(parsed.unparsed_fragments),
                "applicable_mutations": [item.value for item in list_applicable_mutations(record)],
            }
        )
    report: dict[str, object] = {
        "version": LAB_VERSION,
        "origin": "Authored repository scenario templates",
        "synthetic_only": True,
        "real_confirmed_anomalies": 0,
        "candidate_configurations": len(records),
        "hypothetical_network_scenarios": len(SCENARIOS),
        "independent_real_networks": 0,
        "device_acceptance_tested": False,
        "timestamps_are_synthetic": True,
        "partitions": [
            {
                "split": part.split,
                "records": len(part.records),
                "vendors": sorted({str(record.vendor_hint) for record in part.records}),
                "scenarios": sorted({str(record.device_role) for record in part.records}),
            }
            for part in splits.partitions
        ],
        "records": audits,
    }
    path.mkdir(exist_ok=False)
    (path / ".incomplete").write_text("bundle writing\n", encoding="utf-8")
    for record in records:
        (path / f"{record.record_id}.conf").write_text(record.sanitized_text, encoding="utf-8")
    (path / "records.json").write_text(
        json.dumps([r.model_dump(mode="json") for r in records]), encoding="utf-8"
    )
    (path / "deduplication.json").write_text(dedup.model_dump_json(), encoding="utf-8")
    (path / "splits.json").write_text(splits.model_dump_json(), encoding="utf-8")
    (path / "audit.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (path / ".incomplete").unlink()
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output already exists")
    print(json.dumps(write_laboratory_bundle(args.output), indent=2))


if __name__ == "__main__":
    main()
