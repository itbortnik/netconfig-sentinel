"""Two owned toy topologies, bound before model generation, never quality data."""

from dataclasses import dataclass, field
from uuid import UUID

from app.detection.policy_engine import evaluate_policies
from app.explanation.knowledge import text_sha256
from app.explanation.patch_provider import build_patch_prompt
from app.parsers import parse_configuration
from app.verification.snapshots import NetworkSnapshot, prepare_snapshot

from ml.instruct.patch_smoke import OwnedPatchCase


@dataclass(frozen=True)
class OwnedNetworkPatchCase:
    patch: OwnedPatchCase = field(repr=False)
    before: NetworkSnapshot = field(repr=False)


def authored_network_patch_cases() -> tuple[OwnedNetworkPatchCase, ...]:
    cisco_edge = (
        "version 17.9\nhostname edge\nip ssh version 1\n"
        "interface GigabitEthernet0/0\n ip address 192.0.2.1 255.255.255.252\n"
        " no shutdown\n!\nip route 198.51.100.0 255.255.255.0 192.0.2.2\nend\n"
    )
    cisco_core = (
        "version 17.9\nhostname core\ninterface GigabitEthernet0/0\n"
        " ip address 192.0.2.2 255.255.255.252\n no shutdown\n!\n"
        "interface Loopback0\n ip address 198.51.100.1 255.255.255.0\nend\n"
    )
    juniper_edge = (
        "set system host-name edge\nset system services ssh protocol-version v1\n"
        "set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/30\n"
        "set routing-options static route 198.51.100.0/24 next-hop 192.0.2.2\n"
    )
    juniper_core = (
        "set system host-name core\n"
        "set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.2/30\n"
        "set interfaces lo0 unit 0 family inet address 198.51.100.1/24\n"
    )
    cases = []
    for vendor, edge, core, old, new in (
        ("cisco", cisco_edge, cisco_core, "ip ssh version 1", "ip ssh version 2"),
        ("juniper", juniper_edge, juniper_core, "protocol-version v1", "protocol-version v2"),
    ):
        before = prepare_snapshot({UUID(int=1): edge, UUID(int=2): core})
        finding = next(
            row
            for row in evaluate_policies(
                parse_configuration(edge, filename="owned-edge.cfg"), device_id=UUID(int=1)
            )
            if row.category == "management.ssh_version_1"
        )
        prepared = build_patch_prompt(
            edge,
            finding=finding,
            source_sha256=text_sha256(edge),
            baseline=edge.replace(old, new),
            reference_id="owned-network-baseline",
            allow_local_context=True,
        )
        cases.append(OwnedNetworkPatchCase(OwnedPatchCase(vendor, prepared), before))
    return tuple(cases)
