"""Explicit same-device reference comparison for supported parameter facts."""

from __future__ import annotations

import json
from typing import Literal
from uuid import UUID, uuid5

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.domain import CanonicalConfig, Evidence, Finding, Severity, SourceLocation, Vendor

REFERENCE_NAMESPACE = UUID("8ced9be4-dd47-44a8-812d-cb640eb6fe81")
type FactField = Literal[
    "bgp.remote_as",
    "interface.mode",
    "interface.access_vlan",
    "interface.addresses",
    "ospf.network_area",
    "ospf.interface_area",
]


class ExpectedFact(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    field: FactField
    object_key: tuple[str, ...] = Field(min_length=1)
    value: str | int | tuple[str, ...] | None
    locations: tuple[SourceLocation, ...] = ()


class ExpectedConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["expected-config-0.1.0"] = "expected-config-0.1.0"
    reference_id: str = Field(min_length=1, max_length=256)
    device_id: UUID
    vendor: Vendor
    platform: str
    hostname: str | None
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    facts: tuple[ExpectedFact, ...]

    @model_validator(mode="after")
    def unique_facts(self) -> ExpectedConfiguration:
        keys = [(fact.field, fact.object_key) for fact in self.facts]
        if len(keys) != len(set(keys)):
            raise ValueError("ambiguous duplicate reference facts")
        return self


def _facts(config: CanonicalConfig) -> tuple[ExpectedFact, ...]:
    facts = []

    def add(
        field: FactField,
        key: tuple[str, ...],
        value: str | int | tuple[str, ...] | None,
        locations: tuple[SourceLocation, ...],
    ) -> None:
        facts.append(ExpectedFact(field=field, object_key=key, value=value, locations=locations))

    if config.bgp is not None:
        for neighbor in config.bgp.neighbors:
            add(
                "bgp.remote_as",
                (neighbor.address,),
                neighbor.remote_as,
                tuple(neighbor.provenance.values()),
            )
    for interface in config.interfaces:
        key = (interface.name, interface.unit or "")
        if interface.switchport_mode is not None:
            location = interface.provenance.get("switchport_mode")
            add("interface.mode", key, interface.switchport_mode, (location,) if location else ())
        if interface.access_vlan is not None:
            vlan = interface.access_vlan
            add(
                "interface.access_vlan",
                key,
                json.dumps([vlan.vlan_id, vlan.name], separators=(",", ":")),
                (vlan.provenance,),
            )
        if interface.addresses:
            add(
                "interface.addresses",
                key,
                tuple(sorted(address.address for address in interface.addresses)),
                tuple(address.provenance for address in interface.addresses),
            )
    for process in config.ospf:
        for network in process.networks:
            add(
                "ospf.network_area",
                (process.process_id, network.prefix),
                network.area_id,
                (network.provenance,),
            )
        for ospf_interface in process.interfaces:
            if ospf_interface.area_id is not None:
                add(
                    "ospf.interface_area",
                    (process.process_id, ospf_interface.name),
                    ospf_interface.area_id,
                    tuple(ospf_interface.provenance.values()),
                )
    keys = [(fact.field, fact.object_key) for fact in facts]
    if len(keys) != len(set(keys)):
        raise ValueError("ambiguous duplicate configuration facts")
    return tuple(sorted(facts, key=lambda item: (item.field, item.object_key)))


def _validated(config: CanonicalConfig) -> CanonicalConfig:
    validated = CanonicalConfig.model_validate(config.model_dump())
    if validated.parse_warnings or validated.unparsed_fragments or validated.parser_confidence < 1:
        raise ValueError("reference comparison requires fully parsed configurations")
    return validated


def create_expected_configuration(
    config: CanonicalConfig,
    *,
    device_id: UUID,
    reference_id: str,
) -> ExpectedConfiguration:
    """Snapshot a caller-selected reference; this function does not approve its safety."""
    config = _validated(config)
    return ExpectedConfiguration(
        reference_id=reference_id,
        device_id=device_id,
        vendor=config.device.vendor,
        platform=config.device.platform,
        hostname=config.device.hostname,
        source_sha256=config.source.sha256,
        facts=_facts(config),
    )


def compare_expected_configuration(
    config: CanonicalConfig,
    reference: ExpectedConfiguration,
    *,
    device_id: UUID,
) -> list[Finding]:
    """Report parameter additions/changes/removals without invented current-line anchors."""
    config = _validated(config)
    reference = ExpectedConfiguration.model_validate(reference.model_dump())
    if (device_id, config.device.vendor, config.device.platform, config.device.hostname) != (
        reference.device_id,
        reference.vendor,
        reference.platform,
        reference.hostname,
    ):
        raise ValueError("configuration identity differs from the selected reference")
    expected = {(fact.field, fact.object_key): fact for fact in reference.facts}
    observed = {(fact.field, fact.object_key): fact for fact in _facts(config)}
    findings = []
    for key in sorted(expected.keys() | observed.keys()):
        before, after = expected.get(key), observed.get(key)
        if before is not None and after is not None and before.value == after.value:
            continue
        current_locations = after.locations if after is not None else ()
        lines = sorted({line for location in current_locations for line in location.source_lines})
        evidence = [
            Evidence(
                kind="current_configuration",
                message=f"Current fact {key[0]} on {key[1]}.",
                source_location=location,
            )
            for location in current_locations
        ]
        reference_lines = (
            sorted({line for location in before.locations for line in location.source_lines})
            if before
            else []
        )
        evidence.append(
            Evidence(
                kind="explicit_reference",
                message=(
                    f"Compared with selected reference {reference.reference_id}, "
                    f"SHA-256 {reference.source_sha256}."
                ),
            )
        )
        limitations = [
            "A difference from a selected reference is not proof of incorrect network behavior.",
            "Scores describe an exact fact difference, not a calibrated probability of a fault.",
            "Reference selection and approval are external; "
            "MEDIUM is a review priority, not simulated impact.",
            "Only supported BGP neighbor AS, interface mode/access VLAN/addresses "
            "and OSPF area facts are compared.",
        ]
        if after is None:
            limitations.append(
                "Expected fact is absent; reference lines are not current affected lines."
            )
        identity = json.dumps(
            [
                str(device_id),
                reference.reference_id,
                reference.source_sha256,
                config.source.sha256,
                key,
            ],
            separators=(",", ":"),
        )
        findings.append(
            Finding(
                finding_id=uuid5(REFERENCE_NAMESPACE, identity),
                device_id=device_id,
                detector="expected_configuration",
                category=f"baseline.expected.{key[0]}",
                title=f"Reference deviation: {key[0]} on {' / '.join(key[1])}",
                severity=Severity.MEDIUM,
                confidence=1.0,
                anomaly_score=1.0,
                affected_lines=lines,
                evidence=evidence,
                observed={
                    "object_key": key[1],
                    "present": after is not None,
                    "value": after.value if after else None,
                    "source_sha256": config.source.sha256,
                },
                expected={
                    "object_key": key[1],
                    "present": before is not None,
                    "value": before.value if before else None,
                    "reference_id": reference.reference_id,
                    "source_sha256": reference.source_sha256,
                    "reference_lines": reference_lines,
                },
                remediation=(
                    "Review the intended change against the selected device reference "
                    "before taking action."
                ),
                references=["docs/expected-configuration.md"],
                limitations=limitations,
                model_version=reference.version,
            )
        )
    return findings
