"""Explicit reference parameter comparisons, identity guards and source evidence."""

from uuid import UUID

import pytest
from app.detection.baseline.expected import (
    ExpectedConfiguration,
    compare_expected_configuration,
    create_expected_configuration,
)
from app.domain import Vendor
from app.parsers import parse_configuration

from ml.datasets.laboratory import laboratory_records
from ml.mutation import MutationType, mutate_configuration

DEVICE = UUID("f6156954-3f3b-4aa2-b693-5a710fe35d44")


@pytest.mark.parametrize("vendor", [Vendor.CISCO, Vendor.JUNIPER])
@pytest.mark.parametrize(
    ("scenario", "mutation", "field"),
    [
        ("bgp-edge", MutationType.BGP_REMOTE_AS_MISMATCH, "bgp.remote_as"),
        ("bgp-edge", MutationType.MISSING_BGP_NEIGHBOR, "bgp.remote_as"),
        ("ospf-core", MutationType.OSPF_AREA_MISMATCH, "ospf."),
        ("ospf-core", MutationType.CONFLICTING_IP_ADDRESS, "interface.addresses"),
        ("access-switch", MutationType.VLAN_MISMATCH, "interface.access_vlan"),
        ("access-switch", MutationType.INCORRECT_ACCESS_TRUNK_MODE, "interface.mode"),
    ],
)
def test_reference_detects_structural_mutations_with_evidence(
    vendor: Vendor,
    scenario: str,
    mutation: MutationType,
    field: str,
) -> None:
    record = next(
        record
        for record in laboratory_records()
        if record.vendor_hint is vendor and record.device_role == scenario
    )
    original = parse_configuration(record.sanitized_text, filename="original.conf")
    reference = create_expected_configuration(
        original, device_id=DEVICE, reference_id="lab-reference-v1"
    )
    assert compare_expected_configuration(original, reference, device_id=DEVICE) == []
    sample = mutate_configuration(record, (mutation,), seed=17)
    changed = parse_configuration(sample.mutated_text, filename="current.conf")
    findings = compare_expected_configuration(changed, reference, device_id=DEVICE)
    matching = [finding for finding in findings if field in finding.category]
    assert matching
    assert findings == compare_expected_configuration(changed, reference, device_id=DEVICE)
    for finding in matching:
        assert finding.observed["value"] != finding.expected["value"]
        assert finding.expected["source_sha256"] == original.source.sha256
        assert finding.observed["source_sha256"] == changed.source.sha256
        assert finding.expected["reference_lines"]
        if mutation is MutationType.MISSING_BGP_NEIGHBOR:
            assert not finding.affected_lines
            assert finding.observed["present"] is False
        else:
            assert set(finding.affected_lines) & set(sample.affected_lines)


def test_reference_identity_unknown_syntax_and_formatting_guards() -> None:
    record = laboratory_records()[0]
    original = parse_configuration(record.sanitized_text, filename="original.conf")
    reference = create_expected_configuration(
        original, device_id=DEVICE, reference_id="selected-v1"
    )
    shifted = parse_configuration("\n! review\n" + record.sanitized_text, filename="shifted.conf")
    assert compare_expected_configuration(shifted, reference, device_id=DEVICE) == []
    with pytest.raises(ValueError, match="identity"):
        compare_expected_configuration(original, reference, device_id=UUID(int=1))
    original.device.hostname = "different-device"
    with pytest.raises(ValueError, match="identity"):
        compare_expected_configuration(original, reference, device_id=DEVICE)
    unknown = parse_configuration(
        record.sanitized_text + "unsupported-command\n", filename="unknown.conf"
    )
    with pytest.raises(ValueError, match="fully parsed"):
        create_expected_configuration(unknown, device_id=DEVICE, reference_id="unknown")
    with pytest.raises(ValueError, match="fully parsed"):
        compare_expected_configuration(unknown, reference, device_id=DEVICE)


@pytest.mark.parametrize("vendor", [Vendor.CISCO, Vendor.JUNIPER])
def test_reference_addition_roundtrip_and_snapshot(vendor: Vendor) -> None:
    record = next(
        record
        for record in laboratory_records()
        if record.vendor_hint is vendor and record.device_role == "bgp-edge"
    )
    sample = mutate_configuration(record, (MutationType.MISSING_BGP_NEIGHBOR,), seed=17)
    reduced = parse_configuration(sample.mutated_text, filename="reference.conf")
    reference = create_expected_configuration(reduced, device_id=DEVICE, reference_id="reduced")
    reference = ExpectedConfiguration.model_validate_json(reference.model_dump_json())
    current = parse_configuration(record.sanitized_text, filename="current.conf")
    findings = compare_expected_configuration(current, reference, device_id=DEVICE)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.category == "baseline.expected.bgp.remote_as"
    assert finding.observed["present"] is True
    assert finding.expected["present"] is False
    assert finding.expected["reference_lines"] == []
    assert finding.affected_lines
    saved = reference.model_dump_json()
    reduced.interfaces.clear()
    assert reference.model_dump_json() == saved
    duplicate = reference.model_dump()
    duplicate["facts"] = (*duplicate["facts"], duplicate["facts"][0])
    with pytest.raises(ValueError, match="duplicate"):
        ExpectedConfiguration.model_validate(duplicate)
