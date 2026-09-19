"""Structurally different authored scenarios, deterministic provenance and split isolation."""

import json
from pathlib import Path

import pytest
from app.domain import Vendor
from app.parsers.registry import parse_configuration

from ml.datasets import deduplicate_dataset, split_deduplicated_dataset
from ml.datasets.laboratory import laboratory_records, write_laboratory_bundle
from ml.mutation import MutationType, list_applicable_mutations


def test_scenarios_are_parsed_structurally_and_have_management_mutations() -> None:
    records = laboratory_records()
    assert records == laboratory_records()
    assert len(records) == 12
    assert len({record.sanitized_sha256 for record in records}) == 12
    for record in records:
        config = parse_configuration(record.sanitized_text, filename=record.record_id)
        assert not config.parse_warnings
        assert not config.unparsed_fragments
        assert config.device.vendor == record.vendor_hint
        assert config.management.aaa_enabled
        assert config.management.ssh_enabled
        assert not config.management.telnet_enabled
        applicable = list_applicable_mutations(record)
        assert MutationType.AAA_DISABLED in applicable
        assert MutationType.TELNET_ENABLED in applicable
        if record.device_role == "bgp-edge":
            assert config.bgp is not None
            assert MutationType.BGP_REMOTE_AS_MISMATCH in applicable
        elif record.device_role == "ospf-core":
            assert config.ospf
        elif record.device_role == "filtered-router":
            assert config.acls and config.static_routes
        elif record.device_role == "static-branch":
            assert config.static_routes
        else:
            assert config.vlans


def test_network_pairs_and_scenarios_do_not_cross_partitions() -> None:
    records = laboratory_records()
    splits = split_deduplicated_dataset(records, deduplicate_dataset(records))
    assert [len(partition.records) for partition in splits.partitions] == [8, 2, 2]
    placements = {}
    for partition in splits.partitions:
        assert {record.vendor_hint for record in partition.records} == {
            Vendor.CISCO,
            Vendor.JUNIPER,
        }
        for record in partition.records:
            assert placements.setdefault(record.network_id, partition.split) == partition.split
            assert (
                placements.setdefault(str(record.device_role), partition.split) == partition.split
            )


def test_bundle_records_provenance_and_refuses_overwrite(tmp_path: Path) -> None:
    path = tmp_path / "lab"
    audit = write_laboratory_bundle(path)
    assert audit["independent_real_networks"] == 0
    assert audit["real_confirmed_anomalies"] == 0
    assert audit["timestamps_are_synthetic"] is True
    assert not (path / ".incomplete").exists()
    assert len(list(path.glob("*.conf"))) == 12
    assert len(json.loads((path / "records.json").read_text(encoding="utf-8"))) == 12
    with pytest.raises(FileExistsError):
        write_laboratory_bundle(path)
