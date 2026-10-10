"""Versioned CIDR semantics, legacy bytes, and existing dataset consumers."""

import hashlib
from datetime import UTC, datetime
from ipaddress import ip_address, ip_interface, ip_network
from pathlib import Path

import pytest
from app.domain import Vendor
from pydantic import ValidationError

from ml.datasets import (
    DatasetManifest,
    DatasetRecord,
    DatasetSource,
    DatasetSourceType,
    DatasetUse,
    ImportedDatasetRecord,
    LicenseReviewStatus,
    import_local_dataset,
)
from ml.mutation import (
    STRUCTURAL_MUTATION_ENGINE_VERSION,
    MutationType,
    mutate_configuration,
    reverse_mutation,
)
from ml.preprocessing import (
    NETWORK_SANITIZATION_VERSION,
    SANITIZATION_VERSION,
    SanitizationPolicy,
    sanitize_configuration,
)
from ml.preprocessing.blocks import segment_configuration

KEY = b"owned-fixture-only-pseudonym-key-001"
SCOPE = "owned-hierarchical-route"
POLICY = SanitizationPolicy(version=NETWORK_SANITIZATION_VERSION)


def _sanitize(text: str, *, key: bytes = KEY, scope: str = SCOPE):
    return sanitize_configuration(text, topology_id=scope, pseudonymization_key=key, policy=POLICY)


@pytest.mark.parametrize(
    "role",
    (
        "route",
        "route-filter",
        "network",
        "aggregate-address",
        "source-address",
        "destination-address",
        "prefix-list owned-list",
    ),
)
@pytest.mark.parametrize(
    "network,host,prefix",
    (("198.51.100.0/24", "198.51.100.1", 24), ("2001:db8:100::/64", "2001:db8:100::1", 64)),
)
@pytest.mark.parametrize("key", (KEY, b"different-reviewed-fixture-key"))
def test_explicit_network_roles_keep_canonical_prefix_and_host_membership(
    role: str, network: str, host: str, prefix: int, key: bytes
) -> None:
    source = f"{role} {network};\naddress {host}/{prefix};\nnext-hop {host};\n"
    result = _sanitize(source, key=key)
    lines = result.text.splitlines()
    mapped_network = ip_network(lines[0].split()[-1].rstrip(";"), strict=True)
    mapped_interface = ip_interface(lines[1].split()[1].rstrip(";"))
    mapped_next_hop = ip_address(lines[2].split()[1].rstrip(";"))
    assert mapped_network.prefixlen == prefix
    assert mapped_interface.ip == mapped_next_hop
    assert mapped_next_hop in mapped_network
    assert mapped_interface.network == mapped_network
    assert str(mapped_network) != network
    assert result.version == NETWORK_SANITIZATION_VERSION
    assert result.replacements == {"ip_address": 3}
    assert result.text.count("\n") == source.count("\n")
    assert result == _sanitize(source, key=key)


@pytest.mark.parametrize("host,prefix", (("192.0.2.0", 31), ("2001:db8::", 127)))
def test_interface_zero_host_bits_are_not_mistaken_for_network_role(host: str, prefix: int) -> None:
    result = _sanitize(f"address {host}/{prefix};\nnext-hop {host};\n")
    interface, next_hop = result.text.splitlines()
    assert ip_interface(interface.split()[1].rstrip(";")).ip == ip_address(
        next_hop.split()[1].rstrip(";")
    )


@pytest.mark.parametrize(
    "source",
    (
        "route 198.51.100.1/24;",
        "route 2001:db8::1/64;",
        "address 192.0.2.1/33;",
        "address 2001:db8::1/129;",
        "unrecognized 198.51.100.0/24;",
        "    2001:db8::/32;",
        "prefix-list { 198.51.100.0/24; }",
        "route-filter 198.51.100.7/24 exact;",
    ),
)
def test_unsupported_or_invalid_cidr_is_refused_without_echoing_source(source: str) -> None:
    with pytest.raises(ValueError, match="unsupported or invalid CIDR") as error:
        _sanitize(source)
    assert source not in str(error.value)


@pytest.mark.parametrize(
    "source",
    ("ip route 198.51.100.0 255.255.255.0 192.0.2.2", "network 10.0.0.0 0.0.0.255 area 0"),
)
def test_separate_network_masks_are_explicitly_unqualified(source: str) -> None:
    with pytest.raises(ValueError, match="separate network masks"):
        _sanitize(source)


def test_legacy_mapping_and_default_are_not_silently_changed() -> None:
    source = "route 198.51.100.0/24;\naddress 198.51.100.1/24;\n"
    legacy = sanitize_configuration(source, topology_id=SCOPE, pseudonymization_key=KEY)
    explicit = sanitize_configuration(
        source,
        topology_id=SCOPE,
        pseudonymization_key=KEY,
        policy=SanitizationPolicy(version=SANITIZATION_VERSION),
    )
    assert legacy == explicit
    assert legacy.version == SANITIZATION_VERSION
    assert legacy.text == "route 125.190.172.100/24;\naddress 125.190.172.101/24;\n"
    assert _sanitize(source).text == "route 125.190.172.0/24;\naddress 125.190.172.101/24;\n"


def test_scope_separation_and_explicit_no_ip_policy() -> None:
    source = "route 198.51.100.0/24;\n"
    assert _sanitize(source).text != _sanitize(source, scope="other-owned-topology").text
    result = sanitize_configuration(
        source,
        topology_id=SCOPE,
        pseudonymization_key=KEY,
        policy=SanitizationPolicy(
            version=NETWORK_SANITIZATION_VERSION, pseudonymize_ip_addresses=False
        ),
    )
    assert result.text == source and result.replacements == {}
    assert result.version == NETWORK_SANITIZATION_VERSION
    with pytest.raises(ValidationError):
        SanitizationPolicy(version="future-version")


def test_import_segmentation_and_reversible_mutation_accept_explicit_version(
    tmp_path: Path,
) -> None:
    source = (
        "system {\n    host-name owned-edge;\n}\n"
        "routing-options {\n    static {\n        route 198.51.100.0/24 {\n"
        "            next-hop 192.0.2.2;\n        }\n    }\n}\n"
    )
    path = tmp_path / "owned.conf"
    path.write_text(source, encoding="utf-8")
    captured = datetime(2026, 1, 1, tzinfo=UTC)
    manifest = DatasetManifest(
        source=DatasetSource(
            source_id="owned-network-version",
            source_type=DatasetSourceType.LAB,
            origin="authored regression fixture",
            license_id="INTERNAL-OWNED-FIXTURE",
            license_review=LicenseReviewStatus.APPROVED,
            allowed_uses=frozenset({DatasetUse.EVALUATION}),
            collected_at=captured,
        ),
        records=(
            DatasetRecord(
                record_id="owned-edge",
                relative_path="owned.conf",
                network_id="owned-network",
                site_id="owned-site",
                device_id="owned-edge",
                captured_at=captured,
                vendor_hint=Vendor.JUNIPER,
                expected_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
            ),
        ),
    )
    (record,) = import_local_dataset(
        manifest,
        root=tmp_path,
        intended_use=DatasetUse.EVALUATION,
        pseudonymization_key=KEY,
        sanitization_policy=POLICY,
    )
    assert record.sanitization_version == NETWORK_SANITIZATION_VERSION
    assert "".join(block.text for block in segment_configuration(record)) == record.sanitized_text
    sample = mutate_configuration(
        record,
        (MutationType.REMOVED_STATIC_ROUTE,),
        seed=17,
        engine_version=STRUCTURAL_MUTATION_ENGINE_VERSION,
    )
    assert reverse_mutation(sample, sample.mutated_text) == record.sanitized_text
    assert sample.formal_validation.status == "not_run"
    unsupported = ImportedDatasetRecord.model_validate(
        {
            **record.model_dump(),
            "sanitization_version": "unrecognized-version",
        }
    )
    with pytest.raises(ValueError, match="unsupported sanitization version"):
        segment_configuration(unsupported)
    with pytest.raises(ValueError, match="unsupported sanitization version"):
        mutate_configuration(unsupported, (MutationType.REMOVED_STATIC_ROUTE,))
