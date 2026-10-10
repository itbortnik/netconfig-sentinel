"""Explicit IOS/XE CIDR roles without changing historical sanitization."""

import hashlib
from datetime import UTC, datetime
from ipaddress import ip_address, ip_network
from pathlib import Path

import pytest
from app.domain import Vendor
from app.parsers.coverage import parse_configuration_with_coverage

from ml.datasets import (
    DatasetManifest,
    DatasetQualityPolicy,
    DatasetRecord,
    DatasetSource,
    DatasetSourceType,
    DatasetUse,
    LicenseReviewStatus,
    build_dataset_quality_report,
    deduplicate_dataset,
    import_local_dataset,
    load_dataset_artifact,
    scan_sanitized_content,
    split_deduplicated_dataset,
    write_dataset_artifact,
)
from ml.mutation import MutationType, mutate_configuration, reverse_mutation
from ml.preprocessing import (
    NETWORK_SANITIZATION_VERSION,
    PREFIX_LIST_SANITIZATION_VERSION,
    SANITIZATION_VERSION,
    SanitizationPolicy,
    sanitize_configuration,
)
from ml.preprocessing.blocks import segment_configuration

KEY = b"authored-prefix-list-only-key-001"
POLICY = SanitizationPolicy(version=PREFIX_LIST_SANITIZATION_VERSION)
CAPTURED = datetime(2026, 1, 1, tzinfo=UTC)


def _sanitize(source: str, *, key: bytes = KEY, scope: str = "owned-prefixes"):
    return sanitize_configuration(
        source, topology_id=scope, pseudonymization_key=key, policy=POLICY
    )


@pytest.mark.parametrize(
    "family,prefix,host,qualifier",
    (
        ("ip", "198.51.100.0/24", "198.51.100.1", "ge 25 le 32"),
        ("ipv6", "2001:db8:1::/48", "2001:db8:1::1", "ge 64 le 128"),
    ),
)
@pytest.mark.parametrize("sequence", ("", "seq 10 ", "seq 4294967294 "))
@pytest.mark.parametrize("action", ("permit", "deny"))
@pytest.mark.parametrize("ending", ("\n", "\r\n"))
def test_prefix_network_alias_keeps_peer_membership_and_textual_parameters(
    family: str,
    prefix: str,
    host: str,
    qualifier: str,
    sequence: str,
    action: str,
    ending: str,
) -> None:
    entry = f"  {family.upper()} PREFIX-LIST owned_LIST-1 {sequence}{action} {prefix} {qualifier}"
    source = entry + ending + f"neighbor {host}" + ending
    result = _sanitize(source)
    first, second = result.text.splitlines()
    original = entry.split()
    transformed = first.split()
    network_index = original.index(prefix)
    mapped = ip_network(transformed[network_index], strict=True)
    peer = ip_address(second.split()[1])
    assert peer in mapped and str(mapped) != prefix and str(peer) != host
    assert mapped.prefixlen == ip_network(prefix).prefixlen
    assert transformed[:network_index] == original[:network_index]
    assert transformed[network_index + 1 :] == original[network_index + 1 :]
    assert first.startswith("  ") and result.text.count(ending) == 2
    assert result.version == PREFIX_LIST_SANITIZATION_VERSION
    assert result.replacements == {"ip_address": 2}
    assert result == _sanitize(source)
    assert result.text != _sanitize(source, scope="another-owned-scope").text
    assert result.text != _sanitize(source, key=b"another-reviewed-owned-key-001").text


@pytest.mark.parametrize(
    "entry",
    (
        "ip prefix-list owned permit 198.51.100.1/24",
        "ipv6 prefix-list owned deny 2001:db8::1/64",
        "ip prefix-list owned permit 2001:db8::/64",
        "ipv6 prefix-list owned permit 198.51.100.0/24",
        "ip prefix-list owned permit 198.51.100.0/33",
        "ipv6 prefix-list owned deny 2001:db8::/129",
        "ip prefix-list owned seq 0 permit 198.51.100.0/24",
        "ip prefix-list owned seq 4294967295 permit 198.51.100.0/24",
        "ip prefix-list owned seq -1 permit 198.51.100.0/24",
        "ip prefix-list owned seq missing permit 198.51.100.0/24",
        "ip prefix-list owned permit 198.51.100.0/24 ge 24",
        "ipv6 prefix-list owned permit 2001:db8::/64 ge 64",
        "ip prefix-list owned permit 198.51.100.0/24 le 23",
        "ip prefix-list owned permit 198.51.100.0/24 ge 30 le 29",
        "ip prefix-list owned permit 198.51.100.0/24 ge 33",
        "ipv6 prefix-list owned deny 2001:db8::/64 le 129",
        "ip prefix-list owned permit 198.51.100.0/24 le 32 ge 25",
        "ip prefix-list owned permit 198.51.100.0/24 ge 25 ge 26",
        "ip prefix-list owned permit 198.51.100.0/24 eq 32",
        "ip prefix-list owned permit 198.51.100.0/24;",
        "ip prefix-list owned permit 198.51.100.0/24 # arbitrary comment",
        "ip prefix-list owned permit 198.51.100.0/24 description private",
        "ip prefix-list owned description 198.51.100.0/24",
        "ip prefix-list detail permit 198.51.100.0/24",
        "ipv6 prefix-list summary deny 2001:db8::/64",
        'ip prefix-list "owned name" permit 198.51.100.0/24',
        "ip prefix-list owned bogus 198.51.100.0/24",
        "no ip prefix-list owned permit 198.51.100.0/24",
        "set policy-options prefix-list owned { 198.51.100.0/24; }",
        "unrecognized ip prefix-list owned permit 198.51.100.0/24",
        "ip route 198.51.100.0 255.255.255.0 192.0.2.2",
    ),
    ids=lambda entry: entry.replace("198.51.100", "fixture-v4").replace("2001:db8", "fixture-v6"),
)
def test_invalid_or_unqualified_context_refuses_without_disclosing_values(entry: str) -> None:
    with pytest.raises(ValueError) as error:
        _sanitize(entry)
    assert entry not in str(error.value)
    assert "198.51.100" not in str(error.value) and "2001:db8" not in str(error.value)


@pytest.mark.parametrize(
    "entry",
    (
        "ip prefix-list owned permit 0.0.0.0/0",
        "ipv6 prefix-list owned deny ::/0",
        "ip prefix-list owned permit 198.51.100.1/32",
        "ipv6 prefix-list owned deny 2001:db8::1/128",
        "ip prefix-list owned permit 198.51.100.0/24 ge 25",
        "ipv6 prefix-list owned permit 2001:db8::/64 le 128",
        "ip prefix-list owned permit 198.51.100.0/24 le 24",
        "ipv6 prefix-list owned deny 2001:db8::/64 ge 65 le 65",
    ),
)
def test_default_host_and_single_length_bounds_are_explicit(entry: str) -> None:
    result = _sanitize(entry)
    tokens = result.text.split()
    index = next(index for index, token in enumerate(tokens) if "/" in token)
    original = entry.split()[index]
    assert ip_network(tokens[index], strict=True).prefixlen == ip_network(original).prefixlen
    if original in {"0.0.0.0/0", "::/0"}:
        assert tokens[index] == original


def test_legacy_versions_and_non_cidr_inputs_do_not_silently_change() -> None:
    source = "route 198.51.100.0/24;\naddress 198.51.100.1/24;\n"
    old = sanitize_configuration(
        source,
        topology_id="owned-prefixes",
        pseudonymization_key=KEY,
        policy=SanitizationPolicy(version=NETWORK_SANITIZATION_VERSION),
    )
    new = _sanitize(source)
    assert (old.text, old.replacements) == (new.text, new.replacements)
    prefix = "ip prefix-list owned permit 198.51.100.0/24\n"
    legacy = sanitize_configuration(prefix, topology_id="owned-prefixes", pseudonymization_key=KEY)
    assert legacy.version == SANITIZATION_VERSION
    with pytest.raises(ValueError, match="unsupported or invalid CIDR"):
        sanitize_configuration(
            prefix,
            topology_id="owned-prefixes",
            pseudonymization_key=KEY,
            policy=SanitizationPolicy(version=NETWORK_SANITIZATION_VERSION),
        )
    description = "ip prefix-list owned description route/to/owned-lab\n"
    assert _sanitize(description).text == description
    disabled = sanitize_configuration(
        "ip prefix-list owned permit 198.51.100.0/24\n",
        topology_id="owned-prefixes",
        pseudonymization_key=KEY,
        policy=SanitizationPolicy(
            version=PREFIX_LIST_SANITIZATION_VERSION, pseudonymize_ip_addresses=False
        ),
    )
    assert disabled.text == "ip prefix-list owned permit 198.51.100.0/24\n"
    assert disabled.replacements == {}


def test_import_parse_segment_mutate_and_quality_artifact_use_explicit_version(
    tmp_path: Path,
) -> None:
    records = []
    for index in range(1, 7):
        source = (
            f"hostname authored-{index}\n"
            f"ip prefix-list owned-{index} seq {index} permit "
            f"198.51.{100 + index}.0/24 ge 25 le 32\n"
            "ipv6 prefix-list owned-v6 deny 2001:db8::/32 le 128\n"
            f"ipv6 route 2001:db8:{index}::/48 2001:db8::2\n"
            f"interface GigabitEthernet0/{index}\n shutdown\n"
        )
        path = tmp_path / f"authored-{index}.cfg"
        path.write_text(source, encoding="utf-8")
        records.append(
            DatasetRecord(
                record_id=f"authored-{index}",
                relative_path=path.name,
                network_id=f"owned-network-{index}",
                site_id=f"owned-site-{index}",
                device_id=f"owned-device-{index}",
                captured_at=CAPTURED,
                vendor_hint=Vendor.CISCO,
                device_role="authored-test-only",
                expected_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
            )
        )
    manifest = DatasetManifest(
        source=DatasetSource(
            source_id="authored-prefix-source",
            source_type=DatasetSourceType.LAB,
            origin="authored functional test, not upstream metadata or real independent sites",
            license_id="INTERNAL-OWNED-FIXTURE",
            license_review=LicenseReviewStatus.APPROVED,
            allowed_uses=frozenset({DatasetUse.EVALUATION}),
            collected_at=CAPTURED,
        ),
        records=tuple(records),
    )
    imported = import_local_dataset(
        manifest,
        root=tmp_path,
        intended_use=DatasetUse.EVALUATION,
        pseudonymization_key=KEY,
        sanitization_policy=POLICY,
    )
    for record in imported:
        assert record.sanitization_version == PREFIX_LIST_SANITIZATION_VERSION
        assert (
            "".join(block.text for block in segment_configuration(record)) == record.sanitized_text
        )
        parsed = parse_configuration_with_coverage(
            record.sanitized_text, filename="owned.cfg", collected_at=CAPTURED
        )
        assert parsed.coverage.unparsed_units == 0
        assert len(parsed.canonical.prefix_lists) == 2
        rule = parsed.canonical.prefix_lists[0].rules[0]
        assert rule.action == "permit" and rule.ge == 25 and rule.le == 32
        assert rule.provenance.source_lines == [2]
        assert (
            rule.provenance.raw_text_hash
            == hashlib.sha256(record.sanitized_text.splitlines()[1].encode()).hexdigest()
        )
        sample = mutate_configuration(record, (MutationType.REMOVED_STATIC_ROUTE,), seed=7)
        assert reverse_mutation(sample, sample.mutated_text) == record.sanitized_text
        assert sample.formal_validation.status == "not_run"
        assert (
            scan_sanitized_content(
                record.sanitized_text,
                sanitized_sha256=record.sanitized_sha256,
                sanitization_version=record.sanitization_version,
                allowed_versions=(PREFIX_LIST_SANITIZATION_VERSION,),
            )
            == ()
        )
    dedup = deduplicate_dataset(imported)
    split = split_deduplicated_dataset(imported, dedup)
    strict = build_dataset_quality_report(
        imported,
        dedup,
        split,
        sources=[manifest.source],
        intended_use=DatasetUse.EVALUATION,
        synthetic_anomaly_count=0,
        confirmed_anomaly_count=0,
    )
    assert not strict.technically_valid
    explicit = build_dataset_quality_report(
        imported,
        dedup,
        split,
        sources=[manifest.source],
        intended_use=DatasetUse.EVALUATION,
        synthetic_anomaly_count=0,
        confirmed_anomaly_count=0,
        policy=DatasetQualityPolicy(
            allowed_sanitization_versions=(PREFIX_LIST_SANITIZATION_VERSION,)
        ),
    )
    assert explicit.technically_valid and not explicit.poc_scale_ready
    result = write_dataset_artifact(
        imported,
        dedup,
        split,
        explicit,
        output_root=tmp_path,
        artifact_name="owned-reviewed-bundle",
    )
    assert load_dataset_artifact(result.path) == result.manifest
    assert result.manifest.pipeline_versions["sanitization"] == PREFIX_LIST_SANITIZATION_VERSION
