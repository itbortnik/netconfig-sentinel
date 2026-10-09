"""Measured peer fractions use source counts, not the historical confidence proxy."""

from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest
from app.detection.baseline.peer_v2 import (
    build_expanded_peer_baseline,
    evaluate_expanded_peer_baseline,
)
from app.detection.baseline.peer_v3 import (
    MeasuredPeerBaseline,
    MeasuredPeerEvaluation,
    build_measured_peer_baseline,
    evaluate_measured_peer_baseline,
)
from app.parsers.coverage import ParsedConfiguration, parse_configuration_with_coverage

STAMP = datetime(2026, 10, 10, tzinfo=UTC)
DEVICE = UUID("f6156954-3f3b-4aa2-b693-5a710fe35d44")


def source(host, form="ios", address="192.0.2.10", unknown=False):
    if form == "ios":
        return (
            f"! owned\nhostname {host}\nip ssh version 2\nntp server {address}\n"
            + ("unknown PRIVATE_VALUE\n" if unknown else "")
            + "end\n"
        )
    if form == "set":
        return (
            f"set system host-name {host}\nset system services ssh\n"
            f"set system ntp server {address}\n"
            + ("set unknown PRIVATE_VALUE\n" if unknown else "")
        )
    return (
        f"system {{\n host-name {host};\n services {{\n  ssh;\n }}\n"
        f" ntp {{\n  server {address};\n }}\n"
        + (" unknown PRIVATE_VALUE;\n" if unknown else "")
        + "}\n"
    )


def parsed(host, form="ios", address="192.0.2.10", unknown=False):
    result = parse_configuration_with_coverage(
        source(host, form, address, unknown), filename="owned.cfg", collected_at=STAMP
    )
    result.canonical.device.role = "edge"
    result.canonical.device.site_class = "branch"
    result.canonical.device.service_profile = "owned"
    return result


def peers(form="ios"):
    return [parsed(f"peer-{number}", form) for number in range(3)]


@pytest.mark.parametrize("form", ["ios", "set", "blocks"])
def test_new_peer_fraction_and_property_skip_come_from_actual_adapter_source(form):
    population = peers(form)
    baseline = build_measured_peer_baseline(population)
    current = parsed("target", form, "192.0.2.99", unknown=True)
    old_configs = [item.canonical.model_dump_json() for item in population]
    old_profile = build_expanded_peer_baseline([item.canonical for item in population])
    old_bytes = old_profile.model_dump_json()
    old_report = evaluate_expanded_peer_baseline(current.canonical, old_profile, device_id=DEVICE)
    report = evaluate_measured_peer_baseline(current, baseline, device_id=DEVICE)
    assert report.coverage == current.coverage
    assert report.coverage.unparsed_fraction != old_report.unsupported_ratio
    assert report.status == "partial" and not report.compared_features
    assert report.skipped_features == report.profile_features
    assert len(report.findings) == 1
    finding = report.findings[0]
    assert finding.category == "baseline.parser.unparsed_fraction_high"
    assert (
        finding.observed["value"]
        == current.coverage.unparsed_units / current.coverage.command_units
    )
    assert finding.observed["command_units"] == current.coverage.command_units
    assert finding.observed["unparsed_units"] == current.coverage.unparsed_units
    assert finding.affected_lines == [
        unit.source_line for unit in current.coverage.units if unit.disposition == "unparsed"
    ]
    assert finding.model_version == "peer-baseline-0.3.0"
    assert finding.expected["baseline_sha256"] == baseline.fingerprint()
    assert "PRIVATE_VALUE" not in report.model_dump_json() + baseline.model_dump_json()
    assert evaluate_measured_peer_baseline(current, baseline, device_id=DEVICE) == report
    assert MeasuredPeerBaseline.model_validate_json(baseline.model_dump_json()) == baseline
    assert MeasuredPeerEvaluation.model_validate_json(report.model_dump_json()) == report
    assert old_profile.model_dump_json() == old_bytes
    assert [item.canonical.model_dump_json() for item in population] == old_configs


@pytest.mark.parametrize("form", ["ios", "set", "blocks"])
def test_all_existing_supported_property_templates_remain_real_comparisons(form):
    population = peers(form)
    baseline = build_measured_peer_baseline(population)
    normal = evaluate_measured_peer_baseline(parsed("target", form), baseline, device_id=DEVICE)
    assert normal.status == "completed" and normal.findings == ()
    assert len(normal.compared_features) == 19 and normal.skipped_features == ()
    target = parsed("target", form, address="192.0.2.99")
    report = evaluate_measured_peer_baseline(target, baseline, device_id=DEVICE)
    old = evaluate_expanded_peer_baseline(
        target.canonical,
        build_expanded_peer_baseline([item.canonical for item in population]),
        device_id=DEVICE,
    )
    assert report.status == "completed" and len(report.findings) == len(old.findings) == 1
    new_finding, old_finding = report.findings[0], old.findings[0]
    assert (
        new_finding.category == old_finding.category == "baseline.management.ntp_servers_deviation"
    )
    assert new_finding.observed["value"] == old_finding.observed["value"]
    assert new_finding.affected_lines == old_finding.affected_lines
    assert new_finding.finding_id != old_finding.finding_id
    assert new_finding.expected["peer_support_count"] == 3


def test_threshold_is_inclusive_and_small_partial_fraction_never_claims_property_checks():
    baseline = build_measured_peer_baseline(peers(), unparsed_fraction_tolerance=0.25)
    current = parsed("target", unknown=True)
    report = evaluate_measured_peer_baseline(current, baseline, device_id=DEVICE)
    assert current.coverage.unparsed_fraction == 0.25
    assert report.findings == () and report.status == "partial" and report.skipped_features
    lower = build_measured_peer_baseline(peers(), unparsed_fraction_tolerance=0.249)
    assert len(evaluate_measured_peer_baseline(current, lower, device_id=DEVICE).findings) == 1


@pytest.mark.parametrize(
    "case",
    [
        "partial",
        "duplicate",
        "group",
        "coverage-source",
        "missing-coverage",
        "bad-count",
        "wrong-adapter",
        "few",
    ],
)
def test_population_refuses_missing_corrupt_or_nonindependent_inputs(case):
    selected = peers()
    if case == "partial":
        selected[2] = parsed("peer-2", unknown=True)
    elif case == "duplicate":
        selected[2] = selected[0]
    elif case == "group":
        selected[2].canonical.device.role = "other"
    elif case == "coverage-source":
        selected[2] = ParsedConfiguration(selected[2].canonical, selected[0].coverage)
    elif case == "missing-coverage":
        selected[2] = ParsedConfiguration(selected[2].canonical, None)
    elif case == "bad-count":
        selected[2] = ParsedConfiguration(
            selected[2].canonical, selected[2].coverage.model_copy(update={"accepted_units": 100})
        )
    elif case == "wrong-adapter":
        selected[2] = ParsedConfiguration(
            selected[2].canonical,
            selected[2].coverage.model_copy(update={"adapter_version": "unsupported"}),
        )
    else:
        selected = selected[:2]
    with pytest.raises(ValueError):
        build_measured_peer_baseline(selected)


@pytest.mark.parametrize(
    "case", ["self", "future", "group", "coverage-source", "missing-coverage", "zero-denominator"]
)
def test_target_refusals_are_not_zero_measurements(case):
    baseline = build_measured_peer_baseline(peers())
    target = parsed("target")
    if case == "self":
        target = peers()[0]
    elif case == "future":
        target.canonical.source.collected_at = STAMP - timedelta(days=1)
    elif case == "group":
        target.canonical.device.role = "other"
    elif case == "coverage-source":
        target = ParsedConfiguration(target.canonical, peers()[0].coverage)
    elif case == "missing-coverage":
        target = ParsedConfiguration(target.canonical, None)
    else:
        target = parse_configuration_with_coverage(
            "## Last commit: owned\n}\n", filename="owned.cfg", collected_at=STAMP
        )
        target.canonical.device.role = "edge"
        target.canonical.device.site_class = "branch"
        target.canonical.device.service_profile = "owned"
    with pytest.raises(ValueError):
        evaluate_measured_peer_baseline(target, baseline, device_id=DEVICE)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -0.01, 1.01, True])
def test_invalid_thresholds_are_refused(value):
    with pytest.raises(ValueError):
        build_measured_peer_baseline(peers(), unparsed_fraction_tolerance=value)
    with pytest.raises(ValueError):
        build_measured_peer_baseline(peers(), consensus_threshold=value)


@pytest.mark.parametrize(
    "case", ["version", "coverage-order", "source", "inert-proxy", "threshold"]
)
def test_profile_contract_preserves_complete_source_bindings(case):
    profile = build_measured_peer_baseline(peers()).model_dump(mode="json")
    if case == "version":
        profile["model_version"] = "peer-baseline-0.4.0"
    elif case == "coverage-order":
        profile["coverage"].reverse()
    elif case == "source":
        profile["coverage"][0]["source_sha256"] = "a" * 64
    elif case == "inert-proxy":
        profile["properties"]["unsupported_ratio_limit"] = 0.05
    else:
        profile["unparsed_fraction_limit"] = True
    with pytest.raises(ValueError):
        MeasuredPeerBaseline.model_validate(profile)


@pytest.mark.parametrize(
    "case",
    [
        "version",
        "source",
        "status",
        "missing-finding",
        "fake-ratio",
        "threshold",
        "confidence",
        "finding-version",
        "identity",
        "severity",
        "evidence",
        "evidence-hash",
        "boolean-count",
    ],
)
def test_evaluation_rejects_impossible_or_unbound_claims(case):
    baseline = build_measured_peer_baseline(peers())
    report = evaluate_measured_peer_baseline(
        parsed("target", unknown=True), baseline, device_id=DEVICE
    )
    changed = deepcopy(report.model_dump(mode="json"))
    if case == "version":
        changed["version"] = "peer-comparison-report-0.4.0"
    elif case == "source":
        changed["source_sha256"] = "a" * 64
    elif case == "status":
        changed["status"] = "completed"
    elif case == "missing-finding":
        changed["findings"] = []
    elif case == "fake-ratio":
        changed["findings"][0]["observed"]["value"] = 0.01
    elif case == "threshold":
        changed["unparsed_fraction_limit"] = 0.5
    elif case == "confidence":
        changed["findings"][0]["confidence"] = 0.1
    elif case == "finding-version":
        changed["findings"][0]["model_version"] = "peer-baseline-0.2.0"
    elif case == "identity":
        changed["findings"][0]["finding_id"] = str(DEVICE)
    elif case == "severity":
        changed["findings"][0]["severity"] = "critical"
    elif case == "evidence":
        changed["findings"][0]["evidence"] = []
    elif case == "evidence-hash":
        changed["findings"][0]["evidence"][0]["source_location"]["raw_text_hash"] = "a" * 64
    else:
        changed["findings"][0]["observed"]["unparsed_units"] = True
    with pytest.raises(ValueError):
        MeasuredPeerEvaluation.model_validate(changed)


@pytest.mark.parametrize(
    "relative,hostname",
    [
        ("cisco_ios/edge-secure.cfg", "cisco-edge-01"),
        ("juniper_junos/edge-secure.conf", "juniper-edge-01"),
    ],
)
def test_rich_raw_vlan_acl_bgp_ospf_templates_preserve_v2_property_semantics(relative, hostname):
    # Deliberate authored peer-template views; not additional independent network data.
    original = (Path(__file__).resolve().parents[3] / "samples" / relative).read_text(
        encoding="utf-8"
    )

    def read(host, changed=False):
        text = original.replace(hostname, host)
        if changed:
            text = text.replace("65001", "65003").replace("192.0.2.10", "192.0.2.99")
        item = parse_configuration_with_coverage(text, filename="owned.cfg", collected_at=STAMP)
        item.canonical.device.role = "edge"
        item.canonical.device.site_class = "branch"
        item.canonical.device.service_profile = "owned"
        return item

    population = [read(f"peer-{number}") for number in range(3)]
    baseline = build_measured_peer_baseline(population)
    target = read("target", changed=True)
    report = evaluate_measured_peer_baseline(target, baseline, device_id=DEVICE)
    old = evaluate_expanded_peer_baseline(
        target.canonical,
        build_expanded_peer_baseline([item.canonical for item in population]),
        device_id=DEVICE,
    )
    assert report.profile_features == old.profile_features and len(report.profile_features) == 19
    assert (
        {item.category for item in report.findings}
        == {item.category for item in old.findings}
        == {"baseline.bgp.local_as_deviation", "baseline.management.ntp_servers_deviation"}
    )
    assert "acls.patterns" in report.compared_features
    assert "vlans.set" in report.compared_features
    assert "ospf.process_patterns" in report.compared_features


@pytest.mark.parametrize("scope", ["profile", "evaluation"])
def test_explicit_report_size_limits_fail_closed(scope, monkeypatch):
    baseline = build_measured_peer_baseline(peers())
    report = evaluate_measured_peer_baseline(parsed("target"), baseline, device_id=DEVICE)
    monkeypatch.setattr("app.detection.baseline.peer_v3.MAX_PROJECTION_BYTES", 1)
    with pytest.raises(ValueError, match=f"measured peer {scope} exceeds its byte limit"):
        if scope == "profile":
            build_measured_peer_baseline(peers())
        else:
            MeasuredPeerEvaluation.model_validate(report.model_dump())
