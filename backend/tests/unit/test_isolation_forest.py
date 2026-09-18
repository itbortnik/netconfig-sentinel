"""Tests for structured features and the Isolation Forest control model."""

from datetime import UTC, datetime
from uuid import UUID

import pytest
from app.detection import (
    FEATURE_NAMES,
    evaluate_isolation_forest,
    extract_structured_features,
    fit_isolation_forest,
)
from app.domain import CanonicalConfig
from app.parsers import parse_configuration

COLLECTED_AT = datetime(2026, 1, 1, tzinfo=UTC)
DEVICE_ID = UUID("7dfc2136-74ca-4ca9-b5f9-6714f3cecf5c")


def _config(
    hostname: str,
    *,
    vlan_count: int = 2,
    route_count: int = 1,
    ssh_version: str = "2",
    telnet: bool = False,
    aaa: bool = True,
    unknown_count: int = 0,
) -> CanonicalConfig:
    lines = [
        "version 17.9",
        f"hostname {hostname}",
        "aaa new-model" if aaa else "no aaa new-model",
        f"ip ssh version {ssh_version}",
        "snmp-server group SECURE v3 priv",
        "ntp server 192.0.2.10",
        "logging host 192.0.2.20",
    ]
    for index in range(vlan_count):
        vlan_id = 10 + index
        lines.extend((f"vlan {vlan_id}", f" name VLAN-{vlan_id}", "!"))
        lines.extend(
            (
                f"interface GigabitEthernet0/{index + 1}",
                " switchport mode access",
                f" switchport access vlan {vlan_id}",
                " no shutdown",
                "!",
            )
        )
    lines.extend(
        (
            "ip access-list extended MGMT",
            " 10 permit tcp host 192.0.2.10 any eq 22",
            " 20 deny ip any any",
            "!",
        )
    )
    for index in range(route_count):
        lines.append(f"ip route 198.51.{index}.0 255.255.255.0 192.0.2.1")
    if telnet:
        lines.extend(("line vty 0 4", " transport input telnet", "!"))
    lines.extend(f"unsupported feature {index}" for index in range(unknown_count))
    config = parse_configuration(
        "\n".join(lines) + "\n",
        filename=f"{hostname}.cfg",
        collected_at=COLLECTED_AT,
    )
    config.device.role = "access-switch"
    config.device.site_class = "branch"
    config.device.service_profile = "user-access"
    return config


def _training_configs() -> list[CanonicalConfig]:
    return [
        _config(
            f"access-{index:02d}",
            vlan_count=1 + index % 3,
            route_count=index % 2,
        )
        for index in range(16)
    ]


def test_structured_feature_schema_is_stable_and_has_provenance() -> None:
    config = _config("access-01", vlan_count=2, route_count=1)

    first = extract_structured_features(config)
    repeated = extract_structured_features(config)

    assert first == repeated
    assert first.names == FEATURE_NAMES
    assert len(first.values) == 33
    values = first.as_dict()
    assert values["management.ssh_enabled"] == 1.0
    assert values["management.ssh_v1"] == 0.0
    assert values["vlans.count"] == 2.0
    assert values["interfaces.access_count"] == 2.0
    assert values["static_routes.count"] == 1.0
    assert first.locations["management.ssh_enabled"][0].source_lines == [4]


def test_isolation_forest_training_is_reproducible() -> None:
    configs = _training_configs()

    first = fit_isolation_forest(configs, estimator_count=64)
    repeated = fit_isolation_forest(configs, estimator_count=64)

    assert first.metadata == repeated.metadata
    assert first.metadata.library_version
    assert first.metadata.feature_names == FEATURE_NAMES
    assert first.estimator.predict(
        [extract_structured_features(config).as_row() for config in configs]
    ).tolist() == repeated.estimator.predict(
        [extract_structured_features(config).as_row() for config in configs]
    ).tolist()


def test_isolation_forest_flags_obvious_outlier_with_diagnostics() -> None:
    model = fit_isolation_forest(_training_configs(), estimator_count=64)
    outlier = _config(
        "access-outlier",
        vlan_count=20,
        route_count=12,
        ssh_version="1",
        telnet=True,
        aaa=False,
        unknown_count=12,
    )

    first = evaluate_isolation_forest(outlier, model, device_id=DEVICE_ID)
    repeated = evaluate_isolation_forest(outlier, model, device_id=DEVICE_ID)

    assert len(first) == 1
    assert first[0].finding_id == repeated[0].finding_id
    assert first[0].category == "statistical.configuration_outlier"
    assert first[0].detector == "isolation_forest"
    assert first[0].model_version == "isolation-forest-0.1.0"
    assert first[0].anomaly_score == 1.0
    assert first[0].confidence == 0.32
    assert first[0].affected_lines
    assert first[0].evidence
    assert first[0].observed["decision_function"] < 0
    assert first[0].observed["top_feature_deviations"]
    assert len(first[0].limitations) == 2


def test_training_population_contains_inliers() -> None:
    configs = _training_configs()
    model = fit_isolation_forest(configs, estimator_count=64)

    findings = [
        evaluate_isolation_forest(config, model, device_id=DEVICE_ID)
        for config in configs
    ]

    assert sum(not item for item in findings) >= 12


def test_training_rejects_small_or_mixed_peer_groups() -> None:
    configs = _training_configs()
    mismatched = _config("datacenter-01")
    mismatched.device.site_class = "datacenter"

    with pytest.raises(ValueError, match="at least 8"):
        fit_isolation_forest(configs[:4])
    with pytest.raises(ValueError, match="one peer group"):
        fit_isolation_forest([*configs[:7], mismatched])


def test_evaluation_rejects_wrong_peer_group() -> None:
    model = fit_isolation_forest(_training_configs(), estimator_count=64)
    target = _config("datacenter-01")
    target.device.service_profile = "datacenter-access"

    with pytest.raises(ValueError, match="does not belong"):
        evaluate_isolation_forest(target, model, device_id=DEVICE_ID)
