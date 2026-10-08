"""Explicitly opt-in live loopback smoke test; skipped in the normal suite."""

import json
import os
from importlib.metadata import version
from uuid import UUID

import pytest
from app.verification.batfish import ReachabilityScope, check_with_batfish
from app.verification.snapshots import NetworkSnapshot, prepare_snapshot


def _snapshot_pair(vendor: str = "cisco") -> tuple[NetworkSnapshot, NetworkSnapshot]:
    edge = (
        "version 17.9\nhostname edge\ninterface GigabitEthernet0/0\n"
        " ip address 192.0.2.1 255.255.255.252\n no shutdown\n!\n"
        "ip route 198.51.100.0 255.255.255.0 192.0.2.2\nend\n"
    )
    core = (
        "version 17.9\nhostname core\ninterface GigabitEthernet0/0\n"
        " ip address 192.0.2.2 255.255.255.252\n no shutdown\n!\n"
        "interface Loopback0\n ip address 198.51.100.1 255.255.255.0\nend\n"
    )
    route = "ip route 198.51.100.0 255.255.255.0 192.0.2.2"
    discard = "ip route 198.51.100.0 255.255.255.0 Null0"
    if vendor == "juniper":
        edge = (
            "set system host-name edge\n"
            "set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/30\n"
            "set routing-options static route 198.51.100.0/24 next-hop 192.0.2.2\n"
        )
        core = (
            "set system host-name core\n"
            "set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.2/30\n"
            "set interfaces lo0 unit 0 family inet address 198.51.100.1/24\n"
        )
        route = "set routing-options static route 198.51.100.0/24 next-hop 192.0.2.2"
        discard = "set routing-options static route 198.51.100.0/24 discard"
    elif vendor != "cisco":
        raise ValueError("unknown owned fixture vendor")
    before = prepare_snapshot({UUID(int=1): edge, UUID(int=2): core})
    after = prepare_snapshot(
        {
            UUID(int=1): edge.replace(route, discard),
            UUID(int=2): core,
        }
    )
    return before, after


@pytest.mark.parametrize("vendor", ["cisco", "juniper"])
def test_live_fixture_is_locally_parseable_without_engine(vendor: str) -> None:
    before, after = _snapshot_pair(vendor)
    assert len(before.configs) == len(after.configs) == 2
    assert before.digest != after.digest


@pytest.mark.skipif(
    os.environ.get("NETCONFIG_LIVE_BATFISH") != "1",
    reason="requires explicit loopback upload permission and a running Batfish engine",
)
@pytest.mark.parametrize("vendor", ["cisco", "juniper"])
@pytest.mark.parametrize(
    "scenario,expected_status",
    [
        ("route_loss", "differences_found"),
        ("unchanged_reachable", "no_differences_in_scope"),
        ("empty_scope", "inconclusive"),
    ],
)
def test_live_static_route_regression(vendor: str, scenario: str, expected_status: str) -> None:
    before, after = _snapshot_pair(vendor)
    if scenario != "route_loss":
        after = before
    destination = "203.0.113.1/32" if scenario == "empty_scope" else "198.51.100.1/32"
    result = check_with_batfish(
        before,
        after,
        ReachabilityScope(start_node="edge", destination=destination),
        allow_local_upload=True,
        timeout_seconds=120,
    )
    # These are six owned diagnostic queries, not independent production networks.
    print(
        "OWNED_BATFISH_RESULT="
        + json.dumps(
            {
                "vendor": vendor,
                "scenario": scenario,
                "sdk_version": version("pybatfish"),
                "status": result.status,
                "reason": result.reason,
                "engine_version": result.engine_version,
                "difference_count": result.difference_count,
                "before_reachable_count": result.before_reachable_count,
                "after_reachable_count": result.after_reachable_count,
                "cleanup_complete": result.cleanup_complete,
                "requires_human_review": result.requires_human_review,
            },
            sort_keys=True,
        )
    )
    assert result.status == expected_status, result.model_dump_json()
    assert result.engine_version
    assert result.cleanup_complete is True
    if scenario == "route_loss":
        assert result.before_reachable_count and result.after_reachable_count == 0
        assert result.difference_count
    elif scenario == "unchanged_reachable":
        assert result.before_reachable_count and result.after_reachable_count
        assert result.difference_count == 0
    else:
        assert result.before_reachable_count == result.after_reachable_count == 0
        assert result.difference_count == 0
