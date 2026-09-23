"""Explicitly opt-in live loopback smoke test; skipped in the normal suite."""

import os
from uuid import UUID

import pytest
from app.verification.batfish import ReachabilityScope, check_with_batfish
from app.verification.snapshots import NetworkSnapshot, prepare_snapshot


def _snapshot_pair() -> tuple[NetworkSnapshot, NetworkSnapshot]:
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
    before = prepare_snapshot({UUID(int=1): edge, UUID(int=2): core})
    after = prepare_snapshot(
        {
            UUID(int=1): edge.replace(
                "ip route 198.51.100.0 255.255.255.0 192.0.2.2",
                "ip route 198.51.100.0 255.255.255.0 Null0",
            ),
            UUID(int=2): core,
        }
    )
    return before, after


def test_live_fixture_is_locally_parseable_without_engine() -> None:
    before, after = _snapshot_pair()
    assert len(before.configs) == len(after.configs) == 2
    assert before.digest != after.digest


@pytest.mark.skipif(
    os.environ.get("NETCONFIG_LIVE_BATFISH") != "1",
    reason="requires explicit loopback upload permission and a running Batfish engine",
)
def test_live_static_route_regression() -> None:
    before, after = _snapshot_pair()
    result = check_with_batfish(
        before,
        after,
        ReachabilityScope(start_node="edge", destination="198.51.100.1/32"),
        allow_local_upload=True,
        timeout_seconds=120,
    )
    assert result.status == "differences_found", result.model_dump_json()
    assert result.engine_version
    assert result.cleanup_complete is True
