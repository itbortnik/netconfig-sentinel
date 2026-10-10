"""Owned generated JunOS route loss; live queries require explicit loopback opt-in."""

import hashlib
import json
import os
from datetime import UTC, datetime
from importlib.metadata import version
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import UUID, uuid4

import pytest
from app.domain import Vendor
from app.verification.batfish import ReachabilityScope, check_with_batfish
from app.verification.batfish_worker import _session
from app.verification.snapshots import (
    NetworkSnapshot,
    prepare_snapshot,
    validate_snapshot_pair,
    write_snapshot,
)

from ml.datasets import ImportedDatasetRecord
from ml.mutation import (
    STRUCTURAL_MUTATION_ENGINE_VERSION,
    MutationType,
    SyntheticMutationSample,
    mutate_configuration,
    reverse_mutation,
)
from ml.preprocessing import sanitize_configuration

EDGE = """system {
    host-name owned-edge;
}
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                address 192.0.2.1/30;
            }
        }
    }
}
routing-options {
    static {
        route 198.51.100.0/24 {
            next-hop 192.0.2.2;
        }
    }
}
"""

CORE = """system {
    host-name owned-core;
}
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                address 192.0.2.2/30;
            }
        }
    }
    lo0 {
        unit 0 {
            family inet {
                address 198.51.100.1/24;
            }
        }
    }
}
"""

SCENARIOS = (
    ("generated_route_loss", "198.51.100.1/32", True, "differences_found"),
    ("unchanged_reachable_control", "198.51.100.1/32", False, "no_differences_in_scope"),
    ("generated_direct_peer_control", "192.0.2.2/32", True, "no_differences_in_scope"),
    ("generated_empty_scope", "203.0.113.1/32", True, "inconclusive"),
)


def _owned_initialization_diagnostic(before: NetworkSnapshot, after: NetworkSnapshot) -> None:
    """Test-only details from these exact authored fixtures, never operator inputs."""
    _, expected_before, expected_after = _generated_pair()
    assert before == expected_before and after == expected_after
    session = _session()
    network = "sentinel-" + uuid4().hex
    assert network not in session.list_networks()
    created = False
    try:
        session.set_network(network)
        created = True
        with TemporaryDirectory(prefix="owned-mutation-init-") as directory:
            for side, snapshot in (("before", before), ("after", after)):
                output = Path(directory) / side
                write_snapshot(snapshot, output)
                session.init_snapshot(
                    str(output),
                    name=side,
                    overwrite=False,
                    extra_args={"ignoremanagementinterfaces": False},
                )
                statuses = session.q.fileParseStatus().answer(snapshot=side).frame()
                issues = session.q.initIssues().answer(snapshot=side).frame()
                # Only this test's public authored input can reach this diagnostic.
                # Omit Line_Text, filenames and full rows; production worker unchanged.
                rows = [
                    {
                        "type": str(row.get("Type", ""))[:128],
                        "details": str(row.get("Details", ""))[:512],
                    }
                    for row in issues.to_dict(orient="records")[:20]
                ]
                print(
                    "OWNED_MUTATION_INIT_DIAGNOSTIC="
                    + json.dumps(
                        {
                            "side": side,
                            "parse_statuses": sorted(str(value) for value in statuses["Status"]),
                            "issue_count": len(issues),
                            "issues": rows,
                        },
                        sort_keys=True,
                    )
                )
    finally:
        if created:
            session.delete_network(network)
            print("OWNED_MUTATION_INIT_DIAGNOSTIC_CLEANUP=true")


def _generated_pair() -> tuple[SyntheticMutationSample, NetworkSnapshot, NetworkSnapshot]:
    """Only authored documentation prefixes, sanitized before generation/upload."""
    sanitized = [
        sanitize_configuration(
            text,
            topology_id="owned-hierarchical-route",
            pseudonymization_key=b"owned-fixture-only-pseudonym-key-001",
        )
        for text in (EDGE, CORE)
    ]
    parent, peer = sanitized
    record = ImportedDatasetRecord(
        source_id="owned-mutation-live",
        record_id="authored-edge-001",
        network_id="network-000000000001",
        site_id="site-000000000001",
        device_id="device-000000000001",
        captured_at=datetime(2026, 1, 1, tzinfo=UTC),
        vendor_hint=Vendor.JUNIPER,
        device_role="edge-router",
        raw_sha256=hashlib.sha256(EDGE.encode()).hexdigest(),
        sanitized_sha256=hashlib.sha256(parent.text.encode()).hexdigest(),
        sanitized_text=parent.text,
        raw_byte_count=len(EDGE.encode()),
        replacements=parent.replacements,
        sanitization_version=parent.version,
    )
    sample = mutate_configuration(
        record,
        (MutationType.REMOVED_STATIC_ROUTE,),
        seed=17,
        engine_version=STRUCTURAL_MUTATION_ENGINE_VERSION,
    )
    before = prepare_snapshot({UUID(int=1): parent.text, UUID(int=2): peer.text})
    after = prepare_snapshot({UUID(int=1): sample.mutated_text, UUID(int=2): peer.text})
    validate_snapshot_pair(before, after)
    assert before.configs[0].digest == sample.original_sha256
    assert after.configs[0].digest == sample.mutated_sha256
    assert before.configs[1] == after.configs[1]
    assert reverse_mutation(sample, sample.mutated_text) == parent.text
    assert record.sanitized_text == parent.text
    assert sample.syntax_validation.status == "passed"
    assert sample.formal_validation.status == "not_run"
    assert sample.affected_lines == ()
    assert sample.localization and all(
        item.kind == "delete" for item in sample.localization.changes
    )
    assert all(label.synthetic and not label.real_confirmed for label in sample.labels)
    return sample, before, after


@pytest.mark.parametrize("scenario,destination,candidate_selected,expected_status", SCENARIOS)
def test_generated_pair_and_no_upload_gate_without_engine(
    scenario: str, destination: str, candidate_selected: bool, expected_status: str
) -> None:
    sample, before, candidate = _generated_pair()
    after = candidate if candidate_selected else before
    scope = ReachabilityScope(start_node=before.configs[0].hostname, destination=destination)
    result = check_with_batfish(before, after, scope, allow_local_upload=False)
    assert result.status == "unavailable" and result.reason == "upload_not_authorized"
    assert result.before_sha256 == before.digest and result.after_sha256 == after.digest
    assert result.engine_version is None and result.difference_count is None
    assert result.cleanup_complete is None
    assert (before.digest != after.digest) is candidate_selected
    assert sample.formal_validation.status == "not_run"


@pytest.mark.skipif(
    os.environ.get("NETCONFIG_LIVE_BATFISH") != "1",
    reason="requires explicit owned loopback upload permission and a running Batfish engine",
)
@pytest.mark.parametrize("scenario,destination,candidate_selected,expected_status", SCENARIOS)
def test_live_generated_hierarchical_route(
    scenario: str, destination: str, candidate_selected: bool, expected_status: str
) -> None:
    sample, before, candidate = _generated_pair()
    serialized_sample = sample.model_dump_json()
    after = candidate if candidate_selected else before
    scope = ReachabilityScope(start_node=before.configs[0].hostname, destination=destination)
    result = check_with_batfish(before, after, scope, allow_local_upload=True, timeout_seconds=120)
    if result.status == "incomplete" and scenario == "generated_route_loss":
        _owned_initialization_diagnostic(before, candidate)
    # This observation binds the precise generated edit, not a different hand edit.
    # Control queries explicitly disclose whether the candidate was selected.
    print(
        "OWNED_MUTATION_BATFISH_RESULT="
        + json.dumps(
            {
                "scenario": scenario,
                "candidate_selected": candidate_selected,
                "engine_version": result.engine_version,
                "sdk_version": version("pybatfish"),
                "mutation_id": sample.mutation_id,
                "mutation_engine_version": sample.engine_version,
                "source_sha256": sample.original_sha256,
                "candidate_sha256": sample.mutated_sha256,
                "before_snapshot_sha256": result.before_sha256,
                "after_snapshot_sha256": result.after_sha256,
                "scope": scope.model_dump(mode="json"),
                "status": result.status,
                "reason": result.reason,
                "before_reachable_count": result.before_reachable_count,
                "after_reachable_count": result.after_reachable_count,
                "difference_count": result.difference_count,
                "cleanup_complete": result.cleanup_complete,
                "requires_human_review": result.requires_human_review,
                "sample_formal_validation": sample.formal_validation.status,
            },
            sort_keys=True,
        )
    )
    assert result.before_sha256 == before.digest and result.after_sha256 == after.digest
    assert sample.model_dump_json() == serialized_sample
    assert sample.formal_validation.status == "not_run"
    assert result.status == expected_status, result.model_dump_json()
    assert result.engine_version and result.cleanup_complete is True
    if scenario == "generated_route_loss":
        assert result.before_reachable_count and result.after_reachable_count == 0
        assert result.difference_count
    elif expected_status == "no_differences_in_scope":
        assert result.before_reachable_count and result.after_reachable_count
        assert result.difference_count == 0
    else:
        assert result.before_reachable_count == result.after_reachable_count == 0
        assert result.difference_count == 0
