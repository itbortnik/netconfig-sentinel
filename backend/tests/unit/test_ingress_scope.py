"""Saved ingress observations must replay deterministically without an engine."""

import copy
from hashlib import sha256

import pytest
from app.verification.batfish import ReachabilityScope, check_with_batfish_scope_evidence
from app.verification.ingress_scope import (
    BatfishScopeExecution,
    IngressScopeObservation,
    empty_ingress_scope,
)
from app.verification.ingress_scope_worker import canonical_id, extract_side
from test_batfish_execution import envelope, pair, request
from test_ingress_scope_worker import answers, observed_payload
from test_reachability_impact import Answer, impact


def test_normal_junos_capture_remains_observed_with_unknown_parent_eligibility():
    junos = answers(
        [
            ("ge-0/0/0", True, False, []),
            ("ge-0/0/0.0", True, False, ["192.0.2.1/30"]),
        ]
    )
    value = IngressScopeObservation.model_validate(observed_payload(junos, junos))
    assert value.acquisition_state == "observed" and value.eligibility_complete is False
    assert len(value.before.interfaces) == 2
    assert value.selected_before_only == value.selected_after_only == ()
    assert value.common_eligible is value.before_eligible_only is value.after_eligible_only is None
    assert value.after_common_assignments is None
    parent = next(row for row in value.before.interfaces if row.interface == "ge-0/0/0")
    assert parent.eligible is None and parent.eligibility_reason == "no_concrete_ipv4"
    assert parent.source_ip_rendering == "EmptyIpSpace"


@pytest.mark.parametrize(
    "active,switchport,prefixes,eligible,reason",
    [
        (False, False, [], False, "inactive"),
        (False, True, [], False, "inactive"),
        (True, True, ["192.0.2.1/32"], False, "switchport"),
        (True, False, ["192.0.2.1/32"], True, "active_concrete_ipv4"),
        (True, False, ["169.254.0.1/16"], True, "active_concrete_ipv4"),
        (True, False, [], None, "no_concrete_ipv4"),
    ],
)
def test_bounded_origination_eligibility_is_not_inferred_from_empty_ip_rendering(
    active, switchport, prefixes, eligible, reason
):
    result = extract_side(answers([("Loopback0", active, switchport, prefixes)]), "edge")
    row = result["interfaces"][0]
    assert row["eligible"] is eligible and row["eligibility_reason"] == reason


def test_shutdown_removal_and_after_context_address_change_have_distinct_saved_sets():
    before = answers(
        [
            ("eth0", True, False, ["192.0.2.1/30"]),
            ("eth1", True, False, ["198.51.100.1/24"]),
            ("eth2", True, False, ["203.0.113.1/24"]),
        ],
        source="before-opaque",
    )
    after = answers(
        [
            ("eth0", False, False, ["192.0.2.1/30"]),
            ("eth2", True, False, ["203.0.113.2/24"]),
            ("eth3", True, False, ["198.51.100.2/24"]),
        ],
        source="after-opaque",
    )
    value = IngressScopeObservation.model_validate(observed_payload(before, after))
    assert value.selected_before_only == (canonical_id("edge", "eth1"),)
    assert value.selected_after_only == (canonical_id("edge", "eth3"),)
    assert value.before_eligible_only == tuple(
        sorted([canonical_id("edge", "eth0"), canonical_id("edge", "eth1")])
    )
    assert value.common_eligible == (canonical_id("edge", "eth2"),)
    assert value.after_eligible_only == (canonical_id("edge", "eth3"),)
    assignment = value.after_common_assignments[0]
    assert assignment.source_ip_rendering == "after-opaque"
    assert assignment.source_ip_sha256 == sha256(b"after-opaque").hexdigest()
    assert value.source_assignment_context == "after"
    assert not value.semantic_ip_sets_verified and not value.complete_flow_coverage


def test_fully_observed_empty_selection_has_honest_empty_lists():
    value = IngressScopeObservation.model_validate(observed_payload(answers([]), answers([])))
    assert value.eligibility_complete is True
    assert value.before.interfaces == value.after.interfaces == ()
    assert value.common_eligible == value.after_common_assignments == ()


@pytest.mark.parametrize(
    "field",
    [
        "selected_before_only",
        "selected_after_only",
        "common_eligible",
        "before_eligible_only",
        "after_eligible_only",
        "after_common_assignments",
        "eligibility_complete",
    ],
)
def test_rehashed_or_resealed_forged_derived_lists_cannot_replace_saved_child_truth(field):
    data = observed_payload()
    data[field] = False if field == "eligibility_complete" else ["f" * 64]
    with pytest.raises(ValueError):
        IngressScopeObservation.model_validate(data)


@pytest.mark.parametrize(
    "field,value",
    [
        ("canonical_id_sha256", "f" * 64),
        ("location_rendering", "forged"),
        ("source_ip_sha256", "f" * 64),
        ("active", 1),
        ("switchport", "false"),
        ("eligible", False),
        ("eligibility_reason", "inactive"),
        ("concrete_ipv4_prefixes", ["192.0.2.0/30"]),
        ("concrete_ipv4_prefixes", ["192.0.2.1/30", "192.0.2.1/30"]),
    ],
)
def test_invalid_saved_observations_cannot_replay_as_valid(field, value):
    data = observed_payload()
    data["before"]["interfaces"][0][field] = value
    # Prefix changes are valid observations in isolation; force the contradictory eligibility.
    if field == "concrete_ipv4_prefixes" and len(value) == 1:
        data["before"]["interfaces"][0]["eligible"] = False
    with pytest.raises(ValueError):
        IngressScopeObservation.model_validate(data)


def test_prefixes_preserve_host_bits_and_canonical_identity_is_versioned():
    value = IngressScopeObservation.model_validate(observed_payload())
    assert value.before.interfaces[0].concrete_ipv4_prefixes == ("192.0.2.1/30",)
    assert canonical_id("edge", "eth0") != sha256(b'{"interface":"eth0","node":"edge"}').hexdigest()


@pytest.mark.parametrize("field", ["semantic_ip_sets_verified", "complete_flow_coverage"])
@pytest.mark.parametrize("value", [0, 0.0, "false", True])
def test_false_claim_flags_are_strict_booleans(field, value):
    data = observed_payload()
    data[field] = value
    with pytest.raises(ValueError):
        IngressScopeObservation.model_validate(data)


@pytest.mark.parametrize(
    "field,value",
    [
        ("semantic_ip_sets_verified", True),
        ("complete_flow_coverage", True),
        ("method", "unbounded"),
        ("source_assignment_context", "before"),
        ("version", "ingress-scope-9.0.0"),
    ],
)
@pytest.mark.parametrize("boundary", ["observation", "execution", "copied_execution"])
def test_copied_typed_observations_cannot_bypass_qualification_literals(field, value, boundary):
    data = envelope(request()) | {
        "version": "batfish-execution-0.4.0",
        "ingress_scope": observed_payload(),
        "reachability_impact": impact(Answer([])).model_dump(mode="json"),
    }
    execution = BatfishScopeExecution.model_validate(data)
    forged = execution.ingress_scope.model_copy(update={field: value})
    with pytest.raises(ValueError):
        if boundary == "observation":
            IngressScopeObservation.model_validate(forged)
        elif boundary == "execution":
            BatfishScopeExecution(**(data | {"ingress_scope": forged}))
        else:
            BatfishScopeExecution.model_validate(
                execution.model_copy(update={"ingress_scope": forged})
            )


def test_copied_outer_execution_version_is_revalidated():
    data = envelope(request()) | {
        "version": "batfish-execution-0.4.0",
        "ingress_scope": observed_payload(),
        "reachability_impact": impact(Answer([])).model_dump(mode="json"),
    }
    execution = BatfishScopeExecution.model_validate(data)
    with pytest.raises(ValueError):
        BatfishScopeExecution.model_validate(
            execution.model_copy(update={"version": "batfish-execution-9.0.0"})
        )


@pytest.mark.parametrize(
    "state,reason",
    [
        ("not_observed", "not_run"),
        ("unknown", "query_failed"),
        ("unknown", "budget_exceeded"),
        ("unknown", "cleanup_unconfirmed"),
    ],
)
def test_unavailable_sides_and_derived_lists_are_null_not_zero(state, reason):
    value = empty_ingress_scope(
        "a" * 64,
        "b" * 64,
        ReachabilityScope(start_node="edge", destination="192.0.2.0/24"),
        state=state,
        reason=reason,
    )
    assert value.before is value.after is value.eligibility_complete is None
    assert (
        value.common_eligible
        is value.selected_before_only
        is value.after_common_assignments
        is None
    )
    forged = value.model_dump(mode="json")
    forged["selected_before_only"] = []
    with pytest.raises(ValueError):
        IngressScopeObservation.model_validate(forged)


def test_unknown_eligibility_cannot_advertise_partial_complete_common_set():
    data = observed_payload(answers([("ge0", True, False, [])]), answers())
    data["common_eligible"] = []
    with pytest.raises(ValueError):
        IngressScopeObservation.model_validate(data)


@pytest.mark.parametrize(
    "mutation",
    [
        "before",
        "after",
        "node",
        "destination",
        "network",
        "cleanup",
        "unperformed",
    ],
)
def test_execution_binds_observation_to_exact_snapshots_scope_network_and_attempt(mutation):
    data = envelope(request()) | {
        "version": "batfish-execution-0.4.0",
        "ingress_scope": observed_payload(),
        "reachability_impact": impact(Answer([])).model_dump(mode="json"),
    }
    if mutation in {"before", "after"}:
        data["ingress_scope"][mutation + "_sha256"] = "f" * 64
    elif mutation == "node":
        data["result"]["scope"] = dict(start_node="other", destination="192.0.2.0/24")
    elif mutation == "destination":
        data["ingress_scope"]["scope"]["destination"] = "198.51.100.0/24"
    elif mutation == "network":
        data["ingress_scope"]["network_name"] = "sentinel-" + "f" * 32
    elif mutation == "cleanup":
        data["result"]["cleanup_complete"] = False
    else:
        data["result"] = dict(
            before_sha256="a" * 64,
            after_sha256="b" * 64,
            scope=request()["scope"],
            status="error",
            reason="engine_error",
            network_name=request()["network_name"],
        )
        data["reachability_impact"] = dict(
            state="not_observed",
            reason="not_run",
            direction=None,
            lost_witness_count=None,
            gained_witness_count=None,
            witnesses=[],
        )
    with pytest.raises(ValueError):
        BatfishScopeExecution.model_validate(copy.deepcopy(data))


def test_consent_refusal_returns_additive_unobserved_record_without_sdk(monkeypatch):
    before, after, scope = pair()

    def forbidden(*args, **kwargs):
        pytest.fail("unapproved upload called worker")

    monkeypatch.setattr("app.verification.batfish.subprocess.run", forbidden)
    value = check_with_batfish_scope_evidence(before, after, scope)
    assert value.result.reason == "upload_not_authorized"
    assert value.ingress_scope.acquisition_state == "not_observed"
    assert value.ingress_scope.network_name is None


def test_serialized_replay_needs_no_engine_or_extraction_call(monkeypatch):
    data = observed_payload()
    encoded = IngressScopeObservation.model_validate(data).model_dump_json()

    def forbidden(*args, **kwargs):
        pytest.fail("saved observation called engine")

    monkeypatch.setattr("app.verification.ingress_scope_worker.observe_scope", forbidden)
    assert IngressScopeObservation.model_validate_json(encoded).model_dump(mode="json") == data
