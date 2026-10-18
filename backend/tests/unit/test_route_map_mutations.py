"""Normalized configured order and exact source reversal, without network promotion."""

import json

import pytest
from app.domain import Vendor
from test_mutation_engine import CISCO_TEXT, JUNOS_SET_TEXT, _record

from ml.mutation import (
    ROUTE_MAP_MUTATION_ENGINE_VERSION,
    MutationNotApplicableError,
    MutationType,
    MutationValidationError,
    MutationValidationStatus,
    SyntheticMutationSample,
    mutate_configuration,
    reverse_mutation,
)

KIND = MutationType.ROUTE_MAP_ORDER_CHANGE


def mutate(text=CISCO_TEXT, types=(KIND,), *, seed=17):
    return mutate_configuration(
        _record(text, Vendor.CISCO),
        types,
        seed=seed,
        engine_version=ROUTE_MAP_MUTATION_ENGINE_VERSION,
    )


def test_real_mutation_records_normalized_body_swap_and_replays_exact_source():
    sample = mutate()
    evidence = sample.route_map_validation
    assert evidence is not None
    assert sample.syntax_validation.status is MutationValidationStatus.PASSED
    assert sample.formal_validation.status is MutationValidationStatus.NOT_RUN
    assert evidence.canonical_schema_version == "1.2"
    assert evidence.original_sha256 == sample.original_sha256
    assert evidence.mutated_sha256 == sample.mutated_sha256
    assert evidence.before.name == evidence.after.name == "EXPORT"
    assert [item.sequence for item in evidence.before.clauses] == [10, 20]
    assert [item.sequence for item in evidence.after.clauses] == [10, 20]
    assert evidence.before.clauses[0].match_ipv4_prefix_lists == ("TRUSTED",)
    assert evidence.after.clauses[1].match_ipv4_prefix_lists == ("TRUSTED",)
    assert evidence.before.clauses[1].set_metric == evidence.after.clauses[0].set_metric == 50
    assert evidence.before.clauses[0].provenance["header"].source_lines == (
        evidence.after.clauses[1].provenance["header"].source_lines
    )
    assert sample.localization is not None and len(sample.affected_lines) == 2
    assert sample.affected_lines == sample.localization.changed_result_lines
    assert evidence.vendor_syntax_checked is evidence.network_behavior_checked is False
    assert reverse_mutation(sample, sample.mutated_text) == CISCO_TEXT
    replay = SyntheticMutationSample.model_validate_json(sample.model_dump_json())
    assert reverse_mutation(replay, replay.mutated_text) == CISCO_TEXT


def test_released_route_map_mutation_retains_partial_status_serialization_and_distinct_id():
    legacy = mutate_configuration(_record(CISCO_TEXT, Vendor.CISCO), (KIND,), seed=17)
    current = mutate()
    assert legacy.syntax_validation.status is MutationValidationStatus.PARTIAL
    assert legacy.route_map_validation is None
    assert "route_map_validation" not in json.loads(legacy.model_dump_json())
    assert "localization" not in json.loads(legacy.model_dump_json())
    assert legacy.mutation_id != current.mutation_id
    assert reverse_mutation(legacy, legacy.mutated_text) == CISCO_TEXT


@pytest.mark.parametrize("kind", list(MutationType))
def test_explicit_cisco_version_preserves_other_required_recipes_and_reverse(kind):
    sample = mutate(types=(kind,))
    assert reverse_mutation(sample, sample.mutated_text) == CISCO_TEXT
    assert sample.localization is not None
    assert (sample.route_map_validation is not None) == (kind is KIND)
    assert sample.syntax_validation.status is MutationValidationStatus.PASSED
    assert sample.formal_validation.status is MutationValidationStatus.NOT_RUN


@pytest.mark.parametrize("newline", ["\n", "\r\n"])
@pytest.mark.parametrize(
    "types",
    [
        (KIND, MutationType.AAA_DISABLED, MutationType.MISSING_NTP_SYSLOG),
        (MutationType.MISSING_NTP_SYSLOG, KIND, MutationType.TELNET_ENABLED),
    ],
)
def test_linked_edits_keep_final_anchor_positions_and_exact_reverse(newline, types):
    source = CISCO_TEXT.replace("\n", newline)
    sample = mutate(source, types)
    assert reverse_mutation(sample, sample.mutated_text) == source
    assert sample.route_map_validation is not None
    assert len(sample.labels) == len(types)
    for config, text in (
        (sample.route_map_validation.before, source),
        (sample.route_map_validation.after, sample.mutated_text),
    ):
        for clause in config.clauses:
            line = clause.provenance["header"].source_lines[0]
            assert (
                text.splitlines()[line - 1] == f"route-map EXPORT {clause.action} {clause.sequence}"
            )


@pytest.mark.parametrize(
    "fragment",
    [
        " continue 20\n",
        " call OTHER\n",
        " set metric +5\n",
        " set metric 1\n set metric 2\n",
        " match ip address prefix-list A\n match ip address prefix-list B\n",
    ],
)
def test_selected_incomplete_map_is_refused_instead_of_promoting_text_only_swap(fragment):
    source = (
        "hostname owned\nroute-map A permit 10\n"
        + fragment
        + "!\nroute-map A permit 20\n set metric 50\n!\n"
    )
    with pytest.raises(MutationNotApplicableError):
        mutate(source)


@pytest.mark.parametrize("bodies", ["", " set metric 50\n"])
def test_swapping_identical_configured_bodies_is_not_an_observed_order_change(bodies):
    source = (
        "hostname owned\nroute-map A permit 10\n"
        + bodies
        + "!\nroute-map A permit 20\n"
        + bodies
        + "!\n"
    )
    with pytest.raises(MutationNotApplicableError):
        mutate(source)


def test_duplicate_sequence_is_refused_even_if_header_spelling_differs():
    source = "hostname owned\nroute-map A permit 10\n set metric 10\n!\nroute-map A deny 010\n!\n"
    with pytest.raises(MutationNotApplicableError):
        mutate(source)


@pytest.mark.parametrize("comment", ["!", "! descriptive comment", " ! comment", "\t! comment"])
def test_comment_cannot_detach_unknown_continue_from_a_mutation_candidate(comment):
    source = (
        "hostname owned\nroute-map A permit 10\n match ip address prefix-list X\n"
        + comment
        + "\n continue 20\n!\nroute-map A deny 20\n set metric 50\n!\n"
    )
    with pytest.raises(MutationNotApplicableError):
        mutate(source)


@pytest.mark.parametrize("indent", ["", " ", "\t"])
@pytest.mark.parametrize("opening", ["banner motd ^C", "macro name CUSTOM", "tclsh"])
def test_opaque_block_indentation_cannot_turn_script_text_into_mutation_evidence(indent, opening):
    source = (
        "hostname owned\n" + indent + opening + "\nroute-map FAKE permit 10\n set metric 50\n"
        "route-map FAKE deny 20\n set metric 100\n^C\n"
    )
    with pytest.raises(MutationNotApplicableError):
        mutate(source)


def test_unrelated_unknown_is_preserved_as_partial_and_cannot_be_relabelled_passed():
    source = CISCO_TEXT + "unsupported owned-command\n"
    sample = mutate(source)
    assert sample.syntax_validation.status is MutationValidationStatus.PARTIAL
    assert sample.syntax_validation.unparsed_fragment_count == 1
    assert reverse_mutation(sample, sample.mutated_text) == source
    forged = sample.model_copy(
        update={
            "syntax_validation": sample.syntax_validation.model_copy(
                update={"status": MutationValidationStatus.PASSED}
            )
        }
    )
    with pytest.raises(MutationValidationError, match="reproduce"):
        reverse_mutation(forged, forged.mutated_text)


@pytest.mark.parametrize("fault", ["source", "body", "anchor", "localization", "formal", "count"])
def test_new_replay_rechecks_source_clause_evidence_parser_summary_and_formal_boundary(fault):
    sample = mutate()
    value = sample.model_dump(mode="json")
    if fault == "source":
        value["route_map_validation"]["original_sha256"] = "0" * 64
    elif fault == "body":
        # Keep the body-permutation invariant so refusal requires actual source replay.
        value["route_map_validation"]["before"]["clauses"][1]["set_metric"] = 99
        value["route_map_validation"]["after"]["clauses"][0]["set_metric"] = 99
    elif fault == "anchor":
        value["route_map_validation"]["before"]["clauses"][0]["provenance"]["header"][
            "raw_text_hash"
        ] = "0" * 64
    elif fault == "localization":
        value["localization"]["changes"][0]["original_start_line"] += 1
    elif fault == "formal":
        value["formal_validation"]["status"] = "passed"
    else:
        value["syntax_validation"]["unparsed_fragment_count"] = 1
    with pytest.raises((ValueError, MutationValidationError)):
        forged = SyntheticMutationSample.model_validate(value)
        reverse_mutation(forged, forged.mutated_text)


@pytest.mark.parametrize("seed", [True, 1.5, "17"])
def test_new_version_refuses_coerced_seed(seed):
    with pytest.raises(ValueError, match="integer"):
        mutate(seed=seed)


@pytest.mark.parametrize("fault", ["type", "forward_location"])
def test_replay_requires_each_recorded_effect_and_both_operation_coordinates(fault):
    sample = mutate()
    value = sample.model_dump(mode="json")
    if fault == "type":
        value["operations"][0]["mutation_type"] = "aaa_disabled"
        value["labels"][0]["mutation_type"] = "aaa_disabled"
        value["route_map_validation"] = None
    else:
        value["operations"][0]["original_start_line"] += 1
    forged = SyntheticMutationSample.model_validate(value)
    with pytest.raises(MutationValidationError, match="reproduce"):
        reverse_mutation(forged, forged.mutated_text)


def test_version_is_cisco_only_and_deterministic_without_changing_released_default():
    with pytest.raises(MutationNotApplicableError, match="requires Cisco"):
        mutate_configuration(
            _record(JUNOS_SET_TEXT, Vendor.JUNIPER),
            (KIND,),
            engine_version=ROUTE_MAP_MUTATION_ENGINE_VERSION,
        )
    assert mutate() == mutate()
