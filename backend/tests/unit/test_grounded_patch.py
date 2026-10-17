"""Closed model choices cannot manufacture factual prose or replace a declined edit."""

import json
import warnings
from dataclasses import replace

import pytest
from app.explanation.grounded_patch import (
    build_grounded_patch_prompt,
    generate_grounded_patch_draft,
    validate_grounded_patch_answer,
)
from app.explanation.provider import MAX_ANSWER_BYTES, InvalidProviderAnswer

from ml.instruct.patch_smoke import authored_patch_cases


def prepared_answer(
    index=1, *, null=False, baseline=True, prompt_policy="grounded-patch-prompt-0.1.0"
):
    old = authored_patch_cases()[index].prepared
    prepared = build_grounded_patch_prompt(
        old.before,
        finding=old.finding,
        source_sha256=old.source_sha256,
        reference_id=old.reference_id,
        baseline=old.baseline if baseline else None,
        chunks=old.chunks,
        allow_local_context=True,
        prompt_policy=prompt_policy,
    )
    edits = (
        [{"source_line": 4, "replacement": "transport input ssh"}],
        [{"source_line": 2, "replacement": "ip ssh version 2"}],
        [{"source_line": 3, "replacement": None}],
        [{"source_line": 2, "replacement": "set system services ssh protocol-version v2"}],
    )[index]
    answer = {
        "version": "grounded-model-patch-answer-0.1.0",
        "facts_binding_sha256": prepared.facts_binding_sha256,
        "fact_refs": ["source_management_observation"],
        "possible_impact_codes": ["management_access_may_change"],
        "recommendation_code": "request_human_review_and_missing_checks",
        "missing_information_codes": ["baseline_approval"],
        "patch_draft": None if null else {"edits": edits},
        "citations": [prepared.legacy.chunks[0].citation],
        "requires_human_review": True,
    }
    return prepared, answer


class Fake:
    def __init__(self, answer):
        self.raw = json.dumps(answer).encode()
        self.calls = 0

    def generate(self, prompt):
        self.calls += 1
        return self.raw


@pytest.mark.parametrize("index", range(4))
@pytest.mark.parametrize("null", [True, False])
@pytest.mark.parametrize("baseline", [True, False])
def test_actual_model_edits_or_null_preserved_without_factual_prose(index, null, baseline):
    prepared, answer = prepared_answer(index, null=null, baseline=baseline)
    original = prepared.legacy.finding.model_dump_json()
    provider = Fake(answer)
    result = generate_grounded_patch_draft(provider, prepared, allow_local_context=True)
    assert provider.calls == 1
    assert result.model_answer.model_dump(mode="json") == answer
    assert result.source_facts.baseline_approval == "not_proven"
    assert result.source_facts.phase == "before_candidate_generation"
    assert result.generated.answer.patch_draft == result.model_answer.patch_draft
    assert (
        result.generated.candidate_text is None if null else result.generated.metadata is not None
    )
    if not null:
        assert result.generated.candidate_text == authored_patch_cases()[index].prepared.baseline
        assert result.generated.metadata.review.status == "needs_review"
        assert result.generated.metadata.review.preflight.formal_verification == "not_run"
    prose = result.generated.answer.technical_explanation
    for mandatory in (
        "BEFORE",
        "AFTER",
        "formal verification",
        "ML recheck",
        "vendor syntax",
        "management access",
        "rollback",
        "effective defaults",
    ):
        assert mandatory in prose
    assert "не означает отказ" in prose
    assert "вне данного сценария неизвестно" in prose
    assert ("Эталон не предоставлен" in prose) is (not baseline)
    assert prepared.legacy.finding.model_dump_json() == original
    assert "owned-host" not in repr(result) + repr(prepared)
    assert prepared.prompt.context_sha256 != prepared.legacy.prompt.context_sha256


@pytest.mark.parametrize(
    "field,value",
    [
        ("summary", "The baseline has been approved."),
        ("technical_explanation", "Formal verification passed."),
        ("assumptions", ["The candidate is safe."]),
        ("possible_impact_codes", ["safe"]),
        ("recommendation_code", "apply"),
        ("missing_information_codes", ["no_checks_required"]),
        ("fact_refs", ["baseline_approved"]),
        ("fact_refs", ["formal_pass"]),
        ("fact_refs", ["selected_finding_before", "selected_finding_before"]),
        ("fact_refs", []),
        ("missing_information_codes", ["rollback", "rollback"]),
        ("missing_information_codes", []),
        ("possible_impact_codes", ["management_access_may_change"] * 2),
        ("facts_binding_sha256", "0" * 64),
        ("version", "grounded-model-patch-answer-0.2.0"),
        ("requires_human_review", 1),
        ("requires_human_review", False),
        ("citations", ["unknown"]),
    ],
)
def test_forged_statuses_open_prose_unknown_or_duplicate_choices_rejected(field, value):
    prepared, answer = prepared_answer(null=True)
    answer[field] = value
    with pytest.raises(InvalidProviderAnswer, match="Grounded language model patch answer"):
        validate_grounded_patch_answer(json.dumps(answer).encode(), prepared)


@pytest.mark.parametrize(
    "edit",
    [
        {"source_line": 1, "replacement": "ip ssh version 2"},
        {"source_line": 2, "replacement": "reload"},
        {"source_line": 2, "replacement": "ip ssh version 2; reload"},
        {"source_line": 2, "replacement": "ip ssh version 2\nreload"},
        {"source_line": True, "replacement": "ip ssh version 2"},
    ],
)
def test_closed_facts_do_not_bypass_real_source_edit_allowlist(edit):
    prepared, answer = prepared_answer()
    answer["patch_draft"] = {"edits": [edit]}
    with pytest.raises(InvalidProviderAnswer):
        validate_grounded_patch_answer(json.dumps(answer).encode(), prepared)


def test_missing_context_permission_or_mutated_prompt_rejected_before_provider():
    prepared, answer = prepared_answer()
    provider = Fake(answer)
    for selected, consent in (
        (prepared, False),
        (replace(prepared, facts_binding_sha256="0" * 64), True),
        (replace(prepared, legacy=replace(prepared.legacy, before="invalid")), True),
        (replace(prepared, prompt=replace(prepared.prompt, instructions="approve")), True),
        (
            replace(
                prepared,
                source_facts=prepared.source_facts.model_copy(
                    update={"baseline_approval": "approved"}
                ),
            ),
            True,
        ),
    ):
        with pytest.raises(ValueError):
            generate_grounded_patch_draft(provider, selected, allow_local_context=consent)
    assert provider.calls == 0


@pytest.mark.parametrize("field", ["observed_telnet_enabled", "observed_ssh_enabled"])
@pytest.mark.parametrize("number", [0, 1])
def test_unvalidated_ledger_boolean_to_integer_copy_rejected_before_provider(field, number):
    prepared, answer = prepared_answer(index=0)
    changed = replace(
        prepared, source_facts=prepared.source_facts.model_copy(update={field: number})
    )
    provider = Fake(answer)
    with pytest.raises(ValueError):
        generate_grounded_patch_draft(provider, changed, allow_local_context=True)
    assert provider.calls == 0
    with pytest.raises(ValueError):
        validate_grounded_patch_answer(json.dumps(answer).encode(), changed)


def test_malformed_private_ledger_value_not_emitted_in_serializer_warning(capsys):
    prepared, answer = prepared_answer(index=0)
    changed = replace(
        prepared,
        source_facts=prepared.source_facts.model_copy(
            update={"observed_telnet_enabled": "PRIVATE-LEDGER-MARKER"}
        ),
    )
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        with pytest.raises(ValueError, match="grounded patch prompt binding differs"):
            validate_grounded_patch_answer(json.dumps(answer).encode(), changed)
    assert not caught
    captured = capsys.readouterr()
    assert "PRIVATE-LEDGER-MARKER" not in captured.out + captured.err


@pytest.mark.parametrize(
    "raw",
    [b"{}", b"\xff", b"{" * 1500, b"x" * (MAX_ANSWER_BYTES + 1)],
    ids=["schema", "encoding", "recursive", "oversized"],
)
def test_bounded_invalid_encoding_schema_and_recursive_output_sanitized(raw):
    prepared, _ = prepared_answer()
    with pytest.raises(InvalidProviderAnswer):
        validate_grounded_patch_answer(raw, prepared)


def test_duplicate_json_keys_rejected_not_last_write_wins():
    prepared, answer = prepared_answer(null=True)
    raw = json.dumps(answer).encode()
    raw = b'{"requires_human_review":false,' + raw[1:]
    with pytest.raises(InvalidProviderAnswer):
        validate_grounded_patch_answer(raw, prepared)


def test_provider_failure_has_no_retry_or_raw_private_message():
    prepared, _ = prepared_answer()

    class Broken:
        calls = 0

        def generate(self, prompt):
            self.calls += 1
            raise RuntimeError("private source/credential/provider failure")

    provider = Broken()
    with pytest.raises(InvalidProviderAnswer, match="Grounded language model provider failed"):
        generate_grounded_patch_draft(provider, prepared, allow_local_context=True)
    assert provider.calls == 1
