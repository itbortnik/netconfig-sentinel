"""Review provider tests use declared fixtures, not actual inference/engine evidence."""

import json
from dataclasses import replace

import pytest
from app.explanation.candidate_review import (
    REVIEW_INSTRUCTIONS,
    build_candidate_review_prompt,
    generate_candidate_review,
)
from app.explanation.provider import DraftAnswer, InvalidProviderAnswer
from app.patching.candidate_review import CandidateReviewUnavailable, build_candidate_review
from test_candidate_review import inputs, selected_ml


def prepared_review(*, with_results=True):
    case, generated, scope, network = inputs()
    pins = ("1" * 64,) if with_results else ()
    report = build_candidate_review(
        generated,
        prepared=case.patch.prepared,
        before=case.before,
        scope=scope,
        network_result=network if with_results else None,
        ml_reviews=(selected_ml(generated),) if with_results else (),
        expected_model_sha256s=pins,
    )
    return build_candidate_review_prompt(
        generated,
        prepared=case.patch.prepared,
        before=case.before,
        report=report,
        expected_model_sha256s=pins,
        allow_local_context=True,
    )


def test_prompt_contains_exact_minimized_results_not_original_prose_or_addresses():
    selected = prepared_review()
    context = json.loads(selected.prompt.context_json)
    assert context["version"] == "candidate-review-context-0.2.0"
    assert context["formal_verification"]["status"] == "no_differences_in_scope"
    assert context["formal_verification"]["before_reachable_count"] == 1
    assert context["candidate"]["status"] == "needs_review"
    assert context["before_change"]["management"]["ssh_version"] == "1"
    assert context["candidate"]["management"]["ssh_version"] == "2"
    assert context["candidate"]["temporal_role"] == "after_change"
    assert context["original_finding_before_change"]["observed"]["ssh_version"] == "1"
    assert "finding" not in context and "safe_diff" not in context
    assert context["selected_baseline"]["approval"] == "not_proven"
    assert context["before_change"]["diff_to_selected_baseline"]["changes"][0]["observed"] == "1"
    assert context["ml_checks"][0]["selected_category_supported"] is False
    assert context["ml_checks"][0]["before_anomaly_score"] == 0.3
    assert context["execution_authenticated"] is False
    assert "192.0.2.1" not in selected.prompt.context_json
    assert "198.51.100.1" not in selected.prompt.context_json
    assert "Declared unit candidate" not in selected.prompt.context_json
    assert "declared-unit-version" not in selected.prompt.context_json
    assert selected.prompt.instructions == REVIEW_INSTRUCTIONS
    schema = json.loads(selected.prompt.answer_schema_json)
    assert schema["properties"]["patch_draft"]["type"] == "null"
    assert schema["properties"]["possible_impact"]["maxItems"] == 2


@pytest.mark.parametrize(
    "mutation", ["list_length", "word_budget", "unretrieved", "duplicate", "patch", "review"]
)
def test_review_only_output_bounds_and_citations_fail_closed_without_retry(mutation):
    selected = prepared_review()
    payload = {
        "summary": "Declared output, not actual inference.",
        "technical_explanation": "Supplied candidate uses SSH version two.",
        "recommendation": "Engineer review is required.",
        "possible_impact": [],
        "patch_draft": None,
        "assumptions": [],
        "missing_information": [],
        "citations": [selected.prepared.chunks[0].citation],
        "requires_human_review": True,
    }
    if mutation == "list_length":
        payload["possible_impact"] = ["One", "Two", "Three"]
    elif mutation == "word_budget":
        payload["summary"] = "word " * 121
    elif mutation == "unretrieved":
        payload["citations"] = ["private-unretrieved#section"]
    elif mutation == "duplicate":
        payload["citations"] *= 2
    elif mutation == "patch":
        payload["patch_draft"] = "apply changes"
    else:
        payload["requires_human_review"] = False

    class Fake:
        calls = 0

        def generate(self, prompt):
            self.calls += 1
            return json.dumps(payload).encode()

    provider = Fake()
    with pytest.raises(InvalidProviderAnswer, match=r"^Language model answer was rejected\.$"):
        generate_candidate_review(provider, selected, allow_local_context=True)
    assert provider.calls == 1 and selected.report.status == "needs_review"


def test_absent_results_stay_explicitly_missing():
    selected = prepared_review(with_results=False)
    context = json.loads(selected.prompt.context_json)
    assert context["formal_verification"]["status"] == "not_supplied"
    assert context["ml_checks"] == []
    assert "formal_report_not_supplied" in context["missing_checks"]


@pytest.mark.parametrize("permission", [False, None, 1, "true"])
def test_explicit_context_permission_required(permission):
    case, generated, scope, _ = inputs()
    report = build_candidate_review(
        generated, prepared=case.patch.prepared, before=case.before, scope=scope
    )
    with pytest.raises(CandidateReviewUnavailable):
        build_candidate_review_prompt(
            generated,
            prepared=case.patch.prepared,
            before=case.before,
            report=report,
            allow_local_context=permission,
        )


def test_fresh_provider_answer_is_null_only_and_does_not_modify_review():
    selected = prepared_review()
    previous = selected.report.model_dump()

    class Fake:
        calls = 0

        def generate(self, prompt):
            self.calls += 1
            assert prompt == selected.prompt
            return json.dumps(
                {
                    "summary": "The supplied scope has one reachable answer row.",
                    "technical_explanation": "The supplied ML head does not cover SSHv1.",
                    "recommendation": "Complete all missing checks with an engineer.",
                    "possible_impact": [],
                    "patch_draft": None,
                    "assumptions": [],
                    "missing_information": ["SSH access and vendor syntax are unverified."],
                    "citations": [selected.prepared.chunks[0].citation],
                    "requires_human_review": True,
                }
            ).encode()

    provider = Fake()
    answer = generate_candidate_review(provider, selected, allow_local_context=True)
    assert isinstance(answer, DraftAnswer) and answer.patch_draft is None
    assert provider.calls == 1 and selected.report.model_dump() == previous


@pytest.mark.parametrize("mutation", ["context", "instructions", "schema", "pin", "scores"])
def test_tampering_is_rejected_before_provider(mutation):
    selected = prepared_review()
    if mutation == "scores":
        selected.report.ml_reviews[0].transformer.before.category_scores["telnet_enabled"] = 0.9
    elif mutation == "pin":
        selected = replace(selected, expected_model_sha256s=("f" * 64,))
    else:
        field = {
            "context": "context_json",
            "instructions": "instructions",
            "schema": "answer_schema_json",
        }[mutation]
        selected = replace(selected, prompt=replace(selected.prompt, **{field: "private-invalid"}))

    class NoCall:
        def generate(self, prompt):
            pytest.fail("provider called for stale or tampered facts")

    with pytest.raises(CandidateReviewUnavailable):
        generate_candidate_review(NoCall(), selected, allow_local_context=True)


def test_provider_failure_does_not_retry_or_fabricate_an_answer():
    class Failed:
        calls = 0

        def generate(self, prompt):
            self.calls += 1
            raise RuntimeError("private-error")

    provider = Failed()
    with pytest.raises(InvalidProviderAnswer, match=r"^Language model provider failed\.$"):
        generate_candidate_review(provider, prepared_review(), allow_local_context=True)
    assert provider.calls == 1
