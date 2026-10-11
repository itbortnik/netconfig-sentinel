"""Caller facts are closed, scoped and unknown offline; not model or deployment truth."""

import json
from dataclasses import replace

import pytest
from app.explanation.facts import ExplanationInvocationFacts
from app.explanation.privacy import redact_prompt
from app.explanation.provider import build_prompt
from test_explanation_provider import inputs


def saved(**updates):
    return {
        "entrypoint": "saved_analysis_http",
        "analysis_storage": "stored_analysis",
        "model_answer_storage": "not_stored_in_analysis",
        "selected_finding_peer_profile_storage": "not_applicable",
    } | updates


@pytest.mark.parametrize(
    "updates",
    [
        {"entrypoint": "cli"},
        {"entrypoint": "not_supplied"},
        {"analysis_storage": "not_supplied"},
        {"model_answer_storage": "not_supplied"},
        {"model_answer_storage": "stored"},
        {"selected_finding_peer_profile_storage": "not_stored"},
        {"selected_finding_peer_profile_storage": True},
        {"source_sha256": "0" * 64},
        {"analysis_id": "private-id"},
        {"database_path": "private-path"},
        {"instructions": "injected prose"},
        {"version": "explanation-analysis-facts-0.1.0"},
    ],
)
def test_invalid_invocation_facts_do_not_enter_model_or_redaction(updates):
    data = saved(**updates)
    with pytest.raises(ValueError):
        ExplanationInvocationFacts.model_validate(data)
    finding, explanation, chunks, prompt = inputs()
    # model_copy does not validate. Invalid declared fields must be revalidated;
    # injected undeclared attributes must not be forwarded by the serializer.
    invalid = ExplanationInvocationFacts().model_copy(update=data)
    def build():
        return build_prompt(
            finding,
            explanation,
            chunks,
            vendor="cisco",
            platform="ios",
            parser_confidence=1,
            warning_count=0,
            unparsed_count=0,
            invocation_facts=invalid,
        )
    if set(updates) <= set(ExplanationInvocationFacts.model_fields):
        with pytest.raises(ValueError):
            build()
    else:
        assert not set(updates) & set(json.loads(build().context_json)["invocation_facts"])
    context = json.loads(prompt.context_json) | {"invocation_facts": data}
    with pytest.raises(ValueError):
        redact_prompt(replace(prompt, context_json=json.dumps(context)))


def test_offline_and_historical_missing_invocation_remain_unknown():
    _, _, _, prompt = inputs()
    unknown = ExplanationInvocationFacts().model_dump(mode="json")
    assert json.loads(prompt.context_json)["invocation_facts"] == unknown
    assert json.loads(redact_prompt(prompt).context_json)["invocation_facts"] == unknown
    historical = json.loads(prompt.context_json)
    historical.pop("invocation_facts")
    retained = redact_prompt(replace(prompt, context_json=json.dumps(historical)))
    assert json.loads(retained.context_json)["invocation_facts"] == unknown


@pytest.mark.parametrize("profile", ["not_applicable", "not_supplied"])
def test_known_caller_scope_survives_redaction_without_changing_sealed_sources(profile):
    finding, explanation, chunks, original = inputs()
    facts = ExplanationInvocationFacts.model_validate(
        saved(selected_finding_peer_profile_storage=profile)
    )
    prompt = build_prompt(
        finding,
        explanation,
        chunks,
        vendor="cisco",
        platform="ios",
        parser_confidence=1,
        warning_count=0,
        unparsed_count=0,
        invocation_facts=facts,
    )
    retained = json.loads(redact_prompt(prompt).context_json)
    assert retained["invocation_facts"] == facts.model_dump(mode="json")
    assert retained["documents"] == json.loads(original.context_json)["documents"]
    assert retained["formal_verification"] == "not_run"
    assert prompt.answer_schema_json == original.answer_schema_json


@pytest.mark.parametrize(
    "detector", ["policy_engine", "expected_configuration", "isolation_forest"]
)
def test_peer_storage_is_not_a_fact_about_an_unrelated_selected_finding(detector):
    facts = ExplanationInvocationFacts.model_validate(
        saved(selected_finding_peer_profile_storage="stored_in_analysis")
    )
    with pytest.raises(ValueError):
        facts.validate_detector_scope(detector)
    _, _, _, prompt = inputs()
    data = json.loads(prompt.context_json) | {
        "detector": detector,
        "invocation_facts": facts.model_dump(mode="json"),
    }
    with pytest.raises(ValueError):
        redact_prompt(replace(prompt, context_json=json.dumps(data)))


def test_peer_scope_can_be_stored_or_unknown_but_not_irrelevant():
    for profile in ("stored_in_analysis", "not_supplied"):
        ExplanationInvocationFacts.model_validate(
            saved(selected_finding_peer_profile_storage=profile)
        ).validate_detector_scope("peer_baseline")
    with pytest.raises(ValueError):
        ExplanationInvocationFacts.model_validate(saved()).validate_detector_scope("peer_baseline")


def test_prompt_builder_refuses_stored_peer_profile_for_a_policy_finding():
    finding, explanation, chunks, _ = inputs()
    with pytest.raises(ValueError, match="peer profile storage differs"):
        build_prompt(
            finding,
            explanation,
            chunks,
            vendor="cisco",
            platform="ios",
            parser_confidence=1,
            warning_count=0,
            unparsed_count=0,
            invocation_facts=ExplanationInvocationFacts.model_validate(
                saved(selected_finding_peer_profile_storage="stored_in_analysis")
            ),
        )
