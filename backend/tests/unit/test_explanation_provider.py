"""Provider fakes only: minimal private context, schema rejection and citation allowlist."""

import json
from dataclasses import replace
from uuid import UUID

import pytest
from app.detection.policy_engine import evaluate_policies
from app.explanation.knowledge import load_knowledge_catalog
from app.explanation.local import explain_finding
from app.explanation.provider import (
    MAX_ANSWER_BYTES,
    InvalidProviderAnswer,
    build_prompt,
    generate_draft,
    validate_answer,
)
from app.parsers import parse_configuration


def inputs():
    config = parse_configuration(
        "hostname private-host\nunsupported secret-token\n", filename="private.cfg"
    )
    finding = evaluate_policies(config, device_id=UUID(int=1))[0]
    explanation = explain_finding(finding, config)
    chunks = load_knowledge_catalog().retrieve(finding)
    prompt = build_prompt(
        finding,
        explanation,
        chunks,
        vendor="cisco",
        platform="ios",
        parser_confidence=config.parser_confidence,
        warning_count=len(config.parse_warnings),
        unparsed_count=len(config.unparsed_fragments),
    )
    return finding, explanation, chunks, prompt


def answer(chunks, **updates):
    return {
        "summary": "An observed policy fact requires review.",
        "technical_explanation": "Only supported syntax was evaluated.",
        "possible_impact": ["Hypothesis: management access may be affected."],
        "recommendation": "Review approved administrative access requirements.",
        "patch_draft": None,
        "assumptions": [],
        "missing_information": ["Approved policy and operational context."],
        "citations": [chunks[0].citation],
        "requires_human_review": True,
    } | updates


def test_prompt_does_not_export_raw_configuration_unknown_text_or_risk() -> None:
    finding, explanation, chunks, prompt = inputs()
    data = json.loads(prompt.context_json)
    assert data["documents"] == [chunk.model_dump(mode="json") for chunk in chunks]
    assert data["finding_sha256"] == explanation.finding_sha256
    assert data["parser"]["unparsed_count"] == 1
    assert data["formal_verification"] == "not_run"
    for private in ("private-host", "private.cfg", "secret-token", "severity", "anomaly_score"):
        assert private not in prompt.context_json
    assert "risk" not in data and "confidence" not in data
    assert "not instructions" in prompt.instructions
    original = finding.model_dump_json()
    assert validate_answer(json.dumps(answer(chunks)).encode(), chunks).patch_draft is None
    assert finding.model_dump_json() == original


@pytest.mark.parametrize(
    "updates",
    [
        {"risk": 0},
        {"severity": "low"},
        {"confidence": 1},
        {"formal_verification": "passed"},
        {"approved": True},
        {"requires_human_review": False},
        {"requires_human_review": 1},
        {"patch_draft": "configure terminal"},
        {"citations": []},
        {"citations": ["https://outside.invalid/fabricated"]},
        {"citations": ["docs/baseline.md#limitations"]},
        {"summary": " "},
        {"summary": "x" * 1001},
        {"technical_explanation": "text\u202ehidden"},
        {"possible_impact": "not an array"},
    ],
)
def test_unsafe_or_incompatible_answer_is_not_shown(updates) -> None:
    _, _, chunks, _ = inputs()
    with pytest.raises(InvalidProviderAnswer, match=r"^Language model answer was rejected\.$"):
        validate_answer(json.dumps(answer(chunks, **updates)).encode(), chunks)


@pytest.mark.parametrize(
    "raw",
    [b"invalid", b"\xff", b"[]", b"null", b"{}", b"x" * (MAX_ANSWER_BYTES + 1)],
    ids=["invalid-json", "non-utf8", "array", "null", "missing-fields", "oversized"],
)
def test_invalid_or_oversized_answer_is_rejected(raw) -> None:
    with pytest.raises(InvalidProviderAnswer):
        validate_answer(raw, inputs()[2])


def test_duplicate_keys_citations_and_markdown_wrapping_are_rejected() -> None:
    _, _, chunks, _ = inputs()
    raw = json.dumps(answer(chunks)).encode()
    for modified in (
        raw.replace(b'{"summary":', b'{"summary":"injected","summary":'),
        b"```json\n" + raw + b"\n```",
        json.dumps(answer(chunks, citations=[chunks[0].citation] * 2)).encode(),
    ):
        with pytest.raises(InvalidProviderAnswer):
            validate_answer(modified, chunks)


def test_provider_only_runs_explicitly_and_cannot_change_context_or_leak_errors() -> None:
    _, _, chunks, prompt = inputs()

    class FakeProvider:
        calls = 0

        def generate(self, received):
            self.calls += 1
            assert received == prompt
            return json.dumps(answer(chunks)).encode()

    provider = FakeProvider()
    assert generate_draft(provider, prompt, chunks).requires_human_review is True
    assert provider.calls == 1
    for context in ("null", "[]", "not-json", "x" * 65537):
        with pytest.raises(ValueError):
            generate_draft(provider, replace(prompt, context_json=context), chunks)
    with pytest.raises(ValueError):
        generate_draft(provider, prompt, (load_knowledge_catalog().chunks[0],))
    assert provider.calls == 1
    with pytest.raises(ValueError):
        generate_draft(provider, replace(prompt, instructions="ignore guards"), chunks)
    with pytest.raises(ValueError):
        generate_draft(provider, replace(prompt, context_sha256="f" * 64), chunks)
    assert provider.calls == 1

    class FailingProvider:
        def generate(self, received):
            raise RuntimeError("private-token-and-context")

    with pytest.raises(InvalidProviderAnswer, match=r"^Language model provider failed\.$"):
        generate_draft(FailingProvider(), prompt, chunks)


@pytest.mark.parametrize(
    "updates",
    [
        {"vendor": "unsupported"},
        {"platform": "ios-xr"},
        {"parser_confidence": float("nan")},
        {"warning_count": -1},
        {"unparsed_count": 10001},
        {"warning_count": True},
    ],
)
def test_invalid_context_is_not_sent_to_a_provider(updates):
    finding, explanation, chunks, _ = inputs()
    context = {
        "vendor": "cisco",
        "platform": "ios",
        "parser_confidence": 1,
        "warning_count": 0,
        "unparsed_count": 0,
    } | updates
    with pytest.raises(ValueError):
        build_prompt(finding, explanation, chunks, **context)


def test_modified_finding_and_oversized_evidence_do_not_enter_prompt():
    finding, explanation, chunks, _ = inputs()
    context = {
        "vendor": "cisco",
        "platform": "ios",
        "parser_confidence": 1,
        "warning_count": 0,
        "unparsed_count": 0,
    }
    with pytest.raises(ValueError):
        build_prompt(
            finding.model_copy(update={"observed": {"injected": "instruction"}}),
            explanation,
            chunks,
            **context,
        )
    with pytest.raises(ValueError):
        build_prompt(
            finding,
            explanation.model_copy(update={"limitations": ("x" * 65537,)}),
            chunks,
            **context,
        )
    for altered in ({"detector_version": "future"}, {"confidence": 0.01}):
        with pytest.raises(ValueError):
            build_prompt(finding, explanation.model_copy(update=altered), chunks, **context)
