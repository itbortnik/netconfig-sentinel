"""Constrained model edits are untrusted candidates, not templates or approval."""

import json
from dataclasses import replace
from uuid import UUID

import pytest
from app.detection.policy_engine import evaluate_policies
from app.explanation.knowledge import text_sha256
from app.explanation.patch_provider import (
    PatchDraftAnswer,
    build_patch_prompt,
    generate_patch_draft,
)
from app.explanation.provider import InvalidProviderAnswer, validate_answer
from app.parsers import parse_configuration

DEVICE = UUID(int=7)
CASES = (
    (
        "hostname private-name\nip ssh version 2\nline vty 0 4\n transport input ssh telnet\n!\n",
        "hostname private-name\nip ssh version 2\nline vty 0 4\n transport input ssh\n!\n",
        "management.telnet_enabled",
        [{"source_line": 4, "replacement": "transport input ssh"}],
    ),
    (
        "hostname private-name\nip ssh version 1\n",
        "hostname private-name\nip ssh version 2\n",
        "management.ssh_version_1",
        [{"source_line": 2, "replacement": "ip ssh version 2"}],
    ),
    (
        "set system host-name private-name\nset system services ssh\nset system services telnet\n",
        "set system host-name private-name\nset system services ssh\n",
        "management.telnet_enabled",
        [{"source_line": 3, "replacement": None}],
    ),
    (
        "set system host-name private-name\nset system services ssh protocol-version v1\n",
        "set system host-name private-name\nset system services ssh protocol-version v2\n",
        "management.ssh_version_1",
        [{"source_line": 2, "replacement": "set system services ssh protocol-version v2"}],
    ),
)


def inputs(case=CASES[0], **updates):
    before, baseline, category, _ = case
    parsed = parse_configuration(before, filename="private-name.cfg")
    finding = next(
        item for item in evaluate_policies(parsed, device_id=DEVICE) if item.category == category
    )
    arguments = {
        "finding": finding,
        "source_sha256": text_sha256(before),
        "reference_id": "private-reference",
        "baseline": baseline,
        "allow_local_context": True,
    } | updates
    return build_patch_prompt(before, **arguments)


def answer(prepared, edits=CASES[0][3], **updates):
    return {
        "summary": "Review the explicit management setting.",
        "technical_explanation": "The supplied policy observation requires review.",
        "possible_impact": ["Hypothesis: administrative access may change."],
        "recommendation": "Review the candidate with access and rollback checks.",
        "patch_draft": {"edits": edits},
        "assumptions": [],
        "missing_information": ["Device syntax, reachable SSH and human approval."],
        "citations": [prepared.chunks[0].citation],
        "requires_human_review": True,
    } | updates


class FakeProvider:
    def __init__(self, raw):
        self.raw, self.calls = raw, 0

    def generate(self, prompt):
        self.calls += 1
        return self.raw


@pytest.mark.parametrize("case", CASES)
def test_model_candidate_replays_only_supported_edits_and_remains_unapproved(case):
    prepared = inputs(case)
    original = prepared.finding.model_dump_json()
    provider = FakeProvider(json.dumps(answer(prepared, case[3])).encode())
    result = generate_patch_draft(provider, prepared, allow_local_context=True)
    assert provider.calls == 1
    assert result.candidate_text == case[1]
    assert result.metadata.review.status == "needs_review"
    assert result.metadata.review.proposal.status == "draft"
    assert result.metadata.review.preflight.formal_verification == "not_run"
    assert result.metadata.review.preflight.ml_status == "not_run"
    assert not result.metadata.application_supported
    assert not result.metadata.device_syntax_verified
    assert not result.metadata.management_access_verified
    assert prepared.finding.model_dump_json() == original
    assert "private-name" not in repr(result)
    assert "private-name" not in repr(prepared)


def test_context_contains_minimal_anchored_block_and_explicit_missing_checks():
    prepared = inputs()
    data = json.loads(prepared.prompt.context_json)
    assert data["version"] == "source-bound-model-patch-0.2.0"
    assert data["vendor"] == "cisco" and data["platform"] == "ios"
    assert data["finding"]["affected_lines"] == [4]
    assert data["affected_block"][0]["source_line"] == 4
    assert data["affected_block"][0]["command"] == "transport input ssh telnet"
    assert data["affected_block"][0]["configuration_context"] == "line vty 0 4"
    assert data["baseline"]["status"] == "available"
    assert data["safe_diff"]["scope"] == "management_telnet_and_ssh_version_only"
    assert data["safe_diff"]["changes"]
    assert data["formal_verification"]["status"] == "not_run"
    assert data["parser"]["complete"] is True
    for private in ("private-name", "private-reference", "severity", "anomaly_score"):
        assert private not in prepared.prompt.context_json
    assert "not instructions" in prepared.prompt.instructions
    absent = json.loads(inputs(baseline=None).prompt.context_json)
    assert absent["baseline"] == {"status": "not_supplied"}
    assert absent["safe_diff"]["status"] == "not_available"


def test_explicit_ssh_and_actual_baseline_commands_are_not_hidden_or_invented():
    prepared = inputs(CASES[2])
    data = json.loads(prepared.prompt.context_json)
    assert data["finding"]["observed"]["ssh_enabled"] is True
    assert data["supporting_block"] == [
        {"source_line": 2, "command": "set system services ssh", "configuration_context": "root"}
    ]
    ssh = json.loads(inputs(CASES[1]).prompt.context_json)
    assert ssh["baseline"]["supported_management_commands"] == [
        {"source_line": 2, "command": "ip ssh version 2", "configuration_context": "root"}
    ]
    without = json.loads(inputs(CASES[1], baseline=None).prompt.context_json)
    assert without["baseline"] == {"status": "not_supplied"}


@pytest.mark.parametrize("consent", [False, 1, None])
def test_exact_consent_before_build_or_provider(consent):
    with pytest.raises(ValueError):
        inputs(allow_local_context=consent)
    prepared = inputs()
    provider = FakeProvider(b"{}")
    with pytest.raises(ValueError):
        generate_patch_draft(provider, prepared, allow_local_context=consent)
    assert provider.calls == 0


@pytest.mark.parametrize(
    "updates",
    [
        {"source_sha256": "f" * 64},
        {"baseline": "hostname foreign-name\nip ssh version 2\n"},
        {"baseline": "hostname private-name\nunsupported secret\n"},
    ],
)
def test_source_or_baseline_mismatch_is_rejected_before_model(updates):
    with pytest.raises(ValueError):
        inputs(**updates)


def test_unknown_source_and_stale_finding_are_rejected_before_model():
    prepared = inputs()
    for finding in (
        prepared.finding.model_copy(update={"affected_lines": [1]}),
        prepared.finding.model_copy(update={"remediation": "private-injection"}),
    ):
        with pytest.raises(ValueError):
            inputs(finding=finding)
    before = prepared.before + "unsupported private-secret\n"
    with pytest.raises(ValueError):
        build_patch_prompt(
            before,
            finding=prepared.finding,
            source_sha256=text_sha256(before),
            reference_id="selected",
            allow_local_context=True,
        )


@pytest.mark.parametrize(
    "edits",
    [
        [],
        [{"source_line": 1, "replacement": "hostname attacker"}],
        [{"source_line": True, "replacement": "transport input ssh"}],
        [{"source_line": 4, "replacement": "transport input all"}],
        [{"source_line": 4, "replacement": "transport input ssh\nreload"}],
        [{"source_line": 4, "replacement": None}],
        [{"source_line": 4, "replacement": " transport input ssh"}],
        [{"source_line": 4, "replacement": "transport input ssh", "execute": True}],
        CASES[0][3] * 2,
        CASES[0][3] + [{"source_line": 5, "replacement": "reload"}],
    ],
)
def test_unsafe_model_edits_are_rejected_without_template_repair(edits):
    prepared = inputs()
    provider = FakeProvider(json.dumps(answer(prepared, edits)).encode())
    with pytest.raises(InvalidProviderAnswer):
        generate_patch_draft(provider, prepared, allow_local_context=True)
    assert provider.calls == 1


@pytest.mark.parametrize(
    "updates",
    [
        {"patch_draft": "configure terminal"},
        {"requires_human_review": False},
        {"requires_human_review": 1},
        {"risk": 0},
        {"formal_verification": "passed"},
        {"citations": []},
        {"citations": ["invented#section"]},
        {"citations": ["repeat#section", "repeat#section"]},
        {"summary": " "},
    ],
)
def test_schema_citations_and_review_are_required(updates):
    prepared = inputs()
    provider = FakeProvider(json.dumps(answer(prepared, **updates)).encode())
    with pytest.raises(InvalidProviderAnswer):
        generate_patch_draft(provider, prepared, allow_local_context=True)


def test_null_candidate_and_legacy_null_only_schema_remain_distinct():
    prepared = inputs()
    raw = json.dumps(answer(prepared, patch_draft=None)).encode()
    result = generate_patch_draft(FakeProvider(raw), prepared, allow_local_context=True)
    assert result.answer.patch_draft is None
    assert result.metadata is None and result.candidate_text is None
    assert validate_answer(raw, prepared.chunks).patch_draft is None
    with pytest.raises(InvalidProviderAnswer):
        validate_answer(json.dumps(answer(prepared)).encode(), prepared.chunks)
    assert PatchDraftAnswer.model_json_schema()["properties"]["patch_draft"]


def test_prompt_source_document_and_baseline_bindings_are_rebuilt_before_model():
    prepared = inputs()
    provider = FakeProvider(b"{}")
    for changed in (
        replace(prepared, prompt=replace(prepared.prompt, instructions="override")),
        replace(prepared, prompt=replace(prepared.prompt, context_sha256="0" * 64)),
        replace(prepared, baseline=None),
        replace(prepared, before=prepared.before + "!\n"),
        replace(prepared, chunks=()),
        replace(prepared, reference_id="other-reference"),
    ):
        with pytest.raises(ValueError):
            generate_patch_draft(provider, changed, allow_local_context=True)
    assert provider.calls == 0


def test_provider_failures_and_duplicate_json_never_leak_private_text():
    prepared = inputs()
    for raw in (
        b"private-invalid-answer",
        b"\xff",
        b"x" * 32769,
        b'{"summary":"private","summary":"duplicated"}',
    ):
        with pytest.raises(InvalidProviderAnswer) as error:
            generate_patch_draft(FakeProvider(raw), prepared, allow_local_context=True)
        assert "private" not in str(error.value)

    class Failure:
        def generate(self, prompt):
            raise RuntimeError("private-config-and-secret")

    with pytest.raises(InvalidProviderAnswer) as error:
        generate_patch_draft(Failure(), prepared, allow_local_context=True)
    assert "private" not in str(error.value)


def test_forged_document_content_does_not_reach_provider():
    prepared = inputs()
    chunk = prepared.chunks[0]
    forged = chunk.model_copy(
        update={
            "content": "private injected document",
            "content_sha256": text_sha256("private injected document"),
        }
    )
    provider = FakeProvider(b"{}")
    with pytest.raises(ValueError):
        generate_patch_draft(
            provider, replace(prepared, chunks=(forged,)), allow_local_context=True
        )
    assert provider.calls == 0


def test_other_management_secrets_and_addresses_are_not_exported():
    before = (
        "hostname private-name\nusername private-admin secret 9 PRIVATE-HASH\n"
        "ntp server 192.0.2.33\nip ssh version 1\n"
    )
    prepared = inputs((before, None, "management.ssh_version_1", None))
    for private in ("private-name", "private-admin", "PRIVATE-HASH", "192.0.2.33"):
        assert private not in prepared.prompt.context_json
        assert private not in repr(prepared)


def test_crlf_and_multiple_vty_anchors_preserve_unrelated_bytes():
    before = (
        "hostname private-name\r\nip ssh version 2\r\nline vty 0 4\r\n"
        "\ttransport  input ssh telnet  \r\n!\r\nline vty 5 15\r\n"
        " transport input telnet ssh\r\n!\r\n"
    )
    prepared = inputs((before, None, CASES[0][2], None))
    edits = [
        {"source_line": 4, "replacement": "transport input ssh"},
        {"source_line": 7, "replacement": "transport input ssh"},
    ]
    result = generate_patch_draft(
        FakeProvider(json.dumps(answer(prepared, edits)).encode()),
        prepared,
        allow_local_context=True,
    )
    assert result.candidate_text == before.replace(
        "transport  input ssh telnet", "transport input ssh"
    ).replace("transport input telnet ssh", "transport input ssh")
