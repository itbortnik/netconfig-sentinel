"""Literal target/consent validation and request-local pseudonymization of all strings."""

import json
from dataclasses import replace
from uuid import UUID

import pytest
from app.core.local_model import LocalModelSettings
from app.detection.policy_engine import evaluate_policies
from app.explanation.knowledge import load_knowledge_catalog, text_sha256
from app.explanation.local import explain_finding
from app.explanation.privacy import redact_prompt
from app.explanation.provider import build_prompt
from app.parsers import parse_configuration


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://127.0.0.1:9000/v1/chat/completions",
        "http://localhost:9000/v1/chat/completions",
        "http://192.0.2.1:9000/v1/chat/completions",
        "http://127.0.0.2:9000/v1/chat/completions",
        "http://127.0.0.1:80/v1/chat/completions",
        "http://127.0.0.1:9000/other",
        "http://127.0.0.1:9000/v1/chat/completions?secret=query",
        "http://127.0.0.1:9000/v1/chat/completions#fragment",
        "http://user:secret@127.0.0.1:9000/v1/chat/completions",
        "http://127.0.0.1:09000/v1/chat/completions",
        "http://2130706433:9000/v1/chat/completions",
        "http://[::1]:9000/v1/chat/completions",
        "http://127.0.0.1:9000/v1/chat/completions\n",
    ],
)
def test_ambiguous_remote_or_noncanonical_targets_are_refused(endpoint):
    with pytest.raises(ValueError) as error:
        LocalModelSettings(endpoint, "test-model", allow_local_context=True)
    assert endpoint not in str(error.value)


@pytest.mark.parametrize(
    "updates",
    [
        {"allow_local_context": False},
        {"allow_local_context": 1},
        {"model": "private/path"},
        {"api_key": "secret\nheader"},
        {"timeout_seconds": 0},
        {"timeout_seconds": 21},
        {"timeout_seconds": True},
    ],
)
def test_configuration_requires_permission_and_bounded_header_safe_fields(updates):
    with pytest.raises(ValueError):
        LocalModelSettings(
            "http://127.0.0.1:9000/v1/chat/completions",
            **({"model": "test-model", "allow_local_context": True} | updates),
        )


def test_environment_is_opt_in_and_missing_fields_fail_closed(monkeypatch):
    for name in (
        "NETCONFIG_LLM_ENDPOINT",
        "NETCONFIG_LLM_MODEL",
        "NETCONFIG_LLM_API_KEY",
        "NETCONFIG_LLM_ALLOW_LOCAL_CONTEXT",
        "NETCONFIG_LLM_ALLOW_PATCH_DRAFT",
    ):
        monkeypatch.delenv(name, raising=False)
    assert LocalModelSettings.from_environment() is None
    monkeypatch.setenv("NETCONFIG_LLM_ENDPOINT", "http://127.0.0.1:9000/v1/chat/completions")
    with pytest.raises(ValueError):
        LocalModelSettings.from_environment()
    monkeypatch.setenv("NETCONFIG_LLM_MODEL", "test-model")
    with pytest.raises(ValueError):
        LocalModelSettings.from_environment()
    monkeypatch.setenv("NETCONFIG_LLM_ALLOW_LOCAL_CONTEXT", "1")
    monkeypatch.setenv("NETCONFIG_LLM_API_KEY", "private-key")
    selected = LocalModelSettings.from_environment()
    assert selected is not None
    assert "private-key" not in repr(selected) and "127.0.0.1" not in repr(selected)


def test_redaction_replaces_keys_values_messages_and_limits_without_exporting_alias_mapping():
    config = parse_configuration("hostname private-host\n", filename="private-file.cfg")
    finding = evaluate_policies(config, device_id=UUID(int=1))[0]
    explanation = explain_finding(finding, config)
    chunks = load_knowledge_catalog().retrieve(finding)
    prompt = build_prompt(
        finding,
        explanation,
        chunks,
        vendor="cisco",
        platform="ios",
        parser_confidence=1,
        warning_count=0,
        unparsed_count=0,
    )
    original = json.loads(prompt.context_json)
    original.update(
        observed={
            "private-key": ["secret-password", "192.0.2.1", 42, True, None],
            "nested": {"private-nested-key": "secret-password"},
        },
        expected={"private-key": ["secret-password", "192.0.2.2", 43, False]},
        evidence=[{"message": "private-evidence", "kind": "private-kind", "source_location": None}],
        limitations=["private-limitation"],
    )
    modified = replace(prompt, context_json=json.dumps(original))
    redacted = redact_prompt(modified)
    for private in (
        "private-key",
        "private-nested-key",
        "secret-password",
        "192.0.2",
        "private-evidence",
        "private-kind",
        "private-limitation",
    ):
        assert private not in redacted.context_json
    result = json.loads(redacted.context_json)
    assert result["documents"] == original["documents"]
    assert result["evidence"] == [{"source_location": None}]
    shared = next(iter(result["expected"]))
    assert result["expected"][shared][0] == result["observed"][shared][0]
    assert result["observed"][shared][2:] == [42, True, None]
    assert redacted.context_sha256 == text_sha256(redacted.context_json)
    assert "alias_mapping" not in result


@pytest.mark.parametrize("value", [None, 0, 1, "true"])
def test_patch_mode_requires_exact_operator_boolean(value):
    with pytest.raises(ValueError):
        LocalModelSettings(
            "http://127.0.0.1:9000/v1/chat/completions",
            "test",
            allow_local_context=True,
            allow_patch_draft=value,
        )


@pytest.mark.parametrize("permission", ["", "0", "1", "true", "2"])
def test_patch_environment_requires_existing_context_permission(monkeypatch, permission):
    monkeypatch.setenv("NETCONFIG_LLM_ENDPOINT", "http://127.0.0.1:9000/v1/chat/completions")
    monkeypatch.setenv("NETCONFIG_LLM_MODEL", "test")
    monkeypatch.setenv("NETCONFIG_LLM_ALLOW_LOCAL_CONTEXT", "1")
    monkeypatch.setenv("NETCONFIG_LLM_ALLOW_PATCH_DRAFT", permission)
    if permission in {"true", "2"}:
        with pytest.raises(ValueError):
            LocalModelSettings.from_environment()
    else:
        selected = LocalModelSettings.from_environment()
        assert selected is not None and selected.allow_patch_draft is (permission == "1")
