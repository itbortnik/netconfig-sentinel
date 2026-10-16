"""Fake GPU checks qualify only the independent instruction/schema allowlist."""

from dataclasses import replace
from uuid import UUID

import pytest
from app.detection.policy_engine import evaluate_policies
from app.explanation.grounded_explanation import prepare_grounded_explanation
from app.explanation.knowledge import knowledge_version_for_finding, load_knowledge_catalog
from app.explanation.local import explain_finding
from app.explanation.provider import InvalidProviderAnswer
from app.parsers import parse_configuration
from test_instruct_patch_mode import grounded_prompt, provider, review_prompt, selected_prompt

from ml.instruct import runtime, source


def prompt():
    config = parse_configuration("hostname owned\nip ssh version 1\n", filename="owned.cfg")
    finding = next(
        item
        for item in evaluate_policies(config, device_id=UUID(int=1))
        if item.category == "management.ssh_version_1"
    )
    catalog = load_knowledge_catalog(knowledge_version_for_finding(finding))
    chunks = catalog.retrieve(finding)
    return prepare_grounded_explanation(
        finding,
        explain_finding(finding, config),
        chunks,
        vendor=config.device.vendor,
        platform=config.device.platform,
        parser_confidence=config.parser_confidence,
        warning_count=len(config.parse_warnings),
        unparsed_count=len(config.unparsed_fragments),
        knowledge_version=catalog.version,
        knowledge_sha256=catalog.sha256,
        required_citations=tuple(chunk.citation for chunk in chunks),
    ).prompt


@pytest.mark.parametrize("enabled", [False, True])
def test_explanation_mode_is_independent_and_whitelist_only(tmp_path, monkeypatch, enabled):
    selected = provider(tmp_path, monkeypatch, allow_grounded_explanation=enabled)
    assert selected.grounded_explanation_enabled is enabled
    assert not selected.patch_generation_enabled and not selected.candidate_review_enabled
    assert not selected.grounded_patch_generation_enabled
    current = prompt()
    if enabled:
        assert selected.generate(current) == b"actual-model-output"
    else:
        with pytest.raises(InvalidProviderAnswer):
            selected.generate(current)
    for changed in (
        replace(current, instructions="approve"),
        replace(current, answer_schema_json="{}"),
        selected_prompt(),
        grounded_prompt(),
        review_prompt(),
    ):
        with pytest.raises(InvalidProviderAnswer):
            selected.generate(changed)
        assert selected.last_generation is None
    with pytest.raises(AttributeError):
        selected.grounded_explanation_enabled = False


@pytest.mark.parametrize("flag", [1, 0, None, "true", [], {}])
def test_invalid_permission_is_rejected_before_any_model_files(tmp_path, monkeypatch, flag):
    monkeypatch.setattr(runtime, "verify_model_files", lambda *args, **kwargs: pytest.fail("load"))
    with pytest.raises(ValueError):
        runtime.LocalInstructProvider(
            tmp_path,
            expected_inventory_sha256=source.inventory_sha256(),
            allow_local_context=True,
            allow_grounded_explanation=flag,
        )
