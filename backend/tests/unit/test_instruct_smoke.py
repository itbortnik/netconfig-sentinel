"""Owned diagnostics use actual detectors/redaction; no fabricated language model answer."""

import json

import pytest
from app.explanation.privacy import PRIVACY_VERSION
from app.explanation.provider import DraftAnswer

from ml.instruct import smoke
from ml.instruct.runtime import GenerationObservation
from ml.instruct.smoke import authored_cases, run_cases


def test_four_authored_cases_bind_both_vendors_and_actual_detector_facts():
    cases = authored_cases()
    assert [(item.vendor, item.category) for item in cases] == [
        ("cisco", "management.telnet_enabled"),
        ("cisco", "management.ssh_version_1"),
        ("juniper", "management.telnet_enabled"),
        ("juniper", "management.ssh_version_1"),
    ]
    for case in cases:
        context = json.loads(case.prompt.context_json)
        assert context["category"] == case.category
        assert context["formal_verification"] == "not_run"
        assert context["privacy"]["version"] == PRIVACY_VERSION
        assert context["documents"] == [chunk.model_dump(mode="json") for chunk in case.chunks]
        assert case.finding_sha256 == context["finding_sha256"]
        assert case.source_sha256 == context["source_sha256"]
        assert "owned-host" not in case.prompt.context_json


def test_invalid_model_answers_are_measured_as_rejected_not_replaced():
    class Invalid:
        last_generation = None

        def generate(self, prompt):
            return b'{"invented":"private raw output is not a fallback"}'

    results = run_cases(Invalid(), authored_cases())
    assert len(results) == 4
    assert all(item["status"] == "rejected" and item["answer"] is None for item in results)
    assert "private raw output" not in json.dumps(results)


def test_schema_valid_mock_is_only_validator_test_not_inference_evidence():
    class Valid:
        last_generation = None

        def generate(self, prompt):
            context = json.loads(prompt.context_json)
            return (
                DraftAnswer(
                    summary="Owned fixture",
                    technical_explanation="Fixture text",
                    possible_impact=[],
                    recommendation="Human review",
                    patch_draft=None,
                    assumptions=[],
                    missing_information=["Formal check not run"],
                    citations=[context["documents"][0]["citation"]],
                    requires_human_review=True,
                )
                .model_dump_json()
                .encode()
            )

    results = run_cases(Valid(), authored_cases())
    assert all(item["status"] == "schema_valid_draft" for item in results)
    assert all(item["generation"] is None for item in results)
    assert all(not item["semantic_truth_proven"] for item in results)


def test_prior_generation_observation_cannot_be_reused_for_another_context():
    class Busy:
        last_generation = GenerationObservation(10, 20, 0.5, context_sha256="0" * 64)

        def generate(self, prompt):
            raise RuntimeError("private busy state")

    results = run_cases(Busy(), authored_cases())
    assert all(item["status"] == "rejected" and item["generation"] is None for item in results)


@pytest.mark.parametrize("target", ["existing", "suffix", "missing_parent", "token_limit"])
def test_cli_refuses_unsafe_output_and_limit_before_allocating_model(
    tmp_path, monkeypatch, capsys, target
):
    calls = []

    def must_not_load(*args, **kwargs):
        calls.append(True)
        raise AssertionError("model allocation must not run")

    monkeypatch.setattr(smoke, "LocalInstructProvider", must_not_load)
    output = tmp_path / "result.json"
    extra = []
    if target == "existing":
        output.write_text("original output")
    elif target == "suffix":
        output = tmp_path / "result.bin"
    elif target == "missing_parent":
        output = tmp_path / "missing" / "result.json"
    else:
        extra = ["--max-new-tokens", "2049"]
    assert (
        smoke.main(
            [
                "--source",
                str(tmp_path / "private-model-path"),
                "--expected-source-sha256",
                "0" * 64,
                "--allow-owned-context",
                "--output",
                str(output),
                *extra,
            ]
        )
        == 1
    )
    assert calls == []
    printed = capsys.readouterr()
    assert printed.out == "" and printed.err == "Owned instruct diagnostic is unavailable.\n"
    assert str(tmp_path) not in printed.err
    if target == "existing":
        assert output.read_text() == "original output"
