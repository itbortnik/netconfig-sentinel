"""Owned patch diagnostics preserve refusals; fake outputs are not model evidence."""

import json

from app.explanation.provider import InvalidProviderAnswer

from ml.instruct import patch_smoke


def test_owned_cases_have_current_findings_minimal_sources_and_baseline_bindings():
    cases = patch_smoke.authored_patch_cases()
    assert len(cases) == 4
    assert {case.vendor for case in cases} == {"cisco", "juniper"}
    assert {case.prepared.finding.category for case in cases} == {
        "management.telnet_enabled",
        "management.ssh_version_1",
    }
    for case in cases:
        context = json.loads(case.prepared.prompt.context_json)
        assert context["baseline"]["status"] == "available"
        assert context["formal_verification"]["status"] == "not_run"
        assert "owned-host" not in case.prepared.prompt.context_json


def test_no_candidate_and_rejected_cases_remain_in_denominator_without_fake_observations():
    class Failed:
        last_generation = None

        def generate(self, prompt):
            raise InvalidProviderAnswer("unavailable")

    results = patch_smoke.run_patch_cases(Failed(), patch_smoke.authored_patch_cases())
    assert len(results) == 4
    assert all(item["status"] == "rejected" for item in results)
    assert all(item["answer"] is None and item["generation"] is None for item in results)
    assert all(item["formal_verification"] == "not_run" for item in results)
    assert all(item["production_quality_proven"] is False for item in results)


def test_cli_invalid_selection_has_generic_failure_and_no_report(tmp_path, capsys):
    target = tmp_path / "report.json"
    assert (
        patch_smoke.main(
            [
                "--source",
                str(tmp_path / "absent"),
                "--expected-source-sha256",
                "f" * 64,
                "--allow-owned-context",
                "--output",
                str(target),
            ]
        )
        == 1
    )
    assert not target.exists()
    assert "absent" not in capsys.readouterr().err
