"""Both vendors through real ASGI endpoints, isolated SQLite, native drafts and restart reads."""

import json
import subprocess
import sys
from pathlib import Path

import pytest
from app.demo.workflow import DemoReport, run_demonstration


def test_owned_demo_exercises_both_vendors_and_never_claims_mvp_acceptance(tmp_path):
    output = tmp_path / "demo"
    report = run_demonstration(output)
    assert {row.vendor for row in report.devices} == {"cisco", "juniper"}
    assert report.transport == "in_process_asgi"
    assert report.database == "isolated_sqlite"
    assert not report.customer_data_used and not report.production_qualified
    assert not report.actual_instruct_model and not report.live_batfish
    assert not report.transformer_run and not report.device_commands_executed
    assert report.operation_records_checked >= 40
    assert report.encrypted_payloads_checked >= 25
    for row in report.devices:
        assert row.training_snapshots == 8 and row.peer_snapshots == 3
        assert row.policy_telnet_found and row.peer_telnet_found
        assert row.reference_difference_found and row.statistical_status == "completed"
        assert row.source_citations_checked >= 1 and row.finding_anchors_checked
        assert row.reader_write_status == 403 and row.unavailable_llm_status == 503
        assert row.unavailable_formal_status == 503
        assert row.partial_analysis_status == "partial" and not row.partial_risk_present
        assert row.native_candidate_rechecked and row.engineer_feedback_replayed
        assert row.patch_status == "draft" and row.review_status == "needs_review"
        assert row.formal_verification == "not_run"
        assert row.fresh_application_readback_checked and row.saved_analysis_unchanged
    saved = DemoReport.model_validate_json((output / "report.json").read_bytes())
    assert saved == report and not (output / ".incomplete").exists()
    assert (
        "api_token" not in report.model_dump_json()
        and "encryption_key" not in report.model_dump_json()
    )
    assert "content" not in report.model_dump_json() and "comment" not in report.model_dump_json()
    with pytest.raises(FileExistsError):
        run_demonstration(output)


def test_separate_demo_cli_process_new_only_and_safe_summary(tmp_path, monkeypatch):
    # The CLI worker must not inherit operator storage/providers or external context consent.
    monkeypatch.setenv("NETCONFIG_DATABASE_URL", "invalid-private-deployment-value")
    monkeypatch.setenv("NETCONFIG_API_TOKEN", "private-deployment-token")
    output = tmp_path / "demo"
    root = Path(__file__).resolve().parents[3]
    command = [sys.executable, "-m", "app.demo.cli", "--output", str(output)]
    first = subprocess.run(
        command, cwd=root, capture_output=True, text=True, timeout=60, check=False
    )
    assert first.returncode == 0, first.stderr
    summary = json.loads(first.stdout)
    assert summary["devices"] == 2 and summary["customer_data_used"] is False
    assert summary["formal_verification"] == "not_run" and not summary["mvp_accepted"]
    original = (output / "report.json").read_bytes()
    second = subprocess.run(
        command, cwd=root, capture_output=True, text=True, timeout=60, check=False
    )
    assert second.returncode == 2
    assert not second.stdout and str(output) not in second.stderr
    assert (output / "report.json").read_bytes() == original


def test_failed_demo_leaves_incomplete_owned_directory_without_success_report(
    tmp_path, monkeypatch
):
    def failed(*args, **kwargs):
        raise ValueError("owned injected observation failure")

    monkeypatch.setattr("app.demo.workflow.create_vendor_draft", failed)
    output = tmp_path / "failed"
    with pytest.raises(ValueError, match="injected"):
        run_demonstration(output)
    assert (output / ".incomplete").is_file() and not (output / "report.json").exists()
    with pytest.raises(FileExistsError):
        run_demonstration(output)
