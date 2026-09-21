"""Exercise the real local command process for both supported vendors."""

import json
import subprocess
import sys
from pathlib import Path

import pytest
from app.domain import Vendor

from ml.datasets.laboratory import laboratory_records
from ml.mutation import MutationType, mutate_configuration

ROOT = Path(__file__).resolve().parents[3]


def _run(before: Path, after: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "app.verification.preflight_cli",
            "--before",
            str(before),
            "--after",
            str(after),
            "--device-id",
            "7f64381c-fda8-48f9-8e8a-fb772b2f64dc",
            "--reference-id",
            "local-review",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=30,
        check=False,
    )


@pytest.mark.parametrize("vendor", [Vendor.CISCO, Vendor.JUNIPER])
def test_command_mutation_and_partial_result(tmp_path: Path, vendor: Vendor) -> None:
    record = next(item for item in laboratory_records() if item.vendor_hint is vendor)
    before, after = tmp_path / "before.cfg", tmp_path / "after.conf"
    before.write_text(record.sanitized_text, encoding="utf-8")
    sample = mutate_configuration(record, (MutationType.TELNET_ENABLED,), seed=17)
    after.write_text(sample.mutated_text, encoding="utf-8")
    result = _run(before, after)
    assert result.returncode == 1
    assert not result.stderr
    report = json.loads(result.stdout)
    assert report["policy_changes"]["introduced"]
    assert report["formal_verification"] == "not_run"
    assert report["review_status"] == "needs_review"
    assert str(tmp_path) not in result.stdout
    assert before.read_text(encoding="utf-8") == record.sanitized_text
    assert after.read_text(encoding="utf-8") == sample.mutated_text
    after.write_text(sample.mutated_text + "unsupported-command secret-value\n", encoding="utf-8")
    result = _run(before, after)
    assert result.returncode == 3
    report = json.loads(result.stdout)
    assert report["policy_changes"] is None
    assert report["reference_status"] == "unavailable"
    assert report["after_policy_findings"]
    assert "secret-value" not in result.stdout + result.stderr


@pytest.mark.parametrize("invalid", [b"\xff", b"\0", b"secret-value"])
def test_command_invalid_input_is_private(tmp_path: Path, invalid: bytes) -> None:
    source = tmp_path / "private.cfg"
    source.write_bytes(invalid)
    result = _run(source, source)
    assert result.returncode == 2
    assert not result.stdout
    assert "Traceback" not in result.stderr
    assert "secret-value" not in result.stderr
    assert str(source) not in result.stderr


def test_command_clean_supported_snapshot_is_not_approved(tmp_path: Path) -> None:
    source = tmp_path / "clean.cfg"
    source.write_text(
        "hostname edge\naaa new-model\nip ssh version 2\n"
        "line vty 0 4\n transport input ssh\n!\n"
        "ntp server 192.0.2.1\nlogging host 192.0.2.2\nsnmp-server group NMS v3 priv\n",
        encoding="utf-8",
    )
    result = _run(source, source)
    assert result.returncode == 0, result.stderr + result.stdout
    report = json.loads(result.stdout)
    assert not report["after_policy_findings"]
    assert not report["reference_findings"]
    assert report["requires_human_review"] is True
    assert report["formal_verification"] == "not_run"
