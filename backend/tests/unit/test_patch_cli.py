"""Draft CLI preserves inputs and artifacts, including all rejection paths."""

import json
from pathlib import Path

import pytest
from app.domain import Vendor
from app.patching.cli import main

from ml.datasets.laboratory import laboratory_records
from ml.mutation import MutationType, mutate_configuration

DEVICE = "7f64381c-fda8-48f9-8e8a-fb772b2f64dc"


@pytest.mark.parametrize("vendor", [Vendor.CISCO, Vendor.JUNIPER])
def test_cli_create_check_and_stale_guard(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], vendor: Vendor
) -> None:
    record = next(item for item in laboratory_records() if item.vendor_hint is vendor)
    sample = mutate_configuration(record, (MutationType.AAA_DISABLED,), seed=17)
    before, after, output = (
        tmp_path / "before.cfg",
        tmp_path / "after.conf",
        tmp_path / "draft.json",
    )
    before.write_text(record.sanitized_text, encoding="utf-8")
    after.write_text(sample.mutated_text, encoding="utf-8")
    original_bytes = before.read_bytes(), after.read_bytes()
    common = ["--before", str(before), "--after", str(after), "--device-id", DEVICE]
    create = ["create", *common, "--reference-id", "local-v1", "--output", str(output)]
    check = ["check", *common, "--artifact", str(output)]
    assert main(create) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["applied"] is False
    assert result["formal_verification"] == "not_run"
    assert "formal_verification_not_run" in result["validation_blockers"]
    saved = output.read_bytes()
    assert main(check) == 0
    assert json.loads(capsys.readouterr().out)["proposal_id"] == result["proposal_id"]
    assert (before.read_bytes(), after.read_bytes()) == original_bytes
    assert main(create) == 2
    assert not capsys.readouterr().out
    assert output.read_bytes() == saved
    after.write_text(sample.mutated_text + "\n", encoding="utf-8")
    assert main(check) == 2
    assert not capsys.readouterr().out
    assert output.read_bytes() == saved


def test_cli_invalid_input_and_output_never_leak_secrets(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    before, after, output = tmp_path / "before.cfg", tmp_path / "after.cfg", tmp_path / "draft.json"
    before.write_text("hostname edge\n", encoding="utf-8")
    after.write_text("private-secret", encoding="utf-8")
    args = [
        "create",
        "--before",
        str(before),
        "--after",
        str(after),
        "--device-id",
        DEVICE,
        "--reference-id",
        "v1",
        "--output",
        str(output),
    ]
    assert main(args) == 2
    captured = capsys.readouterr()
    assert not captured.out
    assert "private-secret" not in captured.err
    assert str(after) not in captured.err
    assert not output.exists()


def test_cli_has_no_approval_or_application_command() -> None:
    for command in ("apply", "approve", "validate"):
        with pytest.raises(SystemExit) as error:
            main([command])
        assert error.value.code == 2
