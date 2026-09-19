"""Local comparison entry point and fail-closed input boundaries."""

import json
from pathlib import Path

import pytest
from app.detection.baseline import compare_cli
from app.domain import Vendor

from ml.datasets.laboratory import laboratory_records
from ml.mutation import MutationType, mutate_configuration


def _args(reference: Path, current: Path) -> list[str]:
    return [
        "--reference",
        str(reference),
        "--current",
        str(current),
        "--device-id",
        "f6156954-3f3b-4aa2-b693-5a710fe35d44",
        "--reference-id",
        "selected-v1",
    ]


@pytest.mark.parametrize("vendor", [Vendor.CISCO, Vendor.JUNIPER])
def test_cli_comparison(tmp_path: Path, capsys: pytest.CaptureFixture[str], vendor: Vendor) -> None:
    record = next(
        item
        for item in laboratory_records()
        if item.vendor_hint is vendor and item.device_role == "bgp-edge"
    )
    reference, current = tmp_path / "reference.cfg", tmp_path / "current.conf"
    reference.write_text(record.sanitized_text, encoding="utf-8")
    current.write_text(record.sanitized_text, encoding="utf-8-sig")
    args = _args(reference, current)
    assert compare_cli.main(args) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "no_supported_differences"
    assert report["finding_count"] == 0
    sample = mutate_configuration(record, (MutationType.MISSING_BGP_NEIGHBOR,), seed=17)
    current.write_text(sample.mutated_text, encoding="utf-8")
    assert compare_cli.main(args) == 1
    result = capsys.readouterr()
    assert not result.err
    report = json.loads(result.out)
    assert report["finding_count"] == 1
    assert report["findings"][0]["affected_lines"] == []
    assert report["findings"][0]["expected"]["reference_lines"]
    assert compare_cli.main(args) == 1
    assert capsys.readouterr().out == result.out
    assert reference.read_text(encoding="utf-8") == record.sanitized_text


@pytest.mark.parametrize("invalid", [b"", b"\xff", b"\x00", b"secret-value"])
def test_cli_rejects_invalid_without_echo(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], invalid: bytes
) -> None:
    source = tmp_path / "private.cfg"
    source.write_bytes(invalid)
    assert compare_cli.main(_args(source, source)) == 2
    result = capsys.readouterr()
    assert not result.out
    assert "secret-value" not in result.err
    assert str(source) not in result.err


def test_cli_limits_and_missing_files(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "input.cfg"
    assert compare_cli.main(_args(source, source)) == 2
    source.write_text("hostname router\n", encoding="utf-8")
    monkeypatch.setattr(compare_cli, "MAX_INPUT_BYTES", 5)
    assert compare_cli.main(_args(source, source)) == 2
    monkeypatch.setattr(compare_cli, "MAX_INPUT_BYTES", 1000)
    monkeypatch.setattr(compare_cli, "MAX_INPUT_LINES", 1)
    source.write_text("hostname router\n! comment\n", encoding="utf-8")
    assert compare_cli.main(_args(source, source)) == 2
    other = tmp_path / "input.bin"
    other.write_text("hostname router\n", encoding="utf-8")
    assert compare_cli.main(_args(other, other)) == 2
    assert not capsys.readouterr().out


@pytest.mark.parametrize("change", ["unknown", "hostname"])
def test_cli_rejects_unsupported_or_wrong_identity(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], change: str
) -> None:
    record = laboratory_records()[0]
    reference, current = tmp_path / "reference.cfg", tmp_path / "current.cfg"
    reference.write_text(record.sanitized_text, encoding="utf-8")
    if change == "unknown":
        changed = record.sanitized_text + "unsupported-command secret-value\n"
    else:
        changed = "\n".join(
            "hostname secret-value" if line.startswith("hostname ") else line
            for line in record.sanitized_text.splitlines()
        )
    current.write_text(changed, encoding="utf-8")
    assert compare_cli.main(_args(reference, current)) == 2
    result = capsys.readouterr()
    assert not result.out
    assert "secret-value" not in result.err
