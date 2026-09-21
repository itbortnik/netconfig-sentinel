"""Review exit codes distinguish findings, errors and partial checks."""

import json
from pathlib import Path

import pytest
from app.verification.preflight_cli import main

CLEAN = (
    "hostname edge\naaa new-model\nip ssh version 2\nsnmp-server group NMS v3 priv\n"
    "ntp server 192.0.2.1\nlogging host 192.0.2.2\n"
    "line vty 0 4\n transport input ssh\n"
)


@pytest.mark.parametrize(
    "case", ["clean", "persistent", "introduced", "resolved", "partial", "error"]
)
def test_preflight_exit_codes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], case: str
) -> None:
    before, after = tmp_path / "before.cfg", tmp_path / "after.cfg"
    violating = CLEAN.replace("transport input ssh", "transport input telnet")
    before.write_text(violating if case in {"persistent", "resolved"} else CLEAN, encoding="utf-8")
    if case != "error":
        text = violating if case in {"persistent", "introduced"} else CLEAN
        if case == "partial":
            text += "unsupported-command secret-value\n"
        after.write_text(text, encoding="utf-8")
    result = main(
        [
            "--before",
            str(before),
            "--after",
            str(after),
            "--device-id",
            "7f64381c-fda8-48f9-8e8a-fb772b2f64dc",
            "--reference-id",
            "test",
        ]
    )
    expected = {
        "clean": 0,
        "persistent": 1,
        "introduced": 1,
        "resolved": 1,
        "partial": 3,
        "error": 2,
    }
    assert result == expected[case]
    output = capsys.readouterr()
    assert "secret-value" not in output.out + output.err
    if case == "error":
        assert not output.out
        assert output.err
    else:
        assert not output.err
        report = json.loads(output.out)
        assert report["formal_verification"] == "not_run"
        assert report["requires_human_review"] is True
