"""CLI explanations retain the existing preflight exit-code contract."""

import json
from pathlib import Path
from uuid import UUID

import pytest
from app.verification.preflight_cli import main


def test_explain_cli_partial_result(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    before, after = tmp_path / "before.cfg", tmp_path / "after.cfg"
    before.write_text("hostname edge\naaa new-model\n", encoding="utf-8")
    after.write_text("hostname edge\nno aaa new-model\nunknown private-secret\n", encoding="utf-8")
    assert (
        main(
            [
                "--before",
                str(before),
                "--after",
                str(after),
                "--device-id",
                str(UUID(int=1)),
                "--reference-id",
                "previous",
                "--explain",
            ]
        )
        == 3
    )
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert result["report"]["policy_changes"] is None
    assert result["after_policy_explanations"]
    assert not result["reference_explanations"]
    assert "private-secret" not in captured.out + captured.err
