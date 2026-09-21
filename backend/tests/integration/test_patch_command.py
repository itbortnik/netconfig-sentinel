"""Real process lifecycle of a private draft artifact."""

import json
import subprocess
import sys
from pathlib import Path


def test_draft_command_roundtrip(tmp_path: Path) -> None:
    before, after, output = tmp_path / "old.cfg", tmp_path / "new.cfg", tmp_path / "review.json"
    before.write_text("hostname edge\naaa new-model\n", encoding="utf-8")
    after.write_text("hostname edge\nno aaa new-model\n", encoding="utf-8")
    common = [
        "--before",
        str(before),
        "--after",
        str(after),
        "--device-id",
        "7f64381c-fda8-48f9-8e8a-fb772b2f64dc",
    ]
    root = Path(__file__).resolve().parents[3]
    for action, flags in [
        ("create", ["--output", str(output), "--reference-id", "local"]),
        ("check", ["--artifact", str(output)]),
    ]:
        result = subprocess.run(
            [sys.executable, "-m", "app.patching.cli", action, *common, *flags],
            cwd=root,
            capture_output=True,
            encoding="utf-8",
            timeout=30,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert not result.stderr
        summary = json.loads(result.stdout)
        assert summary["proposal_status"] == "draft"
        assert summary["review_status"] == "needs_review"
        assert summary["formal_verification"] == "not_run"
        assert "aaa new-model" not in result.stdout
