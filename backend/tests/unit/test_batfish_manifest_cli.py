"""Offline CLI checks never authorize engine uploads implicitly."""

import json
from pathlib import Path

import pytest
from app.verification.batfish_cli import main


@pytest.mark.parametrize("case", ["offline", "escape", "duplicate", "missing_node"])
def test_manifest_cli(tmp_path: Path, capsys: pytest.CaptureFixture[str], case: str) -> None:
    (tmp_path / "before.cfg").write_text("hostname edge\n", encoding="utf-8")
    (tmp_path / "after.cfg").write_text("hostname edge\n! after\n", encoding="utf-8")
    device = {
        "device_id": "7f64381c-fda8-48f9-8e8a-fb772b2f64dc",
        "before": "../secret.cfg" if case == "escape" else "before.cfg",
        "after": "after.cfg",
    }
    data = {
        "version": "network-check-0.1.0",
        "devices": [device],
        "scope": {
            "start_node": "other" if case == "missing_node" else "edge",
            "destination": "192.0.2.0/24",
        },
    }
    if case == "duplicate":
        data["devices"] = [device, device]
    manifest = tmp_path / "network.json"
    manifest.write_text(json.dumps(data), encoding="utf-8")
    code = main(["--manifest", str(manifest)])
    captured = capsys.readouterr()
    if case == "offline":
        assert code == 3
        assert json.loads(captured.out)["reason"] == "upload_not_authorized"
    else:
        assert code == 2 and not captured.out
        assert "secret.cfg" not in captured.err


def test_manifest_cli_links_saved_draft(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from uuid import UUID

    from app.patching.artifacts import save_patch_review
    from app.patching.proposal import create_patch_proposal
    from app.patching.review import review_patch_proposal

    device = UUID(int=1)
    before, after = "hostname edge\naaa new-model\n", "hostname edge\nno aaa new-model\n"
    (tmp_path / "before.cfg").write_text(before, encoding="utf-8", newline="")
    (tmp_path / "after.cfg").write_text(after, encoding="utf-8", newline="")
    draft = create_patch_proposal(before, after, device_id=device, reference_id="v1")
    artifact = tmp_path / "review.json"
    save_patch_review(review_patch_proposal(draft, before, after, device_id=device), artifact)
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "version": "network-check-0.1.0",
                "devices": [
                    {
                        "device_id": str(device),
                        "before": "before.cfg",
                        "after": "after.cfg",
                    }
                ],
                "scope": {"start_node": "edge", "destination": "192.0.2.0/24"},
            }
        ),
        encoding="utf-8",
    )
    saved = artifact.read_bytes()
    assert main(["--manifest", str(manifest), "--patch-review", str(artifact)]) == 3
    report = json.loads(capsys.readouterr().out)
    assert report["local_review"]["proposal"]["proposal_id"] == str(draft.proposal_id)
    assert report["network_result"]["reason"] == "upload_not_authorized"
    assert artifact.read_bytes() == saved
