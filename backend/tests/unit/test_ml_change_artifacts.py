"""Private artifact integrity and isolated CLI with an actual authored model."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from app.patching.artifacts import save_patch_review
from test_ml_change_review import AFTER, BEFORE, KEY, local, run
from test_ml_change_review import model as model

from ml.evaluation.metrics import canonical_hash
from ml.inference.change_artifacts import load_ml_change_review, save_ml_change_review
from ml.inference.change_cli import KEY_ENV, main
from ml.inference.change_review import review_patch_ml
from ml.training.multitask_training import multitask_identity, save_multitask


def test_private_roundtrip_no_overwrite_and_no_automatic_current_recheck(model, tmp_path):
    result = run(model)
    target = tmp_path / "private.json"
    save_ml_change_review(result, target)
    assert load_ml_change_review(target) == result
    assert "private-customer-host" not in target.read_text(encoding="utf-8")
    assert KEY.decode() not in target.read_text(encoding="utf-8")
    with pytest.raises(FileExistsError):
        save_ml_change_review(result, target)
    # A checksum is integrity only: current exact input/model rerun is still required.
    data = json.loads(target.read_text(encoding="utf-8"))
    data["payload"]["transformer"]["after"]["anomaly_score"] = 0.123
    data["sha256"] = canonical_hash(data["payload"])
    target.write_text(json.dumps(data), encoding="utf-8")
    changed = load_ml_change_review(target)
    assert changed != run(model)


@pytest.mark.parametrize("damage", ["checksum", "duplicates", "truncated", "nan", "extra"])
def test_damaged_private_artifact_refused(damage, tmp_path):
    result = review_patch_ml(local(), BEFORE, AFTER)
    target = tmp_path / "private.json"
    save_ml_change_review(result, target)
    data = json.loads(target.read_text(encoding="utf-8"))
    if damage == "checksum":
        data["sha256"] = "0" * 64
    elif damage == "extra":
        data["unexpected"] = "untrusted"
    elif damage == "nan":
        data["payload"]["transformer"]["before"] = {"anomaly_score": float("nan")}
    if damage == "duplicates":
        text = '{"version":"ml-change-artifact-0.1.0","version":"duplicate"}'
    elif damage == "truncated":
        text = "{"
    else:
        text = json.dumps(data)
    target.write_text(text, encoding="utf-8")
    with pytest.raises(ValueError):
        load_ml_change_review(target)


@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_cli_actual_pinned_model_recheck_and_generic_refusal(
    model, tmp_path, monkeypatch, capsys, newline
):
    before, after = tmp_path / "private-customer-old.cfg", tmp_path / "private-customer-new.cfg"
    old, new = BEFORE.replace("\n", newline), AFTER.replace("\n", newline)
    before.write_bytes(old.encode("utf-8"))
    after.write_bytes(new.encode("utf-8"))
    review, output, bundle = tmp_path / "local.json", tmp_path / "ml.json", tmp_path / "model"
    save_patch_review(local(old, new), review)
    save_multitask(model, bundle)
    monkeypatch.setenv(KEY_ENV, "91" * 32)
    shared = [
        "--before",
        str(before),
        "--after",
        str(after),
        "--model",
        str(bundle),
        "--model-sha256",
        multitask_identity(model),
    ]
    assert main(["review", *shared, "--patch-review", str(review), "--output", str(output)]) == 0
    assert main(["check", *shared, "--artifact", str(output)]) == 0
    stdout, stderr = capsys.readouterr()
    assert not stderr and "completed" in stdout
    assert "private-customer" not in stdout and "line_scores" not in stdout
    assert "91" * 32 not in stdout
    after.write_bytes((new + "ntp server 192.0.2.1" + newline).encode("utf-8"))
    assert main(["check", *shared, "--artifact", str(output)]) == 2
    stdout, stderr = capsys.readouterr()
    assert not stdout and "private-customer" not in stderr and "192.0.2.1" not in stderr
    assert before.read_text(encoding="utf-8") == BEFORE


def test_missing_key_bad_pin_bad_inventory_and_failed_load_do_not_write(
    model, tmp_path, monkeypatch
):
    before, after, review = tmp_path / "old.cfg", tmp_path / "new.cfg", tmp_path / "local.json"
    before.write_bytes(BEFORE.encode("utf-8"))
    after.write_bytes(AFTER.encode("utf-8"))
    save_patch_review(local(), review)
    bundle = tmp_path / "model"
    save_multitask(model, bundle)
    output = tmp_path / "ml.json"
    common = [
        "review",
        "--before",
        str(before),
        "--after",
        str(after),
        "--patch-review",
        str(review),
        "--output",
        str(output),
    ]
    selected = ["--model", str(bundle), "--model-sha256", multitask_identity(model)]
    monkeypatch.delenv(KEY_ENV, raising=False)
    assert main([*common, *selected]) == 2
    monkeypatch.setenv(KEY_ENV, "91" * 32)
    assert main([*common, "--model", str(bundle)]) == 2
    assert main([*common, "--model-sha256", "0" * 64]) == 2
    assert main([*common, "--model", str(bundle), "--model-sha256", "0" * 64]) == 2
    (bundle / "unexpected.txt").write_text("untrusted", encoding="utf-8")
    assert main([*common, *selected]) == 2
    assert not output.exists()


def test_isolated_base_path_has_no_torch_and_cli_actual_process(model, tmp_path):
    root = Path(__file__).resolve().parents[3]
    base = subprocess.run(
        [
            sys.executable,
            "-c",
            "import ml.inference.change_cli, sys; "
            "assert 'torch' not in sys.modules and 'transformers' not in sys.modules",
        ],
        cwd=root,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert base.returncode == 0, base.stderr
    before, after, review = tmp_path / "old.cfg", tmp_path / "new.cfg", tmp_path / "local.json"
    before.write_bytes(BEFORE.encode("utf-8"))
    after.write_bytes(AFTER.encode("utf-8"))
    save_patch_review(local(), review)
    bundle, output = tmp_path / "model", tmp_path / "ml.json"
    save_multitask(model, bundle)
    flags = [
        "--before",
        str(before),
        "--after",
        str(after),
        "--model",
        str(bundle),
        "--model-sha256",
        multitask_identity(model),
    ]
    environment = {**os.environ, KEY_ENV: "71" * 32}
    for action, extras in (
        ("review", ["--patch-review", str(review), "--output", str(output)]),
        ("check", ["--artifact", str(output)]),
    ):
        result = subprocess.run(
            [sys.executable, "-m", "ml.inference.change_cli", action, *flags, *extras],
            cwd=root,
            env=environment,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        summary = json.loads(result.stdout)
        assert summary["transformer_status"] == "completed"
        assert summary["formal_verification"] == "not_run" and not summary["applied"]
        assert "private-customer" not in result.stdout and not result.stderr


def test_linked_artifact_parent_refused_on_actual_filesystem(tmp_path):
    private = tmp_path / "private"
    private.mkdir()
    artifact = private / "review.json"
    result = review_patch_ml(local(), BEFORE, AFTER)
    save_ml_change_review(result, artifact)
    link = tmp_path / "linked"
    try:
        link.symlink_to(private, target_is_directory=True)
    except OSError:
        if os.name != "nt":
            pytest.skip("symbolic links are unavailable on this platform")
        subprocess.run(
            ["cmd.exe", "/d", "/c", "mklink", "/J", str(link), str(private)],
            cwd=tmp_path,
            capture_output=True,
            check=True,
            timeout=30,
        )
        assert link.is_junction()
    with pytest.raises(ValueError, match="linked"):
        load_ml_change_review(link / "review.json")
    with pytest.raises(ValueError, match="linked"):
        save_ml_change_review(result, link / "another.json")
