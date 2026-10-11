"""Actual shared-case fixture comparison, with retained source and unchanged checkpoints."""

import json
import subprocess
import sys
from pathlib import Path

import pytest
import torch
from test_fixture_registry import input_payload
from test_fixture_transfer import fitted as fitted
from test_fixture_transfer import inputs as inputs

from ml.evaluation.comparison import ComparisonInput, DetectionComparisonReport, compare_detectors
from ml.evaluation.comparison_smoke import main
from ml.evaluation.multitask_validation import build_multitask_validation
from ml.training.multitask_training import multitask_identity, save_multitask


def arguments(inputs, fitted, tmp_path):
    save_multitask(fitted, tmp_path / "model")
    admission = tmp_path / "admission.json"
    admission.write_text(json.dumps(input_payload(inputs)))
    return [
        "--native-model",
        str(tmp_path / "model"),
        "--native-sha256",
        multitask_identity(fitted),
        "--fixture-admission",
        str(admission),
        "--output",
        str(tmp_path / "output"),
    ]


def test_actual_fixture_forest_and_native_use_the_complete_same_truth(
    inputs, fitted, tmp_path, capsys
):
    args = arguments(inputs, fitted, tmp_path)
    pin = multitask_identity(fitted)
    rng, threads = torch.get_rng_state().clone(), torch.get_num_threads()
    main(args)
    output = tmp_path / "output"
    assert {path.name for path in output.iterdir()} == {
        "input.json",
        "forest.json",
        "fixture-source.json",
        "report.json",
    }
    comparison = ComparisonInput.model_validate_json((output / "input.json").read_text())
    report = DetectionComparisonReport.model_validate_json((output / "report.json").read_text())
    assert report == compare_detectors(comparison)
    batch = build_multitask_validation(fitted, inputs[2], inputs[3], fixture_corpus=inputs[0])
    assert len(comparison.truth) == 12 and sum(row.anomaly_truth for row in comparison.truth) == 4
    assert {row.case_id for row in comparison.truth} == {row.case_id for row in batch.cases}
    for run in comparison.runs:
        assert {row.case_id for row in run.predictions} == {row.case_id for row in batch.cases}
        assert run.protocol.dataset_manifest_sha256 == batch.protocol.dataset_manifest_sha256
        assert run.protocol.target_semantics == "injected_mutation"
        assert run.protocol.purpose == "validation_diagnostic"
        assert run.protocol.detection_threshold == 0.5 and run.protocol.calibration_sha256 is None
    assert set(report.models) == {"isolation_forest", "native_encoder"}
    assert report.models["native_encoder"].model_sha256 == pin
    assert json.loads((output / "fixture-source.json").read_text()) == (
        fitted.report.pretraining.model_dump(mode="json")
    )
    assert len(comparison.runs[0].protocol.train) == 16
    assert len(comparison.runs[1].protocol.train) == 48
    assert all(
        len({identity.family_key for identity in run.protocol.train}) == 16
        for run in comparison.runs
    )
    assert report.cohorts["synthetic"].summary.configurations == 12
    assert report.cohorts["synthetic"].summary.unique_devices == 4
    assert report.cohorts["synthetic"].common_unseen_sites is None
    assert report.cohorts["real_confirmed"].summary is None
    assert not report.production_quality_proven and not report.risk_updated
    assert multitask_identity(fitted) == pin
    assert torch.equal(rng, torch.get_rng_state()) and torch.get_num_threads() == threads
    captured = capsys.readouterr()
    assert "sanitized_text" not in captured.out + captured.err
    assert str(tmp_path) not in captured.out + captured.err


@pytest.mark.parametrize("damage", ["pin", "truth", "permission", "missing", "split"])
def test_changed_retained_comparison_context_refuses_before_output(
    inputs, fitted, tmp_path, capsys, damage
):
    args = arguments(inputs, fitted, tmp_path)
    payload = input_payload(inputs)
    if damage == "pin":
        args[args.index("--native-sha256") + 1] = "f" * 64
    elif damage == "truth":
        payload["examples"][0]["annotation"]["annotation_sha256"] = "f" * 64
    elif damage == "permission":
        payload["manifest"]["source"]["allowed_uses"] = []
    elif damage == "missing":
        payload["records"].pop()
    else:
        from ml.training.pretraining_smoke import pretraining_fixtures

        payload["splits"] = pretraining_fixtures()[0].model_dump(mode="json")
    (tmp_path / "admission.json").write_text(json.dumps(payload))
    with pytest.raises(SystemExit) as error:
        main(args)
    assert error.value.code == 2 and not (tmp_path / "output").exists()
    captured = capsys.readouterr()
    assert str(tmp_path) not in captured.out + captured.err
    assert "sanitized_text" not in captured.out + captured.err


@pytest.mark.parametrize("damage", ["missing_fixture_context", "mixed_modes", "existing_output"])
def test_comparison_modes_and_unused_output_are_explicit(
    inputs, fitted, tmp_path, monkeypatch, damage
):
    args = arguments(inputs, fitted, tmp_path)
    if damage == "missing_fixture_context":
        index = args.index("--fixture-admission")
        del args[index : index + 2]
    elif damage == "mixed_modes":
        args += ["--foundation-model", "unused-model"]
    else:
        (tmp_path / "output").mkdir()
    monkeypatch.setattr(
        "ml.evaluation.comparison_smoke.load_multitask",
        lambda *args: pytest.fail("invalid mode/output must refuse before model loading"),
    )
    with pytest.raises(SystemExit) as error:
        main(args)
    assert error.value.code == 2
    assert not (tmp_path / "output" / "report.json").exists()


def test_actual_fixture_comparison_needs_no_external_retrieval_runtime(inputs, fitted, tmp_path):
    args = arguments(inputs, fitted, tmp_path)
    project = Path(__file__).resolve().parents[3]
    code = """
import sys
from importlib.abc import MetaPathFinder
sys.path[:0] = [sys.argv[1], sys.argv[2]]
class DenyExternalRuntime(MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] in ('transformers', 'safetensors'):
            raise ModuleNotFoundError('external runtime blocked')
sys.meta_path.insert(0, DenyExternalRuntime())
from ml.evaluation.comparison_smoke import main
main(sys.argv[3:])
assert 'transformers' not in sys.modules and 'safetensors' not in sys.modules
"""
    completed = subprocess.run(
        [sys.executable, "-I", "-c", code, str(project), str(project / "backend"), *args],
        capture_output=True,
        text=True,
        timeout=45,
    )
    assert completed.returncode == 0, completed.stderr
    assert (tmp_path / "output" / "report.json").is_file()
    assert "sanitized_text" not in completed.stdout and str(tmp_path) not in completed.stdout
