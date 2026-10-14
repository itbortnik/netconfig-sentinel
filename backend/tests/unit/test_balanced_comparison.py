"""Same authored truth/control and strict retained admission for cost-sensitive heads."""

import copy
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

import app
import pytest
import torch
from test_fixture_comparison import arguments
from test_fixture_registry import input_payload
from test_fixture_transfer import inputs as inputs
from test_fixture_transfer import train

import ml
from ml.evaluation.comparison import ComparisonInput, DetectionComparisonReport, compare_detectors
from ml.evaluation.comparison_smoke import main
from ml.mutation import MutationType
from ml.training.fixture_transfer_smoke import authored_transfer_splits
from ml.training.localization_contracts import TrainBalancedLocalization
from ml.training.multitask_smoke import authored_supervision
from ml.training.multitask_training import MultiTaskBalancedFixtureReport, multitask_identity


@pytest.fixture(scope="module", params=["legacy-telnet-0.1.0", "bilateral-telnet-0.1.0"])
def comparison_context(inputs, request):
    splits = authored_transfer_splits(scenario=request.param)
    examples = authored_supervision(splits, (MutationType.TELNET_ENABLED,))
    data = (*inputs[:2], splits, examples)
    fitted = train(data, localization_objective=TrainBalancedLocalization())
    return request.param, data, fitted


def selected_arguments(context, tmp_path):
    scenario, data, fitted = context
    return [*arguments(data, fitted, tmp_path), "--owned-scenario", scenario]


def test_balanced_complete_truth_original_forest_parents_and_private_objective(
    comparison_context, tmp_path, capsys
):
    scenario, data, fitted = comparison_context
    pin, rng, threads = multitask_identity(fitted), torch.get_rng_state(), torch.get_num_threads()
    main(selected_arguments(comparison_context, tmp_path))
    output = tmp_path / "output"
    assert {path.name for path in output.iterdir()} == {
        "input.json",
        "forest.json",
        "fixture-source.json",
        "fixture-training.json",
        "report.json",
    }
    recorded = MultiTaskBalancedFixtureReport.model_validate_json(
        (output / "fixture-training.json").read_text()
    )
    assert recorded == fitted.report
    assert recorded.localization_objective.train_fingerprint == recorded.train_fingerprint
    comparison = ComparisonInput.model_validate_json((output / "input.json").read_text())
    report = DetectionComparisonReport.model_validate_json((output / "report.json").read_text())
    assert report == compare_detectors(comparison)
    count, positives = (16, 8) if scenario == "bilateral-telnet-0.1.0" else (12, 4)
    assert len(comparison.truth) == count
    assert sum(row.anomaly_truth for row in comparison.truth) == positives
    if scenario == "bilateral-telnet-0.1.0":
        assert Counter((row.vendor, row.anomaly_truth) for row in comparison.truth) == {
            (vendor, truth): 4 for vendor in ("cisco", "juniper") for truth in (True, False)
        }
    for run in comparison.runs:
        assert {row.case_id for row in run.predictions} == {row.case_id for row in comparison.truth}
        assert run.protocol.detection_threshold == 0.5 and run.protocol.calibration_sha256 is None
        assert run.protocol.purpose == "validation_diagnostic"
        assert run.protocol.target_semantics == "injected_mutation"
    assert len(comparison.runs[0].protocol.train) == 16
    assert len(comparison.runs[1].protocol.train) == (64 if count == 16 else 48)
    assert comparison.runs[1].protocol.model_version == "multitask-training-0.4.0"
    assert report.models["native_encoder"].model_sha256 == pin
    cohort = report.cohorts["synthetic"]
    assert cohort.summary.configurations == count and cohort.summary.unique_devices == 4
    assert cohort.common_unseen_sites is None
    assert report.cohorts["real_confirmed"].summary is None
    assert report.cohorts["laboratory"].summary is None
    assert not report.production_quality_proven and not report.risk_updated
    assert multitask_identity(fitted) == pin
    assert torch.equal(rng, torch.get_rng_state()) and torch.get_num_threads() == threads
    assert (
        data[2].model_dump_json() == authored_transfer_splits(scenario=scenario).model_dump_json()
    )
    captured = capsys.readouterr()
    assert str(tmp_path) not in captured.out + captured.err
    assert "sanitized_text" not in captured.out + captured.err


@pytest.mark.parametrize("damage", ["pin", "truth", "permission", "missing", "scenario", "ratio"])
def test_balanced_admission_refuses_before_forest_and_output(
    comparison_context, tmp_path, monkeypatch, capsys, damage
):
    _, data, fitted = comparison_context
    args = selected_arguments(comparison_context, tmp_path)
    payload = input_payload(data)
    if damage == "pin":
        args[args.index("--native-sha256") + 1] = "f" * 64
    elif damage == "truth":
        payload["examples"][0]["annotation"]["annotation_sha256"] = "f" * 64
    elif damage == "permission":
        payload["manifest"]["source"]["allowed_uses"] = []
    elif damage == "missing":
        payload["records"].pop()
    elif damage == "scenario":
        selected = args.index("--owned-scenario") + 1
        args[selected] = (
            "legacy-telnet-0.1.0"
            if args[selected] == "bilateral-telnet-0.1.0"
            else "bilateral-telnet-0.1.0"
        )
    else:
        forged = copy.copy(fitted)
        objective = fitted.report.localization_objective
        forged.report = fitted.report.model_copy(
            update={
                "localization_objective": objective.model_copy(
                    update={
                        "positive_lines": 1,
                        "negative_lines": objective.eligible_lines - 1,
                        "positive_weight": float(objective.eligible_lines - 1),
                    }
                ),
            }
        )
        args[args.index("--native-sha256") + 1] = multitask_identity(forged)
        monkeypatch.setattr("ml.evaluation.comparison_smoke.load_multitask", lambda *args: forged)
    (tmp_path / "admission.json").write_text(json.dumps(payload))
    monkeypatch.setattr(
        "ml.evaluation.comparison_smoke.fit_isolation_forest",
        lambda *args, **kwargs: pytest.fail("invalid balanced context fitted a forest"),
    )
    with pytest.raises(SystemExit) as error:
        main(args)
    assert error.value.code == 2 and not (tmp_path / "output").exists()
    captured = capsys.readouterr()
    assert str(tmp_path) not in captured.out + captured.err
    assert "sanitized_text" not in captured.out + captured.err


def test_balanced_owned_child_requires_no_external_runtime(comparison_context, tmp_path):
    code = """
import json
import sys
from importlib.abc import MetaPathFinder
from pathlib import Path
sys.path[:0] = [sys.argv[1], sys.argv[2]]
class DenyExternal(MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] in ('transformers', 'safetensors'):
            raise ModuleNotFoundError('external runtime blocked')
sys.meta_path.insert(0, DenyExternal())
from ml.evaluation.comparison_smoke import main
main(sys.argv[3:])
assert 'transformers' not in sys.modules and 'safetensors' not in sys.modules
count = 0
for name, module in tuple(sys.modules.items()):
    if name.split('.')[0] in ('app', 'ml') and getattr(module, '__file__', None):
        root = Path(sys.argv[1 if name.split('.')[0] == 'app' else 2]).resolve()
        assert Path(module.__file__).resolve().is_relative_to(root)
        count += 1
print(json.dumps({'native_only_imports': count, 'checkout_fallback': False}))
"""
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            code,
            str(Path(app.__file__).resolve().parent.parent),
            str(Path(ml.__file__).resolve().parent.parent),
            *selected_arguments(comparison_context, tmp_path),
        ],
        capture_output=True,
        text=True,
        timeout=45,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout.splitlines()[-1])["native_only_imports"] > 0
    assert (tmp_path / "output" / "fixture-training.json").is_file()
    assert "sanitized_text" not in result.stdout and str(tmp_path) not in result.stdout
