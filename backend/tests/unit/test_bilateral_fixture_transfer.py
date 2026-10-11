"""Explicit balanced owned views, not additional independent networks or healthy labels."""

import json
import subprocess
import sys
from collections import Counter
from dataclasses import replace
from pathlib import Path

import app
import pytest
from app.domain import Vendor
from app.parsers import parse_configuration
from test_fixture_comparison import arguments
from test_fixture_transfer import inputs as inputs
from test_fixture_transfer import train

import ml
from ml.datasets import DatasetSplit
from ml.evaluation.comparison import ComparisonInput, DetectionComparisonReport
from ml.evaluation.comparison_smoke import main as compare_main
from ml.evaluation.metrics import evaluate
from ml.evaluation.multitask_validation import build_multitask_validation
from ml.mutation import MutationType
from ml.preprocessing.blocks import digest
from ml.training.fixture_transfer_smoke import authored_transfer_splits, run_fixture_transfer
from ml.training.multitask import HeadPolicy
from ml.training.multitask_smoke import authored_supervision
from ml.training.multitask_training import (
    load_multitask,
    multitask_identity,
    predict_multitask,
    save_multitask,
    validate_supervised_rows,
)
from ml.training.pretraining import pretraining_identity, save_pretraining
from ml.training.pretraining_smoke import pretraining_fixtures
from ml.training.pretraining_transfer import objective_split_identity

SCENARIO = "bilateral-telnet-0.1.0"


@pytest.fixture(scope="module")
def bilateral_inputs(inputs):
    splits = authored_transfer_splits(scenario=SCENARIO)
    examples = authored_supervision(splits, (MutationType.TELNET_ENABLED,))
    return inputs[0], inputs[1], splits, examples


@pytest.fixture(scope="module")
def bilateral_fitted(bilateral_inputs):
    return train(bilateral_inputs)


@pytest.fixture(scope="module")
def legacy_fitted(inputs):
    return train(inputs)


def test_legacy_default_and_explicit_full_split_remain_identical():
    default = authored_transfer_splits()
    assert (
        default.model_dump_json()
        == authored_transfer_splits(scenario="legacy-telnet-0.1.0").model_dump_json()
    )
    assert objective_split_identity(default) == (
        "5266e170bc0547d61f544f1dc707e66ac34e1b6fef675296a894e0e3a0fb4777"
    )
    with pytest.raises(ValueError, match="unknown owned"):
        authored_transfer_splits(scenario="unknown")


def test_versioned_authored_raw_provenance_and_same_entity_memberships(bilateral_inputs):
    legacy = authored_transfer_splits()
    original, _ = pretraining_fixtures()
    raw = {row.record_id: row for part in original.partitions for row in part.records}
    current = bilateral_inputs[2]
    for old, new in zip(legacy.partitions, current.partitions, strict=True):
        assert old.split is new.split and len(old.records) == len(new.records)
        for before, after in zip(old.records, new.records, strict=True):
            assert after.source_id == "synthetic-fixture-transfer-bilateral-0.1.0"
            for field in (
                "record_id",
                "network_id",
                "site_id",
                "device_id",
                "captured_at",
                "vendor_hint",
                "device_role",
            ):
                assert getattr(before, field) == getattr(after, field)
            text = raw[after.record_id].sanitized_text
            if after.vendor_hint is Vendor.CISCO:
                text += "line vty 0 4\n transport input ssh\n"
                assert before.sanitized_text != after.sanitized_text
                assert after.sanitized_text.endswith("line vty 0 4\n transport input ssh\n")
            else:
                assert before.sanitized_text == after.sanitized_text
            assert after.raw_sha256 == digest(text)
            assert after.raw_byte_count == len(text.encode())
            assert after.sanitized_sha256 == digest(after.sanitized_text)
    assert objective_split_identity(current) != objective_split_identity(legacy)


def test_both_vendors_have_exact_labels_line_anchors_and_no_test_views(bilateral_inputs):
    splits, examples = bilateral_inputs[2:]
    memberships = {row.record_id: part.split for part in splits.partitions for row in part.records}
    counts = Counter(
        (memberships[row.record.record_id], row.record.vendor_hint, row.annotation.anomaly)
        for row in examples
    )
    assert len(examples) == 80
    for vendor in (Vendor.CISCO, Vendor.JUNIPER):
        for positive in (False, True):
            assert counts[DatasetSplit.TRAIN, vendor, positive] == 16
            assert counts[DatasetSplit.VALIDATION, vendor, positive] == 4
    assert not any(memberships[row.record.record_id] is DatasetSplit.TEST for row in examples)
    assert len({row.record.record_id for row in examples}) == 20
    for base, view in zip(examples[::2], examples[1::2], strict=True):
        assert view.record.sanitized_text == "\n" + base.record.sanitized_text
        assert view.parent_sha256 == base.parent_sha256
        assert view.annotation.positive_lines == tuple(
            line + 1 for line in base.annotation.positive_lines
        )
    for row in examples:
        config = parse_configuration(row.record.sanitized_text, filename="owned.cfg")
        assert config.management.telnet_enabled is row.annotation.anomaly
        assert row.annotation.category_targets == (int(row.annotation.anomaly),)
        assert row.annotation.severity is None and not row.annotation.deletion_only
        assert len(row.annotation.positive_lines) == int(row.annotation.anomaly)
        if row.annotation.anomaly:
            line = row.record.sanitized_text.splitlines()[row.annotation.positive_lines[0] - 1]
            assert "telnet" in line or line.strip() == "transport input all"


def test_actual_bilateral_training_round_trip_and_complete_validation(
    bilateral_inputs, bilateral_fitted, tmp_path
):
    corpus, _, splits, examples = bilateral_inputs
    fitted = bilateral_fitted
    assert fitted.report.train_examples == 64 and fitted.report.validation_examples == 16
    assert fitted.report.version == "multitask-training-0.3.0"
    assert fitted.report.pretraining.exposure.heldout_overlap_count == 0
    assert not fitted.report.pretraining.exposure.physical_pretraining_isolation_proven
    save_multitask(fitted, tmp_path / "model")
    restored = load_multitask(tmp_path / "model")
    assert restored.report == fitted.report
    assert multitask_identity(restored) == multitask_identity(fitted)
    assert all(
        predict_multitask(restored, row.record) == predict_multitask(fitted, row.record)
        for row in examples
    )
    batch = build_multitask_validation(restored, splits, examples, fixture_corpus=corpus)
    assert len(batch.cases) == 16
    metrics = evaluate(batch)
    assert not metrics.independent_test and metrics.cohorts["real_confirmed"].summary is None
    assert not metrics.production_quality_proven


def test_reserved_parent_and_changed_annotation_refuse_before_features(bilateral_inputs):
    splits, examples = bilateral_inputs[2:]
    reserved = next(part for part in splits.partitions if part.split is DatasetSplit.TEST)
    bad = replace(
        examples[0], record=reserved.records[0], parent_sha256=reserved.records[0].sanitized_sha256
    )
    with pytest.raises(ValueError, match="test examples"):
        validate_supervised_rows(splits, (*examples, bad), HeadPolicy(classes=("telnet_enabled",)))
    changed = replace(
        examples[0],
        annotation=examples[0].annotation.model_copy(update={"source_sha256": "f" * 64}),
    )
    with pytest.raises(ValueError):
        validate_supervised_rows(
            splits, (changed, *examples[1:]), HeadPolicy(classes=("telnet_enabled",))
        )


def test_bilateral_comparison_uses_all_same_truth_and_original_train_parents(
    bilateral_inputs, bilateral_fitted, tmp_path
):
    args = arguments(bilateral_inputs, bilateral_fitted, tmp_path)
    compare_main([*args, "--owned-scenario", SCENARIO])
    output = tmp_path / "output"
    comparison = ComparisonInput.model_validate_json((output / "input.json").read_text())
    report = DetectionComparisonReport.model_validate_json((output / "report.json").read_text())
    assert len(comparison.truth) == 16
    assert sum(row.anomaly_truth for row in comparison.truth) == 8
    for run in comparison.runs:
        assert {row.case_id for row in run.predictions} == {row.case_id for row in comparison.truth}
        assert run.protocol.detection_threshold == 0.5
    assert len(comparison.runs[0].protocol.train) == 16
    assert len(comparison.runs[1].protocol.train) == 64
    assert report.cohorts["synthetic"].summary.configurations == 16
    assert report.cohorts["real_confirmed"].summary is None
    assert not report.production_quality_proven and not report.risk_updated


@pytest.mark.parametrize("selected", ["legacy-telnet-0.1.0", SCENARIO])
def test_comparison_rejects_scenario_mismatch_without_output(
    inputs, bilateral_inputs, bilateral_fitted, selected, tmp_path
):
    context = inputs if selected == SCENARIO else bilateral_inputs
    args = arguments(context, bilateral_fitted, tmp_path)
    with pytest.raises(SystemExit) as error:
        compare_main([*args, "--owned-scenario", selected])
    assert error.value.code == 2 and not (tmp_path / "output").exists()


def test_bilateral_external_mode_refuses_before_loading_model(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "ml.evaluation.comparison_smoke.load_multitask",
        lambda *args: pytest.fail("bilateral external mode must refuse before loading"),
    )
    with pytest.raises(SystemExit) as error:
        compare_main(
            [
                "--native-model",
                "unused",
                "--native-sha256",
                "f" * 64,
                "--owned-scenario",
                SCENARIO,
                "--output",
                str(tmp_path / "output"),
            ]
        )
    assert error.value.code == 2 and not (tmp_path / "output").exists()


@pytest.mark.parametrize("selected", ["legacy-telnet-0.1.0", SCENARIO])
def test_matching_admission_and_scenario_refuse_model_from_other_scenario(
    inputs, bilateral_inputs, bilateral_fitted, legacy_fitted, selected, tmp_path, monkeypatch
):
    context = bilateral_inputs if selected == SCENARIO else inputs
    model = legacy_fitted if selected == SCENARIO else bilateral_fitted
    args = arguments(context, model, tmp_path)
    monkeypatch.setattr(
        "ml.evaluation.comparison_smoke.fit_isolation_forest",
        lambda *args, **kwargs: pytest.fail("foreign model must refuse before fitting forest"),
    )
    with pytest.raises(SystemExit) as error:
        compare_main([*args, "--owned-scenario", selected])
    assert error.value.code == 2 and not (tmp_path / "output").exists()


def test_explicit_bilateral_run_records_scenario_and_preserves_legacy_default(inputs, tmp_path):
    corpus, source, _, _ = inputs
    bundle = tmp_path / "source"
    save_pretraining(source, bundle)
    manifest, records = tmp_path / "manifest.json", tmp_path / "records.json"
    manifest.write_text(corpus.manifest.model_dump_json())
    records.write_text(json.dumps([row.model_dump(mode="json") for row in corpus.imported]))
    pin = pretraining_identity(source)
    for scenario in ("legacy-telnet-0.1.0", SCENARIO):
        output = tmp_path / scenario
        result = run_fixture_transfer(
            bundle, pin, manifest, records, output, epochs=2, scenario=scenario
        )
        protocol = json.loads((output / "protocol.json").read_text())
        expected = 48 if scenario == "legacy-telnet-0.1.0" else 64
        assert result["train_examples"] == expected
        assert result["selection_examples"] == expected // 4
        assert result["source_unchanged"] and result["round_trip_predictions_equal"]
        assert not (output / ".incomplete").exists()
        if scenario == SCENARIO:
            assert result["owned_scenario"] == protocol["owned_scenario"] == SCENARIO
        else:
            assert "owned_scenario" not in result and "owned_scenario" not in protocol
    with pytest.raises(ValueError, match="unknown owned"):
        run_fixture_transfer(
            bundle, pin, manifest, records, tmp_path / "invalid", epochs=2, scenario="unknown"
        )
    assert not (tmp_path / "invalid").exists()


def test_bilateral_comparison_runs_without_external_runtime(
    bilateral_inputs, bilateral_fitted, tmp_path
):
    args = [*arguments(bilateral_inputs, bilateral_fitted, tmp_path), "--owned-scenario", SCENARIO]
    app_root = Path(app.__file__).resolve().parent.parent
    ml_root = Path(ml.__file__).resolve().parent.parent
    code = """
import json
import sys
from importlib.abc import MetaPathFinder
from pathlib import Path
sys.path[:0] = [sys.argv[1], sys.argv[2]]
class DenyExternalRuntime(MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] in ('transformers', 'safetensors'):
            raise ModuleNotFoundError('external runtime blocked')
sys.meta_path.insert(0, DenyExternalRuntime())
from ml.evaluation.comparison_smoke import main
main(sys.argv[3:])
assert 'transformers' not in sys.modules and 'safetensors' not in sys.modules
imports = 0
for name, module in tuple(sys.modules.items()):
    package = name.split('.')[0]
    if package in ('app', 'ml') and getattr(module, '__file__', None):
        expected = Path(sys.argv[1 if package == 'app' else 2]).resolve()
        assert Path(module.__file__).resolve().is_relative_to(expected)
        imports += 1
assert imports > 0
print(json.dumps({'native_only_child_imports': imports, 'runtime_roots_pinned': True}))
"""
    completed = subprocess.run(
        [sys.executable, "-I", "-c", code, str(app_root), str(ml_root), *args],
        capture_output=True,
        text=True,
        timeout=45,
    )
    assert completed.returncode == 0, completed.stderr
    audit = json.loads(completed.stdout.splitlines()[-1])
    assert audit["runtime_roots_pinned"] and audit["native_only_child_imports"] > 0
    assert (tmp_path / "output" / "report.json").is_file()
    assert "sanitized_text" not in completed.stdout and str(tmp_path) not in completed.stdout
