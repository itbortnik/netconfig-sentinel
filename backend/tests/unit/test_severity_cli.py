"""Real offline CLI fit/apply/report on explicit numbers, with closed failure paths."""

from __future__ import annotations

import json
import math
import subprocess
import sys
from collections import Counter
from pathlib import Path
from xml.etree import ElementTree

import pytest

from ml.evaluation import calibration_cli, cli
from ml.evaluation.metrics import canonical_hash
from ml.evaluation.severity import (
    SeverityCalibrationArtifact,
    severity_artifact_identity,
    severity_batch_identity,
)
from ml.evaluation.severity_contracts import SEVERITY_CLASSES, SeverityEvaluationBatch
from ml.evaluation.severity_smoke import authored_numeric_severity_batches

ROOT = Path(__file__).resolve().parents[3]
PRIVATE = "PRIVATE-SOURCE-NEVER-ECHO"


@pytest.fixture(scope="module")
def numeric_batches():
    return authored_numeric_severity_batches()


def _write(path, value):
    path.write_text(value.model_dump_json(indent=2) + "\n", encoding="utf-8")
    return path


def _subprocess(directory, name, module, arguments):
    result = subprocess.run(
        [sys.executable, "-m", module, *map(str, arguments)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )
    (directory / f"{name}.log").write_text(
        f"returncode={result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}",
        encoding="utf-8",
    )
    assert result.returncode == 0, result.stderr
    assert PRIVATE not in result.stdout + result.stderr
    return result


@pytest.fixture(scope="module")
def numerical_run(tmp_path_factory, numeric_batches):
    directory = tmp_path_factory.mktemp("severity-numeric-cli")
    fitting, evaluation = numeric_batches
    paths = {
        "fitting": _write(directory / "numeric-calibration-input.json", fitting),
        "evaluation": _write(directory / "numeric-reserved-input.json", evaluation),
        "artifact": directory / "numeric-calibration.json",
        "calibrated": directory / "numeric-calibrated-input.json",
        "raw_report": directory / "numeric-raw-report.json",
        "report": directory / "numeric-calibrated-report.json",
        "svg": directory / "numeric-class-reliability.svg",
    }
    before = {key: paths[key].read_bytes() for key in ("fitting", "evaluation")}
    _subprocess(
        directory,
        "fit",
        "ml.evaluation.calibration_cli",
        [
            "fit-severity",
            "--input",
            paths["fitting"],
            "--output",
            paths["artifact"],
        ],
    )
    _subprocess(
        directory,
        "apply",
        "ml.evaluation.calibration_cli",
        [
            "apply-severity",
            "--input",
            paths["evaluation"],
            "--calibration",
            paths["artifact"],
            "--calibration-input",
            paths["fitting"],
            "--output",
            paths["calibrated"],
        ],
    )
    _subprocess(
        directory,
        "raw-report",
        "ml.evaluation.cli",
        [
            "--task",
            "severity",
            "--input",
            paths["evaluation"],
            "--output",
            paths["raw_report"],
        ],
    )
    _subprocess(
        directory,
        "calibrated-report",
        "ml.evaluation.cli",
        [
            "--task",
            "severity",
            "--input",
            paths["calibrated"],
            "--output",
            paths["report"],
            "--reliability-svg",
            paths["svg"],
        ],
    )
    assert {key: paths[key].read_bytes() for key in before} == before
    return paths


def _arguments(mode, paths, output, *, input_path=None, artifact=None, retained=None):
    source = input_path or paths["evaluation"]
    if mode == "report":
        return cli, ["--task", "severity", "--input", str(source), "--output", str(output)]
    if mode == "fit":
        return calibration_cli, [
            "fit-severity",
            "--input",
            str(input_path or paths["fitting"]),
            "--output",
            str(output),
        ]
    return calibration_cli, [
        "apply-severity",
        "--input",
        str(source),
        "--calibration",
        str(artifact or paths["artifact"]),
        "--calibration-input",
        str(retained or paths["fitting"]),
        "--output",
        str(output),
    ]


def _refused(module, arguments, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", [module.__name__, *arguments])
    with pytest.raises(SystemExit) as rejected:
        module.main()
    assert rejected.value.code == 2
    captured = capsys.readouterr()
    assert PRIVATE not in captured.out + captured.err
    assert "Traceback" not in captured.out + captured.err
    assert "Offline" in captured.err


def test_factory_is_explicit_numeric_fixture_with_balanced_varied_rows_and_reserved_identities(
    numeric_batches,
):
    fitting, evaluation = numeric_batches
    assert authored_numeric_severity_batches() == numeric_batches
    for batch in numeric_batches:
        protocol = batch.protocol
        assert protocol.target_semantics == "authored_severity_fixture"
        assert protocol.score_provenance == "authored_numeric_fixture"
        assert protocol.train == protocol.selection == ()
        assert protocol.tokenizer_sha256 is protocol.training_report_sha256 is None
        assert protocol.reserved_test == tuple(row.identity for row in evaluation.cases)
        assert Counter(row.severity_truth for row in batch.cases) == dict.fromkeys(
            SEVERITY_CLASSES, 10
        )
        assert len({row.probabilities for row in batch.cases}) == len(batch.cases) == 50
        assert {row.vendor for row in batch.cases} == {"cisco", "juniper"}
        assert all(row.cohort == "synthetic" and row.anomaly_truth is True for row in batch.cases)
        for field in ("family_key", "device_key", "site_key", "network_key"):
            assert len({getattr(row.identity, field) for row in batch.cases}) == 1
        assert len({row.identity.source_sha256 for row in batch.cases}) == 50
        mistakes = [
            row
            for row in batch.cases
            if (
                SEVERITY_CLASSES[max(range(5), key=lambda index: row.probabilities[index])]
                != row.severity_truth
            )
        ]
        assert 0 < len(mistakes) < 50
        assert any(max(row.probabilities) >= 0.8 for row in mistakes)
    assert fitting.protocol.purpose == "validation_diagnostic"
    assert evaluation.protocol.purpose == "independent_test"
    for field in ("source_sha256", "family_key", "device_key", "site_key", "network_key"):
        assert {getattr(row.identity, field) for row in fitting.cases}.isdisjoint(
            {getattr(row.identity, field) for row in evaluation.cases}
        )


def test_numeric_source_hash_identifies_an_actual_numeric_record(numeric_batches):
    first = numeric_batches[0].cases[0]
    record = {
        "version": "authored-severity-numeric-record-0.1.0",
        "kind": "numeric_table_entry",
        "partition": "calibration",
        "index_within_class": 0,
        "declared_severity": "info",
        "probabilities": first.probabilities,
        "hypothetical_vendor": "cisco",
        "hypothetical_role": "hypothetical-edge",
    }
    assert first.identity.source_sha256 == canonical_hash(record)
    record["probabilities"] = (0.2,) * 5
    assert first.identity.source_sha256 != canonical_hash(record)


def test_factory_import_does_not_load_model_or_numerical_runtimes():
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; from ml.evaluation.severity_smoke import "
            "authored_numeric_severity_batches; "
            "assert not {'torch', 'numpy', 'sklearn'} & set(sys.modules); "
            "assert tuple(len(x.cases) for x in authored_numeric_severity_batches()) == (50, 50)",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr


def test_real_cli_fit_apply_report_preserves_raw_artifacts_and_truth_bindings(
    numerical_run, numeric_batches
):
    fitting, raw = numeric_batches
    paths = numerical_run
    artifact = SeverityCalibrationArtifact.model_validate_json(paths["artifact"].read_bytes())
    result = cli.load_severity_batch(paths["calibrated"])
    assert artifact.policy.minimum_class_support == 10
    assert artifact.calibration_input_sha256 == severity_batch_identity(fitting)
    assert artifact.fit_cohort_counts == {"synthetic": 50}
    assert all(
        point.positive_cases == 10 and point.negative_cases == 40
        for point in artifact.operating_points
    )
    assert artifact.calibrated_multiclass_nll <= artifact.original_multiclass_nll
    assert result.protocol.application_input_sha256 == severity_batch_identity(raw)
    assert result.protocol.calibration_sha256 == severity_artifact_identity(artifact)
    assert result.protocol.class_thresholds == tuple(
        point.threshold for point in artifact.operating_points
    )
    assert result.protocol.threshold_policy_sha256 == canonical_hash(
        [point.model_dump(mode="json") for point in artifact.operating_points]
    )
    if artifact.temperature == 1.0:
        assert tuple(row.probabilities for row in result.cases) == tuple(
            row.probabilities for row in raw.cases
        )
    else:
        assert any(
            before.probabilities != after.probabilities
            for before, after in zip(raw.cases, result.cases, strict=True)
        )
    for before, after in zip(raw.cases, result.cases, strict=True):
        assert before.model_dump(exclude={"probabilities"}) == after.model_dump(
            exclude={"probabilities"}
        )
        assert sum(after.probabilities) == pytest.approx(1.0, abs=1e-12)
        powered = tuple(value ** (1.0 / artifact.temperature) for value in before.probabilities)
        assert after.probabilities == pytest.approx(
            tuple(value / math.fsum(powered) for value in powered), abs=1e-12
        )
    assert paths["fitting"].read_text(encoding="utf-8") == fitting.model_dump_json(indent=2) + "\n"
    assert paths["evaluation"].read_text(encoding="utf-8") == raw.model_dump_json(indent=2) + "\n"


def test_cli_report_has_honest_missing_cohorts_and_fixed_safe_ovr_panels(
    numerical_run, numeric_batches
):
    report = json.loads(numerical_run["report"].read_text(encoding="utf-8"))
    assert report["version"] == "severity-metrics-0.1.0"
    assert report["classes"] == list(SEVERITY_CLASSES)
    assert report["identity_holdout_checked"] is True
    assert report["physical_independence_proven"] is report["production_quality_proven"] is False
    assert report["risk_fused"] is report["online_risk_updated"] is False
    assert report["protocol"]["exposure_counts"] == {
        "train": 0,
        "selection": 0,
        "calibration": 50,
        "reserved_test": 50,
    }
    assert report["cohorts"]["synthetic"]["summary"]["cases"] == 50
    assert report["cohorts"]["synthetic"]["summary"]["declared_unique_devices"] == 1
    for origin in ("laboratory", "real_confirmed"):
        assert report["cohorts"][origin]["status"] == "missing"
        assert report["cohorts"][origin]["summary"] is None
    diagram = numerical_run["svg"].read_text(encoding="utf-8")
    tree = ElementTree.fromstring(diagram)
    assert tree.tag.endswith("svg")
    assert diagram.count("missing data") == 10
    for origin in ("synthetic", "laboratory", "real_confirmed"):
        assert all(f"{origin}: {label}" in diagram for label in SEVERITY_CLASSES)
    assert "<script" not in diagram
    assert numeric_batches[1].cases[0].identity.source_sha256 not in diagram
    assert numeric_batches[1].cases[0].identity.device_key not in json.dumps(report)


@pytest.mark.parametrize("mode", ["fit", "apply", "report"])
@pytest.mark.parametrize(
    "fault", ["duplicate", "malformed", "recursive", "missing-version", "unknown-version"]
)
def test_cli_rejects_ambiguous_or_unversioned_input_without_echoing_private_values(
    numerical_run, tmp_path, mode, fault, monkeypatch, capsys
):
    source = tmp_path / "invalid.json"
    if fault == "duplicate":
        text = '{"protocol":{},"protocol":{"private":"' + PRIVATE + '"}}'
    elif fault == "malformed":
        text = '{"private":"' + PRIVATE + '",'
    elif fault == "recursive":
        text = "[" * 2000 + json.dumps(PRIVATE) + "]" * 2000
    else:
        value = json.loads(
            numerical_run["fitting" if mode == "fit" else "evaluation"].read_text(encoding="utf-8")
        )
        if fault == "missing-version":
            del value["protocol"]["version"]
        else:
            value["protocol"]["version"] = PRIVATE
        text = json.dumps(value)
    source.write_text(text, encoding="utf-8")
    output = tmp_path / "must-not-exist.json"
    module, arguments = _arguments(mode, numerical_run, output, input_path=source)
    _refused(module, arguments, monkeypatch, capsys)
    assert not output.exists()


@pytest.mark.parametrize("version", [None, "unknown-severity-artifact"])
def test_apply_requires_explicit_calibration_artifact_version(
    numerical_run, tmp_path, version, monkeypatch, capsys
):
    value = json.loads(numerical_run["artifact"].read_text(encoding="utf-8"))
    if version is None:
        del value["version"]
    else:
        value["version"] = version
    artifact = tmp_path / "artifact.json"
    artifact.write_text(json.dumps(value), encoding="utf-8")
    output = tmp_path / "must-not-exist.json"
    module, arguments = _arguments("apply", numerical_run, output, artifact=artifact)
    _refused(module, arguments, monkeypatch, capsys)
    assert not output.exists()


@pytest.mark.parametrize("mode", ["fit", "apply", "report"])
def test_cli_outputs_are_exclusive(numerical_run, tmp_path, mode, monkeypatch, capsys):
    output = tmp_path / "existing.json"
    output.write_bytes(b"existing-output-preserved\n")
    module, arguments = _arguments(mode, numerical_run, output)
    _refused(module, arguments, monkeypatch, capsys)
    assert output.read_bytes() == b"existing-output-preserved\n"


@pytest.mark.parametrize("mode", ["fit", "apply", "report"])
def test_cli_refuses_dangling_output_symlinks(numerical_run, tmp_path, mode, monkeypatch, capsys):
    output, target = tmp_path / "link.json", tmp_path / "uncreated-target.json"
    try:
        output.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("Symbolic links are unavailable for this test process.")
    module, arguments = _arguments(mode, numerical_run, output)
    _refused(module, arguments, monkeypatch, capsys)
    assert output.is_symlink() and not target.exists()


@pytest.mark.parametrize("mode", ["fit", "apply", "report"])
def test_cli_guard_refuses_when_filesystem_reports_an_output_symlink(
    numerical_run, tmp_path, mode, monkeypatch, capsys
):
    # Exercise the guard on platforms where this user cannot create actual links;
    # the separate real-filesystem tests retain that availability distinction.
    output = tmp_path / "reported-symlink.json"
    original = Path.is_symlink
    monkeypatch.setattr(Path, "is_symlink", lambda path: path == output or original(path))
    module, arguments = _arguments(mode, numerical_run, output)
    _refused(module, arguments, monkeypatch, capsys)
    assert not output.exists()


def test_report_refuses_conflicting_output_targets_before_writing(
    numerical_run, tmp_path, monkeypatch, capsys
):
    output = tmp_path / "same.json"
    module, arguments = _arguments("report", numerical_run, output)
    _refused(module, [*arguments, "--reliability-svg", str(output)], monkeypatch, capsys)
    assert not output.exists()
    diagram = tmp_path / "existing.svg"
    diagram.write_text("previous diagram", encoding="utf-8")
    _refused(module, [*arguments, "--reliability-svg", str(diagram)], monkeypatch, capsys)
    assert not output.exists() and diagram.read_text(encoding="utf-8") == "previous diagram"


def test_reserved_test_is_not_fitted_and_calibrated_scores_are_not_applied_twice(
    numerical_run, tmp_path, monkeypatch, capsys
):
    for mode, source in [
        ("fit", numerical_run["evaluation"]),
        ("apply", numerical_run["calibrated"]),
    ]:
        output = tmp_path / f"forbidden-{mode}.json"
        module, arguments = _arguments(mode, numerical_run, output, input_path=source)
        _refused(module, arguments, monkeypatch, capsys)
        assert not output.exists()


@pytest.mark.parametrize("tampering", ["probabilities", "annotation", "artifact-temperature"])
def test_apply_rechecks_retained_fitting_data_and_exact_artifact(
    numerical_run, tmp_path, tampering, monkeypatch, capsys
):
    artifact, retained = numerical_run["artifact"], numerical_run["fitting"]
    if tampering == "artifact-temperature":
        value = json.loads(artifact.read_text(encoding="utf-8"))
        value["temperature"] = 1.0 if value["temperature"] != 1.0 else 2.0
        artifact = tmp_path / "tampered-artifact.json"
        artifact.write_text(json.dumps(value), encoding="utf-8")
    else:
        value = json.loads(retained.read_text(encoding="utf-8"))
        if tampering == "probabilities":
            value["cases"][0]["probabilities"] = [0.2] * 5
        else:
            value["cases"][0]["annotation_sha256"] = "0" * 64
        retained = tmp_path / "tampered-calibration-input.json"
        retained.write_text(json.dumps(value), encoding="utf-8")
        SeverityEvaluationBatch.model_validate(value)  # Refusal must depend on retained binding.
    output = tmp_path / "must-not-exist.json"
    module, arguments = _arguments(
        "apply", numerical_run, output, artifact=artifact, retained=retained
    )
    _refused(module, arguments, monkeypatch, capsys)
    assert not output.exists()
