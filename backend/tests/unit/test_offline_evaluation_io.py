"""Coverage lexer parity, sanitized CLI errors, real predictor and bundle binding."""

import json
import subprocess
import sys
from pathlib import Path
from xml.etree import ElementTree

import pytest
from app.domain import CanonicalConfig
from app.parsers import parse_configuration
from test_offline_evaluation import batch, case

from ml.evaluation.cli import load_batch, reliability_svg, write_report
from ml.evaluation.coverage import parser_coverage
from ml.evaluation.metrics import evaluate

ROOT = Path(__file__).resolve().parents[3]


@pytest.mark.parametrize(
    ("text", "total", "recognized"),
    [
        ("! comment\n\nhostname test\nunsupported PRIVATE\n", 2, 1),
        ("# comment\nset system host-name test # inline\nset unknown PRIVATE\n", 2, 1),
        ("system {\n host-name test; # inline\n}\n", 3, 3),
        ('set system host-name "test#quoted"\n', 1, 1),
    ],
)
def test_parser_coverage_counts_actual_commands_not_blank_comment_padding(text, total, recognized):
    config = parse_configuration(text, filename="synthetic.cfg")
    coverage = parser_coverage(text, config)
    assert coverage.significant_lines == total and coverage.recognized_lines == recognized
    with pytest.raises(ValueError, match="match"):
        parser_coverage(text + "\n", config)


def test_parser_coverage_rejects_rebound_unsupported_anchors():
    text = "hostname test\nunsupported PRIVATE\n"
    config = parse_configuration(text, filename="synthetic.cfg").model_dump()
    config["unparsed_fragments"][0]["location"]["source_lines"] = [50]
    with pytest.raises(ValueError, match="anchors"):
        parser_coverage(text, CanonicalConfig.model_validate(config))


def test_json_roundtrip_refuses_duplicate_keys_and_produces_safe_origin_diagram(tmp_path):
    source = batch(
        [case("a"), case("b", anomaly_truth=True, detection_score=0.8, category_truth=("routing",))]
    )
    path = tmp_path / "predictions.json"
    path.write_text(source.model_dump_json(), encoding="utf-8")
    assert load_batch(path) == source
    report = evaluate(source)
    svg = reliability_svg(report)
    ElementTree.fromstring(svg)
    assert "real_confirmed" in svg and "missing data" in svg
    assert "<script" not in svg and source.cases[0].case_id not in svg
    output, diagram = tmp_path / "metrics.json", tmp_path / "reliability.svg"
    write_report(report, output, diagram)
    assert json.loads(output.read_text())["cohorts"]["real_confirmed"]["status"] == "missing"
    with pytest.raises(ValueError, match="new"):
        write_report(report, output, diagram)
    path.write_text('{"protocol": {}, "protocol": {"private": "PRIVATE"}}')
    with pytest.raises(ValueError, match="duplicate"):
        load_batch(path)


def test_cli_error_never_echoes_raw_input_and_success_does_not_overwrite(tmp_path):
    source = tmp_path / "predictions.json"
    output = tmp_path / "metrics.json"
    source.write_text('{"PRIVATE": "PRIVATE", "protocol": {}}')
    command = [
        sys.executable,
        "-m",
        "ml.evaluation.cli",
        "--input",
        str(source),
        "--output",
        str(output),
    ]
    rejected = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=20)
    assert rejected.returncode == 2 and "PRIVATE" not in rejected.stdout + rejected.stderr
    assert not output.exists()
    source.write_text(batch([case("a")]).model_dump_json())
    accepted = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=20)
    assert accepted.returncode == 0 and output.exists()
    before = output.read_bytes()
    again = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=20)
    assert again.returncode == 2 and output.read_bytes() == before


def test_calibration_cli_fit_apply_report_and_refuse_test_fit(tmp_path):
    from test_offline_calibration import calibration_rows

    calibration_input = tmp_path / "calibration-input.json"
    artifact = tmp_path / "calibration.json"
    calibration_input.write_text(
        batch(calibration_rows(), purpose="validation_diagnostic").model_dump_json()
    )
    command = [sys.executable, "-m", "ml.evaluation.calibration_cli"]
    fitted = subprocess.run(
        [*command, "fit", "--input", str(calibration_input), "--output", str(artifact)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert fitted.returncode == 0 and artifact.exists()
    test_input, calibrated = tmp_path / "test.json", tmp_path / "calibrated-test.json"
    test_input.write_text(batch([case("held-out")]).model_dump_json())
    applied = subprocess.run(
        [
            *command,
            "apply",
            "--input",
            str(test_input),
            "--calibration",
            str(artifact),
            "--output",
            str(calibrated),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert applied.returncode == 0
    report = evaluate(load_batch(calibrated))
    assert report.independent_test and report.calibration_sha256
    bad_output = tmp_path / "forbidden-test-fit.json"
    rejected = subprocess.run(
        [*command, "fit", "--input", str(test_input), "--output", str(bad_output)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert rejected.returncode == 2 and not bad_output.exists()


def test_real_probe_and_localizer_adapter_is_measured_diagnostic_and_state_preserving():
    import torch

    from ml.evaluation.probe_validation import build_probe_validation
    from ml.mutation import MutationType
    from ml.preprocessing.tokenization import TokenizerPolicy, train_config_tokenizer
    from ml.training.classification import ProbePolicy, train_mutation_probe
    from ml.training.classification_smoke import classification_fixtures
    from ml.training.localization import LinePolicy, train_line_localizer
    from ml.training.transformer import EncoderPolicy, TrainingPolicy, train_masked_language_model

    splits = classification_fixtures()
    tokenizer = train_config_tokenizer(
        splits, policy=TokenizerPolicy(vocab_size=300, context_length=16)
    )
    pretrained = train_masked_language_model(
        splits,
        tokenizer,
        encoder_policy=EncoderPolicy(hidden_size=16, heads=2, layers=1, feedforward_size=32),
        training_policy=TrainingPolicy(epochs=1),
    )
    types = (MutationType.TELNET_ENABLED, MutationType.AAA_DISABLED)
    probe = train_mutation_probe(splits, pretrained, types, policy=ProbePolicy(epochs=1))
    localizer = train_line_localizer(splits, pretrained, types, policy=LinePolicy(epochs=1))
    threads, rng = torch.get_num_threads(), torch.get_rng_state().clone()
    before = {key: value.clone() for key, value in probe.head.state_dict().items()}
    source = build_probe_validation(probe, localizer=localizer)
    result = evaluate(source)
    assert not result.independent_test and result.target_semantics == "injected_mutation"
    summary = result.cohorts["synthetic"].summary
    assert summary.latency.measured_cases == summary.configurations
    assert summary.parser_coverage.measured_cases == summary.configurations
    assert summary.localization.annotated_cases == summary.configurations
    assert summary.unknown_ranking.annotated_cases == 0
    assert result.cohorts["real_confirmed"].summary is None
    assert "PRIVATE" not in source.model_dump_json()
    assert torch.get_num_threads() == threads and torch.equal(rng, torch.get_rng_state())
    assert all(torch.equal(value, probe.head.state_dict()[key]) for key, value in before.items())
    localizer.report = localizer.report.model_copy(update={"encoder_sha256": "0" * 64})
    with pytest.raises(ValueError, match="localizer"):
        build_probe_validation(probe, localizer=localizer)
    probe.report = probe.report.model_copy(update={"validation_fingerprint": "0" * 64})
    with pytest.raises(ValueError, match="probe"):
        build_probe_validation(probe)
