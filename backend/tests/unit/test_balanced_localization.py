"""Train-only line balance, historical parity, strict format and offline gates."""

import copy
import json
import sys
from dataclasses import replace

import pytest
import torch
from pydantic import ValidationError
from test_fixture_transfer import inputs as fixture_inputs
from test_fixture_transfer import train
from test_multitask_heads import outputs, targets

from ml.datasets import DatasetSplit
from ml.evaluation.metrics import evaluate
from ml.evaluation.multitask_validation import build_multitask_validation
from ml.registry.admission import load_fixture_admission
from ml.registry.store import initialize_registry, register_model
from ml.training.localization_objective import (
    FittedLocalizationObjective,
    TrainBalancedLocalization,
    fit_localization_objective,
)
from ml.training.multitask import HeadPolicy, LossWeights, MultiTaskHeads, multitask_loss
from ml.training.multitask_training import (
    FineTunePolicy,
    MultiTaskBalancedFixtureReport,
    _targets,
    _verified_report,
    extract_aligned_features,
    fit_aligned_heads,
    load_multitask,
    multitask_identity,
    predict_multitask,
    save_multitask,
    validate_multitask_inputs,
    validate_supervised_rows,
)
from ml.training.pretraining import pretraining_identity

inputs = fixture_inputs


@pytest.fixture(scope="module")
def balanced(inputs):
    return train(inputs, localization_objective=TrainBalancedLocalization())


def test_exact_masked_positive_loss_and_gradients():
    model = MultiTaskHeads(16, HeadPolicy(classes=("routing", "management")))
    output = outputs(model)
    labels = targets()
    weights = LossWeights(anomaly=0, category=0, localization=1, severity=0, contrastive=0)
    logits = output.line_logits.detach().clone().requires_grad_()
    output = replace(output, line_logits=logits)
    actual = multitask_loss(output, labels, weights, localization_positive_weight=3.0)
    mask = labels.lines != -100
    expected = (
        -3 * labels.lines[mask] * torch.nn.functional.logsigmoid(logits[mask])
        - (1 - labels.lines[mask]) * torch.nn.functional.logsigmoid(-logits[mask])
    ).mean()
    assert torch.allclose(actual.total, expected, atol=1e-7)
    gradient = torch.autograd.grad(actual.total, logits, retain_graph=True)[0]
    assert torch.allclose(gradient, torch.autograd.grad(expected, logits)[0], atol=1e-7)
    assert gradient[-1] == 0 and actual.supervised_counts["localization"] == 4
    default = multitask_loss(output, labels, weights)
    explicit_none = multitask_loss(output, labels, weights, localization_positive_weight=None)
    legacy = torch.nn.functional.binary_cross_entropy_with_logits(logits[mask], labels.lines[mask])
    assert torch.equal(default.total, explicit_none.total) and torch.equal(default.total, legacy)
    assert torch.equal(
        torch.autograd.grad(default.total, logits, retain_graph=True)[0],
        torch.autograd.grad(legacy, logits)[0],
    )


@pytest.mark.parametrize("coefficient", [True, 1, 0.0, -1.0, float("nan"), float("inf")])
def test_invalid_explicit_coefficient_refuses(coefficient):
    model = MultiTaskHeads(16, HeadPolicy(classes=("routing", "management")))
    with pytest.raises(ValueError, match="coefficient"):
        multitask_loss(
            outputs(model), targets(), LossWeights(), localization_positive_weight=coefficient
        )


@pytest.mark.parametrize("labels", [[0, 0, -100], [1, -100], [-100], [1, 0.5], [float("nan")]])
def test_missing_or_invalid_train_classes_refuse(labels):
    with pytest.raises(ValueError):
        fit_localization_objective(torch.tensor(labels), "a" * 64, TrainBalancedLocalization())


def test_strict_balance_contract_and_ignored_counts():
    fitted = fit_localization_objective(
        torch.tensor([1, 0, 0, -100]), "a" * 64, TrainBalancedLocalization()
    )
    assert (
        fitted.positive_lines,
        fitted.negative_lines,
        fitted.eligible_lines,
        fitted.positive_weight,
    ) == (1, 2, 3, 2)
    assert FineTunePolicy().model_dump() == dict(
        seed=17,
        epochs=20,
        learning_rate=0.01,
        weight_decay=0.01,
        gradient_clip=1.0,
        max_total_windows=10000,
        max_feature_values=4000000,
    )
    assert set(LossWeights.model_fields) == {
        "anomaly",
        "category",
        "localization",
        "severity",
        "contrastive",
    }
    for updates in (
        {"positive_weight": 3.0},
        {"positive_lines": True},
        {"eligible_lines": 4},
        {"extra": 1},
    ):
        with pytest.raises(ValidationError):
            FittedLocalizationObjective.model_validate({**fitted.model_dump(), **updates})
    for updates in ({"mode": "validation_ratio"}, {"reduction": "sum_weights"}, {"extra": 1}):
        with pytest.raises(ValidationError):
            TrainBalancedLocalization.model_validate(
                {**TrainBalancedLocalization().model_dump(), **updates}
            )


def test_actual_balanced_fit_round_trip_and_default_identity(inputs, balanced, tmp_path):
    corpus, source, splits, examples = inputs
    identity = pretraining_identity(source)
    rng, threads = torch.get_rng_state().clone(), torch.get_num_threads()
    repeated = train(inputs, localization_objective=TrainBalancedLocalization())
    assert torch.equal(rng, torch.get_rng_state()) and threads == torch.get_num_threads()
    assert multitask_identity(repeated) == multitask_identity(balanced)
    assert pretraining_identity(source) == identity
    assert isinstance(balanced.report, MultiTaskBalancedFixtureReport)
    assert balanced.report.version == "multitask-training-0.4.0"
    objective = balanced.report.localization_objective
    assert objective.train_fingerprint == balanced.report.train_fingerprint
    assert objective.eligible_lines == balanced.report.supervised_counts["localization"]
    assert not any(parameter.requires_grad for parameter in balanced.pretrained.model.parameters())
    baseline, explicit_none = train(inputs), train(inputs, localization_objective=None)
    assert baseline.report.version == "multitask-training-0.3.0"
    assert "localization_objective" not in baseline.report.model_dump()
    assert baseline.report.model_dump_json() == explicit_none.report.model_dump_json()
    assert multitask_identity(baseline) == multitask_identity(explicit_none)
    save_multitask(balanced, tmp_path / "weighted")
    restored = load_multitask(tmp_path / "weighted")
    assert restored.report == balanced.report and multitask_identity(
        restored
    ) == multitask_identity(balanced)
    for example in examples:
        assert predict_multitask(restored, example.record) == predict_multitask(
            balanced, example.record
        )
    batch = build_multitask_validation(restored, splits, examples, fixture_corpus=corpus)
    assert batch.protocol.model_version == "multitask-training-0.4.0"
    assert not evaluate(batch).independent_test
    assert evaluate(batch).cohorts["real_confirmed"].summary is None


def test_report_spoofing_and_retained_train_counts_refuse(inputs, balanced):
    corpus, _, splits, examples = inputs
    for updates in (
        {"version": "multitask-training-0.3.0"},
        {"localization_objective": None},
        {
            "localization_objective": balanced.report.localization_objective.model_copy(
                update={"train_fingerprint": "b" * 64}
            )
        },
    ):
        forged = copy.copy(balanced)
        forged.report = balanced.report.model_copy(update=updates)
        with pytest.raises(ValueError):
            _verified_report(forged)
    forged = copy.copy(balanced)
    # Self-consistent counts/ratio still must match the actual aligned train labels.
    altered = balanced.report.localization_objective.model_copy(
        update={
            "positive_lines": 1,
            "negative_lines": balanced.report.supervised_counts["localization"] - 1,
            "positive_weight": float(balanced.report.supervised_counts["localization"] - 1),
        }
    )
    forged.report = balanced.report.model_copy(update={"localization_objective": altered})
    with pytest.raises(ValueError, match="retained aligned train"):
        validate_multitask_inputs(forged, splits, examples, fixture_corpus=corpus)


def test_ignored_deletion_and_unreviewed_are_excluded_and_selection_cannot_fit_ratio(inputs):
    _, source, splits, examples = inputs
    policy = HeadPolicy(classes=("telnet_enabled",), embedding_size=8, max_examples=128)
    rows = validate_supervised_rows(splits, examples, policy)
    source = copy.deepcopy(source)
    source.model.eval().requires_grad_(False)
    features = {
        split: tuple(
            extract_aligned_features(row.record, source, max_windows=10000) for row in group
        )
        for split, group in rows.items()
    }
    first = rows[DatasetSplit.TRAIN][0]
    aligned = features[DatasetSplit.TRAIN][0]
    reviewed = replace(
        first,
        annotation=first.annotation.model_copy(
            update={
                "anomaly": True,
                "localization_reviewed": True,
                "positive_lines": (aligned.line_numbers[0],),
                "ignored_lines": (aligned.line_numbers[1],),
            }
        ),
    )
    unknown = replace(
        reviewed,
        annotation=reviewed.annotation.model_copy(
            update={
                "localization_reviewed": False,
                "positive_lines": (),
                "ignored_lines": (),
            }
        ),
    )
    deleted = replace(
        reviewed,
        annotation=reviewed.annotation.model_copy(
            update={
                "deletion_only": True,
                "positive_lines": (),
                "ignored_lines": (),
            }
        ),
    )
    target = _targets((reviewed, unknown, deleted), (aligned,) * 3).lines
    objective = fit_localization_objective(target, "a" * 64, TrainBalancedLocalization())
    assert (
        objective.positive_lines == 1 and objective.eligible_lines == len(aligned.line_numbers) - 1
    )
    weights = LossWeights(severity=0)
    with torch.random.fork_rng(devices=[]):
        torch.manual_seed(17)
        first_fit = fit_aligned_heads(
            rows,
            features,
            16,
            policy,
            FineTunePolicy(epochs=1),
            weights,
            localization_objective=TrainBalancedLocalization(),
        )
        changed = {
            **rows,
            DatasetSplit.VALIDATION: tuple(
                replace(row, annotation=row.annotation.model_copy(update={"positive_lines": ()}))
                for row in rows[DatasetSplit.VALIDATION]
            ),
        }
        torch.manual_seed(17)
        second_fit = fit_aligned_heads(
            changed,
            features,
            16,
            policy,
            FineTunePolicy(epochs=1),
            weights,
            localization_objective=TrainBalancedLocalization(),
        )
    assert first_fit.localization_objective == second_fit.localization_objective
    assert all(
        torch.equal(value, second_fit.heads.state_dict()[name])
        for name, value in first_fit.heads.state_dict().items()
    )
    assert (
        first_fit.losses[0].validation_components["localization"]
        != second_fit.losses[0].validation_components["localization"]
    )


def test_disabled_loss_and_online_admission_explicitly_refuse(inputs, balanced, tmp_path):
    with pytest.raises(ValueError, match="enabled loss"):
        train(
            inputs,
            localization_objective=TrainBalancedLocalization(),
            loss_weights=LossWeights(localization=0, severity=0),
        )
    registry = tmp_path / "registry"
    initialize_registry(registry)
    before = {
        path.relative_to(registry): path.read_bytes()
        for path in registry.rglob("*")
        if path.is_file()
    }
    with pytest.raises(ValueError, match="offline-only"):
        register_model(registry, balanced, expected_identity=multitask_identity(balanced))
    assert before == {
        path.relative_to(registry): path.read_bytes()
        for path in registry.rglob("*")
        if path.is_file()
    }
    with pytest.raises(ValueError, match="explicit fixture transfer"):
        load_fixture_admission(tmp_path / "nonexistent.json", balanced)


@pytest.mark.parametrize("objective", ["unweighted", "train-balanced"])
@pytest.mark.parametrize("task_weight", [None, 592 / 1120])
def test_cli_explicit_objective_and_seed_are_forwarded(
    objective, task_weight, tmp_path, monkeypatch
):
    from ml.training import fixture_transfer_smoke

    calls = []
    monkeypatch.setattr(
        fixture_transfer_smoke,
        "run_fixture_transfer",
        lambda *args, **kwargs: calls.append(kwargs) or {},
    )
    monkeypatch.setattr(
        "sys.argv",
        [
            "transfer",
            "--source-model",
            "private",
            "--source-sha256",
            "f" * 64,
            "--manifest",
            "private",
            "--records",
            "private",
            "--output",
            str(tmp_path / "new"),
            "--seed",
            "41",
            "--line-objective",
            objective,
            "--owned-scenario",
            "bilateral-telnet-0.1.0",
        ],
    )
    if task_weight is not None:
        monkeypatch.setattr("sys.argv", [*sys.argv, "--localization-task-weight", str(task_weight)])
    assert fixture_transfer_smoke.main() == 0
    assert calls[0]["seed"] == 41 and calls[0]["epochs"] == 20
    assert calls[0]["localization_task_weight"] == (1 if task_weight is None else task_weight)
    assert calls[0]["localization_objective"] == (
        TrainBalancedLocalization() if objective == "train-balanced" else None
    )


@pytest.mark.parametrize("failure", ["budget", "missing_class"])
def test_weighted_failure_restores_source_and_runtime_state(inputs, failure):
    corpus, source, splits, examples = inputs
    before = pretraining_identity(source)
    rng, threads = torch.get_rng_state().clone(), torch.get_num_threads()
    deterministic = torch.are_deterministic_algorithms_enabled()
    modes = tuple(module.training for module in source.model.modules())
    parameters = tuple(parameter.requires_grad for parameter in source.model.parameters())
    if failure == "missing_class":
        examples = tuple(
            replace(row, annotation=row.annotation.model_copy(update={"positive_lines": ()}))
            for row in examples
        )
    with pytest.raises(
        ValueError, match="budget" if failure == "budget" else "both train line classes"
    ):
        train(
            (corpus, source, splits, examples),
            localization_objective=TrainBalancedLocalization(),
            training_policy=FineTunePolicy(
                epochs=1, max_feature_values=1024 if failure == "budget" else 4000000
            ),
        )
    assert pretraining_identity(source) == before and torch.equal(rng, torch.get_rng_state())
    assert (
        threads == torch.get_num_threads()
        and deterministic == torch.are_deterministic_algorithms_enabled()
    )
    assert modes == tuple(module.training for module in source.model.modules())
    assert parameters == tuple(parameter.requires_grad for parameter in source.model.parameters())


def test_legacy_encoder_cannot_silently_accept_balanced_request():
    from test_multitask_training import inputs as legacy_fixture
    from test_multitask_training import train as legacy_train

    legacy = legacy_fixture.__wrapped__()
    with pytest.raises(ValueError, match="native fixture source"):
        legacy_train(legacy, localization_objective=TrainBalancedLocalization())


@pytest.mark.parametrize("value", [-1.0, float("nan"), float("inf"), 101.0, 0.0])
def test_invalid_scaled_task_weight_refuses_before_source_or_output(value, tmp_path, monkeypatch):
    from ml.training.fixture_transfer_smoke import run_fixture_transfer

    monkeypatch.setattr(
        "ml.training.fixture_transfer_smoke.load_fixture_pretraining",
        lambda *_: pytest.fail("invalid task weight must refuse before source loading"),
    )
    output = tmp_path / "output"
    with pytest.raises(ValueError):
        run_fixture_transfer(
            tmp_path / "source",
            "f" * 64,
            tmp_path / "manifest",
            tmp_path / "records",
            output,
            localization_objective=TrainBalancedLocalization(),
            localization_task_weight=value,
        )
    assert not output.exists()


def test_task_rescaling_changes_only_total_weight_not_component_and_train_mass():
    model = MultiTaskHeads(16, HeadPolicy(classes=("routing", "management")))
    logits = torch.zeros(593, requires_grad=True)
    output = replace(outputs(model), line_logits=logits)
    annotation = targets(
        lines=torch.cat((torch.ones(32), torch.zeros(560), torch.tensor([-100.0])))
    )
    disabled = dict(anomaly=0, category=0, severity=0, contrastive=0)
    unweighted = multitask_loss(output, annotation, LossWeights(localization=1, **disabled))
    balanced = multitask_loss(
        output,
        annotation,
        LossWeights(localization=1, **disabled),
        localization_positive_weight=17.5,
    )
    scaled = multitask_loss(
        output,
        annotation,
        LossWeights(localization=592 / 1120, **disabled),
        localization_positive_weight=17.5,
    )
    assert torch.equal(balanced.components["localization"], scaled.components["localization"])
    assert torch.allclose(scaled.total, unweighted.total, atol=1e-6)
    assert torch.allclose(scaled.total, (592 / 1120) * balanced.total, atol=1e-7)
    before = torch.autograd.grad(balanced.total, logits, retain_graph=True)[0]
    after = torch.autograd.grad(scaled.total, logits)[0]
    assert torch.allclose(after, (592 / 1120) * before, atol=1e-8)
    assert after[-1] == 0


@pytest.mark.parametrize("balanced", [False, True])
def test_actual_cli_default_and_explicit_unit_task_weight_preserve_protocol_and_model(
    inputs, balanced, tmp_path
):
    from ml.training.fixture_transfer_smoke import run_fixture_transfer
    from ml.training.pretraining import save_pretraining

    corpus, source = inputs[:2]
    source_path = tmp_path / "source"
    save_pretraining(source, source_path)
    manifest, records = tmp_path / "manifest.json", tmp_path / "records.json"
    manifest.write_text(corpus.manifest.model_dump_json(), encoding="utf-8")
    records.write_text(
        json.dumps([row.model_dump(mode="json") for row in corpus.imported]), encoding="utf-8"
    )
    options = dict(
        epochs=1, localization_objective=TrainBalancedLocalization() if balanced else None
    )
    first, second = tmp_path / "absent", tmp_path / "explicit"
    default = run_fixture_transfer(
        source_path, pretraining_identity(source), manifest, records, first, **options
    )
    explicit = run_fixture_transfer(
        source_path,
        pretraining_identity(source),
        manifest,
        records,
        second,
        localization_task_weight=1.0,
        **options,
    )
    assert default["model_identity"] == explicit["model_identity"]
    assert (first / "protocol.json").read_bytes() == (second / "protocol.json").read_bytes()
    assert (first / "model/heads.json").read_bytes() == (second / "model/heads.json").read_bytes()
