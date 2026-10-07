"""Artificial source tensors test mechanics; actual publisher weights run separately offline."""

import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
import torch
from tokenizers import Tokenizer
from tokenizers.models import WordLevel
from tokenizers.pre_tokenizers import WhitespaceSplit

from ml.datasets import DatasetSplit
from ml.evaluation.foundation_validation import build_foundation_validation
from ml.evaluation.metrics import canonical_hash, evaluate
from ml.mutation import MutationType
from ml.preprocessing.blocks import digest
from ml.retrieval import minilm
from ml.training.foundation import ConfigFoundation
from ml.training.foundation_transfer import (
    foundation_transfer_identity,
    load_foundation_transfer,
    predict_foundation_transfer,
    save_foundation_transfer,
    train_foundation_transfer,
)
from ml.training.multitask import HeadPolicy, LossWeights
from ml.training.multitask_smoke import authored_supervision
from ml.training.multitask_training import FineTunePolicy
from ml.training.pretraining_smoke import pretraining_fixtures


class ArtificialSource(torch.nn.Module):
    def __init__(self):
        super().__init__()
        self.weight = torch.nn.Parameter(torch.arange(384).float() / 384)
        self.calls = []

    def forward(self, ids, attention_mask):
        assert not torch.is_grad_enabled()
        assert ids.device.type == "cpu" and bool((attention_mask == 1).all())
        self.calls.append(ids[0].tolist())
        output = self.weight[None, None, :] + ids[:, :, None].float() / 100
        # Framing tokens must not affect content block/line pooling.
        output[:, 0, :] = 10000
        output[:, -1, :] = -10000
        return SimpleNamespace(last_hidden_state=output)


@pytest.fixture
def source(tmp_path, monkeypatch):
    root = tmp_path / "artificial-source"
    root.mkdir()
    native = Tokenizer(
        WordLevel(
            {
                "<s>": 0,
                "<pad>": 1,
                "</s>": 2,
                "<unk>": 3,
                "head": 4,
                "tail": 5,
                "hostname": 6,
                "set": 7,
                "system": 8,
                "host-name": 9,
            },
            unk_token="<unk>",
        )
    )
    native.pre_tokenizer = WhitespaceSplit()
    native.save(str(root / "tokenizer.json"))
    monkeypatch.setattr(minilm, "verify_model_files", lambda path: None)
    monkeypatch.setattr(
        minilm, "_load_model", lambda path: ArtificialSource().eval().requires_grad_(False)
    )
    return root, ConfigFoundation(root)


@pytest.fixture
def inputs(source):
    splits, _ = pretraining_fixtures()
    examples = authored_supervision(splits, (MutationType.TELNET_ENABLED,))
    return splits, source[1], examples


def train(inputs, **updates):
    values = dict(
        head_policy=HeadPolicy(classes=("telnet_enabled",), embedding_size=8, max_examples=128),
        training_policy=FineTunePolicy(epochs=3, learning_rate=0.001),
        loss_weights=LossWeights(severity=0),
    )
    values.update(updates)
    return train_foundation_transfer(*inputs, **values)


@pytest.mark.parametrize("vendor", ("cisco", "juniper"))
@pytest.mark.parametrize("newline", ("\n", "\r\n"))
def test_complete_token_windows_unicode_blank_lines_and_framing(source, inputs, vendor, newline):
    record = next(row.record for row in inputs[2] if row.record.vendor_hint.value == vendor)
    text = (
        ("hostname " if vendor == "cisco" else "set system host-name ") + "head " * 252 + "tail\n\n"
    )
    text += "! Привет tail\n" if vendor == "cisco" else "# Привет tail\n"
    text += "ip ssh version 2\n" if vendor == "cisco" else "set system services ssh\n"
    text = text.replace("\n", newline)
    record = record.model_copy(update={"sanitized_text": text, "sanitized_sha256": digest(text)})
    encoder = source[1]
    features = encoder.features(record, max_windows=100)
    assert features.total_lines == 4 and features.line_numbers == (1, 3, 4)
    assert features.windows >= 4
    calls = encoder._model.calls
    assert all(row[0] == 0 and row[-1] == 2 and len(row) <= 128 for row in calls)
    content = [item for row in calls for item in row[1:-1]]
    assert content.count(4) == 252 and content.count(5) == 2
    # No CLS/SEP contribution despite their deliberately extreme fake hidden values.
    assert bool((features.blocks.abs() < 2).all())
    assert bool((features.lines.abs() < 2).all())
    assert not features.blocks.requires_grad and not features.lines.requires_grad


def test_actual_feature_heads_fit_and_checkpoint_match_without_source_updates(
    inputs, source, tmp_path
):
    before = inputs[1].verify()
    rng, threads = torch.get_rng_state().clone(), torch.get_num_threads()
    deterministic = torch.are_deterministic_algorithms_enabled()
    result, again = train(inputs), train(inputs)
    assert foundation_transfer_identity(result) == foundation_transfer_identity(again)
    assert result.report == again.report
    assert inputs[1].verify() == before
    assert torch.equal(rng, torch.get_rng_state()) and torch.get_num_threads() == threads
    assert torch.are_deterministic_algorithms_enabled() == deterministic
    report = result.report
    assert report.encoder_frozen and not report.test_evaluated
    assert not report.foundation.configuration_pretrained
    assert report.foundation.external_training_exposure == "unknown"
    assert not report.external_pretraining_isolation_proven and not report.attention_lora
    assert report.trainable_parameters < report.parameter_count
    assert report.losses[-1].train_total < report.losses[0].train_total
    prediction = predict_foundation_transfer(result, inputs[2][0].record)
    assert prediction.severity_scores is None and not prediction.calibrated
    assert prediction.category_scores is not None and prediction.embedding is not None
    assert len(prediction.line_scores) == len(inputs[2][0].record.sanitized_text.splitlines())
    assert sum(prediction.block_attention) == pytest.approx(1)
    path = tmp_path / "model"
    pin = save_foundation_transfer(result, path)
    assert set(item.name for item in path.iterdir()) == {"heads.json", "heads.sha256"}
    assert "source_root" not in (path / "heads.json").read_text()
    restored = load_foundation_transfer(path, source_root=source[0], expected_identity=pin)
    assert predict_foundation_transfer(restored, inputs[2][0].record) == prediction
    with pytest.raises(FileExistsError):
        save_foundation_transfer(result, path)
    metrics = evaluate(build_foundation_validation(result, inputs[0], inputs[2]))
    assert not metrics.independent_test and metrics.cohorts["real_confirmed"].summary is None
    assert metrics.cohorts["synthetic"].summary.configurations == report.validation_examples


@pytest.mark.parametrize("case", ("weight", "tokenizer", "nested_mode", "gradient", "dtype"))
def test_changed_foundation_state_cannot_supply_inference(inputs, case):
    result = train(inputs)
    source = inputs[1]
    if case == "weight":
        with torch.no_grad():
            source._model.weight[0] += 1
    elif case == "tokenizer":
        source._tokenizer.enable_truncation(8)
    elif case == "nested_mode":
        source._model.train()
    elif case == "gradient":
        source._model.weight.grad = torch.zeros_like(source._model.weight)
    else:
        source._model.double()
    with pytest.raises(ValueError):
        predict_foundation_transfer(result, inputs[2][0].record)


@pytest.mark.parametrize("case", ("window", "feature", "examples", "severity"))
def test_budget_or_unreviewed_task_failure_restores_runtime_state(inputs, case):
    rng, threads = torch.get_rng_state().clone(), torch.get_num_threads()
    changes = {
        "window": {"training_policy": FineTunePolicy(epochs=1, max_total_windows=1)},
        "feature": {"training_policy": FineTunePolicy(epochs=1, max_feature_values=1024)},
        "examples": {"head_policy": HeadPolicy(classes=("telnet_enabled",), max_examples=2)},
        "severity": {"loss_weights": LossWeights()},
    }
    with pytest.raises(ValueError):
        train(inputs, **changes[case])
    assert torch.equal(rng, torch.get_rng_state()) and torch.get_num_threads() == threads


@pytest.mark.parametrize("case", ("parent", "annotation", "metadata", "test", "duplicate"))
def test_original_parent_and_current_annotation_membership_are_mandatory(inputs, case):
    splits, source, examples = inputs
    row = examples[0]
    if case == "parent":
        row = replace(row, parent_sha256="0" * 64)
    elif case == "annotation":
        row = replace(row, annotation=row.annotation.model_copy(update={"source_sha256": "0" * 64}))
    elif case == "metadata":
        row = replace(row, record=row.record.model_copy(update={"network_id": "foreign"}))
    elif case == "test":
        record = next(
            part for part in splits.partitions if part.split is DatasetSplit.TEST
        ).records[0]
        row = replace(row, record=record, parent_sha256=record.sanitized_sha256)
    else:
        row = examples[1]
    with pytest.raises(ValueError):
        train((splits, source, (row, *examples[1:])))


@pytest.mark.parametrize(
    "damage", ("extra", "incomplete", "pin", "report", "shape", "nan", "duplicate")
)
def test_bound_bundle_rejects_damage_even_with_recomputed_checksum(
    inputs, source, tmp_path, damage
):
    result = train(inputs)
    path = tmp_path / "model"
    pin = save_foundation_transfer(result, path)
    if damage in ("extra", "incomplete"):
        (path / ("extra" if damage == "extra" else ".incomplete")).write_text("unfinished")
    elif damage == "pin":
        pin = "0" * 64
    else:
        payload = json.loads((path / "heads.json").read_text())
        if damage == "report":
            payload["report"]["foundation"]["weights_sha256"] = "0" * 64
        elif damage == "shape":
            payload["weights"]["category.weight"] = [[0.0]]
        elif damage == "nan":
            payload["weights"]["category.weight"][0][0] = float("nan")
        text = json.dumps(payload)
        if damage == "duplicate":
            text = text[:-1] + ', "weights": {}}'
        else:
            # Deliberately update even the pin to exercise inner consistency checks.
            if damage != "nan":
                pin = canonical_hash(payload)
        (path / "heads.json").write_text(text, encoding="utf-8")
        (path / "heads.sha256").write_text(digest(text), encoding="ascii")
    with pytest.raises((ValueError, RuntimeError)):
        load_foundation_transfer(path, source_root=source[0], expected_identity=pin)


@pytest.mark.parametrize("kind", ("is_symlink", "is_junction"))
@pytest.mark.parametrize("target", ("root", "parent", "heads.json"))
def test_bundle_linked_components_refused(inputs, source, tmp_path, monkeypatch, kind, target):
    result = train(inputs)
    path = tmp_path / "model"
    pin = save_foundation_transfer(result, path)
    linked = path if target == "root" else path.parent if target == "parent" else path / target
    original = getattr(Path, kind)
    monkeypatch.setattr(Path, kind, lambda self: self == linked or original(self))
    with pytest.raises(ValueError, match="linked"):
        load_foundation_transfer(path, source_root=source[0], expected_identity=pin)


def test_evaluation_does_not_accept_changed_labels_and_disabled_heads(inputs):
    result = train(inputs)
    row = inputs[2][0]
    changed = replace(
        row, annotation=row.annotation.model_copy(update={"annotation_sha256": "0" * 64})
    )
    with pytest.raises(ValueError, match="exposure"):
        build_foundation_validation(result, inputs[0], (changed, *inputs[2][1:]))
    disabled = train(inputs, loss_weights=LossWeights(category=0, severity=0, contrastive=0))
    prediction = predict_foundation_transfer(disabled, row.record)
    assert prediction.category_scores is None and prediction.embedding is None
    with pytest.raises(ValueError, match="heads"):
        build_foundation_validation(disabled, inputs[0], inputs[2])


def test_all_five_terms_require_explicit_annotations_and_blank_lines_have_no_score(inputs):
    reviewed = tuple(
        replace(
            row,
            annotation=row.annotation.model_copy(
                update={"severity": "high" if row.annotation.anomaly else None}
            ),
        )
        for row in inputs[2]
    )
    result = train((inputs[0], inputs[1], reviewed), loss_weights=LossWeights())
    assert all(count > 0 for count in result.report.supervised_counts.values())
    row = next(row for row in reviewed if row.record.sanitized_text.startswith("\n"))
    prediction = predict_foundation_transfer(result, row.record)
    assert prediction.line_scores[0] is None
    assert set(prediction.severity_scores) == {"info", "low", "medium", "high", "critical"}
    assert sum(prediction.severity_scores.values()) == pytest.approx(1)


def test_inventory_metadata_is_not_a_prediction_feature(inputs):
    result = train(inputs)
    record = inputs[2][0].record
    changed = record.model_copy(
        update={
            "source_id": "different",
            "record_id": "different",
            "network_id": "different",
            "site_id": "different",
            "device_id": "different",
            "device_role": "different",
        }
    )
    assert predict_foundation_transfer(result, record) == predict_foundation_transfer(
        result, changed
    )


@pytest.mark.parametrize("case", ("nan", "shape"))
def test_invalid_hidden_outputs_fail_without_a_partial_prediction(inputs, monkeypatch, case):
    result = train(inputs)
    original = inputs[1]._model.forward

    def broken(*args, **kwargs):
        output = original(*args, **kwargs).last_hidden_state
        if case == "nan":
            output[:, 1, :] = float("nan")
        else:
            output = output[:, :, :-1]
        return SimpleNamespace(last_hidden_state=output)

    monkeypatch.setattr(inputs[1]._model, "forward", broken)
    with pytest.raises(ValueError, match="hidden states"):
        predict_foundation_transfer(result, inputs[2][0].record)


@pytest.mark.parametrize(
    "before,category",
    (
        (
            "hostname owned\nip ssh version 2\nline vty 0 4\n transport input ssh telnet\n",
            "management.telnet_enabled",
        ),
        ("hostname owned\nip ssh version 1\n", "management.ssh_version_1"),
        (
            "set system host-name owned\nset system services ssh\nset system services telnet\n",
            "management.telnet_enabled",
        ),
        (
            "set system host-name owned\nset system services ssh protocol-version v1\n",
            "management.ssh_version_1",
        ),
    ),
)
@pytest.mark.parametrize("newline", ("\n", "\r\n"))
def test_source_bound_external_model_review_on_four_native_recipes(
    inputs, before, category, newline
):
    from uuid import UUID

    from app.detection.policy_engine import evaluate_policies
    from app.parsers import parse_configuration
    from app.patching.vendor_drafts import create_vendor_draft

    from ml.inference.change_review import review_patch_ml

    before = before.replace("\n", newline)
    device = UUID("de383e03-1806-4e9b-92f2-5de2d33cf89d")
    finding = next(
        row
        for row in evaluate_policies(
            parse_configuration(before, filename="owned.cfg"), device_id=device
        )
        if row.category == category
    )
    draft = create_vendor_draft(
        before,
        finding=finding,
        source_sha256=digest(before),
        reference_id="owned",
    )
    model = train(inputs)
    pin = foundation_transfer_identity(model)
    source_identity = model.source.verify()
    rng, threads = torch.get_rng_state().clone(), torch.get_num_threads()
    result = review_patch_ml(
        draft.metadata.review,
        before,
        draft.candidate_text,
        model=model,
        expected_model_sha256=pin,
        pseudonymization_key=b"owned-private-config-inference-key",
    )
    assert result.local_review == draft.metadata.review
    assert result.status == "needs_review" and result.formal_verification == "not_run"
    assert not result.applied and not result.independent_quality_evaluation
    assert result.transformer.training_format == "foundation-config-transfer-0.1.0"
    assert result.transformer.status == "completed" and not result.transformer.risk_fused
    assert result.transformer.before.raw_source_sha256 == digest(before)
    assert result.transformer.after.raw_source_sha256 == digest(draft.candidate_text)
    assert result.transformer.before.total_lines == len(before.splitlines())
    assert result.transformer.after.total_lines == len(draft.candidate_text.splitlines())
    assert result.transformer.after.severity_scores is None
    assert (
        "candidate_text" not in result.model_dump_json()
        and "sanitized_text" not in result.model_dump_json()
    )
    assert model.source.verify() == source_identity and foundation_transfer_identity(model) == pin
    assert torch.equal(rng, torch.get_rng_state()) and torch.get_num_threads() == threads


def test_partial_external_model_review_never_calls_inference(inputs, monkeypatch):
    from uuid import UUID

    from app.patching.proposal import create_patch_proposal
    from app.patching.review import review_patch_proposal

    from ml.inference.change_review import review_patch_ml

    before = "hostname owned\nip ssh version 1\nunknown private-value\n"
    after = before.replace("version 1", "version 2")
    device = UUID("de383e03-1806-4e9b-92f2-5de2d33cf89d")
    proposal = create_patch_proposal(before, after, device_id=device, reference_id="owned")
    local = review_patch_proposal(proposal, before, after, device_id=device)
    model = train(inputs)

    def forbidden(*args, **kwargs):
        raise AssertionError("partial external inference was called")

    monkeypatch.setattr("ml.training.foundation_transfer.predict_foundation_transfer", forbidden)
    result = review_patch_ml(
        local,
        before,
        after,
        model=model,
        expected_model_sha256=foundation_transfer_identity(model),
        pseudonymization_key=b"owned-key-123456789",
    )
    assert (
        result.transformer.status == "unavailable"
        and result.transformer.reason == "incomplete_parsing"
    )
    assert result.transformer.before is None and result.transformer.after is None
    assert result.local_review == local and "private-value" not in result.model_dump_json()


@pytest.mark.parametrize("bad_option", ("pin", "key", "source", "heads"))
def test_external_review_refuses_changed_binding_or_selection(inputs, bad_option):
    from uuid import UUID

    from app.patching.proposal import create_patch_proposal
    from app.patching.review import review_patch_proposal

    from ml.inference.change_review import review_patch_ml

    before = "hostname owned\nip ssh version 1\n"
    after = before.replace("version 1", "version 2")
    device = UUID("de383e03-1806-4e9b-92f2-5de2d33cf89d")
    proposal = create_patch_proposal(before, after, device_id=device, reference_id="owned")
    local = review_patch_proposal(proposal, before, after, device_id=device)
    model = train(inputs)
    pin = foundation_transfer_identity(model)
    if bad_option == "pin":
        pin = "0" * 64
    elif bad_option == "source":
        with torch.no_grad():
            model.source._model.weight[0] += 1
    elif bad_option == "heads":
        with torch.no_grad():
            next(model.heads.parameters()).add_(1)
    with pytest.raises(ValueError):
        review_patch_ml(
            local,
            before,
            after,
            model=model,
            expected_model_sha256=pin,
            pseudonymization_key=None if bad_option == "key" else b"owned-key-123456789",
        )


def test_explicit_foundation_cli_review_recheck_and_wrong_kind_are_fail_closed(
    inputs, source, tmp_path, monkeypatch, capsys
):
    from uuid import UUID

    from app.patching.artifacts import save_patch_review
    from app.patching.proposal import create_patch_proposal
    from app.patching.review import review_patch_proposal

    from ml.inference.change_artifacts import load_ml_change_review
    from ml.inference.change_cli import KEY_ENV, main

    before, after = "hostname owned\nip ssh version 1\n", "hostname owned\nip ssh version 2\n"
    device = UUID("de383e03-1806-4e9b-92f2-5de2d33cf89d")
    proposal = create_patch_proposal(before, after, device_id=device, reference_id="owned")
    local = review_patch_proposal(proposal, before, after, device_id=device)
    before_file, after_file = tmp_path / "before.cfg", tmp_path / "after.cfg"
    before_file.write_bytes(before.encode())
    after_file.write_bytes(after.encode())
    local_file, output = tmp_path / "local.json", tmp_path / "ml.json"
    save_patch_review(local, local_file)
    model = train(inputs)
    model_path = tmp_path / "model"
    pin = save_foundation_transfer(model, model_path)
    monkeypatch.setenv(KEY_ENV, "31" * 32)
    args = [
        "--before",
        str(before_file),
        "--after",
        str(after_file),
        "--model",
        str(model_path),
        "--model-sha256",
        pin,
        "--model-kind",
        "foundation",
        "--foundation-source",
        str(source[0]),
    ]
    assert main(["review", *args, "--patch-review", str(local_file), "--output", str(output)]) == 0
    saved = load_ml_change_review(output)
    assert saved.transformer.training_format == "foundation-config-transfer-0.1.0"
    assert main(["check", *args, "--artifact", str(output)]) == 0
    assert main(["review", *args, "--patch-review", str(local_file), "--output", str(output)]) == 2
    wrong = args.copy()
    wrong[wrong.index("foundation")] = "native"
    assert main(["check", *wrong, "--artifact", str(output)]) == 2
    printed = capsys.readouterr()
    assert (
        str(tmp_path) not in printed.out + printed.err
        and "31" * 32 not in printed.out + printed.err
    )
    assert saved.local_review == local and saved.formal_verification == "not_run"
