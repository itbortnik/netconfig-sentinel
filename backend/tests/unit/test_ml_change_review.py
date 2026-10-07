"""Source-bound actual inference supplements cannot promote a private draft."""

import json
from dataclasses import replace
from uuid import UUID

import pytest
import torch
from app.patching.proposal import create_patch_proposal
from app.patching.review import review_patch_proposal

from ml.evaluation.metrics import canonical_hash
from ml.inference.change_contracts import MLChangeReview
from ml.inference.change_review import review_patch_ml
from ml.mutation import MutationType
from ml.preprocessing import sanitize_configuration
from ml.preprocessing.tokenization import TokenizerPolicy, train_config_tokenizer
from ml.training.classification_smoke import classification_fixtures
from ml.training.multitask import HeadPolicy, LossWeights
from ml.training.multitask_smoke import authored_supervision
from ml.training.multitask_training import FineTunePolicy, multitask_identity, train_multitask
from ml.training.transformer import EncoderPolicy, TrainingPolicy, train_masked_language_model

DEVICE = UUID("7f64381c-fda8-48f9-8e8a-fb772b2f64dc")
KEY = b"owned private inference fixture key"
BEFORE = "hostname private-customer-host\nip ssh version 1\n"
AFTER = "hostname private-customer-host\nip ssh version 2\n"


def local(before=BEFORE, after=AFTER):
    proposal = create_patch_proposal(before, after, device_id=DEVICE, reference_id="owned-v1")
    return review_patch_proposal(proposal, before, after, device_id=DEVICE)


@pytest.fixture(scope="module")
def model():
    splits = classification_fixtures()
    tokenizer = train_config_tokenizer(
        splits, policy=TokenizerPolicy(vocab_size=300, context_length=32)
    )
    encoder = train_masked_language_model(
        splits,
        tokenizer,
        encoder_policy=EncoderPolicy(hidden_size=16, heads=2, layers=1, feedforward_size=32),
        training_policy=TrainingPolicy(epochs=1),
    )
    return train_multitask(
        splits,
        encoder,
        authored_supervision(splits, (MutationType.TELNET_ENABLED,)),
        head_policy=HeadPolicy(classes=("telnet_enabled",), embedding_size=8),
        training_policy=FineTunePolicy(epochs=1),
        loss_weights=LossWeights(severity=0),
    )


def run(model, before=BEFORE, after=AFTER, **updates):
    values = dict(
        model=model, expected_model_sha256=multitask_identity(model), pseudonymization_key=KEY
    )
    values.update(updates)
    return review_patch_ml(local(before, after), before, after, **values)


def test_actual_both_sides_preserve_model_process_and_local_status(model):
    review = local()
    identity = multitask_identity(model)
    rng, threads = torch.get_rng_state().clone(), torch.get_num_threads()
    result = run(model)
    assert result == run(model)
    assert result.local_review == review
    assert result.status == "needs_review" and result.formal_verification == "not_run"
    assert not result.applied and not result.independent_quality_evaluation
    supplement = result.transformer
    assert supplement.status == "completed" and not supplement.risk_fused
    assert supplement.model_sha256 == identity
    assert supplement.training_report_sha256 == canonical_hash(model.report.model_dump(mode="json"))
    assert supplement.before.raw_source_sha256 == review.proposal.before_sha256
    assert supplement.after.raw_source_sha256 == review.proposal.after_sha256
    for row, text in ((supplement.before, BEFORE), (supplement.after, AFTER)):
        sanitized = sanitize_configuration(text, topology_id=str(DEVICE), pseudonymization_key=KEY)
        assert row.sanitized_source_sha256 == canonical_text_hash(sanitized.text)
        assert len(row.line_scores) == len(text.splitlines())
        assert row.severity_scores is None and row.embedding_dimensions == 8
        assert row.embedding_sha256 is not None and not row.calibrated
    assert multitask_identity(model) == identity
    assert torch.equal(rng, torch.get_rng_state()) and torch.get_num_threads() == threads
    assert not model.heads.training and not model.pretrained.model.training
    assert "private-customer-host" not in result.model_dump_json()
    assert "sanitized_text" not in result.model_dump_json()
    assert 'embedding":' not in result.model_dump_json()
    assert KEY.decode() not in result.model_dump_json()
    assert MLChangeReview.model_validate_json(result.model_dump_json()) == result


def canonical_text_hash(text):
    from hashlib import sha256

    return sha256(text.encode()).hexdigest()


def test_no_selection_is_explicit_and_partial_selected_never_calls_inference(model, monkeypatch):
    result = review_patch_ml(local(), BEFORE, AFTER)
    assert result.transformer.status == "not_selected"
    assert result.transformer.before is None
    before, after = (
        BEFORE + "unknown-command secret-value\n",
        AFTER + "unknown-command secret-value\n",
    )

    def forbidden(*args, **kwargs):
        raise AssertionError("partial inference must not run")

    monkeypatch.setattr("ml.training.multitask_training.predict_multitask", forbidden)
    result = run(model, before, after)
    assert result.transformer.status == "unavailable"
    assert result.transformer.reason == "incomplete_parsing"
    assert result.transformer.before is None and result.transformer.after is None
    assert "secret-value" not in result.model_dump_json()


@pytest.mark.parametrize(
    "updates",
    [
        {"expected_model_sha256": "0" * 64},
        {"expected_model_sha256": None},
        {"pseudonymization_key": None},
        {"pseudonymization_key": b"short"},
    ],
)
def test_selected_model_requires_independent_pin_and_valid_private_key(model, updates):
    with pytest.raises(ValueError):
        run(model, **updates)


def test_changed_raw_inputs_forged_review_training_mode_and_weights_refused(model):
    review = local()
    with pytest.raises(ValueError):
        review_patch_ml(review, BEFORE, AFTER + "ntp server 192.0.2.2\n")
    forged = review.model_copy(
        update={
            "preflight": review.preflight.model_copy(update={"limitations": ("forged review",)})
        }
    )
    with pytest.raises(ValueError):
        review_patch_ml(forged, BEFORE, AFTER)
    model.heads.train()
    try:
        with pytest.raises(ValueError):
            run(model)
    finally:
        model.heads.eval()
    changed = replace(model)
    import copy

    changed.heads = copy.deepcopy(model.heads)
    with torch.no_grad():
        next(changed.heads.parameters()).add_(0.01)
    with pytest.raises(ValueError):
        run(changed, expected_model_sha256=multitask_identity(model))


@pytest.mark.parametrize(
    "tamper", ["source", "side", "model", "line", "status", "risk", "calibration"]
)
def test_numeric_report_rejects_side_and_status_forgery(model, tamper):
    data = json.loads(run(model).model_dump_json())
    supplement = data["transformer"]
    if tamper == "source":
        supplement["after"]["raw_source_sha256"] = "0" * 64
    elif tamper == "side":
        supplement["before"], supplement["after"] = supplement["after"], supplement["before"]
    elif tamper == "model":
        supplement["after"]["model_sha256"] = "0" * 64
    elif tamper == "line":
        supplement["after"]["line_scores"].append(0.5)
    elif tamper == "status":
        data["status"] = "validated"
    elif tamper == "risk":
        supplement["risk_fused"] = True
    else:
        supplement["calibrated"] = True
    with pytest.raises(ValueError):
        MLChangeReview.model_validate(data)


def test_joint_objective_transfer_native_vendor_candidate_both_sides(tmp_path):
    from app.detection.policy_engine import evaluate_policies
    from app.parsers import parse_configuration
    from app.patching.vendor_drafts import create_vendor_draft

    from ml.training.multitask_training import load_multitask, save_multitask
    from ml.training.pretraining import PretrainingPolicy, train_configuration_objectives
    from ml.training.pretraining_smoke import pretraining_fixtures

    splits, pairs = pretraining_fixtures()
    tokenizer = train_config_tokenizer(
        splits, policy=TokenizerPolicy(vocab_size=300, context_length=32)
    )
    source = train_configuration_objectives(
        splits,
        tokenizer,
        semantic_pairs=pairs,
        encoder_policy=EncoderPolicy(hidden_size=16, heads=2, layers=1, feedforward_size=32),
        training_policy=PretrainingPolicy(epochs=1),
    )
    result = train_multitask(
        splits,
        source,
        authored_supervision(splits, (MutationType.TELNET_ENABLED,)),
        semantic_pairs=pairs,
        head_policy=HeadPolicy(classes=("telnet_enabled",), max_examples=128),
        training_policy=FineTunePolicy(epochs=1),
        loss_weights=LossWeights(severity=0),
    )
    bundle = tmp_path / "model"
    save_multitask(result, bundle)
    loaded = load_multitask(bundle)
    from ml.registry.store import initialize_registry, load_registered_model, register_model

    registry = tmp_path / "registry"
    initialize_registry(registry)
    card = register_model(registry, loaded, expected_identity=multitask_identity(loaded))
    assert card.training_format == "multitask-training-0.2.0"
    assert card.source_manifest_sha256 == loaded.report.pretraining.source_manifest_sha256
    loaded = load_registered_model(registry, card.model_sha256)
    before = (
        "set system host-name private-junos\nset system services ssh\nset system services telnet\n"
    )
    finding = next(
        row
        for row in evaluate_policies(
            parse_configuration(before, filename="before.cfg"), device_id=DEVICE
        )
        if row.category == "management.telnet_enabled"
    )
    draft = create_vendor_draft(
        before, finding=finding, source_sha256=canonical_text_hash(before), reference_id="owned"
    )
    reviewed = review_patch_ml(
        draft.metadata.review,
        before,
        draft.candidate_text,
        model=loaded,
        expected_model_sha256=multitask_identity(result),
        pseudonymization_key=KEY,
    )
    assert reviewed.transformer.status == "completed"
    assert reviewed.transformer.training_format == "multitask-training-0.2.0"
    assert reviewed.transformer.before.total_lines == 3
    assert reviewed.transformer.after.total_lines == 2
    assert reviewed.local_review == draft.metadata.review
    assert not reviewed.transformer.quality_evaluated and not reviewed.applied
    assert "private-junos" not in reviewed.model_dump_json()
