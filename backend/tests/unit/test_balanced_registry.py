"""Exact experimental 0.4 enrollment and diagnostics without silently widening history."""

import copy
import json
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from uuid import uuid4

import app
import pytest
from app.domain import Vendor
from app.patching.proposal import create_patch_proposal
from app.patching.review import review_patch_proposal
from test_balanced_localization import balanced as balanced
from test_balanced_localization import inputs as inputs
from test_fixture_registry import context, input_payload, root

import ml
from ml.evaluation.metrics import canonical_hash
from ml.inference.change_contracts import MLChangeReview
from ml.inference.change_review import review_patch_ml
from ml.inference.configuration import infer_configuration
from ml.registry.admission import load_fixture_admission
from ml.registry.cli import main as registry_main
from ml.registry.contracts import BalancedFixtureModelCard, EntryEnvelope, FixtureModelCard
from ml.registry.store import list_models, load_registered_model, register_model
from ml.training.multitask_training import multitask_identity, save_multitask


def test_exact_existing_balance_and_explicit_cli_admission(inputs, balanced, tmp_path):
    directory, bundle, data = root(tmp_path), tmp_path / "model", tmp_path / "admission.json"
    pin = multitask_identity(balanced)
    save_multitask(balanced, bundle)
    data.write_text(json.dumps(input_payload(inputs)), encoding="utf-8")
    args = ["register", "--root", str(directory), "--model", str(bundle), "--model-sha256", pin]
    assert registry_main(args) == 2
    assert list(directory.iterdir()) == [directory / "registry.json"]
    assert registry_main([*args, "--fixture-admission", str(data)]) == 0
    assert load_fixture_admission(data, balanced) == context(inputs)
    card = list_models(directory)[0]
    assert isinstance(card, BalancedFixtureModelCard)
    assert card.version == "config-model-card-0.3.0"
    assert card.training_format == "multitask-training-0.4.0"
    assert card.localization_objective == balanced.report.localization_objective
    assert card.localization_task_weight == balanced.report.loss_weights.localization
    assert card.line_score_semantics == "cost_sensitive_uncalibrated"
    assert card.pretraining == balanced.report.pretraining
    assert not card.physical_pretraining_isolation_proven and not card.calibrated
    assert not card.activated and not card.production_quality_proven
    restored = load_registered_model(directory, pin)
    assert multitask_identity(restored) == pin and restored.report == balanced.report
    with pytest.raises(ValueError):
        FixtureModelCard.model_validate(card.model_dump())
    with pytest.raises(FileExistsError):
        register_model(
            directory, balanced, expected_identity=pin, fixture_admission=context(inputs)
        )


@pytest.mark.parametrize("damage", ["objective", "task_weight", "train", "semantics", "format"])
def test_rehashed_card_cannot_substitute_objective_or_semantics(inputs, balanced, tmp_path, damage):
    directory, pin = root(tmp_path), multitask_identity(balanced)
    register_model(directory, balanced, expected_identity=pin, fixture_admission=context(inputs))
    path = directory / pin / "entry.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    card = payload["card"]
    if damage == "objective":
        objective = card["localization_objective"]
        objective["positive_lines"], objective["negative_lines"] = (
            objective["negative_lines"],
            objective["positive_lines"],
        )
        objective["positive_weight"] = objective["negative_lines"] / objective["positive_lines"]
    elif damage == "task_weight":
        card["localization_task_weight"] = 0.5
    elif damage == "train":
        card["localization_objective"]["train_fingerprint"] = "f" * 64
    elif damage == "semantics":
        card["line_score_semantics"] = "calibrated_probability"
    else:
        card["version"], card["training_format"] = (
            "config-model-card-0.2.0",
            "multitask-training-0.3.0",
        )
    payload["sha256"] = canonical_hash(card)
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError):
        load_registered_model(directory, pin)


def test_self_consistent_forged_train_ratio_refuses_before_allocation(inputs, balanced, tmp_path):
    forged = copy.copy(balanced)
    count = balanced.report.localization_objective.eligible_lines
    forged.report = balanced.report.model_copy(
        update={
            "localization_objective": balanced.report.localization_objective.model_copy(
                update={
                    "positive_lines": 1,
                    "negative_lines": count - 1,
                    "positive_weight": float(count - 1),
                }
            ),
        }
    )
    directory = root(tmp_path)
    with pytest.raises(ValueError, match="retained aligned train"):
        register_model(
            directory,
            forged,
            expected_identity=multitask_identity(forged),
            fixture_admission=context(inputs),
        )
    assert list(directory.iterdir()) == [directory / "registry.json"]


@pytest.mark.parametrize("damage", ["missing", "corpus", "permission", "annotations", "pin"])
def test_balanced_retained_inputs_remain_mandatory(inputs, balanced, tmp_path, damage):
    directory, admission, pin = root(tmp_path), context(inputs), multitask_identity(balanced)
    if damage == "missing":
        admission = None
    elif damage == "corpus":
        admission = replace(
            admission, corpus=replace(admission.corpus, imported=admission.corpus.imported[:-1])
        )
    elif damage == "permission":
        changed = admission.corpus.manifest.model_copy(
            update={
                "source": admission.corpus.manifest.source.model_copy(update={"allowed_uses": []}),
            }
        )
        admission = replace(admission, corpus=replace(admission.corpus, manifest=changed))
    elif damage == "annotations":
        first = admission.examples[0]
        first = replace(
            first,
            annotation=first.annotation.model_copy(
                update={
                    "annotation_sha256": "f" * 64,
                }
            ),
        )
        admission = replace(admission, examples=(first, *admission.examples[1:]))
    else:
        pin = "f" * 64
    with pytest.raises(ValueError):
        register_model(directory, balanced, expected_identity=pin, fixture_admission=admission)
    assert list(directory.iterdir()) == [directory / "registry.json"]


@pytest.mark.parametrize(
    "flag",
    [
        "physical_pretraining_isolation_proven",
        "calibrated",
        "activated",
        "production_quality_proven",
    ],
)
@pytest.mark.parametrize("value", [True, 0, "false"])
def test_balanced_card_flags_cannot_be_promoted_or_coerced(inputs, balanced, tmp_path, flag, value):
    card = register_model(
        root(tmp_path),
        balanced,
        expected_identity=multitask_identity(balanced),
        fixture_admission=context(inputs),
    )
    with pytest.raises(ValueError):
        BalancedFixtureModelCard.model_validate(card.model_dump() | {flag: value})


def test_balanced_metadata_has_no_optional_tensor_imports(inputs, balanced, tmp_path):
    directory = root(tmp_path)
    register_model(
        directory,
        balanced,
        expected_identity=multitask_identity(balanced),
        fixture_admission=context(inputs),
    )
    code = """
import sys
from importlib.abc import MetaPathFinder
from pathlib import Path
sys.path[:0] = [sys.argv[1], sys.argv[2]]
class DenyRuntime(MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] in ('torch', 'transformers'):
            raise ModuleNotFoundError('optional runtime blocked')
sys.meta_path.insert(0, DenyRuntime())
from ml.registry.store import list_models
from ml.inference.config_contracts import ConfigurationInferenceReport
cards = list_models(Path(sys.argv[3]))
assert cards[0].version == 'config-model-card-0.3.0'
assert cards[0].line_score_semantics == 'cost_sensitive_uncalibrated'
assert 'torch' not in sys.modules and 'transformers' not in sys.modules
print('metadata-only')
"""
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            code,
            str(Path(app.__file__).resolve().parent.parent),
            str(Path(ml.__file__).resolve().parent.parent),
            str(directory),
        ],
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "metadata-only"


@pytest.mark.parametrize("vendor", [Vendor.CISCO, Vendor.JUNIPER])
def test_balanced_actual_configuration_and_change_keep_scores_uncalibrated(balanced, vendor):
    before = (
        "hostname owned\nip ssh version 1\n"
        if vendor is Vendor.CISCO
        else ("set system host-name owned\nset system services telnet\n")
    )
    after = before.replace("version 1", "version 2").replace("services telnet", "services ssh")
    pin, device, key = multitask_identity(balanced), uuid4(), b"owned-balanced-registry-key"
    inference = infer_configuration(
        before,
        vendor=vendor,
        device_id=device,
        model=balanced,
        expected_model_sha256=pin,
        pseudonymization_key=key,
    )
    assert isinstance(inference.model, BalancedFixtureModelCard)
    proposal = create_patch_proposal(before, after, device_id=device, reference_id="owned")
    local = review_patch_proposal(proposal, before, after, device_id=device)
    review = review_patch_ml(
        local, before, after, model=balanced, expected_model_sha256=pin, pseudonymization_key=key
    )
    assert review.transformer.training_format == "multitask-training-0.4.0"
    assert review.status == "needs_review" and review.formal_verification == "not_run"
    assert not review.applied and not review.transformer.risk_fused and not inference.risk_fused
    assert not review.transformer.calibrated and not inference.calibrated
    assert MLChangeReview.model_validate_json(review.model_dump_json()) == review
    envelope = EntryEnvelope(
        card=inference.model, sha256=canonical_hash(inference.model.model_dump(mode="json"))
    )
    assert EntryEnvelope.model_validate_json(envelope.model_dump_json()) == envelope
    assert multitask_identity(balanced) == pin
