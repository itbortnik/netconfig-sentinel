"""Reviewed fixture admission, lightweight metadata and opt-in actual diagnostics."""

import copy
import json
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from uuid import uuid4

import pytest
import torch
from app.domain import Vendor
from app.patching.proposal import create_patch_proposal
from app.patching.review import review_patch_proposal
from test_fixture_transfer import fitted as fitted
from test_fixture_transfer import inputs as inputs

from ml.evaluation.metrics import canonical_hash
from ml.inference.change_contracts import MLChangeReview
from ml.inference.change_review import review_patch_ml
from ml.inference.configuration import infer_configuration
from ml.registry.admission import load_fixture_admission
from ml.registry.cli import main as registry_main
from ml.registry.contracts import EntryEnvelope, FixtureModelCard
from ml.registry.store import (
    FixtureAdmissionContext,
    initialize_registry,
    list_models,
    load_registered_model,
    register_model,
)
from ml.training.multitask_training import multitask_identity, save_multitask

KEY = b"owned-fixture-registry-test-key"


def context(inputs):
    corpus, _, splits, examples = inputs
    return FixtureAdmissionContext(corpus, splits, examples)


def root(tmp_path):
    path = tmp_path / "registry"
    initialize_registry(path)
    return path


def input_payload(inputs):
    corpus, _, splits, examples = inputs
    return {
        "version": "fixture-registry-input-0.1.0",
        "manifest": corpus.manifest.model_dump(mode="json"),
        "records": [row.model_dump(mode="json") for row in corpus.imported],
        "splits": splits.model_dump(mode="json"),
        "examples": [
            {
                "record": row.record.model_dump(mode="json"),
                "parent_sha256": row.parent_sha256,
                "annotation": row.annotation.model_dump(mode="json"),
            }
            for row in examples
        ],
    }


def test_actual_fixture_admission_card_and_selected_load(inputs, fitted, tmp_path):
    directory = root(tmp_path)
    pin = multitask_identity(fitted)
    rng, threads = torch.get_rng_state().clone(), torch.get_num_threads()
    card = register_model(
        directory, fitted, expected_identity=pin, fixture_admission=context(inputs)
    )
    assert isinstance(card, FixtureModelCard) and card.version == "config-model-card-0.2.0"
    assert card.training_format == "multitask-training-0.3.0"
    assert card.pretraining == fitted.report.pretraining
    assert not card.physical_pretraining_isolation_proven
    assert not card.activated and not card.calibrated and not card.production_quality_proven
    assert list_models(directory) == (card,)
    restored = load_registered_model(directory, pin)
    assert multitask_identity(restored) == pin and restored.report == fitted.report
    assert torch.equal(rng, torch.get_rng_state()) and torch.get_num_threads() == threads
    with pytest.raises(FileExistsError):
        register_model(directory, fitted, expected_identity=pin, fixture_admission=context(inputs))


@pytest.mark.parametrize(
    "damage", ["missing", "corpus", "permission", "annotations", "split", "pin"]
)
def test_missing_or_changed_admission_inputs_refuse_before_entry_allocation(
    inputs,
    fitted,
    tmp_path,
    damage,
):
    directory, admission = root(tmp_path), context(inputs)
    pin = multitask_identity(fitted)
    if damage == "missing":
        admission = None
    elif damage == "corpus":
        admission = replace(
            admission, corpus=replace(admission.corpus, imported=admission.corpus.imported[:-1])
        )
    elif damage == "permission":
        manifest = admission.corpus.manifest
        changed = manifest.model_copy(
            update={"source": manifest.source.model_copy(update={"allowed_uses": []})}
        )
        admission = replace(admission, corpus=replace(admission.corpus, manifest=changed))
    elif damage == "annotations":
        row = admission.examples[0]
        changed = replace(
            row, annotation=row.annotation.model_copy(update={"annotation_sha256": "f" * 64})
        )
        admission = replace(admission, examples=(changed, *admission.examples[1:]))
    elif damage == "split":
        from ml.training.pretraining_smoke import pretraining_fixtures

        admission = replace(admission, splits=pretraining_fixtures()[0])
    else:
        pin = "f" * 64
    with pytest.raises(ValueError):
        register_model(directory, fitted, expected_identity=pin, fixture_admission=admission)
    assert sorted(item.name for item in directory.iterdir()) == ["registry.json"]


@pytest.mark.parametrize("damage", ["source", "counts", "isolation", "format", "kind"])
def test_recomputed_metadata_checksum_does_not_authorize_changed_card(
    inputs, fitted, tmp_path, damage
):
    directory = root(tmp_path)
    pin = multitask_identity(fitted)
    register_model(directory, fitted, expected_identity=pin, fixture_admission=context(inputs))
    path = directory / pin / "entry.json"
    payload = json.loads(path.read_text())
    card = payload["card"]
    if damage == "source":
        card["pretraining"]["report_sha256"] = "f" * 64
    elif damage == "counts":
        card["train_examples"] += 1
    elif damage == "isolation":
        card["physical_pretraining_isolation_proven"] = True
    elif damage == "format":
        card["training_format"] = "multitask-training-0.2.0"
    else:
        card["kind"] = "foundation"
    payload["sha256"] = canonical_hash(card)
    path.write_text(json.dumps(payload))
    with pytest.raises(ValueError):
        load_registered_model(directory, pin)


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
def test_fixture_card_cannot_promote_or_coerce_experimental_flags(
    inputs, fitted, tmp_path, flag, value
):
    card = register_model(
        root(tmp_path),
        fitted,
        expected_identity=multitask_identity(fitted),
        fixture_admission=context(inputs),
    )
    changed = card.model_dump() | {flag: value}
    with pytest.raises(ValueError):
        FixtureModelCard.model_validate(changed)


def test_metadata_listing_in_fresh_process_does_not_import_optional_runtime(
    inputs, fitted, tmp_path
):
    directory = root(tmp_path)
    register_model(
        directory,
        fitted,
        expected_identity=multitask_identity(fitted),
        fixture_admission=context(inputs),
    )
    project = Path(__file__).resolve().parents[3]
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
cards = list_models(Path(sys.argv[3]))
assert cards[0].version == 'config-model-card-0.2.0'
assert 'torch' not in sys.modules and 'transformers' not in sys.modules
print('metadata-only')
"""
    completed = subprocess.run(
        [sys.executable, "-I", "-c", code, str(project), str(project / "backend"), str(directory)],
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "metadata-only"


def test_bounded_private_cli_admission_is_explicit_and_general(inputs, fitted, tmp_path, capsys):
    directory = root(tmp_path)
    bundle = tmp_path / "model"
    save_multitask(fitted, bundle)
    pin = multitask_identity(fitted)
    args = ["register", "--root", str(directory), "--model", str(bundle), "--model-sha256", pin]
    assert registry_main(args) == 2
    assert sorted(item.name for item in directory.iterdir()) == ["registry.json"]
    data = tmp_path / "private-admission.json"
    data.write_text(json.dumps(input_payload(inputs)))
    assert load_fixture_admission(data, fitted) == context(inputs)
    assert registry_main([*args, "--fixture-admission", str(data)]) == 0
    captured = capsys.readouterr()
    assert "private-admission.json" not in captured.out + captured.err
    assert "sanitized_text" not in captured.out
    assert registry_main(["check", "--root", str(directory), "--model-sha256", pin]) == 0


def test_native_admission_does_not_require_external_retrieval_runtime(inputs, fitted, tmp_path):
    project = Path(__file__).resolve().parents[3]
    save_multitask(fitted, tmp_path / "model")
    (tmp_path / "admission.json").write_text(json.dumps(input_payload(inputs)))
    code = """
import sys
from importlib.abc import MetaPathFinder
sys.path[:0] = [sys.argv[1], sys.argv[2]]
class DenyExternalRuntime(MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] in ('transformers', 'safetensors'):
            raise ModuleNotFoundError('external runtime blocked')
sys.meta_path.insert(0, DenyExternalRuntime())
from pathlib import Path
from ml.registry.cli import main
root, pin = Path(sys.argv[3]), sys.argv[4]
assert main(['init', '--root', str(root / 'registry')]) == 0
assert main(['register', '--root', str(root / 'registry'), '--model', str(root / 'model'),
             '--model-sha256', pin, '--fixture-admission', str(root / 'admission.json')]) == 0
assert 'transformers' not in sys.modules and 'safetensors' not in sys.modules
print('native-admission-only')
"""
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            code,
            str(project),
            str(project / "backend"),
            str(tmp_path),
            multitask_identity(fitted),
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip().endswith("native-admission-only")
    assert "sanitized_text" not in completed.stdout and str(tmp_path) not in completed.stdout


@pytest.mark.parametrize("damage", ["unknown", "duplicate", "missing", "truth", "permission"])
def test_private_admission_json_does_not_relax_source_or_annotation_contracts(
    inputs, fitted, tmp_path, damage
):
    data = tmp_path / "admission.json"
    payload = input_payload(inputs)
    if damage == "unknown":
        payload["approved"] = True
    elif damage == "missing":
        payload["records"].pop()
    elif damage == "truth":
        payload["examples"][0]["annotation"]["annotation_sha256"] = "f" * 64
    elif damage == "permission":
        payload["manifest"]["source"]["allowed_uses"] = []
    data.write_text(json.dumps(payload))
    if damage == "duplicate":
        data.write_text('{"version":"a","version":"b"}')
    directory = root(tmp_path)
    with pytest.raises(ValueError):
        admission = load_fixture_admission(data, fitted)
        register_model(
            directory,
            fitted,
            expected_identity=multitask_identity(fitted),
            fixture_admission=admission,
        )
    assert sorted(item.name for item in directory.iterdir()) == ["registry.json"]


@pytest.mark.parametrize("kind", ["is_symlink", "is_junction"])
@pytest.mark.parametrize("target", ["file", "parent", "ancestor"])
def test_private_admission_refuses_linked_paths_before_reading(
    fitted, tmp_path, monkeypatch, kind, target
):
    path = tmp_path / "private" / "admission.json"
    selected = {"file": path, "parent": path.parent, "ancestor": tmp_path}[target]
    original = getattr(Path, kind)
    monkeypatch.setattr(Path, kind, lambda self: self == selected or original(self))

    def unexpected_read(*args):
        pytest.fail("linked admission input must be refused before any read")

    monkeypatch.setattr("ml.registry.admission._read_json", unexpected_read)
    with pytest.raises(ValueError, match="linked inference path"):
        load_fixture_admission(path, fitted)


@pytest.mark.parametrize("vendor", [Vendor.CISCO, Vendor.JUNIPER])
def test_actual_single_source_and_pre_post_keep_private_content_and_no_promotion(fitted, vendor):
    before = (
        "hostname owned-private\nip ssh version 1\n"
        if vendor is Vendor.CISCO
        else "set system host-name owned-private\nset system services telnet\n"
    )
    after = before.replace("version 1", "version 2").replace("services telnet", "services ssh")
    pin, device = multitask_identity(fitted), uuid4()
    rng, threads = torch.get_rng_state().clone(), torch.get_num_threads()
    inference = infer_configuration(
        before,
        vendor=vendor,
        device_id=device,
        model=fitted,
        expected_model_sha256=pin,
        pseudonymization_key=KEY,
    )
    assert inference.model.version == "config-model-card-0.2.0"
    assert not inference.model.physical_pretraining_isolation_proven
    assert not inference.risk_fused and not inference.production_quality_proven
    proposal = create_patch_proposal(before, after, device_id=device, reference_id="owned-fixture")
    local = review_patch_proposal(proposal, before, after, device_id=device)
    review = review_patch_ml(
        local, before, after, model=fitted, expected_model_sha256=pin, pseudonymization_key=KEY
    )
    assert (
        review.local_review == local
        and review.transformer.training_format == "multitask-training-0.3.0"
    )
    assert review.status == "needs_review" and review.formal_verification == "not_run"
    assert not review.applied and not review.transformer.risk_fused
    assert MLChangeReview.model_validate_json(review.model_dump_json()) == review
    assert "owned-private" not in inference.model_dump_json()
    assert (
        "sanitized_text" not in inference.model_dump_json()
        and KEY.decode() not in inference.model_dump_json()
    )
    assert multitask_identity(fitted) == pin
    assert torch.equal(rng, torch.get_rng_state()) and torch.get_num_threads() == threads
    envelope = EntryEnvelope(
        card=inference.model, sha256=canonical_hash(inference.model.model_dump(mode="json"))
    )
    assert EntryEnvelope.model_validate_json(envelope.model_dump_json()) == envelope


def test_encoder_drift_is_not_hidden_by_new_card_generation(fitted):
    altered = copy.deepcopy(fitted)
    with torch.no_grad():
        altered.pretrained.model.projection.bias[0] += 1
    with pytest.raises(ValueError):
        infer_configuration(
            "hostname owned\n",
            vendor=Vendor.CISCO,
            device_id=uuid4(),
            model=altered,
            expected_model_sha256=multitask_identity(fitted),
            pseudonymization_key=KEY,
        )
