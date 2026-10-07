"""Private immutable registry enrollment is not model promotion or quality acceptance."""

import json

import pytest

from ml.evaluation.metrics import canonical_hash
from ml.mutation import MutationType
from ml.preprocessing.tokenization import TokenizerPolicy, train_config_tokenizer
from ml.registry.store import (
    initialize_registry,
    list_models,
    load_registered_model,
    register_model,
)
from ml.training.classification_smoke import classification_fixtures
from ml.training.multitask import HeadPolicy, LossWeights
from ml.training.multitask_smoke import authored_supervision
from ml.training.multitask_training import (
    FineTunePolicy,
    multitask_identity,
    predict_multitask,
    train_multitask,
)
from ml.training.transformer import EncoderPolicy, TrainingPolicy, train_masked_language_model


@pytest.fixture(scope="module")
def model():
    splits = classification_fixtures()
    tokenizer = train_config_tokenizer(
        splits, policy=TokenizerPolicy(vocab_size=300, context_length=16)
    )
    encoder = train_masked_language_model(
        splits,
        tokenizer,
        encoder_policy=EncoderPolicy(hidden_size=16, heads=2, layers=1, feedforward_size=32),
        training_policy=TrainingPolicy(epochs=1),
    )
    examples = authored_supervision(splits, (MutationType.TELNET_ENABLED,))
    trained = train_multitask(
        splits,
        encoder,
        examples,
        head_policy=HeadPolicy(classes=("telnet_enabled",), embedding_size=8),
        training_policy=FineTunePolicy(epochs=1),
        loss_weights=LossWeights(severity=0),
    )
    return trained, examples[0].record


def enroll(tmp_path, model):
    root = tmp_path / "registry"
    initialize_registry(root)
    trained, _ = model
    pin = multitask_identity(trained)
    card = register_model(root, trained, expected_identity=pin)
    return root, pin, card


def test_actual_native_enrollment_reload_and_private_numeric_card(model, tmp_path):
    root, pin, card = enroll(tmp_path, model)
    assert card.model_sha256 == pin and card.kind == "native"
    assert card.training_format == "multitask-training-0.1.0"
    assert card.parameter_count > card.trainable_parameters > 0
    assert not card.enabled_heads["severity"]
    assert not card.production_quality_proven and not card.calibrated and not card.activated
    assert card.source_manifest_sha256 is None  # Legacy has no objective manifest binding.
    restored = load_registered_model(root, pin)
    assert multitask_identity(restored) == pin
    assert predict_multitask(restored, model[1]) == predict_multitask(model[0], model[1])
    assert list_models(root) == (card,)
    assert not (root / pin / ".incomplete").exists()
    assert (
        "source_root" not in card.model_dump_json()
        and "sanitized_text" not in card.model_dump_json()
    )


def test_existing_root_and_entry_are_never_overwritten(model, tmp_path):
    root, pin, _ = enroll(tmp_path, model)
    before = (root / pin / "entry.json").read_bytes()
    with pytest.raises(FileExistsError):
        initialize_registry(root)
    with pytest.raises(FileExistsError):
        register_model(root, model[0], expected_identity=pin)
    assert (root / pin / "entry.json").read_bytes() == before


@pytest.mark.parametrize("pin", ("0" * 64, "../private", "F" * 64))
def test_wrong_or_unsafe_pin_does_not_create_an_entry(model, tmp_path, pin):
    root = tmp_path / "registry"
    initialize_registry(root)
    with pytest.raises(ValueError):
        register_model(root, model[0], expected_identity=pin)
    assert {item.name for item in root.iterdir()} == {"registry.json"}
    with pytest.raises(ValueError):
        load_registered_model(root, pin)


@pytest.mark.parametrize("damage", ("count", "kind", "checksum", "incomplete", "extra"))
def test_independent_pin_and_fresh_card_reject_changed_registry_metadata(model, tmp_path, damage):
    root, pin, _ = enroll(tmp_path, model)
    path = root / pin / "entry.json"
    if damage in ("count", "kind", "checksum"):
        payload = json.loads(path.read_text(encoding="utf-8"))
        if damage == "count":
            payload["card"]["train_examples"] += 1
        elif damage == "kind":
            payload["card"]["kind"] = "foundation"
        else:
            payload["sha256"] = "0" * 64
        if damage != "checksum":
            payload["sha256"] = canonical_hash(payload["card"])
        path.write_text(json.dumps(payload), encoding="utf-8")
    elif damage == "incomplete":
        (root / pin / ".incomplete").write_text("partial", encoding="utf-8")
    else:
        (root / pin / "unexpected.json").write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError):
        load_registered_model(root, pin)


@pytest.mark.parametrize("kind", ("is_symlink", "is_junction"))
@pytest.mark.parametrize("target", ("root", "entry", "bundle", "ancestor"))
def test_linked_components_are_refused_without_reading_or_enrolling(
    model, tmp_path, monkeypatch, kind, target
):
    from pathlib import Path

    root, pin, _ = enroll(tmp_path, model)
    linked = {
        "root": root,
        "entry": root / pin,
        "bundle": root / pin / "bundle",
        "ancestor": root.parent,
    }[target]
    original = getattr(Path, kind)
    monkeypatch.setattr(Path, kind, lambda self: self == linked or original(self))
    with pytest.raises(ValueError):
        load_registered_model(root, pin)


def test_native_entry_cannot_use_external_source_or_model_name_as_path(model, tmp_path):
    root, pin, _ = enroll(tmp_path, model)
    with pytest.raises(ValueError):
        load_registered_model(root, pin, foundation_source=tmp_path)
    with pytest.raises(ValueError):
        load_registered_model(root, "../" + pin)


def test_no_unknown_root_files_or_unbounded_entry_inventory(model, tmp_path):
    root, _, _ = enroll(tmp_path, model)
    (root / "unexpected.txt").write_text("private", encoding="utf-8")
    with pytest.raises(ValueError):
        list_models(root)


def test_cli_native_registration_and_check_are_explicit_private_and_new_only(
    model, tmp_path, capsys
):
    from ml.registry.cli import main
    from ml.training.multitask_training import save_multitask

    root, bundle = tmp_path / "registry", tmp_path / "trusted"
    save_multitask(model[0], bundle)
    pin = multitask_identity(model[0])
    assert main(["init", "--root", str(root)]) == 0
    command = ["register", "--root", str(root), "--model", str(bundle), "--model-sha256", pin]
    assert main(command) == 0
    assert main(["list", "--root", str(root)]) == 0
    assert main(["check", "--root", str(root), "--model-sha256", pin]) == 0
    assert main(command) == 2
    printed = capsys.readouterr()
    assert str(tmp_path) not in printed.out + printed.err
    assert '"binding_rechecked": false' in printed.out
    assert '"binding_rechecked": true' in printed.out


def test_metadata_only_import_and_listing_never_load_optional_models(model, tmp_path):
    import subprocess
    import sys
    from pathlib import Path

    root, pin, _ = enroll(tmp_path, model)
    project = Path(__file__).resolve().parents[3]
    code = (
        "import sys; sys.path[:0]=sys.argv[1:3]; "
        "from ml.registry.store import list_models; from pathlib import Path; "
        "assert list_models(Path(sys.argv[3]))[0].model_sha256==sys.argv[4]; "
        "assert 'torch' not in sys.modules and 'transformers' not in sys.modules"
    )
    result = subprocess.run(
        [sys.executable, "-I", "-c", code, str(project), str(project / "backend"), str(root), pin],
        capture_output=True,
        timeout=20,
        check=False,
    )
    assert result.returncode == 0 and not result.stdout and not result.stderr


@pytest.mark.parametrize("damage", ("duplicates", "oversize", "activation", "promotion"))
def test_manifest_is_bounded_unique_and_cannot_promote_a_model(model, tmp_path, damage):
    from ml.registry.store import MAX_METADATA_BYTES

    root, pin, _ = enroll(tmp_path, model)
    path = root / "registry.json"
    if damage == "duplicates":
        content = '{"version":"config-model-registry-0.1.0","version":"duplicate"}'
    elif damage == "oversize":
        content = " " * (MAX_METADATA_BYTES + 1)
    else:
        data = json.loads(path.read_text(encoding="utf-8"))
        data["automatic_activation" if damage == "activation" else "deployment_approval"] = True
        content = json.dumps(data)
    path.write_text(content, encoding="utf-8")
    with pytest.raises(ValueError):
        list_models(root)
    with pytest.raises(ValueError):
        load_registered_model(root, pin)


def test_entry_budget_is_enforced_before_loading_any_model(model, tmp_path, monkeypatch):
    from ml.registry import store

    root, _, _ = enroll(tmp_path, model)
    monkeypatch.setattr(store, "MAX_ENTRIES", 1)
    (root / ("f" * 64)).mkdir()
    with pytest.raises(ValueError):
        list_models(root)


def test_failed_serialization_keeps_incomplete_entry_and_never_reports_success(
    model, tmp_path, monkeypatch
):
    from ml.training import multitask_training

    root = tmp_path / "registry"
    initialize_registry(root)
    pin = multitask_identity(model[0])

    def fail(*_):
        raise OSError("owned failure")

    monkeypatch.setattr(multitask_training, "save_multitask", fail)
    with pytest.raises(OSError):
        register_model(root, model[0], expected_identity=pin)
    assert (root / pin / ".incomplete").is_file()
    with pytest.raises(ValueError):
        list_models(root)
    with pytest.raises(ValueError):
        load_registered_model(root, pin)
    with pytest.raises(FileExistsError):
        register_model(root, model[0], expected_identity=pin)


def test_named_encoder_directories_are_not_regular_checkpoint_files(model, tmp_path):
    root, pin, _ = enroll(tmp_path, model)
    weights = root / pin / "bundle" / "encoder" / "weights.pt"
    weights.unlink()  # Generated fixture only.
    weights.mkdir()
    with pytest.raises(ValueError):
        list_models(root)


@pytest.mark.parametrize("flag", ("activated", "calibrated", "production_quality_proven"))
def test_card_cannot_claim_deployment_calibration_or_quality(model, tmp_path, flag):
    from ml.registry.contracts import ModelCard

    _, _, card = enroll(tmp_path, model)
    with pytest.raises(ValueError):
        ModelCard.model_validate(card.model_copy(update={flag: True}).model_dump())
