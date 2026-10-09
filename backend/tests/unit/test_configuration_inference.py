"""Single-source model diagnostics do not invent calibrated findings or patch checks."""

from copy import deepcopy
from dataclasses import replace
from uuid import uuid4

import pytest
import torch
from app.api.configuration_model_contracts import RunConfigurationModel
from app.core.configuration_model import ConfigurationModelSettings
from app.domain import Vendor

from ml.inference.config_contracts import ConfigurationInferenceReport
from ml.inference.configuration import infer_configuration
from ml.mutation import MutationType
from ml.preprocessing.tokenization import TokenizerPolicy, train_config_tokenizer
from ml.training.classification_smoke import classification_fixtures
from ml.training.multitask import HeadPolicy, LossWeights
from ml.training.multitask_smoke import authored_supervision
from ml.training.multitask_training import FineTunePolicy, multitask_identity, train_multitask
from ml.training.transformer import EncoderPolicy, TrainingPolicy, train_masked_language_model

KEY = b"owned-configuration-inference-key"


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


@pytest.mark.parametrize("vendor", [Vendor.CISCO, Vendor.JUNIPER])
def test_actual_native_single_source_is_sanitized_bound_and_read_only(model, vendor):
    content = (
        "hostname private-account-host\nip ssh version 1\n"
        if vendor == Vendor.CISCO
        else "set system host-name private-account-host\nset system services ssh\n"
    )
    rng, threads = torch.get_rng_state().clone(), torch.get_num_threads()
    pin = multitask_identity(model)
    result = infer_configuration(
        content,
        vendor=vendor,
        device_id=uuid4(),
        model=model,
        expected_model_sha256=pin,
        pseudonymization_key=KEY,
    )
    assert result.model.model_sha256 == pin == result.prediction.model_sha256
    assert len(result.prediction.line_scores) == 2
    assert result.prediction.severity_scores is None
    assert result.prediction.embedding_dimensions == 8
    assert not result.risk_fused and not result.calibrated and not result.quality_evaluated
    assert "private-account-host" not in result.model_dump_json()
    assert KEY.decode() not in result.model_dump_json()
    assert "sanitized_text" not in result.model_dump_json()
    assert torch.equal(rng, torch.get_rng_state()) and torch.get_num_threads() == threads
    assert multitask_identity(model) == pin
    assert ConfigurationInferenceReport.model_validate_json(result.model_dump_json()) == result


@pytest.mark.parametrize("damage", ["model", "classes", "severity", "head", "flag"])
def test_report_refuses_cross_model_or_disabled_head_outputs(model, damage):
    result = infer_configuration(
        "hostname owned\n",
        vendor=Vendor.CISCO,
        device_id=uuid4(),
        model=model,
        expected_model_sha256=multitask_identity(model),
        pseudonymization_key=KEY,
    )
    changed = deepcopy(result.model_dump(mode="json"))
    if damage == "model":
        changed["prediction"]["model_sha256"] = "0" * 64
    elif damage == "classes":
        changed["prediction"]["category_scores"] = {"invented_class": 0.5}
    elif damage == "severity":
        changed["prediction"]["severity_scores"] = dict.fromkeys(
            ("info", "low", "medium", "high", "critical"), 0.2
        )
    elif damage == "head":
        changed["model"]["enabled_heads"]["anomaly"] = False
    else:
        changed["risk_fused"] = True
    with pytest.raises(ValueError):
        ConfigurationInferenceReport.model_validate(changed)


@pytest.mark.parametrize("key", [b"short", None])
def test_single_source_requires_private_key_and_independent_pin(model, key):
    with pytest.raises(ValueError):
        infer_configuration(
            "hostname owned\n",
            vendor=Vendor.CISCO,
            device_id=uuid4(),
            model=model,
            expected_model_sha256=multitask_identity(model),
            pseudonymization_key=key,
        )
    with pytest.raises(ValueError):
        infer_configuration(
            "hostname owned\n",
            vendor=Vendor.CISCO,
            device_id=uuid4(),
            model=model,
            expected_model_sha256="0" * 64,
            pseudonymization_key=KEY,
        )


@pytest.mark.parametrize("mode", ["heads", "encoder"])
def test_single_source_refuses_mutated_nested_training_mode(model, mode):
    module = model.heads if mode == "heads" else model.pretrained.model
    module.train()
    try:
        with pytest.raises(ValueError):
            infer_configuration(
                "hostname owned\n",
                vendor=Vendor.CISCO,
                device_id=uuid4(),
                model=model,
                expected_model_sha256=multitask_identity(model),
                pseudonymization_key=KEY,
            )
    finally:
        module.eval()


def test_settings_are_explicit_fixed_and_request_boolean_is_exact(tmp_path, monkeypatch):
    for name in (
        "NETCONFIG_CONFIG_MODEL_REGISTRY",
        "NETCONFIG_CONFIG_MODEL_SHA256",
        "NETCONFIG_CONFIG_MODEL_FOUNDATION_SOURCE",
    ):
        monkeypatch.delenv(name, raising=False)
    assert ConfigurationModelSettings.from_environment() is None
    settings = ConfigurationModelSettings(registry_root=tmp_path, model_sha256="a" * 64)
    assert settings.timeout_seconds == 60
    with pytest.raises(ValueError):
        replace(settings, timeout_seconds=True)
    with pytest.raises(ValueError):
        replace(settings, model_sha256=None)
    monkeypatch.setenv("NETCONFIG_CONFIG_MODEL_REGISTRY", str(tmp_path))
    with pytest.raises(ValueError):
        ConfigurationModelSettings.from_environment()
    for permission in (1, "true", None):
        with pytest.raises(ValueError):
            RunConfigurationModel(
                inference_id=uuid4(),
                analysis_id=uuid4(),
                source_sha256="a" * 64,
                model_sha256="b" * 64,
                allow_local_model_context=permission,
            )
