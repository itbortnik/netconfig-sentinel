"""Actual tiny authored numeric Forest inputs; no independent quality measurement."""

from datetime import timedelta
from uuid import uuid4

import pytest
from app.api.contracts import (
    AnalysisOptions,
    InventoryLabels,
    TrainModelOptions,
    UploadConfiguration,
)
from app.api.service import AnalysisService
from app.core.settings import ApiSettings
from app.db.migrate import upgrade_database
from app.db.store import Store
from app.detection.statistical.artifact import ForestArtifact
from app.detection.statistical.pair import recheck_original_forest
from app.parsers import parse_configuration
from cryptography.fernet import Fernet


def authored_target_sources(vendor):
    if vendor == "cisco":
        return (
            "hostname target\nline vty 0 4\n transport input telnet ssh\n!\n",
            "hostname target\nline vty 0 4\n transport input ssh\n!\n",
        )
    return (
        "set system host-name target\nset system services telnet\n",
        "set system host-name target\nset system services ssh\n",
    )


@pytest.fixture(scope="module", params=["cisco", "juniper"])
def selected_forest_pair(tmp_path_factory, request):
    directory = tmp_path_factory.mktemp("original-forest-pair")
    store = Store(
        ApiSettings(
            f"sqlite:///{directory / 'owned.sqlite3'}",
            "owned-original-forest-pair-token-000001",
            Fernet.generate_key().decode(),
        )
    )
    upgrade_database(store.engine)
    service = AnalysisService(store)
    inventory = InventoryLabels(
        device_role="edge", site_class="branch", service_profile="owned-control"
    )
    try:
        training = []
        for i in range(8):
            text = (
                (
                    f"hostname train-{i}\nip ssh version 2\n"
                    + "".join(f"ntp server 192.0.2.{20 + j}\n" for j in range(i % 4))
                )
                if request.param == "cisco"
                else (
                    f"set system host-name train-{i}\nset system services ssh\n"
                    + "".join(f"set system ntp server 192.0.2.{20 + j}\n" for j in range(i % 4))
                )
            )
            training.append(
                service.upload(
                    UploadConfiguration(
                        device_id=uuid4(), filename="owned.cfg", content=text, inventory=inventory
                    )
                )
            )
        summary = service.train_model(
            TrainModelOptions(configuration_ids=tuple(s.configuration_id for s in training))
        )
        device = uuid4()
        old, new = authored_target_sources(request.param)
        before, after = [
            service.upload(
                UploadConfiguration(
                    device_id=device,
                    filename="owned.cfg",
                    content=text,
                    inventory=inventory,
                    retain_original_source=True,
                )
            )
            for text in (old, new)
        ]
        analysis = service.analyze(
            before.configuration_id, AnalysisOptions(statistical_model_id=summary.model_id)
        )
        assert analysis is not None and analysis.statistical is not None
        model = store.get_model(summary.model_id)
        assert model is not None
        yield before, after, analysis, model
    finally:
        store.close()


def test_actual_original_artifact_no_refit_and_no_input_mutation(selected_forest_pair, monkeypatch):
    before, after, analysis, model = selected_forest_pair
    frozen = [value.model_dump_json() for value in selected_forest_pair]
    monkeypatch.setattr(
        "sklearn.ensemble.IsolationForest.fit", lambda *a, **k: pytest.fail("refit")
    )
    result = recheck_original_forest(before, after, analysis, model)
    original = analysis.statistical
    assert (
        result.before_score_samples,
        result.before_decision_function,
        result.before_prediction,
    ) == (original.score_samples, original.decision_function, original.prediction)
    assert result.model_id == model.summary.model_id
    assert result.artifact_sha256 == model.artifact.fingerprint()
    assert result.calibrated is result.quality_proven is False
    assert not {"severity", "category_scores", "line_scores", "approved"}.intersection(
        result.model_dump()
    )
    assert [value.model_dump_json() for value in selected_forest_pair] == frozen


@pytest.mark.parametrize(
    "fault",
    [
        "analysis_configuration",
        "analysis_device",
        "analysis_source",
        "no_statistical",
        "model",
        "after_device",
        "same_configuration",
        "same_source",
        "reversed_time",
        "after_group",
        "missing_hostname",
        "training_hostname",
        "training_device",
        "training_source",
        "future_training",
        "partial",
    ],
)
def test_invalid_selection_refuses_before_any_numeric_evaluation(
    selected_forest_pair, monkeypatch, fault
):
    before, after, analysis, model = selected_forest_pair
    if fault.startswith("analysis_"):
        name = fault.removeprefix("analysis_")
        field = {
            "configuration": "configuration_id",
            "device": "device_id",
            "source": "source_sha256",
        }[name]
        analysis = analysis.model_copy(update={field: "b" * 64 if name == "source" else uuid4()})
    elif fault == "no_statistical":
        analysis = analysis.model_copy(update={"statistical": None})
    elif fault == "model":
        model = model.model_copy(
            update={"summary": model.summary.model_copy(update={"model_id": uuid4()})}
        )
    elif fault in {"after_device", "same_configuration", "reversed_time"}:
        field, value = {
            "after_device": ("device_id", uuid4()),
            "same_configuration": ("configuration_id", before.configuration_id),
            "reversed_time": ("created_at", before.created_at - timedelta(seconds=1)),
        }[fault]
        after = after.model_copy(update={field: value})
    elif fault == "same_source":
        after = after.model_copy(update={"canonical": before.canonical, "parser_coverage": None})
    elif fault in {"after_group", "missing_hostname", "training_hostname"}:
        field, value = {
            "after_group": ("role", "different-role"),
            "missing_hostname": ("hostname", None),
            "training_hostname": ("hostname", model.summary.training_hostnames[0]),
        }[fault]
        after = after.model_copy(
            update={
                "canonical": after.canonical.model_copy(
                    update={"device": after.canonical.device.model_copy(update={field: value})}
                )
            }
        )
    elif fault == "partial":
        text = (
            "hostname target\nunknown-command\n"
            if str(after.canonical.device.vendor) == "cisco"
            else "set system host-name target\nset unknown command\n"
        )
        after = after.model_copy(
            update={
                "canonical": parse_configuration(text, filename="owned.cfg"),
                "parser_coverage": None,
            }
        )
    else:
        training = list(model.summary.training)
        row = training[0]
        updates = {
            "training_device": {"device_id": after.device_id},
            "training_source": {"source_sha256": after.canonical.source.sha256},
            "future_training": {"created_at": after.created_at + timedelta(seconds=1)},
        }[fault]
        training[0] = row.model_copy(update=updates)
        summary = model.summary.model_copy(
            update={
                "training": tuple(training),
                "created_at": after.created_at + timedelta(seconds=2),
            }
        )
        model = model.model_copy(update={"summary": summary})
        analysis = analysis.model_copy(
            update={"statistical": analysis.statistical.model_copy(update={"model": summary})}
        )

    monkeypatch.setattr(
        ForestArtifact,
        "score_samples",
        lambda *a: pytest.fail("numeric evaluation before admission"),
    )
    with pytest.raises(ValueError):
        recheck_original_forest(before, after, analysis, model)


def test_changed_original_baseline_refuses_an_otherwise_valid_pair(selected_forest_pair):
    before, after, analysis, model = selected_forest_pair
    original = analysis.statistical
    score = original.score_samples + 1e-6
    decision = score - original.model.decision_offset
    analysis = analysis.model_copy(
        update={
            "statistical": original.model_copy(
                update={
                    "score_samples": score,
                    "decision_function": decision,
                    "prediction": -1 if decision < 0 else 1,
                }
            )
        }
    )
    with pytest.raises(ValueError, match="original statistical baseline differs"):
        recheck_original_forest(before, after, analysis, model)
