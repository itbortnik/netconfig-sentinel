"""Owned synthetic protocol checks; actual model execution is explicitly separate."""

import os
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from app.api.configuration_model_contracts import (
    ConfigurationModelIntent,
    RunConfigurationModel,
    fingerprint,
)
from app.api.contracts import SnapshotBinding
from app.core.configuration_model import ConfigurationModelSettings
from app.core.settings import ApiSettings
from app.db.configuration_model_records import ConfigurationModelRecords
from app.db.migrate import upgrade_database
from app.db.store import make_engine
from app.db.tables import AuditRow, ConfigurationModelIntentRow, ConfigurationModelOutcomeRow
from app.detection.config_model_runtime import (
    ConfigurationModelRuntime,
    ConfigurationModelUnavailable,
)
from app.main import create_app
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import event, select, text
from sqlalchemy.engine import make_url

from ml.inference.config_contracts import ConfigurationInferenceReport

TOKEN = "owned-config-model-admin-token-000001"
ENGINEER = "owned-config-model-engineer-token-000001"
ANALYST = "owned-config-model-analyst-token-000001"
READER = "owned-config-model-reader-token-000001"
HEADERS = {"Authorization": f"Bearer {TOKEN}"}
PIN = "a" * 64


def synthetic_report(source, pin=PIN):
    """Numeric fixture, not an encoder measurement or a quality artifact."""
    return ConfigurationInferenceReport.model_validate(
        {
            "model": {
                "kind": "native",
                "model_sha256": pin,
                "training_format": "multitask-training-0.1.0",
                "report_sha256": "b" * 64,
                "encoder_sha256": "c" * 64,
                "tokenizer_sha256": "d" * 64,
                "source_manifest_sha256": None,
                "train_fingerprint": "e" * 64,
                "selection_fingerprint": "f" * 64,
                "classes": ["telnet_enabled"],
                "enabled_heads": {
                    "anomaly": True,
                    "category": True,
                    "localization": True,
                    "severity": False,
                    "contrastive": False,
                },
                "parameter_count": 200,
                "trainable_parameters": 100,
                "train_examples": 4,
                "selection_examples": 2,
                "target_semantics": "injected_mutation",
                "external_pretraining_exposure": "not_applicable",
            },
            "prediction": {
                "raw_source_sha256": source.snapshot.source_sha256,
                "sanitized_source_sha256": "1" * 64,
                "model_sha256": pin,
                "total_lines": len(source.content.splitlines()),
                "anomaly_score": 0.3,
                "category_scores": {"telnet_enabled": 0.4},
                "severity_scores": None,
                "line_scores": [0.2] * len(source.content.splitlines()),
                "block_attention": [1.0],
                "embedding_sha256": None,
                "embedding_dimensions": 0,
                "replacement_counts": {},
            },
            "runtime_torch_version": "synthetic-fixture",
        }
    )


@pytest.fixture
def model_api(tmp_path, monkeypatch):
    database = f"sqlite:///{tmp_path / 'configuration-model.sqlite3'}"
    configured = os.environ.get("NETCONFIG_TEST_DATABASE_URL", "")
    admin, created, store = None, False, None
    schema_id = uuid4()
    schema = f"sentinel_configuration_model_test_{schema_id.hex}"
    if configured:
        url = make_url(configured)
        if url.drivername != "postgresql+psycopg" or not (url.database or "").endswith("_test"):
            pytest.fail("configuration models require a postgresql+psycopg *_test database")
        admin = make_engine(configured)
    try:
        if admin is not None:
            with admin.begin() as connection:
                connection.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
            created = True
            database = url.update_query_dict(
                {"options": f"-csearch_path={schema}"}
            ).render_as_string(hide_password=False)
        settings = ApiSettings(
            database,
            TOKEN,
            Fernet.generate_key().decode(),
            reader_token=READER,
            analyst_token=ANALYST,
            engineer_token=ENGINEER,
        )
        application = create_app(
            settings,
            configuration_model=ConfigurationModelSettings(
                registry_root=tmp_path, model_sha256=PIN
            ),
        )
        service = application.state.analysis_service
        store = service.store
        upgrade_database(store.engine)
        runtime = application.state.configuration_model
        state = {"calls": 0, "fail": False}

        def infer(snapshot, source, pin):
            state["calls"] += 1
            if state["fail"]:
                raise ConfigurationModelUnavailable()
            return synthetic_report(source, pin)

        monkeypatch.setattr(runtime, "infer", infer)
        with TestClient(application) as client:
            yield client, service, runtime, state, settings
    finally:
        if store is not None:
            store.close()
        if admin is not None:
            assert schema == f"sentinel_configuration_model_test_{schema_id.hex}"
            if created:
                with admin.begin() as connection:
                    connection.exec_driver_sql(f'DROP SCHEMA "{schema}" CASCADE')
            admin.dispose()


def selected(client, *, vendor="cisco", retain=True, partial=False):
    source = (
        "hostname owned-private-host\nip ssh version 1\n"
        if vendor == "cisco"
        else "set system host-name owned-private-host\nset system services ssh\n"
    )
    if partial:
        source += "unsupported owned-command\n"
    snapshot = client.post(
        "/api/v1/configurations",
        headers=HEADERS,
        json={
            "device_id": str(uuid4()),
            "filename": "owned.cfg",
            "content": source,
            "retain_original_source": retain,
        },
    )
    assert snapshot.status_code == 201, snapshot.text
    analysis = client.post(
        f"/api/v1/configurations/{snapshot.json()['configuration_id']}/analyze", headers=HEADERS
    )
    assert analysis.status_code == 201, analysis.text
    return analysis.json(), {
        "inference_id": str(uuid4()),
        "analysis_id": analysis.json()["analysis_id"],
        "source_sha256": analysis.json()["source_sha256"],
        "model_sha256": PIN,
        "allow_local_model_context": True,
    }


def post(client, options, headers=HEADERS):
    return client.post("/api/v1/configuration-model-runs", headers=headers, json=options)


@pytest.mark.parametrize("vendor", ["cisco", "juniper"])
def test_saved_diagnostic_is_encrypted_replayable_and_does_not_reanalyze(model_api, vendor):
    client, service, runtime, state, settings = model_api
    analysis, options = selected(client, vendor=vendor)
    response = post(client, options)
    assert response.status_code == 201, response.text
    saved = response.json()
    assert (
        saved["status"] == "completed" and saved["report"]["prediction"]["severity_scores"] is None
    )
    assert saved["analysis_sha256"] == fingerprint(
        service.store.get_analysis(UUID(options["analysis_id"]))
    )
    assert "owned-private-host" not in response.text
    assert (
        client.get(f"/api/v1/analyses/{analysis['analysis_id']}", headers=HEADERS).json()
        == analysis
    )
    runtime.settings = ConfigurationModelSettings()
    assert post(client, options).status_code == 200
    assert state["calls"] == 1
    assert client.get(
        "/api/v1/configuration-model-runs",
        headers=HEADERS,
        params={"analysis_id": analysis["analysis_id"]},
    ).json() == [saved]
    with service.store.engine.connect() as connection:
        for table in ("configuration_model_intents", "configuration_model_outcomes"):
            for payload in connection.execute(text(f"SELECT payload FROM {table}")).scalars():
                assert options["source_sha256"] not in payload and "telnet_enabled" not in payload
    restart = create_app(settings)
    with TestClient(restart) as other:
        assert (
            other.get(
                f"/api/v1/configuration-model-runs/{options['inference_id']}", headers=HEADERS
            ).json()
            == saved
        )
        assert post(other, options).json() == saved
    assert state["calls"] == 1


@pytest.mark.parametrize(
    "token, expected", [(READER, 403), (ANALYST, 403), (ENGINEER, 201), ("invalid", 401)]
)
def test_model_role_is_checked_before_body_or_worker(model_api, token, expected):
    client, _, _, state, _ = model_api
    _, options = selected(client)
    response = post(client, options, {"Authorization": f"Bearer {token}"})
    assert response.status_code == expected
    assert state["calls"] == int(expected == 201)


@pytest.mark.parametrize(
    "damage, expected",
    [
        ({"allow_local_model_context": False}, 403),
        ({"allow_local_model_context": 1}, 400),
        ({"allow_local_model_context": "true"}, 400),
        ({"source_sha256": "b" * 64}, 409),
        ({"model_sha256": "b" * 64}, 409),
        ({"registry_root": "private-path"}, 400),
        ({"analysis_id": str(uuid4())}, 404),
    ],
)
def test_invalid_selection_reserves_nothing(model_api, damage, expected):
    client, service, _, state, _ = model_api
    _, options = selected(client)
    assert post(client, options | damage).status_code == expected
    assert state["calls"] == 0
    assert ConfigurationModelRecords(service.store).get(UUID(options["inference_id"])) is None


@pytest.mark.parametrize("retain, partial", [(False, False), (True, True)])
def test_original_and_complete_parse_are_required_before_reservation(model_api, retain, partial):
    client, _, _, state, _ = model_api
    _, options = selected(client, retain=retain, partial=partial)
    assert post(client, options).status_code == 409
    assert state["calls"] == 0
    assert (
        client.get(
            f"/api/v1/configuration-model-runs/{options['inference_id']}", headers=HEADERS
        ).status_code
        == 404
    )


def test_busy_disabled_and_capabilities_do_not_claim_execution(model_api):
    client, _, runtime, state, _ = model_api
    _, options = selected(client)
    capabilities = client.get(
        "/api/v1/configuration-model-runs/capabilities", headers=HEADERS
    ).json()
    assert capabilities["model_sha256"] == PIN and capabilities["health_checked"] is False
    assert "registry" not in str(capabilities)
    with runtime.selected_worker():
        assert post(client, options).status_code == 429
    runtime.settings = ConfigurationModelSettings()
    assert post(client, options).status_code == 503
    assert state["calls"] == 0


def test_failed_attempt_is_terminal_and_conflicting_replay_is_refused(model_api):
    client, _, _, state, _ = model_api
    _, options = selected(client)
    state["fail"] = True
    assert post(client, options).status_code == 503
    replay = post(client, options)
    assert replay.status_code == 200 and replay.json()["status"] == "failed"
    assert replay.json()["report"] is None and state["calls"] == 1
    assert post(client, options | {"model_sha256": "2" * 64}).status_code == 409


def test_pending_replay_does_not_assume_live_worker_or_retry(model_api):
    client, service, _, state, _ = model_api
    analysis, options = selected(client)
    snapshot = service.store.get_configuration(UUID(analysis["configuration_id"]))
    intent = ConfigurationModelIntent(
        request=RunConfigurationModel.model_validate(options),
        source=SnapshotBinding.from_snapshot(snapshot),
        analysis_sha256=fingerprint(service.store.get_analysis(UUID(analysis["analysis_id"]))),
        total_lines=2,
        created_at=datetime.now(UTC),
    )
    records = ConfigurationModelRecords(service.store)
    with ThreadPoolExecutor(max_workers=2) as executor:
        assert sorted(executor.map(records.reserve, [intent, intent])) == [False, True]
    assert post(client, options).json()["status"] == "pending" and state["calls"] == 0


@pytest.mark.parametrize("table", [ConfigurationModelIntentRow, ConfigurationModelOutcomeRow])
def test_tampered_record_is_sanitized_storage_failure(model_api, table):
    client, service, _, _, _ = model_api
    _, options = selected(client)
    assert post(client, options).status_code == 201
    with service.store._sessions.begin() as session:
        row = session.get(table, options["inference_id"])
        row.payload = "damaged-private-record"
    response = client.get(
        f"/api/v1/configuration-model-runs/{options['inference_id']}", headers=HEADERS
    )
    assert response.status_code == 503 and "damaged" not in response.text


def test_wrong_source_worker_result_is_failed_not_persisted(model_api, monkeypatch):
    client, _, runtime, _, _ = model_api
    _, options = selected(client)

    def wrong(snapshot, source, pin):
        value = deepcopy(synthetic_report(source, pin).model_dump(mode="json"))
        value["prediction"]["raw_source_sha256"] = "f" * 64
        return ConfigurationInferenceReport.model_validate(value)

    monkeypatch.setattr(runtime, "infer", wrong)
    assert post(client, options).status_code == 503
    assert post(client, options).json()["status"] == "failed"


def test_terminal_audit_failure_rolls_back_outcome_and_never_reexecutes(model_api):
    client, service, _, state, _ = model_api
    _, options = selected(client)

    def refuse_terminal_audit(session, flush_context, instances):
        if any(
            isinstance(row, AuditRow) and row.action == "configuration_model.completed"
            for row in session.new
        ):
            raise ValueError("owned terminal audit refusal")

    event.listen(service.store._sessions, "before_flush", refuse_terminal_audit)
    try:
        assert post(client, options).status_code == 500
    finally:
        event.remove(service.store._sessions, "before_flush", refuse_terminal_audit)
    assert post(client, options).json()["status"] == "pending"
    assert state["calls"] == 1
    with service.store._sessions() as session:
        assert session.scalar(select(ConfigurationModelOutcomeRow)) is None


def test_audit_records_metadata_not_model_scores(model_api):
    client, _, _, _, _ = model_api
    _, options = selected(client)
    response = post(client, options)
    audit = client.get(
        f"/api/v1/operation-audit/{response.headers['X-Operation-Id']}", headers=HEADERS
    )
    assert audit.status_code == 200, audit.text
    assert audit.json()["receipt"]["operation"] == "run_configuration_model"
    assert options["inference_id"] in audit.json()["completion"]["result"]["resource_ids"]
    assert "anomaly_score" not in audit.text and "telnet_enabled" not in audit.text


@pytest.fixture(scope="module")
def native_registry(tmp_path_factory):
    pytest.importorskip("torch")
    from ml.mutation import MutationType
    from ml.preprocessing.tokenization import TokenizerPolicy, train_config_tokenizer
    from ml.registry.store import initialize_registry, register_model
    from ml.training.classification_smoke import classification_fixtures
    from ml.training.multitask import HeadPolicy, LossWeights
    from ml.training.multitask_smoke import authored_supervision
    from ml.training.multitask_training import FineTunePolicy, multitask_identity, train_multitask
    from ml.training.transformer import EncoderPolicy, TrainingPolicy, train_masked_language_model

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
    model = train_multitask(
        splits,
        encoder,
        authored_supervision(splits, (MutationType.TELNET_ENABLED,)),
        head_policy=HeadPolicy(classes=("telnet_enabled",), embedding_size=8),
        training_policy=FineTunePolicy(epochs=1),
        loss_weights=LossWeights(severity=0),
    )
    pin = multitask_identity(model)
    root = tmp_path_factory.mktemp("configuration-native") / "registry"
    initialize_registry(root)
    register_model(root, model, expected_identity=pin)
    return root, pin


@pytest.mark.parametrize("vendor", ["cisco", "juniper"])
def test_actual_isolated_native_saved_configuration(
    model_api, native_registry, vendor, monkeypatch
):
    client, _, runtime, state, _ = model_api
    root, pin = native_registry
    runtime.settings = ConfigurationModelSettings(registry_root=root, model_sha256=pin)
    monkeypatch.setattr(runtime, "infer", ConfigurationModelRuntime.infer.__get__(runtime))
    analysis, options = selected(client, vendor=vendor)
    response = post(client, options | {"model_sha256": pin})
    assert response.status_code == 201, response.text
    result = response.json()
    assert result["report"]["runtime_torch_version"] != "synthetic-fixture"
    assert result["report"]["prediction"]["embedding_dimensions"] == 8
    assert result["report"]["prediction"]["severity_scores"] is None
    assert state["calls"] == 0  # The synthetic adapter was not used.
    assert (
        client.get(f"/api/v1/analyses/{analysis['analysis_id']}", headers=HEADERS).json()
        == analysis
    )
