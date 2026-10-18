"""Owned numeric pair fixture tests; no encoder or quality claim."""

import json
import os
from copy import deepcopy
from uuid import uuid4

import app.patching.source_ml as workflow_module
import pytest
from app.api.source_ml_contracts import SourceMlRecheck
from app.core.configuration_model import ConfigurationModelSettings
from app.core.settings import ApiSettings
from app.db.migrate import upgrade_database
from app.db.source_records import SourceRecords
from app.db.store import make_engine
from app.main import create_app
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.engine import make_url
from test_configuration_model_api import synthetic_report
from test_source_patch_review_api import ANALYST, ENGINEER, HEADERS, READER, TOKEN, draft_pair

from ml.inference.pair_contracts import ConfigurationPairReport

PIN = "a" * 64
BEFORE = "hostname edge\nline vty 0 4\n transport input telnet ssh\n!\n"
AFTER = "hostname edge\nline vty 0 4\n transport input ssh\n!\n! added comment\n"


@pytest.fixture
def source_ml_api(tmp_path, monkeypatch):
    database = f"sqlite:///{tmp_path / 'source-ml.sqlite3'}"
    configured = os.environ.get("NETCONFIG_TEST_DATABASE_URL", "")
    schema = f"sentinel_source_ml_test_{uuid4().hex}"
    admin, created, store = None, False, None
    if configured:
        url = make_url(configured)
        if url.drivername != "postgresql+psycopg" or not (url.database or "").endswith("_test"):
            pytest.fail("source pair ML tests require a postgresql+psycopg *_test database")
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
        store = application.state.analysis_service.store
        upgrade_database(store.engine)
        calls = []

        def worker(settings, job):
            calls.append(job)
            return ConfigurationPairReport(
                before=synthetic_report(job.before_source, job.model_sha256),
                after=synthetic_report(job.after_source, job.model_sha256),
            )

        monkeypatch.setattr(workflow_module, "run_configuration_pair_job", worker)
        with TestClient(application) as client:
            yield client, application, settings, calls
    finally:
        if store is not None:
            store.close()
        if admin is not None:
            try:
                if created:
                    with admin.begin() as connection:
                        connection.exec_driver_sql(f'DROP SCHEMA "{schema}" CASCADE')
            finally:
                admin.dispose()


def pair(client, **kwargs):
    return draft_pair(client, before=BEFORE, after=AFTER, **kwargs)


def options(draft, **updates):
    return {
        "recheck_id": str(uuid4()),
        "draft_sha256": draft["draft_sha256"],
        "model_sha256": PIN,
        "allow_local_model_context": True,
    } | updates


def post(client, draft, body, *, headers=HEADERS):
    return client.post(
        f"/api/v2/patches/{draft['patch_id']}/ml-rechecks", headers=headers, json=body
    )


def get(client, draft, body, *, headers=HEADERS):
    return client.get(
        f"/api/v2/patches/{draft['patch_id']}/ml-rechecks/{body['recheck_id']}",
        headers=headers,
    )


def counts(application):
    with application.state.analysis_service.store.engine.connect() as connection:
        return tuple(
            connection.execute(text(f"SELECT count(*) FROM {name}")).scalar_one()
            for name in ("patch_ml_recheck_intents", "patch_ml_recheck_outcomes")
        )


def test_exact_pair_restart_replay_own_coordinates_and_legacy_bytes(source_ml_api, monkeypatch):
    client, application, settings, calls = source_ml_api
    draft, before, after = pair(client)
    legacy_path = f"/api/v1/patches/{draft['patch_id']}/verify"
    legacy = client.post(
        legacy_path,
        headers=HEADERS,
        json={
            "verification_id": str(uuid4()),
            "draft_sha256": draft["draft_sha256"],
        },
    )
    assert legacy.status_code == 201
    body = options(draft)
    saved = post(client, draft, body)
    assert saved.status_code == 201, saved.text
    view = SourceMlRecheck.model_validate(saved.json())
    assert view.execution_status == "completed"
    assert view.status == "needs_review" and view.formal_verification == "not_run"
    assert view.approved is view.applied is view.quality_proven is view.calibrated is False
    assert view.risk_fused is False
    assert view.outcome.report.before.prediction.total_lines == 4
    assert view.outcome.report.after.prediction.total_lines == 5
    assert view.outcome.report.before.model.classes == ("telnet_enabled",)
    assert view.outcome.report.after.prediction.severity_scores is None
    assert calls[0].before_source.content == BEFORE and calls[0].after_source.content == AFTER
    assert len(calls[0].key_hex) == 64 and calls[0].before.device_id == calls[0].after.device_id
    assert counts(application) == (1, 1)
    listing = client.get(f"/api/v2/patches/{draft['patch_id']}/ml-rechecks", headers=HEADERS).json()
    assert len(listing) == 1 and listing[0]["review_sha256"] == view.review_sha256
    public = saved.text
    assert all(
        secret not in public for secret in (calls[0].key_hex, str(settings.database_url), BEFORE)
    )
    assert (
        json.loads(view.review_json)["outcome"]["report"]["before"]["prediction"]["anomaly_score"]
        == 0.3
    )

    def forbidden(*args, **kwargs):
        pytest.fail("history or identical replay invoked source/worker")

    monkeypatch.setattr(workflow_module, "run_configuration_pair_job", forbidden)
    monkeypatch.setattr(SourceRecords, "get", forbidden)
    with TestClient(create_app(settings)) as restarted:
        assert post(restarted, draft, body).status_code == 200
        assert post(restarted, draft, body).json() == saved.json()
        assert get(restarted, draft, body).json() == saved.json()
    assert (
        client.get(
            legacy_path.rsplit("/", 1)[0] + "/verifications/" + legacy.json()["verification_id"],
            headers=HEADERS,
        ).json()
        == legacy.json()
    )
    for snapshot in (before, after):
        assert (
            client.get(
                f"/api/v1/configurations/{snapshot['configuration_id']}", headers=HEADERS
            ).json()
            == snapshot
        )


@pytest.mark.parametrize("role", [READER, ANALYST])
def test_role_denied_before_body_source_or_reservation(source_ml_api, monkeypatch, role):
    client, application, _settings, calls = source_ml_api
    draft, *_ = pair(client)
    monkeypatch.setattr(SourceRecords, "get", lambda *a, **k: pytest.fail("read original"))
    response = client.post(
        f"/api/v2/patches/{draft['patch_id']}/ml-rechecks",
        content="invalid",
        headers={"Authorization": f"Bearer {role}"},
    )
    assert response.status_code == 403 and counts(application) == (0, 0) and not calls


@pytest.mark.parametrize(
    "update,code",
    [
        ({"allow_local_model_context": False}, 403),
        ({"allow_local_model_context": 1}, 400),
        ({"allow_local_model_context": "true"}, 400),
        ({"model_sha256": "b" * 64}, 409),
        ({"draft_sha256": "b" * 64}, 409),
        ({"registry_root": "/tmp/model"}, 400),
        ({"endpoint": "http://127.0.0.1"}, 400),
    ],
)
def test_invalid_intent_does_not_reserve_or_infer(source_ml_api, update, code):
    client, application, _settings, calls = source_ml_api
    draft, *_ = pair(client)
    assert post(client, draft, options(draft, **update)).status_code == code
    assert counts(application) == (0, 0) and not calls


def test_engineer_allowed_shared_slot_both_directions_and_replay_ignores_busy(source_ml_api):
    client, application, _settings, calls = source_ml_api
    draft, before, *_ = pair(client)
    runtime = application.state.configuration_model
    body = options(draft)
    with runtime.selected_worker():
        assert post(client, draft, body).status_code == 429
        assert counts(application) == (0, 0)
    assert (
        post(client, draft, body, headers={"Authorization": f"Bearer {ENGINEER}"}).status_code
        == 201
    )
    with runtime.selected_worker():
        assert post(client, draft, body).status_code == 200
        single = client.post(
            "/api/v1/configuration-model-runs",
            headers=HEADERS,
            json={
                "inference_id": str(uuid4()),
                "analysis_id": str(uuid4()),
                "source_sha256": before["canonical"]["source"]["sha256"],
                "model_sha256": PIN,
                "allow_local_model_context": True,
            },
        )
        assert single.status_code == 429, single.text
    assert len(calls) == 1


@pytest.mark.parametrize(
    "fault",
    ["exception", "wrong_source", "wrong_line_count", "wrong_model", "bad_pair", "oversized"],
)
def test_unavailable_or_invalid_worker_never_persists_partial_success(
    source_ml_api, monkeypatch, fault
):
    client, application, _settings, calls = source_ml_api
    draft, *_ = pair(client)

    def worker(settings, job):
        calls.append(job)
        if fault == "exception":
            raise ValueError("private raw secret must not escape")
        first = synthetic_report(job.before_source)
        second = synthetic_report(job.after_source)
        if fault == "wrong_source":
            second = second.model_copy(
                update={
                    "prediction": second.prediction.model_copy(
                        update={"raw_source_sha256": "f" * 64}
                    )
                }
            )
        if fault == "wrong_line_count":
            second = second.model_copy(
                update={
                    "prediction": second.prediction.model_copy(
                        update={"total_lines": 4, "line_scores": (0.2,) * 4}
                    )
                }
            )
        if fault == "wrong_model":
            first = synthetic_report(job.before_source, "b" * 64)
            second = synthetic_report(job.after_source, "b" * 64)
        if fault == "bad_pair":
            second = second.model_copy(update={"runtime_torch_version": "different"})
        if fault == "oversized":
            monkeypatch.setattr(workflow_module, "MAX_PAIR_RESULT_BYTES", 1)
        return ConfigurationPairReport.model_construct(before=first, after=second)

    monkeypatch.setattr(workflow_module, "run_configuration_pair_job", worker)
    body = options(draft)
    response = post(client, draft, body)
    assert response.status_code == 201, response.text
    assert response.json()["execution_status"] == "failed"
    assert response.json()["outcome"]["report"] is None
    assert "private raw secret" not in response.text and counts(application) == (1, 1)
    assert post(client, draft, body).json() == response.json() and len(calls) == 1


@pytest.mark.parametrize(
    "retain,profile,before,after,expected",
    [
        (False, None, BEFORE, AFTER, 409),
        (True, None, BEFORE + "unknown-command\n", AFTER, 409),
        (
            True,
            "1.2",
            "hostname edge\nip ssh version 1\n",
            "hostname edge\nip ssh version 2\n",
            201,
        ),
    ],
)
def test_admission_complete_sources_and_full_12_without_network_gate(
    source_ml_api, retain, profile, before, after, expected
):
    client, application, _settings, calls = source_ml_api
    draft, *_ = draft_pair(client, before=before, after=after, retain=retain, profile=profile)
    assert post(client, draft, options(draft)).status_code == expected
    assert counts(application) == ((1, 1) if expected == 201 else (0, 0))
    assert len(calls) == (1 if expected == 201 else 0)


def test_capabilities_audit_and_cross_parent_are_metadata_only(source_ml_api):
    from app.audit.results import _selected

    client, application, _settings, calls = source_ml_api
    cap = client.get("/api/v2/patches/ml-capabilities", headers=HEADERS).json()
    assert cap["inference"] == "configured" and cap["health_checked"] is False and not calls
    draft, *_ = pair(client)
    body = options(draft)
    saved = SourceMlRecheck.model_validate(post(client, draft, body).json())
    metadata = json.dumps(_selected(saved))
    assert saved.review_sha256 in metadata and body["recheck_id"] in metadata
    assert all(
        secret not in metadata
        for secret in ("edge", "review_json", "line_scores", "anomaly_score", "registry_root")
    )
    other, *_ = pair(client)
    assert get(client, other, body).status_code == 404
    changed = deepcopy(body)
    changed["allow_local_model_context"] = False
    assert post(client, draft, changed).status_code == 409
    store = application.state.analysis_service.store
    with store.engine.connect() as connection:
        actions = (
            connection.execute(
                text("SELECT action FROM audit_events WHERE action LIKE 'patch.ml_recheck_%'")
            )
            .scalars()
            .all()
        )
        ciphertexts = (
            connection.execute(text("SELECT payload FROM patch_ml_recheck_intents")).scalars().all()
        )
    assert sorted(actions) == ["patch.ml_recheck_completed", "patch.ml_recheck_requested"]
    assert all("hostname" not in value and "model_sha256" not in value for value in ciphertexts)
