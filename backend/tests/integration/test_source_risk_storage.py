"""Durable priority records, strict dependency integrity and additive schema controls."""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta, timezone
from hashlib import sha256
from uuid import UUID, uuid4

import pytest
from app.api.source_ml_contracts import ml_json
from app.api.source_risk_contracts import CreateSourceRiskAssessment, SourceRiskAssessment
from app.db.migrate import SCHEMA_REVISION, upgrade_database
from app.db.patch_records import PatchConflict
from app.db.source_risk_records import SourceRiskRecords
from app.db.tables import SourceRiskAssessmentRow
from app.patching.source_risk import SourceRiskWorkflow
from sqlalchemy import inspect, select, text
from test_source_direction_api import directional_api as directional_api
from test_source_evidence_api import evidence_api as evidence_api
from test_source_ml_recheck_api import source_ml_api as source_ml_api
from test_source_patch_review_api import HEADERS
from test_source_risk_api import block_execution, counts, get, options, post, prepare, url
from test_source_risk_api import risk_api as risk_api


def reseal(body):
    proof = ml_json(
        {key: value for key, value in body.items() if key not in {"review_json", "review_sha256"}}
    )
    return body | {"review_json": proof, "review_sha256": sha256(proof.encode()).hexdigest()}


def replace_payload(store, key, raw):
    with store._sessions.begin() as session:
        row = session.get(SourceRiskAssessmentRow, key)
        row.payload = store._encode(raw, kind="source_risk_assessment", row_id=key)


@pytest.mark.parametrize("tamper", ["cipher", "kind", "metadata", "proof", "role", "time", "flags"])
def test_corrupted_stored_record_is_unavailable_for_get_list_and_replay(risk_api, tamper):
    client, app, *_ = risk_api
    report, _, _ = prepare(risk_api, network="")
    body = options(report)
    response = post(client, report, body)
    assert response.status_code == 201, response.text
    store = app.state.analysis_service.store
    record = response.json()
    with store._sessions.begin() as session:
        row = session.get(SourceRiskAssessmentRow, body["assessment_id"])
        if tamper == "cipher":
            row.payload = "private-invalid-ciphertext"
        elif tamper == "kind":
            row.payload = store._encode(
                ml_json(record), kind="source_evidence_report", row_id=body["assessment_id"]
            )
        elif tamper == "metadata":
            row.created_at = datetime(2000, 1, 1, tzinfo=UTC)
        else:
            if tamper == "proof":
                record["review_json"] += " "
            elif tamper == "role":
                record["service_role"] = "reader"
                record = reseal(record)
            elif tamper == "time":
                record["created_at"] = "2000-01-01T00:00:00Z"
                record = reseal(record)
                # Keep SQL metadata consistent: chronology must be checked against the parent.
                row.created_at = datetime(2000, 1, 1, tzinfo=UTC)
            else:
                record["approved"] = True
                record = reseal(record)
            row.payload = store._encode(
                ml_json(record), kind="source_risk_assessment", row_id=body["assessment_id"]
            )
    for response in (
        get(client, report, body),
        client.get(url(report), headers=HEADERS),
        post(client, report, body),
    ):
        assert response.status_code == 503, response.text
        assert (
            "private-invalid-ciphertext" not in response.text and "review_json" not in response.text
        )
    assert counts(app) == (1, 1)


def test_resealed_numerically_consistent_false_neural_observation_is_not_saved_evidence(risk_api):
    client, app, *_ = risk_api
    report, _, _ = prepare(risk_api, neural=True)
    body = options(report)
    response = post(client, report, body)
    assert response.status_code == 201, response.text
    record = response.json()
    comp = record["composition"]
    neural = comp["components"][3]
    neural["observation"]["anomaly_score"] = neural["raw_score"] = 0.4
    neural["contribution"] = neural["raw_score"] * neural["effective_weight"]
    comp["score"] = max(
        sum(row["contribution"] or 0 for row in comp["components"]),
        *(guard["floor"] for guard in comp["applied_guardrails"]),
    )
    forged = SourceRiskAssessment.model_validate(reseal(record))
    replace_payload(
        app.state.analysis_service.store, body["assessment_id"], forged.model_dump_json()
    )
    assert get(client, report, body).status_code == 503
    assert client.get(url(report), headers=HEADERS).status_code == 503
    assert post(client, report, body).status_code == 503 and counts(app) == (1, 1)


@pytest.mark.parametrize(
    "table", ["patch_evidence_reports", "patch_deterministic_recheck_outcomes"]
)
def test_corrupt_parent_or_selected_child_blocks_existing_and_new_assessments(risk_api, table):
    client, app, *_ = risk_api
    report, _, _ = prepare(risk_api)
    body = options(report)
    assert post(client, report, body).status_code == 201
    with app.state.analysis_service.store.engine.begin() as connection:
        connection.execute(text(f"UPDATE {table} SET payload='private-invalid-child'"))
    for response in (
        get(client, report, body),
        client.get(url(report), headers=HEADERS),
        post(client, report, body),
        post(client, report, options(report)),
    ):
        assert response.status_code == 503
        assert "private-invalid-child" not in response.text
    assert counts(app) == (1, 1)


def test_insertion_cannot_bypass_complete_recomposition_with_model_construct(risk_api):
    _client, app, *_ = risk_api
    report, _, _ = prepare(risk_api, neural=True)
    store = app.state.analysis_service.store
    records = SourceRiskRecords(store)
    request = CreateSourceRiskAssessment.model_validate(options(report))
    original = records.prepare(
        UUID(report["patch_id"]), UUID(report["report_id"]), request, "engineer"
    )
    body = original.model_dump(mode="json")
    body["composition"]["components"][3]["observation"]["anomaly_score"] = 0.4
    component = body["composition"]["components"][3]
    component["raw_score"] = 0.4
    component["contribution"] = 0.4 * component["effective_weight"]
    forged = SourceRiskAssessment.model_validate(reseal(body))
    with pytest.raises(PatchConflict):
        records.add(forged)
    # Pydantic model_construct cannot smuggle an invalid literal through the public add path.
    invalid = original.model_copy(update={"approved": True})
    with pytest.raises(ValueError):
        records.add(invalid)
    assert counts(app) == (0, 0)


@pytest.mark.parametrize("offset", [-3, 3])
def test_sql_utc_metadata_preserves_original_proof_offset(risk_api, monkeypatch, offset):
    _client, app, *_ = risk_api
    report, _, _ = prepare(risk_api)
    store = app.state.analysis_service.store
    records = SourceRiskRecords(store)
    body = CreateSourceRiskAssessment.model_validate(options(report))
    record = records.prepare(UUID(report["patch_id"]), UUID(report["report_id"]), body, "admin")
    values = record.model_dump(mode="json")
    time = record.created_at.astimezone(timezone(timedelta(hours=offset)))
    values["created_at"] = time.isoformat()
    record = SourceRiskAssessment.model_validate(reseal(values))
    block_execution(monkeypatch)
    saved, created = records.add(record)
    assert created and saved == record
    read = records.get(record.assessment_id)
    assert read.model_dump_json() == record.model_dump_json()
    assert time.isoformat() in read.review_json
    with store._sessions() as session:
        stamp = session.scalar(
            select(SourceRiskAssessmentRow.created_at).where(
                SourceRiskAssessmentRow.id == str(record.assessment_id)
            )
        )
        assert (stamp if stamp.tzinfo else stamp.replace(tzinfo=UTC)) == record.created_at


def test_ciphertext_and_full_payload_limits_refuse_before_domain_insert(risk_api, monkeypatch):
    client, app, *_ = risk_api
    report, _, _ = prepare(risk_api, network="")
    with monkeypatch.context() as narrow:
        narrow.setattr("app.api.source_risk_contracts.MAX_SOURCE_RISK_BYTES", 16)
        assert post(client, report, options(report)).status_code == 413
    monkeypatch.setattr("app.db.source_risk_records.MAX_SOURCE_RISK_CIPHERTEXT_BYTES", 16)
    assert post(client, report, options(report)).status_code == 413
    assert counts(app) == (0, 0)


def test_concurrent_conflicting_intents_preserve_only_one_record_and_audit(risk_api):
    _client, app, *_ = risk_api
    first, _, _ = prepare(risk_api, network="")
    second, _, _ = prepare(risk_api, "juniper", network="")
    shared_id = str(uuid4())
    workflow = SourceRiskWorkflow(app.state.analysis_service.store)

    def create(report):
        request = CreateSourceRiskAssessment.model_validate(
            options(report, assessment_id=shared_id)
        )
        try:
            return workflow.create(
                UUID(report["patch_id"]), UUID(report["report_id"]), request, "admin"
            )
        except PatchConflict:
            return "conflict"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(create, (first, second)))
    assert len([result for result in results if result == "conflict"]) == 1
    assert len([result for result in results if result != "conflict" and result[1]]) == 1
    assert counts(app) == (1, 1)


def physical(connection, tables):
    # SQLAlchemy Row.__repr__ truncates ciphertext. Compare complete physical column tuples.
    return {
        name: set(tuple(row) for row in connection.execute(text(f'SELECT * FROM "{name}"')))
        for name in tables
    }


def test_upgrade_0016_to_0017_is_additive_and_preserves_every_old_physical_row(risk_api):
    client, app, *_ = risk_api
    report, _, _ = prepare(risk_api, neural=True)
    store = app.state.analysis_service.store
    # This fixture owns an isolated database/schema. Recreate the exact predecessor state by
    # removing the empty newer tables and restoring its former Alembic revision marker.
    with store.engine.begin() as connection:
        assert (
            connection.execute(text("SELECT count(*) FROM patch_risk_assessments")).scalar_one()
            == 0
        )
        connection.exec_driver_sql("DROP TABLE native_patch_candidates")
        connection.exec_driver_sql("DROP TABLE patch_risk_assessments")
        connection.execute(
            text("UPDATE alembic_version SET version_num='0016_source_evidence_decisions'")
        )
    assert not store.schema_ready()
    tables = set(inspect(store.engine).get_table_names()) - {"alembic_version"}
    with store.engine.connect() as connection:
        before = physical(connection, tables)
    upgrade_database(store.engine)
    assert SCHEMA_REVISION == "0018_native_patch_candidates" and store.schema_ready()
    assert set(inspect(store.engine).get_table_names()) == tables | {
        "alembic_version",
        "patch_risk_assessments",
        "native_patch_candidates",
    }
    with store.engine.connect() as connection:
        assert physical(connection, tables) == before
    assert post(client, report, options(report)).status_code == 201 and counts(app) == (1, 1)
    indexes = inspect(store.engine).get_indexes("patch_risk_assessments")
    assert any(
        row["column_names"] == ["patch_id", "report_id", "created_at", "id"] for row in indexes
    )
