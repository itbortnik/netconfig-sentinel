"""Content-bound encrypted drafts, idempotent local reviews and no false formal pass."""

import json
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import app.db.migrate as migration_module
import app.patching.persistent as workflow_module
import pytest
from alembic import command
from alembic.config import Config
from app.api.contracts import UploadConfiguration
from app.api.feedback_contracts import SubmitFeedback
from app.api.patch_contracts import PatchDraft, VerificationRun
from app.core.settings import ApiSettings
from app.db.migrate import upgrade_database
from app.main import create_app
from app.patching.review import local_validation_blockers
from app.verification.preflight import PreflightReport
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import event, text

TOKEN = "patch-api-tests-shared-service-token-001"
HEADERS = {"Authorization": f"Bearer {TOKEN}"}


@pytest.fixture
def patch_api(tmp_path: Path) -> Iterator[tuple]:
    settings = ApiSettings(
        f"sqlite:///{tmp_path / 'patches.sqlite3'}", TOKEN, Fernet.generate_key().decode()
    )
    application = create_app(settings)
    service = application.state.analysis_service
    upgrade_database(service.store.engine)
    with TestClient(application) as client:
        yield client, service, settings


def upload(client, contents, device=None):
    response = client.post(
        "/api/v1/configurations",
        headers=HEADERS,
        json={
            "device_id": device or str(uuid4()),
            "filename": "edge.cfg",
            "content": contents,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def pair(client, vendor="cisco", partial=False):
    before_text = (
        "hostname patch-edge\n" if vendor == "cisco" else "set system host-name patch-edge\n"
    )
    after_text = (
        before_text
        + ("ntp server 192.0.2.1\n" if vendor == "cisco" else "set system ntp server 192.0.2.1\n")
        + ("unsupported private raw text\n" if partial else "")
    )
    before = upload(client, before_text)
    after = upload(client, after_text, before["device_id"])
    return before, after


def intent(before, after, **updates):
    return {
        "patch_id": str(uuid4()),
        "before_configuration_id": before["configuration_id"],
        "after_configuration_id": after["configuration_id"],
        "before_source_sha256": before["canonical"]["source"]["sha256"],
        "after_source_sha256": after["canonical"]["source"]["sha256"],
    } | updates


def create(client, body):
    return client.post("/api/v1/patches", headers=HEADERS, json=body)


def verify(client, draft, **updates):
    return client.post(
        f"/api/v1/patches/{draft['patch_id']}/verify",
        headers=HEADERS,
        json={
            "verification_id": str(uuid4()),
            "draft_sha256": draft["draft_sha256"],
        }
        | updates,
    )


@pytest.mark.parametrize("vendor", ["cisco", "juniper"])
@pytest.mark.parametrize("partial", [False, True])
def test_restart_safe_local_review_never_promotes_a_draft(patch_api, vendor, partial):
    client, service, settings = patch_api
    before, after = pair(client, vendor, partial)
    response = create(client, intent(before, after))
    assert response.status_code == 201, response.text
    draft = response.json()
    assert draft["status"] == "draft" and draft["representation"] == "normalized_objects"
    assert draft["diff"]["coverage"] == ("partial" if partial else "supported_complete")
    reviewed = verify(client, draft)
    assert reviewed.status_code == 201, reviewed.text
    review = reviewed.json()
    assert review["status"] == "needs_review"
    assert review["preflight"]["formal_verification"] == "not_run"
    assert review["preflight"]["requires_human_review"] is True
    assert "formal_verification_not_run" in review["validation_blockers"]
    assert "human_review_required" in review["validation_blockers"]
    assert (review["preflight"]["policy_changes"] is None) == partial
    assert (review["preflight"]["current_policy_risk"] is None) == partial
    assert "unsupported private raw text" not in response.text + reviewed.text
    with TestClient(create_app(settings)) as restarted:
        assert (
            restarted.get(f"/api/v1/patches/{draft['patch_id']}", headers=HEADERS).json() == draft
        )
        assert (
            restarted.get(
                f"/api/v1/patches/{draft['patch_id']}/verifications/{review['verification_id']}",
                headers=HEADERS,
            ).json()
            == review
        )
        listed = restarted.get(
            f"/api/v1/patches/{draft['patch_id']}/verifications", headers=HEADERS
        ).json()
        assert listed[0]["verification_id"] == review["verification_id"]
        assert (listed[0]["resolved_count"] is None) == partial
    with service.store.engine.connect() as connection:
        for table in ("patch_proposals", "verification_runs"):
            payload = connection.execute(text(f"SELECT payload FROM {table}")).scalar_one()
            assert "patch-edge" not in payload and "192.0.2.1" not in payload
        assert connection.execute(text("SELECT count(*) FROM audit_events")).scalar_one() == 4


def test_lost_responses_and_concurrent_retries_append_only_once(patch_api):
    client, service, _ = patch_api
    before, after = pair(client)
    body = intent(before, after)
    with ThreadPoolExecutor(max_workers=4) as executor:
        responses = list(executor.map(lambda _: create(client, body), range(4)))
    assert sorted(item.status_code for item in responses) == [200, 200, 200, 201]
    draft = responses[0].json()
    assert all(item.json() == draft for item in responses)
    verification_id = str(uuid4())
    with ThreadPoolExecutor(max_workers=4) as executor:
        responses = list(
            executor.map(lambda _: verify(client, draft, verification_id=verification_id), range(4))
        )
    assert sorted(item.status_code for item in responses) == [200, 200, 200, 201]
    assert all(item.json() == responses[0].json() for item in responses)
    assert create(client, body | {"after_source_sha256": "f" * 64}).status_code == 409
    assert (
        verify(client, draft, verification_id=verification_id, draft_sha256="f" * 64).status_code
        == 409
    )
    with service.store.engine.connect() as connection:
        assert connection.execute(text("SELECT count(*) FROM patch_proposals")).scalar_one() == 1
        assert connection.execute(text("SELECT count(*) FROM verification_runs")).scalar_one() == 1
        assert connection.execute(text("SELECT count(*) FROM audit_events")).scalar_one() == 4


def test_explicit_batfish_request_does_not_fall_back_to_local(patch_api):
    client, _, _ = patch_api
    before, after = pair(client)
    draft = create(client, intent(before, after)).json()
    response = verify(client, draft, mode="batfish")
    assert response.status_code == 503
    assert response.json() == {"detail": "Formal verification is unavailable in this API."}
    assert (
        client.get(f"/api/v1/patches/{draft['patch_id']}/verifications", headers=HEADERS).json()
        == []
    )


@pytest.mark.parametrize("variant", ["foreign", "reverse", "missing", "same", "unchanged"])
def test_invalid_snapshot_pairs_cannot_create_drafts(patch_api, variant):
    client, service, _ = patch_api
    before, after = pair(client)
    expected = 409
    if variant == "foreign":
        after = upload(client, "hostname patch-edge\nntp server 192.0.2.1\n")
    elif variant == "reverse":
        before, after = after, before
    elif variant == "same":
        after = before
        expected = 400
    elif variant == "unchanged":
        after = upload(client, "hostname patch-edge\n! a comment\n", before["device_id"])
    body = intent(before, after)
    if variant == "missing":
        body["before_configuration_id"] = str(uuid4())
        expected = 404
    assert create(client, body).status_code == expected
    with service.store.engine.connect() as connection:
        assert connection.execute(text("SELECT count(*) FROM patch_proposals")).scalar_one() == 0


def test_authorization_and_strict_bounded_write_bodies(patch_api):
    client, _, _ = patch_api
    before, after = pair(client)
    body = intent(before, after)
    draft = create(client, body).json()
    paths = ["/api/v1/patches", f"/api/v1/patches/{draft['patch_id']}/verify"]
    for path in paths:
        assert client.post(path, content=b"x" * 20_000).status_code == 401
        assert (
            client.post(
                path, headers=HEADERS | {"Content-Type": "application/json"}, content=b"x" * 20_000
            ).status_code
            == 413
        )
        invalid = json.dumps(body)[:-1] + ',"patch_id":"duplicate"}'
        response = client.post(
            path, headers=HEADERS | {"Content-Type": "application/json"}, content=invalid
        )
        assert response.status_code == 400
        assert "duplicate" not in response.text
        assert (
            client.post(path, headers=HEADERS, json=body | {"status": "approved"}).status_code
            == 400
        )
        assert client.post(path, headers=HEADERS, json={}).status_code == 400
    for path in [
        "/api/v1/patches",
        f"/api/v1/patches/{draft['patch_id']}",
        f"/api/v1/patches/{draft['patch_id']}/verifications",
        f"/api/v1/patches/{draft['patch_id']}/verifications/{uuid4()}",
    ]:
        assert client.get(path).status_code == 401
    for params in ({"limit": 101}, {"offset": -1}, {"offset": 10001}):
        assert (
            client.get(
                "/api/v1/patches",
                headers=HEADERS,
                params={"after_configuration_id": after["configuration_id"]} | params,
            ).status_code
            == 422
        )


def test_scoped_paging_restart_replay_and_unchanged_analysis(patch_api, monkeypatch):
    client, _, settings = patch_api
    before, after = pair(client)
    analysis_path = f"/api/v1/configurations/{after['configuration_id']}/analyze"
    analysis = client.post(analysis_path, headers=HEADERS).json()
    first = create(client, intent(before, after)).json()
    second = create(client, intent(before, after)).json()
    run = verify(client, first).json()
    verify(client, first)
    path = f"/api/v1/patches/{first['patch_id']}/verifications"
    full = client.get(path, headers=HEADERS).json()
    assert len(full) == 2
    assert client.get(path, headers=HEADERS, params={"limit": 1, "offset": 1}).json() == full[1:]
    assert (
        client.get(
            f"/api/v1/patches/{second['patch_id']}/verifications/{run['verification_id']}",
            headers=HEADERS,
        ).status_code
        == 404
    )
    assert verify(client, second, verification_id=run["verification_id"]).status_code == 409
    drafts = client.get(
        "/api/v1/patches",
        headers=HEADERS,
        params={"after_configuration_id": after["configuration_id"], "limit": 1, "offset": 1},
    ).json()
    assert [item["patch_id"] for item in drafts] == [first["patch_id"]]

    def forbidden_recompute(*args, **kwargs):
        pytest.fail("a saved verification replay must not reevaluate policies")

    monkeypatch.setattr(workflow_module, "review_configuration_change", forbidden_recompute)
    with TestClient(create_app(settings)) as restarted:
        replay = verify(restarted, first, verification_id=run["verification_id"])
        assert replay.status_code == 200 and replay.json() == run
        assert (
            restarted.get(f"/api/v1/analyses/{analysis['analysis_id']}", headers=HEADERS).json()
            == analysis
        )
        assert (
            restarted.get(
                f"/api/v1/configurations/{after['configuration_id']}", headers=HEADERS
            ).json()
            == after
        )


@pytest.mark.parametrize(
    "table,damage",
    [
        ("patch_proposals", "ciphertext"),
        ("verification_runs", "ciphertext"),
        ("patch_proposals", "metadata"),
        ("verification_runs", "metadata"),
        ("patch_proposals", "transplant"),
        ("verification_runs", "transplant"),
        ("patch_proposals", "content"),
        ("verification_runs", "content"),
    ],
)
def test_corrupted_encrypted_records_fail_closed_without_disclosure(patch_api, table, damage):
    client, service, _ = patch_api
    before, after = pair(client)
    draft = create(client, intent(before, after)).json()
    run = verify(client, draft).json()
    row_id = draft["patch_id"] if table == "patch_proposals" else run["verification_id"]
    kind = "patch" if table == "patch_proposals" else "verification"
    value = draft if kind == "patch" else run
    with service.store.engine.begin() as connection:
        if damage == "metadata":
            connection.execute(
                text(f"UPDATE {table} SET created_at=:time WHERE id=:id"),
                {"time": datetime.now(UTC) + timedelta(days=1), "id": row_id},
            )
        else:
            if damage == "ciphertext":
                payload = "private-secret-broken-ciphertext"
            else:
                changed = value | ({"draft_sha256": "f" * 64} if damage == "content" else {})
                payload = service.store._encode(
                    json.dumps(changed),
                    kind=kind,
                    row_id=str(uuid4()) if damage == "transplant" else row_id,
                )
            connection.execute(
                text(f"UPDATE {table} SET payload=:payload WHERE id=:id"),
                {"payload": payload, "id": row_id},
            )
    path = f"/api/v1/patches/{draft['patch_id']}"
    if kind == "verification":
        path += f"/verifications/{run['verification_id']}"
    response = client.get(path, headers=HEADERS)
    assert response.status_code == 503
    assert "private-secret" not in response.text and "patch-edge" not in response.text


@pytest.mark.parametrize("kind", ["draft", "review"])
def test_record_and_audit_rollback_together(patch_api, kind):
    client, service, _ = patch_api
    before, after = pair(client)
    body = intent(before, after)
    draft = create(client, body).json() if kind == "review" else None

    def reject_audit(connection, cursor, statement, parameters, context, executemany):
        if statement.startswith("INSERT INTO audit_events"):
            raise RuntimeError("synthetic audit failure")

    event.listen(service.store.engine, "before_cursor_execute", reject_audit)
    try:
        response = verify(client, draft) if draft else create(client, body)
        assert response.status_code == 500
        assert "synthetic audit failure" not in response.text
    finally:
        event.remove(service.store.engine, "before_cursor_execute", reject_audit)
    table = "verification_runs" if kind == "review" else "patch_proposals"
    with service.store.engine.connect() as connection:
        assert connection.execute(text(f"SELECT count(*) FROM {table}")).scalar_one() == 0
        assert connection.execute(text("SELECT count(*) FROM audit_events")).scalar_one() == (
            3 if draft else 2
        )


def test_contracts_and_output_budgets_never_allow_status_promotion(patch_api, monkeypatch):
    client, _, _ = patch_api
    before, after = pair(client)
    body = intent(before, after)
    draft = create(client, body).json()
    run = verify(client, draft).json()
    for update in (
        {"status": "approved"},
        {"requires_human_review": False},
        {"draft_sha256": "f" * 64},
    ):
        with pytest.raises(ValidationError):
            PatchDraft.model_validate(draft | update)
    for update in (
        {"status": "passed"},
        {"kind": "batfish"},
        {"validation_blockers": []},
        {"preflight": run["preflight"] | {"formal_verification": "passed"}},
    ):
        with pytest.raises(ValidationError):
            VerificationRun.model_validate(run | update)
    monkeypatch.setattr(workflow_module, "MAX_RECORD_BYTES", 1)
    assert create(client, body | {"patch_id": str(uuid4())}).status_code == 413
    assert verify(client, draft).status_code == 413
    assert create(client, body).status_code == 200
    assert verify(client, draft, verification_id=run["verification_id"]).status_code == 200


def test_upgrade_from_feedback_revision_preserves_existing_history(tmp_path):
    settings = ApiSettings(
        f"sqlite:///{tmp_path / 'legacy-patches.sqlite3'}", TOKEN, Fernet.generate_key().decode()
    )
    application = create_app(settings)
    service = application.state.analysis_service
    migration = Config()
    migration.set_main_option(
        "script_location", str(Path(migration_module.__file__).parent / "migrations")
    )
    with service.store.engine.begin() as connection:
        migration.attributes["connection"] = connection
        command.upgrade(migration, "0003_finding_feedback")
    # Populate an actual old schema; never relabel a current database as historical.
    saved = service.upload(
        UploadConfiguration(device_id=uuid4(), filename="edge.cfg", content="hostname patch-edge\n")
    )
    service.upload(
        UploadConfiguration(
            device_id=saved.device_id,
            filename="edge.cfg",
            content="hostname patch-edge\nntp server 192.0.2.1\n",
        )
    )
    result = service.analyze(saved.configuration_id)
    assert result is not None
    assessment, created = service.submit_feedback(
        result.findings[0].finding_id,
        SubmitFeedback(
            feedback_id=uuid4(),
            analysis_id=result.analysis_id,
            finding_sha256=result.explanations[0].finding_sha256,
            verdict="needs_investigation",
            comment="Preserved before draft migration.",
        ),
    )
    assert created
    before = saved.model_dump(mode="json")
    analyzed = result.model_dump(mode="json")
    feedback = assessment.model_dump(mode="json")
    feedback_path = f"/api/v1/findings/{analyzed['findings'][0]['finding_id']}/feedback"
    assert not service.store.ready()
    with TestClient(application) as client:
        assert client.get("/api/v1/configurations", headers=HEADERS).status_code == 503
    with service.store.engine.begin() as connection:
        migration.attributes["connection"] = connection
        command.upgrade(migration, "head")
    assert service.store.ready()
    with TestClient(create_app(settings)) as restarted:
        assert restarted.get(
            feedback_path, headers=HEADERS, params={"analysis_id": analyzed["analysis_id"]}
        ).json() == [feedback]
        assert (
            restarted.get(f"/api/v1/analyses/{analyzed['analysis_id']}", headers=HEADERS).json()
            == analyzed
        )
        assert (
            restarted.get(
                f"/api/v1/configurations/{before['configuration_id']}", headers=HEADERS
            ).json()
            == before
        )


def test_partial_before_does_not_suppress_complete_current_policy_risk(patch_api):
    client, _, _ = patch_api
    before = upload(client, "hostname patch-edge\nunknown private source\n")
    after = upload(client, "hostname patch-edge\nntp server 192.0.2.1\n", before["device_id"])
    draft = create(client, intent(before, after)).json()
    run = verify(client, draft).json()
    assert not run["preflight"]["before"]["complete"]
    assert run["preflight"]["after"]["complete"]
    assert run["preflight"]["policy_changes"] is None
    assert run["preflight"]["current_policy_risk"] is not None
    assert run["preflight"]["reference_status"] == "unavailable"
    assert "incomplete_parsing" in run["validation_blockers"]


def test_authenticated_but_inconsistent_parser_diagnostics_are_rejected(patch_api):
    client, service, _ = patch_api
    before, after = pair(client)
    draft = create(client, intent(before, after)).json()
    run = verify(client, draft).json()
    report = PreflightReport.model_validate(
        run["preflight"]
        | {
            "before": run["preflight"]["before"] | {"confidence": 0.5, "complete": False},
            "policy_changes": None,
            "reference_status": "unavailable",
            "reference_findings": [],
        }
    )
    altered = VerificationRun.model_validate(
        run
        | {
            "preflight": report,
            "validation_blockers": local_validation_blockers(report),
        }
    )
    payload = service.store._encode(
        altered.model_dump_json(), kind="verification", row_id=run["verification_id"]
    )
    with service.store.engine.begin() as connection:
        connection.execute(
            text("UPDATE verification_runs SET payload=:payload WHERE id=:id"),
            {"payload": payload, "id": run["verification_id"]},
        )
    assert (
        client.get(
            f"/api/v1/patches/{draft['patch_id']}/verifications/{run['verification_id']}",
            headers=HEADERS,
        ).status_code
        == 503
    )
