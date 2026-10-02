"""Immutable, scoped assessments, private comments, idempotency and atomic audit."""

import json
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from app.api.feedback_contracts import SubmitFeedback
from app.core.settings import ApiSettings
from app.db.migrate import upgrade_database
from app.main import create_app
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.exc import OperationalError

TOKEN = "feedback-tests-shared-service-token-001"
HEADERS = {"Authorization": f"Bearer {TOKEN}"}


@pytest.fixture
def feedback_api(tmp_path: Path) -> Iterator[tuple]:
    settings = ApiSettings(
        f"sqlite:///{tmp_path / 'feedback.sqlite3'}", TOKEN, Fernet.generate_key().decode()
    )
    application = create_app(settings)
    service = application.state.analysis_service
    upgrade_database(service.store.engine)
    with TestClient(application) as client:
        yield client, service, settings


def analysis(client, *, partial=False):
    uploaded = client.post(
        "/api/v1/configurations",
        headers=HEADERS,
        json={
            "device_id": str(uuid4()),
            "filename": "edge.cfg",
            "content": "hostname feedback-edge\n"
            + ("unsupported private command\n" if partial else ""),
        },
    )
    assert uploaded.status_code == 201
    response = client.post(
        f"/api/v1/configurations/{uploaded.json()['configuration_id']}/analyze", headers=HEADERS
    )
    assert response.status_code == 201
    return response.json()


def target(result, index=0):
    return result["findings"][index]["finding_id"]


def submission(result, index=0, **extra):
    return {
        "feedback_id": str(uuid4()),
        "analysis_id": result["analysis_id"],
        "finding_sha256": result["explanations"][index]["finding_sha256"],
        "verdict": "needs_investigation",
        "comment": "Private review; verify intended configuration.",
    } | extra


def submit(client, result, body, index=0):
    return client.post(
        f"/api/v1/findings/{target(result, index)}/feedback", headers=HEADERS, json=body
    )


def history(client, result, index=0, query=""):
    return client.get(
        f"/api/v1/findings/{target(result, index)}/feedback"
        f"?analysis_id={result['analysis_id']}{query}",
        headers=HEADERS,
    )


def test_assessment_history_is_encrypted_restart_safe_and_does_not_rewrite_analysis(feedback_api):
    client, service, settings = feedback_api
    result = analysis(client)
    created = submit(client, result, submission(result, verdict="confirmed_anomaly"))
    assert created.status_code == 201, created.text
    first = created.json()
    assert first["actor"] == "shared_service_token"
    assert first["configuration_id"] == result["configuration_id"]
    assert first["source_sha256"] == result["source_sha256"]
    second = submit(
        client,
        result,
        submission(
            result,
            verdict="false_positive",
            comment="Changed assessment after reviewing approved intent.",
        ),
    )
    assert second.status_code == 201
    assert history(client, result).json() == [second.json(), first]
    with TestClient(create_app(settings)) as restarted:
        assert history(restarted, result).json() == [second.json(), first]
        assert (
            restarted.get(f"/api/v1/analyses/{result['analysis_id']}", headers=HEADERS).json()
            == result
        )
    with service.store.engine.connect() as connection:
        payloads = connection.execute(text("SELECT payload FROM finding_feedback")).scalars().all()
        assert len(payloads) == 2
        assert all(
            "Private review" not in item and "false_positive" not in item for item in payloads
        )
        assert (
            connection.execute(
                text("SELECT count(*) FROM audit_events WHERE action='finding.feedback_recorded'")
            ).scalar_one()
            == 2
        )


def test_same_submission_retries_once_even_after_restart(feedback_api):
    client, service, settings = feedback_api
    result = analysis(client)
    body = submission(result)
    first = submit(client, result, body)
    repeated = submit(client, result, body)
    assert first.status_code == 201 and repeated.status_code == 200
    assert first.json() == repeated.json()
    with TestClient(create_app(settings)) as restarted:
        retry = submit(restarted, result, body)
        assert retry.status_code == 200 and retry.json() == first.json()
    with service.store.engine.connect() as connection:
        assert connection.execute(text("SELECT count(*) FROM finding_feedback")).scalar_one() == 1
        assert (
            connection.execute(
                text("SELECT count(*) FROM audit_events WHERE action='finding.feedback_recorded'")
            ).scalar_one()
            == 1
        )


def test_concurrent_retry_is_idempotent(feedback_api):
    client, service, _ = feedback_api
    result = analysis(client)
    body = submission(result)
    with ThreadPoolExecutor(max_workers=4) as executor:
        responses = list(executor.map(lambda _: submit(client, result, body), range(4)))
    assert sorted(item.status_code for item in responses) == [200, 200, 200, 201]
    assert all(item.json() == responses[0].json() for item in responses)
    with service.store.engine.connect() as connection:
        assert connection.execute(text("SELECT count(*) FROM finding_feedback")).scalar_one() == 1


@pytest.mark.parametrize("changed", ["comment", "verdict", "analysis", "finding"])
def test_existing_submission_id_cannot_be_overwritten_or_rebound(feedback_api, changed):
    client, _, _ = feedback_api
    result = analysis(client)
    body = submission(result)
    first = submit(client, result, body)
    assert first.status_code == 201
    index = 0
    if changed == "comment":
        body["comment"] = "Different text"
    elif changed == "verdict":
        body["verdict"] = "false_positive"
    elif changed == "analysis":
        result = client.post(
            f"/api/v1/configurations/{result['configuration_id']}/analyze", headers=HEADERS
        ).json()
        body["analysis_id"] = result["analysis_id"]
    else:
        index = 1
        body["finding_sha256"] = result["explanations"][index]["finding_sha256"]
    response = submit(client, result, body, index)
    assert response.status_code == 409, response.text


def test_repeated_finding_id_is_scoped_to_its_analysis(feedback_api):
    client, _, _ = feedback_api
    first = analysis(client)
    second = client.post(
        f"/api/v1/configurations/{first['configuration_id']}/analyze", headers=HEADERS
    ).json()
    assert target(first) == target(second)
    assert submit(client, first, submission(first)).status_code == 201
    assert history(client, second).json() == []
    assert submit(client, second, submission(second)).status_code == 201
    assert len(history(client, first).json()) == len(history(client, second).json()) == 1


def test_partial_results_accept_review_without_claiming_risk_or_approval(feedback_api):
    client, _, _ = feedback_api
    result = analysis(client, partial=True)
    assert result["status"] == "partial" and result["risk"] is None
    response = submit(client, result, submission(result, verdict="confirmed_anomaly"))
    assert response.status_code == 201
    assert client.get(f"/api/v1/analyses/{result['analysis_id']}", headers=HEADERS).json() == result


def test_invalid_or_stale_binding_does_not_create_feedback(feedback_api):
    client, _, _ = feedback_api
    result = analysis(client)
    assert submit(client, result, submission(result, finding_sha256="f" * 64)).status_code == 409
    assert submit(client, result, submission(result, analysis_id=str(uuid4()))).status_code == 404
    assert (
        client.post(
            f"/api/v1/findings/{uuid4()}/feedback", headers=HEADERS, json=submission(result)
        ).status_code
        == 404
    )
    assert history(client, result).json() == []


@pytest.mark.parametrize(
    "changed",
    [
        {"comment": ""},
        {"comment": "x" * 2001},
        {"comment": "private\x00input"},
        {"verdict": "approved"},
        {"actor": "trusted-engineer"},
        {"ground_truth": True},
        {"finding_sha256": "wrong"},
    ],
)
def test_invalid_body_is_sanitized_and_auth_precedes_body(feedback_api, changed):
    client, _, _ = feedback_api
    result = analysis(client)
    body = submission(result) | changed
    path = f"/api/v1/findings/{target(result)}/feedback"
    assert client.post(path, json=body).status_code == 401
    response = client.post(path, headers=HEADERS, json=body)
    assert response.status_code == 400 and response.json() == {
        "detail": "Invalid feedback submission."
    }


def test_bounded_requests_duplicate_keys_and_history_query(feedback_api):
    client, _, _ = feedback_api
    result = analysis(client)
    path = f"/api/v1/findings/{target(result)}/feedback"
    for contents in (b'{"analysis_id":"one","analysis_id":"two"}', b"[[[[invalid"):
        assert (
            client.post(
                path, headers=HEADERS | {"Content-Type": "application/json"}, content=contents
            ).status_code
            == 400
        )
    assert (
        client.post(
            path,
            headers=HEADERS | {"Content-Type": "application/json"},
            content=b"x" * (16 * 1024 + 1),
        ).status_code
        == 413
    )
    assert client.post(path, headers=HEADERS, content="private").status_code == 415
    assert client.get(path, headers=HEADERS).status_code == 422
    assert client.get(path).status_code == 401
    for query in ("&limit=0", "&limit=101", "&offset=10001"):
        assert history(client, result, query=query).status_code == 422
    assert client.get(f"{path}?analysis_id={uuid4()}", headers=HEADERS).status_code == 404


def test_feedback_pagination_does_not_mix_findings(feedback_api):
    client, _, _ = feedback_api
    result = analysis(client)
    entries = [
        submit(client, result, submission(result, comment=f"Assessment {index}")).json()
        for index in range(4)
    ]
    assert submit(client, result, submission(result, index=1), index=1).status_code == 201
    assert history(client, result, query="&limit=2&offset=0").json() == list(reversed(entries))[:2]
    assert history(client, result, query="&limit=2&offset=2").json() == list(reversed(entries))[2:]


def test_missing_audit_rolls_back_feedback(feedback_api):
    client, service, _ = feedback_api
    result = analysis(client)
    with service.store.engine.begin() as connection:
        connection.execute(text("DROP TABLE audit_events"))
    with pytest.raises(OperationalError):
        service.submit_feedback(
            UUID(target(result)), SubmitFeedback.model_validate(submission(result))
        )
    with service.store.engine.connect() as connection:
        assert connection.execute(text("SELECT count(*) FROM finding_feedback")).scalar_one() == 0


@pytest.mark.parametrize("corruption", ["ciphertext", "metadata", "contents", "source_hash"])
def test_corrupted_or_transplanted_feedback_is_never_returned(feedback_api, corruption):
    client, service, _ = feedback_api
    result = analysis(client)
    first = submit(client, result, submission(result)).json()
    second = submit(client, result, submission(result)).json()
    with service.store.engine.begin() as connection:
        if corruption == "ciphertext":
            payload = connection.execute(
                text("SELECT payload FROM finding_feedback WHERE id=:id"),
                {"id": first["feedback_id"]},
            ).scalar_one()
            connection.execute(
                text("UPDATE finding_feedback SET payload=:payload WHERE id=:id"),
                {"id": second["feedback_id"], "payload": payload},
            )
        elif corruption == "metadata":
            connection.execute(
                text("UPDATE finding_feedback SET finding_id=:finding WHERE id=:id"),
                {"id": second["feedback_id"], "finding": target(result, 1)},
            )
        else:
            altered = deepcopy(second)
            altered["actor" if corruption == "contents" else "source_sha256"] = (
                "fabricated-user" if corruption == "contents" else "f" * 64
            )
            payload = service.store._encode(
                json.dumps(altered), kind="feedback", row_id=second["feedback_id"]
            )
            connection.execute(
                text("UPDATE finding_feedback SET payload=:payload WHERE id=:id"),
                {"id": second["feedback_id"], "payload": payload},
            )
    response = history(client, result, index=1 if corruption == "metadata" else 0)
    assert response.status_code == 503 and response.json() == {
        "detail": "Stored data is unavailable."
    }
