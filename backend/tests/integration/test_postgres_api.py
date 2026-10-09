"""Opt-in real PostgreSQL smoke test; use only an explicitly selected *_test database."""

import os
from concurrent.futures import ThreadPoolExecutor
from uuid import UUID, uuid4

import pytest
from app.core.settings import ApiSettings
from app.db.migrate import upgrade_database
from app.db.source_records import SourceRecords
from app.db.store import Store, make_engine
from app.main import create_app
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import IntegrityError


def test_postgresql_encrypted_history_and_restart() -> None:
    configured = os.environ.get("NETCONFIG_TEST_DATABASE_URL", "")
    if not configured:
        pytest.skip("requires an explicitly selected PostgreSQL test database")
    url = make_url(configured)
    if url.drivername != "postgresql+psycopg" or not (url.database or "").endswith("_test"):
        pytest.fail("PostgreSQL smoke test requires a postgresql+psycopg *_test database")
    # All writes and cleanup are confined to a fresh schema owned by this test.
    schema_id = uuid4()
    schema = f"sentinel_api_test_{schema_id.hex}"
    admin = make_engine(configured)
    with admin.begin() as connection:
        connection.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
    selected = url.update_query_dict({"options": f"-csearch_path={schema}"})
    token = "postgres-integration-service-token-001"
    settings = ApiSettings(
        selected.render_as_string(hide_password=False),
        token,
        Fernet.generate_key().decode("ascii"),
    )
    store = Store(settings)
    headers = {"Authorization": f"Bearer {token}"}
    try:
        assert not store.ready()
        upgrade_database(store.engine)
        assert store.ready()
        with TestClient(create_app(settings)) as client:
            uploaded = client.post(
                "/api/v1/configurations",
                headers=headers,
                json={
                    "device_id": str(UUID(int=1)),
                    "filename": "edge.cfg",
                    "content": "hostname edge\n",
                    "retain_original_source": True,
                },
            )
            assert uploaded.status_code == 201
            snapshot = uploaded.json()
            coverage = snapshot["parser_coverage"]
            assert coverage["version"] == "parser-coverage-0.1.0"
            assert coverage["accepted_units"] == coverage["command_units"] == 1
            assert coverage["unparsed_fraction"] == 0
            assert coverage["source_sha256"] == snapshot["canonical"]["source"]["sha256"]
            cid = snapshot["configuration_id"]
            retained = SourceRecords(store).get(
                UUID(cid),
                expected_source_sha256=snapshot["canonical"]["source"]["sha256"],
                allow_local_read=True,
            )
            assert retained.content == "hostname edge\n"
            analyzed = client.post(f"/api/v1/configurations/{cid}/analyze", headers=headers)
            assert analyzed.status_code == 201
            result = analyzed.json()
            assert result["status"] == "completed"
            assert result["risk"] is not None
            context_path = f"/api/v1/findings/{result['findings'][0]['finding_id']}/explain"
            context_body = {
                "analysis_id": result["analysis_id"],
                "finding_sha256": result["explanations"][0]["finding_sha256"],
            }
            explained = client.post(context_path, headers=headers, json=context_body)
            assert explained.status_code == 200, explained.text
            contextual = explained.json()
            assert contextual["explanation"] == result["explanations"][0]
            assert contextual["llm_status"] == "unavailable"
            candidate = client.post(
                "/api/v1/configurations",
                headers=headers,
                json={
                    "device_id": snapshot["device_id"],
                    "filename": "edge.cfg",
                    "content": "hostname edge\nntp server 192.0.2.1\n",
                },
            )
            assert candidate.status_code == 201
            candidate_id = candidate.json()["configuration_id"]
            comparison = client.get(
                f"/api/v1/configurations/{candidate_id}/diff",
                headers=headers,
                params={"reference_configuration_id": cid},
            )
            assert comparison.status_code == 200, comparison.text
            object_diff = comparison.json()
            assert object_diff["modified_count"] == 1
            assert object_diff["changes"][0]["section"] == "management"
            draft_body = {
                "patch_id": str(uuid4()),
                "before_configuration_id": cid,
                "after_configuration_id": candidate_id,
                "before_source_sha256": snapshot["canonical"]["source"]["sha256"],
                "after_source_sha256": candidate.json()["canonical"]["source"]["sha256"],
            }
            with ThreadPoolExecutor(max_workers=4) as executor:
                drafts = list(
                    executor.map(
                        lambda _: client.post("/api/v1/patches", headers=headers, json=draft_body),
                        range(4),
                    )
                )
            assert sorted(item.status_code for item in drafts) == [200, 200, 200, 201]
            draft = drafts[0].json()
            assert all(item.json() == draft for item in drafts)
            review_path = f"/api/v1/patches/{draft['patch_id']}/verify"
            review_body = {"verification_id": str(uuid4()), "draft_sha256": draft["draft_sha256"]}
            with ThreadPoolExecutor(max_workers=4) as executor:
                reviews = list(
                    executor.map(
                        lambda _: client.post(review_path, headers=headers, json=review_body),
                        range(4),
                    )
                )
            assert sorted(item.status_code for item in reviews) == [200, 200, 200, 201]
            review = reviews[0].json()
            assert all(item.json() == review for item in reviews)
            assert review["preflight"]["formal_verification"] == "not_run"
            assert (
                client.post(
                    review_path, headers=headers, json=review_body | {"mode": "batfish"}
                ).status_code
                == 503
            )
        upgrade_database(store.engine)
        with TestClient(create_app(settings)) as restarted:
            assert (
                restarted.post("/api/v1/patches", headers=headers, json=draft_body).json() == draft
            )
            assert restarted.post(review_path, headers=headers, json=review_body).json() == review
            assert (
                restarted.get(
                    f"/api/v1/patches/{draft['patch_id']}/verifications/{review['verification_id']}",
                    headers=headers,
                ).json()
                == review
            )
            assert (
                restarted.post(context_path, headers=headers, json=context_body).json()
                == contextual
            )
            assert (
                restarted.get(f"/api/v1/configurations/{cid}", headers=headers).json() == snapshot
            )
            assert (
                restarted.get(f"/api/v1/analyses/{result['analysis_id']}", headers=headers).json()
                == result
            )
            assert (
                restarted.get(
                    f"/api/v1/configurations/{candidate_id}/diff",
                    headers=headers,
                    params={"reference_configuration_id": cid},
                ).json()
                == object_diff
            )
        with store.engine.connect() as connection:
            assert connection.execute(text("SELECT count(*) FROM audit_events")).scalar_one() == 6
            ciphertext = connection.execute(
                text("SELECT payload FROM configuration_sources")
            ).scalar_one()
            assert "hostname" not in ciphertext
        assert (
            SourceRecords(store).get(
                UUID(cid),
                expected_source_sha256=snapshot["canonical"]["source"]["sha256"],
                allow_local_read=True,
            )
            == retained
        )
        with store.engine.connect() as connection:
            for table in ("patch_proposals", "verification_runs"):
                payload = connection.execute(text(f"SELECT payload FROM {table}")).scalar_one()
                assert "edge" not in payload and "192.0.2.1" not in payload
            ciphertexts = connection.execute(text("SELECT payload FROM configurations")).scalars()
            assert all("hostname" not in ciphertext for ciphertext in ciphertexts)
        with pytest.raises(IntegrityError), store.engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO analyses (id, configuration_id, created_at, payload) "
                    "VALUES ('orphan', 'missing', CURRENT_TIMESTAMP, 'encrypted')"
                )
            )
        with TestClient(create_app(settings)) as client:
            training_ids = []
            labels = {"device_role": "edge", "site_class": "branch", "service_profile": "pg-test"}
            for index in range(9):
                contents = f"hostname pg-forest-{index}\naaa new-model\nip ssh version 2\n"
                contents += "".join(
                    f"vlan {10 + vlan}\n name VLAN-{vlan}\n!\n" for vlan in range(index % 7 + 1)
                )
                response = client.post(
                    "/api/v1/configurations",
                    headers=headers,
                    json={
                        "device_id": str(uuid4()),
                        "filename": "pg-forest.cfg",
                        "content": contents,
                        "inventory": labels,
                    },
                )
                assert response.status_code == 201
                if index < 8:
                    training_ids.append(response.json()["configuration_id"])
                else:
                    target_id = response.json()["configuration_id"]
            trained = client.post(
                "/api/v1/models/isolation-forest",
                headers=headers,
                json={"configuration_ids": training_ids},
            )
            assert trained.status_code == 201, trained.text
            manifest = trained.json()
            analyzed = client.post(
                f"/api/v1/configurations/{target_id}/analyze",
                headers=headers,
                json={"statistical_model_id": manifest["model_id"]},
            )
            assert analyzed.status_code == 201, analyzed.text
            statistical_result = analyzed.json()
            assert statistical_result["statistical"]["model"] == manifest
            finding_id = statistical_result["findings"][0]["finding_id"]
            feedback_path = f"/api/v1/findings/{finding_id}/feedback"
            assessment = {
                "feedback_id": str(uuid4()),
                "analysis_id": statistical_result["analysis_id"],
                "finding_sha256": statistical_result["explanations"][0]["finding_sha256"],
                "verdict": "needs_investigation",
                "comment": "Private PostgreSQL integration review.",
            }
            with ThreadPoolExecutor(max_workers=4) as executor:
                responses = list(
                    executor.map(
                        lambda _: client.post(feedback_path, headers=headers, json=assessment),
                        range(4),
                    )
                )
            assert sorted(item.status_code for item in responses) == [200, 200, 200, 201]
            feedback = responses[0].json()
            assert all(item.json() == feedback for item in responses)
        with TestClient(create_app(settings)) as restarted:
            assert (
                restarted.get(f"/api/v1/models/{manifest['model_id']}", headers=headers).json()
                == manifest
            )
            assert (
                restarted.get(
                    f"/api/v1/analyses/{statistical_result['analysis_id']}", headers=headers
                ).json()
                == statistical_result
            )
            replay = restarted.post(feedback_path, headers=headers, json=assessment)
            assert replay.status_code == 200 and replay.json() == feedback
            history = restarted.get(
                feedback_path,
                headers=headers,
                params={"analysis_id": statistical_result["analysis_id"]},
            )
            assert history.status_code == 200 and history.json() == [feedback]
            assert (
                restarted.post(
                    feedback_path, headers=headers, json=assessment | {"comment": "Changed intent"}
                ).status_code
                == 409
            )
        with store.engine.connect() as connection:
            payload = connection.execute(text("SELECT payload FROM models")).scalar_one()
            assert "pg-forest" not in payload and "thresholds" not in payload
            payload = connection.execute(text("SELECT payload FROM finding_feedback")).scalar_one()
            assert "Private PostgreSQL" not in payload and "needs_investigation" not in payload
            assert (
                connection.execute(
                    text(
                        "SELECT count(*) FROM audit_events WHERE action='finding.feedback_recorded'"
                    )
                ).scalar_one()
                == 1
            )
    finally:
        store.close()
        # The exact schema target derives only from the UUID generated above.
        assert schema == f"sentinel_api_test_{schema_id.hex}"
        with admin.begin() as connection:
            connection.exec_driver_sql(f'DROP SCHEMA "{schema}" CASCADE')
        admin.dispose()
