"""Opt-in real PostgreSQL smoke test; use only an explicitly selected *_test database."""

import os
from uuid import UUID, uuid4

import pytest
from app.core.settings import ApiSettings
from app.db.migrate import upgrade_database
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
                },
            )
            assert uploaded.status_code == 201
            snapshot = uploaded.json()
            cid = snapshot["configuration_id"]
            analyzed = client.post(f"/api/v1/configurations/{cid}/analyze", headers=headers)
            assert analyzed.status_code == 201
            result = analyzed.json()
            assert result["status"] == "completed"
            assert result["risk"] is not None
        upgrade_database(store.engine)
        with TestClient(create_app(settings)) as restarted:
            assert (
                restarted.get(f"/api/v1/configurations/{cid}", headers=headers).json() == snapshot
            )
            assert (
                restarted.get(f"/api/v1/analyses/{result['analysis_id']}", headers=headers).json()
                == result
            )
        with store.engine.connect() as connection:
            assert connection.execute(text("SELECT count(*) FROM audit_events")).scalar_one() == 2
            ciphertext = connection.execute(text("SELECT payload FROM configurations")).scalar_one()
            assert "hostname" not in ciphertext
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
        with store.engine.connect() as connection:
            payload = connection.execute(text("SELECT payload FROM models")).scalar_one()
            assert "pg-forest" not in payload and "thresholds" not in payload
    finally:
        store.close()
        # The exact schema target derives only from the UUID generated above.
        assert schema == f"sentinel_api_test_{schema_id.hex}"
        with admin.begin() as connection:
            connection.exec_driver_sql(f'DROP SCHEMA "{schema}" CASCADE')
        admin.dispose()
