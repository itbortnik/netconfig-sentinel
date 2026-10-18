"""Opt-in authored two-node source pairs through the saved HTTP workflow and real SDK."""

import json
import os
from uuid import uuid4

import app.patching.source_review as workflow_module
import pytest
from app.core.patch_verification import PatchVerificationSettings
from app.core.settings import ApiSettings
from app.db.migrate import upgrade_database
from app.main import create_app
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from test_live_batfish import _snapshot_pair
from test_source_patch_review_api import HEADERS, TOKEN, draft_pair, get, options, post, upload


@pytest.mark.skipif(
    os.environ.get("NETCONFIG_LIVE_BATFISH") != "1",
    reason="requires explicit owned loopback upload and running Batfish",
)
@pytest.mark.parametrize("vendor", ["cisco", "juniper"])
@pytest.mark.parametrize("scenario", ["route_loss", "reachable_control", "empty_scope"])
def test_saved_source_pair_with_actual_owned_engine(tmp_path, monkeypatch, vendor, scenario):
    old, changed = _snapshot_pair(vendor)
    edge, core = old.configs
    candidate = changed.configs[0].text
    if scenario == "reachable_control":
        candidate = edge.text + (
            "ntp server 192.0.2.254\n"
            if vendor == "cisco"
            else "set system ntp server 192.0.2.254\n"
        )
    settings = ApiSettings(
        f"sqlite:///{tmp_path / 'owned-live-source.sqlite3'}",
        TOKEN,
        Fernet.generate_key().decode(),
    )
    application = create_app(
        settings,
        patch_verification=PatchVerificationSettings(
            allow_engine_upload=True,
            engine_timeout_seconds=120,
        ),
    )
    upgrade_database(application.state.analysis_service.store.engine)
    with TestClient(application) as client:
        draft, *_ = draft_pair(client, before=edge.text, after=candidate)
        companion = upload(client, core.text)
        body = options(
            draft,
            companions=[
                {
                    "configuration_id": companion["configuration_id"],
                    "source_sha256": companion["canonical"]["source"]["sha256"],
                }
            ],
            scope={
                "start_node": "edge",
                "destination": "203.0.113.1/32" if scenario == "empty_scope" else "198.51.100.1/32",
            },
        )
        response = post(client, draft, body)
        assert response.status_code == 201, response.text
        saved = response.json()
        result = saved["outcome"]["network_result"]
        expected = {
            "route_loss": "differences_found",
            "reachable_control": "no_differences_in_scope",
            "empty_scope": "inconclusive",
        }[scenario]
        print(
            "OWNED_SOURCE_API_RESULT="
            + json.dumps(
                {
                    "vendor": vendor,
                    "scenario": scenario,
                    "status": result["status"],
                    "reason": result["reason"],
                    "engine_version": result["engine_version"],
                    "before_reachable_count": result["before_reachable_count"],
                    "after_reachable_count": result["after_reachable_count"],
                    "difference_count": result["difference_count"],
                    "cleanup_complete": result["cleanup_complete"],
                    "review_sha256": saved["review_sha256"],
                    "ml_status": saved["ml_status"],
                    "overall_status": saved["status"],
                },
                sort_keys=True,
            )
        )
        assert result["status"] == expected
        assert result["engine_version"] and result["cleanup_complete"] is True
        assert saved["status"] == "needs_review" and saved["ml_status"] == "not_run"
        assert saved["approved"] is saved["applied"] is False
        assert get(client, draft, body).json() == saved
        if scenario == "route_loss":
            assert result["before_reachable_count"] and result["after_reachable_count"] == 0
            assert result["difference_count"]
        elif scenario == "reachable_control":
            assert result["before_reachable_count"] and result["after_reachable_count"]
            assert result["difference_count"] == 0
        else:
            assert result["before_reachable_count"] == result["after_reachable_count"] == 0
        monkeypatch.setattr(
            workflow_module,
            "check_with_batfish",
            lambda *a, **k: pytest.fail("replay must not query engine"),
        )
        with TestClient(create_app(settings)) as restarted:
            assert post(restarted, draft, body).json() == saved
            assert get(restarted, draft, body).json() == saved
        # A foreign parent never exposes this result.
        assert (
            client.get(
                f"/api/v2/patches/{uuid4()}/verifications/{body['verification_id']}",
                headers=HEADERS,
            ).status_code
            == 404
        )
