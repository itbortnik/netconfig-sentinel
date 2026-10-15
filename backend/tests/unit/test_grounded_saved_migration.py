"""DDL preserves opaque historical ciphertext and legacy wire fingerprints."""

from datetime import timedelta
from pathlib import Path
from uuid import uuid4

from alembic import command
from alembic.config import Config
from app.api.model_patch_contracts import ModelPatchIntent, ModelPatchOutcome, fingerprint
from app.core.settings import ApiSettings
from app.db import migrate
from app.db.migrate import upgrade_database
from app.db.store import Store
from cryptography.fernet import Fernet
from sqlalchemy import text
from test_grounded_saved_contracts import records


def test_upgrade9_to10_keeps_legacy_ciphertexts_json_and_fingerprints_exact(tmp_path):
    settings = ApiSettings(
        f"sqlite:///{tmp_path / 'owned-migration.sqlite3'}",
        "owned-migration-service-token-0000001",
        Fernet.generate_key().decode(),
    )
    store = Store(settings)
    try:
        config = Config()
        config.set_main_option("script_location", str(Path(migrate.__file__).parent / "migrations"))
        with store.engine.begin() as connection:
            config.attributes["connection"] = connection
            command.upgrade(config, "0009_configuration_model_runs")
        assert not store.ready()
        _, modern, _ = records()
        values = modern.model_dump()
        legacy = ModelPatchIntent.model_validate(
            {key: values[key] for key in ModelPatchIntent.model_fields if key != "version"}
        )
        outcome = ModelPatchOutcome(
            patch_id=legacy.request.patch_id,
            intent_sha256=fingerprint(legacy),
            completed_at=legacy.created_at + timedelta(seconds=1),
            status="failed",
        )
        key = str(legacy.request.patch_id)
        old_json = legacy.model_dump_json()
        encrypted_intent = store._encode(old_json, kind="model_patch_intent", row_id=key)
        encrypted_outcome = store._encode(
            outcome.model_dump_json(), kind="model_patch_outcome", row_id=key
        )
        # Opaque parent rows are DDL fixtures only, not qualified application snapshots.
        # This test proves physical preservation and old codecs; API tests prove replay.
        with store.engine.begin() as connection:
            connection.execute(
                text("INSERT INTO devices(id,identity_payload) VALUES(:id,:payload)"),
                {
                    "id": str(legacy.source.device_id),
                    "payload": "opaque-historical-device-ciphertext",
                },
            )
            connection.execute(
                text(
                    "INSERT INTO configurations(id,device_id,source_sha256,created_at,payload) "
                    "VALUES(:id,:device,:sha,:created,:payload)"
                ),
                {
                    "id": str(legacy.source.configuration_id),
                    "device": str(legacy.source.device_id),
                    "sha": legacy.source.source_sha256,
                    "created": legacy.source.created_at.isoformat(),
                    "payload": "opaque-historical-source-ciphertext",
                },
            )
            connection.execute(
                text(
                    "INSERT INTO analyses(id,configuration_id,created_at,payload) "
                    "VALUES(:id,:configuration,:created,:payload)"
                ),
                {
                    "id": str(legacy.request.analysis_id),
                    "configuration": str(legacy.source.configuration_id),
                    "created": legacy.source.created_at.isoformat(),
                    "payload": "opaque-historical-analysis-ciphertext",
                },
            )
            connection.execute(
                text(
                    "INSERT INTO model_patch_intents"
                    "(id,analysis_id,configuration_id,created_at,payload) "
                    "VALUES(:id,:analysis,:configuration,:created,:payload)"
                ),
                {
                    "id": key,
                    "analysis": str(legacy.request.analysis_id),
                    "configuration": str(legacy.source.configuration_id),
                    "created": legacy.created_at.isoformat(),
                    "payload": encrypted_intent,
                },
            )
            connection.execute(
                text("INSERT INTO model_patch_outcomes(patch_id,payload) VALUES(:id,:payload)"),
                {
                    "id": key,
                    "payload": encrypted_outcome,
                },
            )
        upgrade_database(store.engine)
        upgrade_database(store.engine)
        assert store.ready()
        with store.engine.connect() as connection:
            stored = connection.execute(
                text("SELECT payload,protocol FROM model_patch_intents WHERE id=:id"), {"id": key}
            ).one()
            completed = connection.execute(
                text("SELECT payload FROM model_patch_outcomes WHERE patch_id=:id"), {"id": key}
            ).scalar_one()
            source_payload = connection.execute(
                text("SELECT payload FROM configurations")
            ).scalar_one()
        assert stored.payload == encrypted_intent and completed == encrypted_outcome
        assert stored.protocol == "legacy-model-patch-0.1.0"
        assert source_payload == "opaque-historical-source-ciphertext"
        restored_json = store._decode(stored.payload, kind="model_patch_intent", row_id=key)
        assert restored_json == old_json
        restored = ModelPatchIntent.model_validate_json(restored_json)
        assert restored == legacy and fingerprint(restored) == fingerprint(legacy)
        # A new row may explicitly choose grounded; no legacy payload rewrite is needed.
        with store.engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO model_patch_intents"
                    "(id,analysis_id,configuration_id,created_at,payload,protocol) "
                    "VALUES(:id,:analysis,:configuration,:created,:payload,:protocol)"
                ),
                {
                    "id": str(uuid4()),
                    "analysis": str(legacy.request.analysis_id),
                    "configuration": str(legacy.source.configuration_id),
                    "created": legacy.created_at.isoformat(),
                    "payload": "opaque-grounded-fixture",
                    "protocol": "grounded-model-patch-0.1.0",
                },
            )
    finally:
        store.close()
