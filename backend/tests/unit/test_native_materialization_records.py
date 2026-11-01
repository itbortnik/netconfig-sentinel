"""Atomic native bridge admission, immutable history, races and fault rollback."""

import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone
from threading import Barrier
from uuid import uuid4

import pytest
from app.api.native_materialization_contracts import (
    CreateNativeMaterialization,
    native_materialization_record,
)
from app.db.migrate import SCHEMA_REVISION, upgrade_database
from app.db.native_materialization_records import (
    NativeMaterializationRecords,
    NativeMaterializationTooLarge,
)
from app.db.native_patch_records import NativePatchRecords
from app.db.patch_records import PatchConflict, PatchRecords
from app.db.source_records import SourceRecords
from app.db.store import StorageIntegrityError
from app.patching.native_materialization_preparation import prepare_native_materialization
from sqlalchemy import event, inspect, text
from sqlalchemy.exc import IntegrityError, OperationalError
from test_native_patch_records import owned_store as owned_store
from test_native_patch_records import prepare_owned_candidate


def materialization_case(
    store, vendor="cisco", *, native=None, outputs=None, role="engineer", created_at=None
):
    native = native or prepare_owned_candidate(store, vendor)
    NativePatchRecords(store).save(native)
    before = store.get_configuration(native.public.configuration_id)
    analysis = store.get_analysis(native.public.request.analysis_id)
    retained = SourceRecords(store).get(
        before.configuration_id,
        expected_source_sha256=before.canonical.source.sha256,
        allow_local_read=True,
    )
    after_id, patch_id = outputs or (uuid4(), uuid4())
    created_at = created_at or datetime.now(UTC)
    prepared = prepare_native_materialization(
        native,
        before,
        analysis,
        retained,
        after_configuration_id=after_id,
        patch_id=patch_id,
        created_at=created_at,
    )
    options = CreateNativeMaterialization(
        version="native-materialization-request-0.1.0",
        after_configuration_id=after_id,
        patch_id=patch_id,
        native_review_sha256=native.public.review_sha256,
        allow_local_source_materialization=True,
        allow_private_candidate_source_retention=True,
    )
    record = native_materialization_record(
        before.configuration_id,
        native.public.candidate_id,
        options,
        native,
        before,
        prepared,
        created_at=created_at,
        service_role=role,
    )
    return record, prepared, retained


def counts(store):
    with store.engine.connect() as connection:
        return tuple(
            connection.execute(text(f"SELECT count(*) FROM {name}")).scalar_one()
            for name in (
                "devices",
                "configurations",
                "configuration_sources",
                "patch_proposals",
                "native_patch_candidates",
                "native_materializations",
                "audit_events",
            )
        )


@pytest.mark.parametrize("vendor", ["cisco", "juniper"])
def test_atomic_outputs_encrypted_source_and_four_domain_audits(owned_store, vendor):
    record, prepared, retained = materialization_case(owned_store, vendor)
    records = NativeMaterializationRecords(owned_store)
    baseline = counts(owned_store)
    assert records.save(record, prepared, retained) == (record, True)
    after = counts(owned_store)
    assert tuple(a - b for a, b in zip(after, baseline, strict=True)) == (0, 1, 1, 1, 0, 1, 4)
    assert (
        records.get(record.candidate_id)
        == records.get_origin(record.after.configuration_id)
        == record
    )
    assert PatchRecords(owned_store).get_draft(record.patch_id) == prepared.draft
    source = SourceRecords(owned_store).get(
        record.after.configuration_id,
        expected_source_sha256=record.after.source_sha256,
        allow_local_read=True,
    )
    assert source.content.encode() == prepared.retained_after.content.encode()
    with owned_store.engine.connect() as connection:
        for name in (
            "configurations",
            "configuration_sources",
            "patch_proposals",
            "native_materializations",
        ):
            for payload in connection.execute(text(f"SELECT payload FROM {name}")).scalars():
                assert "OWNED_UNRELATED_CREDENTIAL" not in payload
        actions = (
            connection.execute(text("SELECT action FROM audit_events ORDER BY rowid DESC LIMIT 4"))
            .scalars()
            .all()
        )
        assert set(actions) == {
            "configuration.created",
            "configuration.source_retained",
            "patch.draft_created",
            "native_patch.materialized",
        }


@pytest.mark.parametrize("stage", range(1, 9))
def test_every_row_and_audit_insert_failure_rolls_back_entire_unit(owned_store, stage):
    values = materialization_case(owned_store)
    baseline = counts(owned_store)
    observed = 0

    def fail_insert(connection, cursor, statement, parameters, context, many):
        nonlocal observed
        if statement.startswith("INSERT INTO"):
            observed += 1
            if observed == stage:
                raise RuntimeError("owned injection")

    event.listen(owned_store.engine, "before_cursor_execute", fail_insert)
    try:
        with pytest.raises(RuntimeError, match="owned injection"):
            NativeMaterializationRecords(owned_store).save(*values)
    finally:
        event.remove(owned_store.engine, "before_cursor_execute", fail_insert)
    assert observed == stage and counts(owned_store) == baseline
    assert NativeMaterializationRecords(owned_store).get(values[0].candidate_id) is None


def test_fresh_source_deletion_conflicts_but_replay_and_history_ignore_all_sources_and_runtime(
    owned_store, monkeypatch
):
    values = materialization_case(owned_store)
    records = NativeMaterializationRecords(owned_store)
    records.save(*values)
    with owned_store.engine.begin() as connection:
        connection.execute(text("DELETE FROM configuration_sources"))

    def forbidden(*args, **kwargs):
        pytest.fail("immutable materialization history called runtime or source lookup")

    for name in (
        "app.db.source_records.SourceRecords.get",
        "app.ingestion.source_retention.prepare_original_source",
        "app.parsers.parse_configuration",
        "app.parsers.coverage.parse_configuration_with_coverage",
        "app.patching.native_materialization_preparation.prepare_native_materialization",
        "app.patching.vendor_drafts.create_vendor_draft",
        "app.detection.policy_engine.evaluate_policies",
    ):
        monkeypatch.setattr(name, forbidden)
    monkeypatch.setattr("app.detection.policy_engine.POLICY_CATALOGS", {})
    assert records.get(values[0].candidate_id) == values[0]
    assert records.get_origin(values[0].after.configuration_id) == values[0]
    assert records.save(values[0], None, None) == (values[0], False)


def test_fresh_missing_source_is_409_without_using_private_native_copy(owned_store):
    values = materialization_case(owned_store)
    with owned_store.engine.begin() as connection:
        connection.execute(text("DELETE FROM configuration_sources"))
    baseline = counts(owned_store)
    with pytest.raises(PatchConflict):
        NativeMaterializationRecords(owned_store).save(*values)
    assert counts(owned_store) == baseline


def test_sqlite_transaction_holds_write_lock_before_source_recheck(owned_store, monkeypatch):
    records = NativeMaterializationRecords(owned_store)
    values = materialization_case(owned_store)
    original = records._source
    observed = []

    def probe(session, retained):
        with owned_store.engine.connect() as peer:
            peer.exec_driver_sql("PRAGMA busy_timeout=1")
            with pytest.raises(OperationalError, match="locked"):
                peer.execute(text("DELETE FROM configuration_sources"))
        observed.append(True)
        return original(session, retained)

    monkeypatch.setattr(records, "_source", probe)
    assert records.save(*values)[1] is True
    assert observed == [True]


@pytest.mark.parametrize("same", [True, False])
def test_candidate_race_has_one_winner_and_only_identical_intent_replays(owned_store, same):
    native = prepare_owned_candidate(owned_store)
    first = materialization_case(owned_store, native=native)
    second = materialization_case(
        owned_store,
        native=native,
        outputs=(first[0].after.configuration_id, first[0].patch_id) if same else None,
        role="admin",
        created_at=first[0].created_at + timedelta(seconds=1),
    )
    baseline = counts(owned_store)
    gate = Barrier(2)

    def worker(values):
        gate.wait(timeout=10)
        try:
            return NativeMaterializationRecords(owned_store).save(*values)
        except PatchConflict:
            return "conflict"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(worker, (first, second)))
    assert sum(item != "conflict" and item[1] for item in results) == 1
    if same:
        assert results[0][0] == results[1][0]
        assert sorted(item[1] for item in results) == [False, True]
    else:
        assert results.count("conflict") == 1
    assert tuple(a - b for a, b in zip(counts(owned_store), baseline, strict=True)) == (
        0,
        1,
        1,
        1,
        0,
        1,
        4,
    )


@pytest.mark.parametrize("collision", ["after", "patch"])
def test_existing_output_ids_are_never_adopted_even_for_identical_rows(owned_store, collision):
    record, prepared, retained = materialization_case(owned_store)
    owned_store.add_configuration(prepared.after)
    if collision == "patch":
        PatchRecords(owned_store).add_draft(prepared.draft)
        native = NativePatchRecords(owned_store).get(record.candidate_id)
        record, prepared, retained = materialization_case(
            owned_store, native=native, outputs=(uuid4(), record.patch_id)
        )
        assert owned_store.get_configuration(record.after.configuration_id) is None
    baseline = counts(owned_store)
    with pytest.raises(PatchConflict):
        NativeMaterializationRecords(owned_store).save(record, prepared, retained)
    assert counts(owned_store) == baseline


@pytest.mark.parametrize(
    "target", ["draft_flag", "draft_diff_flag", "draft_count", "before_bool", "after_bool"]
)
def test_history_rejects_serialized_nested_scalar_coercion(owned_store, target):
    record, prepared, retained = materialization_case(owned_store)
    records = NativeMaterializationRecords(owned_store)
    records.save(record, prepared, retained)
    if target.startswith("draft"):
        table, key, identity, kind = "patch_proposals", "id", record.patch_id, "patch"
        data = prepared.draft.model_dump(mode="json")
        if target == "draft_flag":
            data["requires_human_review"] = 1
        elif target == "draft_diff_flag":
            data["diff"]["source_changed"] = 1
        else:
            data["diff"]["modified_count"] = True
    else:
        before = owned_store.get_configuration(record.configuration_id)
        snapshot = before if target == "before_bool" else prepared.after
        table, key, identity, kind = (
            "configurations", "id", snapshot.configuration_id, "configuration"
        )
        data = snapshot.model_dump(mode="json")
        data["canonical"]["management"]["telnet_enabled"] = int(target == "before_bool")
    with owned_store.engine.begin() as connection:
        connection.execute(
            text(f"UPDATE {table} SET payload=:payload WHERE {key}=:identity"),
            {
                "identity": str(identity),
                "payload": owned_store._encode(json.dumps(data), kind=kind, row_id=str(identity)),
            },
        )
    with pytest.raises(StorageIntegrityError):
        records.get(record.candidate_id)


@pytest.mark.parametrize(
    "target", ["sql_time", "sql_sha", "envelope", "proof", "draft_time", "device"]
)
def test_history_rejects_corrupt_sql_proof_draft_or_real_device(owned_store, target):
    record, prepared, retained = materialization_case(owned_store)
    records = NativeMaterializationRecords(owned_store)
    records.save(record, prepared, retained)
    with owned_store.engine.begin() as connection:
        if target == "sql_time":
            connection.execute(
                text("UPDATE native_materializations SET created_at='2000-01-01 00:00:00'")
            )
        elif target == "sql_sha":
            connection.execute(
                text("UPDATE native_materializations SET public_sha256=:value"), {"value": "f" * 64}
            )
        elif target in {"envelope", "proof"}:
            payload = owned_store._encode(
                record.model_dump_json()
                if target == "envelope"
                else record.model_dump_json().replace(record.review_sha256, "f" * 64),
                kind="patch" if target == "envelope" else "native_materialization",
                row_id=str(record.candidate_id),
            )
            connection.execute(
                text("UPDATE native_materializations SET payload=:payload"), {"payload": payload}
            )
        elif target == "draft_time":
            connection.execute(text("UPDATE patch_proposals SET created_at='2000-01-01 00:00:00'"))
        else:
            payload = owned_store._encode(
                '["cisco","ios","foreign"]', kind="device", row_id=str(record.before.device_id)
            )
            connection.execute(
                text("UPDATE devices SET identity_payload=:payload"), {"payload": payload}
            )
    with pytest.raises(StorageIntegrityError):
        records.get(record.candidate_id)
    with pytest.raises(StorageIntegrityError):
        records.get_origin(record.after.configuration_id)


@pytest.mark.parametrize(
    "table,column",
    [("native_patch_candidates", "id"), ("configurations", "id"), ("patch_proposals", "id")],
)
def test_foreign_keys_restrict_removing_history_parents(owned_store, table, column):
    values = materialization_case(owned_store)
    NativeMaterializationRecords(owned_store).save(*values)
    record = values[0]
    identity = {
        "native_patch_candidates": record.candidate_id,
        "configurations": record.after.configuration_id,
        "patch_proposals": record.patch_id,
    }[table]
    with pytest.raises(IntegrityError), owned_store.engine.begin() as connection:
        connection.execute(
            text(f"DELETE FROM {table} WHERE {column}=:identity"), {"identity": str(identity)}
        )


@pytest.mark.parametrize(
    "constant",
    [
        "MAX_SOURCE_PAYLOAD_BYTES",
        "MAX_RECORD_BYTES",
        "MAX_NATIVE_MATERIALIZATION_PUBLIC_BYTES",
        "MAX_MATERIALIZATION_PLAINTEXT_BYTES",
        "MAX_SOURCE_CIPHERTEXT_BYTES",
        "MAX_DRAFT_CIPHERTEXT_BYTES",
        "MAX_NATIVE_MATERIALIZATION_CIPHERTEXT_BYTES",
        "MAX_MATERIALIZATION_CIPHERTEXT_BYTES",
    ],
)
def test_individual_and_combined_budgets_reject_before_writes(owned_store, monkeypatch, constant):
    import app.db.native_materialization_records as storage

    values = materialization_case(owned_store)
    baseline = counts(owned_store)
    monkeypatch.setattr(storage, constant, 1)
    with pytest.raises(NativeMaterializationTooLarge):
        NativeMaterializationRecords(owned_store).save(*values)
    assert counts(owned_store) == baseline


def test_typed_prepared_flags_and_stale_retained_pin_cannot_bypass_writer(owned_store):
    values = materialization_case(owned_store)
    record, prepared, retained = values
    baseline = counts(owned_store)
    for changed in (
        replace(prepared, draft=prepared.draft.model_copy(update={"requires_human_review": 1})),
        replace(prepared, after=prepared.after.model_copy(update={"device_id": uuid4()})),
    ):
        with pytest.raises(PatchConflict):
            NativeMaterializationRecords(owned_store).save(record, changed, retained)
    with pytest.raises(PatchConflict):
        NativeMaterializationRecords(owned_store).save(
            record, prepared, retained.model_copy(update={"filename": "changed.cfg"})
        )
    assert counts(owned_store) == baseline


def test_offset_aware_times_write_utc_and_replay_preserves_first_role_and_time(owned_store):
    native = prepare_owned_candidate(owned_store)
    created_at = datetime.now(UTC).astimezone(timezone(timedelta(hours=5, minutes=30)))
    first = materialization_case(owned_store, native=native, created_at=created_at)
    second = materialization_case(
        owned_store,
        native=native,
        outputs=(first[0].after.configuration_id, first[0].patch_id),
        role="admin",
    )
    records = NativeMaterializationRecords(owned_store)
    records.save(*first)
    assert records.save(*second) == (first[0], False)
    assert records.get(first[0].candidate_id).created_at == first[0].created_at
    with owned_store.engine.connect() as connection:
        stored = connection.execute(
            text("SELECT created_at FROM native_materializations")
        ).scalar_one()
    assert str(stored).startswith(created_at.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S"))


def test_populated_18_to_19_upgrade_preserves_native_and_all_prior_rows(owned_store):
    native = prepare_owned_candidate(owned_store)
    NativePatchRecords(owned_store).save(native)
    with owned_store.engine.begin() as connection:
        connection.exec_driver_sql("DROP TABLE native_materializations")
        connection.execute(
            text("UPDATE alembic_version SET version_num='0018_native_patch_candidates'")
        )
    names = set(inspect(owned_store.engine).get_table_names()) - {"alembic_version"}

    def physical():
        with owned_store.engine.connect() as connection:
            return {
                name: sorted(map(repr, connection.execute(text(f'SELECT * FROM "{name}"')).all()))
                for name in names
            }

    prior_rows = physical()
    assert not owned_store.schema_ready()
    upgrade_database(owned_store.engine)
    upgrade_database(owned_store.engine)
    assert SCHEMA_REVISION == "0019_native_materializations"
    assert owned_store.schema_ready() and physical() == prior_rows
    assert NativePatchRecords(owned_store).get(native.public.candidate_id) == native
    assert NativeMaterializationRecords(owned_store).get(native.public.candidate_id) is None
