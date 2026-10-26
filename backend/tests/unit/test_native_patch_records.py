"""Owned encrypted native history, SQL bindings, replay races and additive migration."""

import json
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta, timezone
from threading import Barrier, local
from uuid import UUID, uuid4

import pytest
from app.api.contracts import UploadConfiguration
from app.api.native_patch_contracts import (
    GenerateNativePatch,
    NativePatchPrivate,
    native_patch_candidate,
    native_patch_selection,
)
from app.api.service import AnalysisService
from app.core.settings import ApiSettings
from app.db.migrate import SCHEMA_REVISION, upgrade_database
from app.db.native_patch_records import (
    NativePatchInputNotFound,
    NativePatchRecords,
    NativePatchTooLarge,
)
from app.db.patch_records import PatchConflict
from app.db.store import StorageIntegrityError, Store
from app.db.tables import NativePatchCandidateRow
from app.patching.vendor_drafts import create_vendor_draft
from cryptography.fernet import Fernet
from sqlalchemy import inspect, text
from sqlalchemy.exc import IntegrityError


def authored_text(vendor):
    if vendor == "cisco":
        return (
            "hostname owned-native\r\nusername inspector secret 5 OWNED_UNRELATED_CREDENTIAL\r\n"
            "ip ssh version 2\r\nline vty 0 4\r\n\ttransport input ssh telnet  \r\n!\r\n"
        )
    return (
        "set system host-name owned-native\n"
        'set system login user inspector authentication encrypted-password '
        '"OWNED_UNRELATED_CREDENTIAL"\n'
        "set system services ssh\nset system services telnet\n"
    )


def prepare_owned_candidate(
    store, vendor="cisco", *, candidate_id=None, created_at=None, role=None
):
    before_text = authored_text(vendor)
    service = AnalysisService(store)
    snapshot = service.upload(
        UploadConfiguration(
            device_id=uuid4(),
            filename="owned-native.cfg",
            content=before_text,
            retain_original_source=True,
        )
    )
    created = service.analyze(snapshot.configuration_id)
    assert created is not None
    analysis = store.get_analysis(created.analysis_id)
    assert analysis is not None
    selection = native_patch_selection(snapshot, analysis)
    selected = next(row for row in selection.finding_pins)
    request = GenerateNativePatch(
        version="native-patch-request-0.1.0",
        candidate_id=candidate_id or uuid4(),
        analysis_id=analysis.analysis_id,
        finding_id=selected.finding_id,
        analysis_sha256=selection.analysis_sha256,
        finding_sha256=selected.finding_sha256,
        source_sha256=selection.source.source_sha256,
        canonical_sha256=selection.canonical_sha256,
        policy_catalog_version=selection.policy_catalog_version,
        allow_local_native_generation=True,
        allow_private_candidate_retention=True,
    )
    finding = next(row for row in analysis.findings if row.finding_id == selected.finding_id)
    generated = create_vendor_draft(
        before_text,
        finding=finding,
        source_sha256=request.source_sha256,
        reference_id=str(snapshot.configuration_id),
    )
    public = native_patch_candidate(
        snapshot.configuration_id,
        request,
        snapshot,
        analysis,
        generated.metadata,
        created_at=created_at or datetime.now(UTC),
        service_role=role or "engineer",
    )
    return NativePatchPrivate(
        public=public,
        generated_metadata=generated.metadata,
        before_text=before_text,
        candidate_text=generated.candidate_text,
    )


@pytest.fixture
def owned_store(tmp_path):
    store = Store(
        ApiSettings(
            f"sqlite:///{tmp_path / 'native-history.sqlite3'}",
            "owned-native-patch-unit-token-00000001",
            Fernet.generate_key().decode(),
        )
    )
    upgrade_database(store.engine)
    try:
        yield store
    finally:
        store.close()


def counts(store):
    with store.engine.connect() as connection:
        return (
            connection.execute(text("SELECT count(*) FROM native_patch_candidates")).scalar_one(),
            connection.execute(
                text("SELECT count(*) FROM audit_events WHERE action='native_patch.created'")
            ).scalar_one(),
        )


def rebuilt(private, store, *, created_at=None, service_role=None, candidate_id=None):
    public = private.public
    snapshot = store.get_configuration(public.configuration_id)
    analysis = store.get_analysis(public.request.analysis_id)
    assert snapshot is not None and analysis is not None
    request = public.request.model_copy(
        update={"candidate_id": candidate_id or public.candidate_id}
    )
    return NativePatchPrivate(
        public=native_patch_candidate(
            public.configuration_id,
            request,
            snapshot,
            analysis,
            private.generated_metadata,
            created_at=created_at or public.created_at,
            service_role=service_role or public.service_role,
        ),
        generated_metadata=private.generated_metadata,
        before_text=private.before_text,
        candidate_text=private.candidate_text,
    )


@pytest.mark.parametrize("vendor", ["cisco", "juniper"])
def test_encrypted_native_candidate_exact_replay_and_safe_audit(owned_store, vendor):
    store = owned_store
    private = prepare_owned_candidate(store, vendor)
    records = NativePatchRecords(store)
    assert records.save(private) == (private, True)
    later = rebuilt(
        private,
        store,
        created_at=private.public.created_at + timedelta(seconds=1),
        service_role="admin",
    )
    assert later != private
    assert records.save(later) == (private, False)
    assert records.get(private.public.candidate_id) == private
    assert records.get(uuid4()) is None
    assert records.configuration_exists(private.public.configuration_id)
    assert not records.configuration_exists(uuid4())
    assert records.list_ids(private.public.configuration_id, limit=20, offset=0) == [
        private.public.candidate_id
    ]
    assert counts(store) == (1, 1)
    with store.engine.connect() as connection:
        payload = connection.execute(
            text("SELECT payload FROM native_patch_candidates")
        ).scalar_one()
        audit = connection.execute(
            text("SELECT action,resource_id FROM audit_events WHERE action='native_patch.created'")
        ).one()
    assert "OWNED_UNRELATED_CREDENTIAL" in private.before_text
    assert "OWNED_UNRELATED_CREDENTIAL" in private.candidate_text
    assert "OWNED_UNRELATED_CREDENTIAL" not in private.public.model_dump_json()
    assert private.before_text not in repr(private)
    assert "OWNED_UNRELATED_CREDENTIAL" not in payload
    assert str(private.public.candidate_id) not in payload
    assert private.public.review_json not in payload
    assert audit == ("native_patch.created", str(private.public.candidate_id))


@pytest.mark.parametrize("vendor", ["cisco", "juniper"])
def test_restart_history_after_source_removal_uses_no_runtime_generator(
    owned_store, monkeypatch, vendor
):
    store = owned_store
    private = prepare_owned_candidate(store, vendor)
    records = NativePatchRecords(store)
    assert records.save(private)[1]
    later = rebuilt(private, store, created_at=private.public.created_at + timedelta(seconds=1))
    with store.engine.begin() as connection:
        connection.execute(text("DELETE FROM configuration_sources"))

    def forbidden(*args, **kwargs):
        pytest.fail("saved native history attempted source access, parsing, policy or generation")

    for name in (
        "app.db.source_records.SourceRecords.get",
        "app.parsers.parse_configuration",
        "app.ingestion.source_retention.parse_configuration",
        "app.ingestion.source_retention.prepare_original_source",
        "app.detection.policy_engine.evaluate_policies",
        "app.patching.vendor_drafts.parse_configuration",
        "app.patching.vendor_drafts.evaluate_policies",
        "app.patching.vendor_drafts.create_vendor_draft",
        "app.patching.vendor_drafts.check_vendor_draft",
        "app.patching.vendor_drafts._cisco_telnet",
        "app.patching.vendor_drafts._simple_edits",
    ):
        monkeypatch.setattr(name, forbidden)
    monkeypatch.setattr("app.detection.policy_engine.POLICY_CATALOGS", {})
    store.close()
    assert records.get(private.public.candidate_id) == private
    assert records.save(later) == (private, False)
    assert records.list_ids(private.public.configuration_id, limit=20, offset=0) == [
        private.public.candidate_id
    ]


def test_global_candidate_id_conflicts_across_configuration_and_request(owned_store):
    private = prepare_owned_candidate(owned_store)
    records = NativePatchRecords(owned_store)
    assert records.save(private)[1]
    other = prepare_owned_candidate(
        owned_store, "juniper", candidate_id=private.public.candidate_id
    )
    with pytest.raises(PatchConflict):
        records.save(other)
    assert counts(owned_store) == (1, 1)


@pytest.mark.parametrize("parent", ["configuration", "analysis"])
def test_missing_new_parent_has_distinct_input_not_found(owned_store, parent):
    private = prepare_owned_candidate(owned_store)
    with owned_store.engine.begin() as connection:
        connection.execute(text("DELETE FROM analyses"))
        if parent == "configuration":
            connection.execute(text("DELETE FROM configuration_sources"))
            connection.execute(text("DELETE FROM configurations"))
    with pytest.raises(NativePatchInputNotFound):
        NativePatchRecords(owned_store).save(private)
    assert counts(owned_store) == (0, 0)


def change_parent_hostname(store, configuration_id):
    key = str(configuration_id)
    with store.engine.begin() as connection:
        payload = connection.execute(
            text("SELECT payload FROM configurations WHERE id=:key"), {"key": key}
        ).scalar_one()
        data = json.loads(store._decode(payload, kind="configuration", row_id=key))
        data["canonical"]["device"]["hostname"] = "owned-tampered-parent"
        connection.execute(
            text("UPDATE configurations SET payload=:payload WHERE id=:key"),
            {
                "key": key,
                "payload": store._encode(json.dumps(data), kind="configuration", row_id=key),
            },
        )


def test_new_parent_binding_conflicts_and_saved_parent_corruption_is_unavailable(owned_store):
    private = prepare_owned_candidate(owned_store)
    records = NativePatchRecords(owned_store)
    assert records.save(private)[1]
    fresh = rebuilt(private, owned_store, candidate_id=uuid4())
    change_parent_hostname(owned_store, private.public.configuration_id)
    with pytest.raises(PatchConflict):
        records.save(fresh)
    with pytest.raises(StorageIntegrityError):
        records.get(private.public.candidate_id)
    with pytest.raises(StorageIntegrityError):
        records.list_ids(private.public.configuration_id, limit=20, offset=0)
    assert counts(owned_store) == (1, 1)


def test_audit_failure_after_insert_rolls_back_both_records(owned_store, monkeypatch):
    private = prepare_owned_candidate(owned_store)

    def fail(session, key):
        session.flush()
        raise RuntimeError("owned native audit failure")

    monkeypatch.setattr(NativePatchRecords, "_audit", staticmethod(fail))
    with pytest.raises(RuntimeError, match="owned native audit failure"):
        NativePatchRecords(owned_store).save(private)
    assert counts(owned_store) == (0, 0)
    assert NativePatchRecords(owned_store).get(private.public.candidate_id) is None


def test_two_sessions_return_same_first_role_timestamp_and_proof(owned_store, monkeypatch):
    private = prepare_owned_candidate(owned_store)
    other = rebuilt(
        private,
        owned_store,
        created_at=private.public.created_at + timedelta(seconds=1),
        service_role="admin",
    )
    original = NativePatchRecords._get
    barrier, state = Barrier(2), local()

    def synchronized(self, session, candidate_id):
        saved = original(self, session, candidate_id)
        if not getattr(state, "seen", False):
            state.seen = True
            barrier.wait(timeout=10)
        return saved

    monkeypatch.setattr(NativePatchRecords, "_get", synchronized)
    records = NativePatchRecords(owned_store)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(records.save, [private, other]))
    monkeypatch.setattr(NativePatchRecords, "_get", original)
    assert sorted(created for _saved, created in results) == [False, True]
    assert results[0][0] == results[1][0] == records.get(private.public.candidate_id)
    assert counts(owned_store) == (1, 1)


@pytest.mark.parametrize(
    "fault", ["time", "hash", "row", "kind", "before", "after", "proof", "bool"]
)
def test_sql_and_authenticated_private_corruption_refuses_history(owned_store, fault):
    private = prepare_owned_candidate(owned_store)
    records = NativePatchRecords(owned_store)
    assert records.save(private)[1]
    key = str(private.public.candidate_id)
    data = private.model_dump(mode="json")
    with owned_store.engine.begin() as connection:
        if fault == "time":
            connection.execute(text("UPDATE native_patch_candidates SET created_at='2000-01-01'"))
        elif fault == "hash":
            connection.execute(
                text("UPDATE native_patch_candidates SET public_sha256=:hash"), {"hash": "b" * 64}
            )
        else:
            if fault == "before":
                data["before_text"] += "! unrelated injected line\n"
            elif fault == "after":
                data["candidate_text"] += "! unrelated injected line\n"
            elif fault == "proof":
                data["public"]["review_sha256"] = "b" * 64
            elif fault == "bool":
                data["public"]["approved"] = 0
            connection.execute(
                text("UPDATE native_patch_candidates SET payload=:payload"),
                {
                    "payload": owned_store._encode(
                        json.dumps(data),
                        kind="configuration" if fault == "kind" else "native_patch_candidate",
                        row_id=str(uuid4()) if fault == "row" else key,
                    )
                },
            )
    with pytest.raises(StorageIntegrityError, match="Stored data is unavailable"):
        records.get(private.public.candidate_id)
    with pytest.raises(StorageIntegrityError):
        records.list_ids(private.public.configuration_id, limit=10, offset=0)
    assert counts(owned_store) == (1, 1)


@pytest.mark.parametrize("parent", ["configuration", "analysis"])
def test_sql_parent_timestamp_corruption_is_unavailable(owned_store, parent):
    private = prepare_owned_candidate(owned_store)
    records = NativePatchRecords(owned_store)
    assert records.save(private)[1]
    table = "configurations" if parent == "configuration" else "analyses"
    with owned_store.engine.begin() as connection:
        connection.execute(text(f"UPDATE {table} SET created_at='2000-01-01'"))
    with pytest.raises(StorageIntegrityError):
        records.get(private.public.candidate_id)


def test_missing_stored_parent_is_integrity_error_even_when_sql_was_corrupted(owned_store):
    private = prepare_owned_candidate(owned_store)
    records = NativePatchRecords(owned_store)
    assert records.save(private)[1]
    # Simulate an externally corrupted SQLite file. Normal FK-enabled deletion is tested below.
    with owned_store.engine.connect() as connection:
        connection.exec_driver_sql("PRAGMA foreign_keys=OFF")
        connection.execute(text("DELETE FROM analyses"))
        connection.commit()
        connection.exec_driver_sql("PRAGMA foreign_keys=ON")
    with pytest.raises(StorageIntegrityError):
        records.get(private.public.candidate_id)
    with pytest.raises(StorageIntegrityError):
        records.list_ids(private.public.configuration_id, limit=10, offset=0)


@pytest.mark.parametrize("field", ["before_text", "candidate_text", "public"])
def test_typed_copy_is_fully_revalidated_before_save(owned_store, field):
    private = prepare_owned_candidate(owned_store)
    value = (
        private.public.model_copy(update={"approved": 0})
        if field == "public"
        else getattr(private, field) + "! unrelated injected line\n"
    )
    with pytest.raises(PatchConflict):
        NativePatchRecords(owned_store).save(private.model_copy(update={field: value}))
    assert counts(owned_store) == (0, 0)


@pytest.mark.parametrize(
    "constant",
    [
        "MAX_NATIVE_PATCH_TEXT_BYTES",
        "MAX_NATIVE_PATCH_LINES",
        "MAX_NATIVE_PATCH_PROOF_BYTES",
        "MAX_NATIVE_PATCH_PUBLIC_BYTES",
        "MAX_NATIVE_PATCH_PRIVATE_BYTES",
        "MAX_NATIVE_PATCH_CIPHERTEXT_BYTES",
    ],
)
def test_budget_errors_are_413_new_and_integrity_error_for_stored(
    owned_store, monkeypatch, constant
):
    import app.db.native_patch_records as module

    private = prepare_owned_candidate(owned_store)
    fresh = rebuilt(private, owned_store, candidate_id=uuid4())
    records = NativePatchRecords(owned_store)
    assert records.save(private)[1]
    monkeypatch.setattr(module, constant, 1)
    with pytest.raises(NativePatchTooLarge):
        records.save(fresh)
    with pytest.raises(StorageIntegrityError):
        records.get(private.public.candidate_id)
    assert counts(owned_store) == (1, 1)


def test_budget_exception_wrapped_by_nested_dto_revalidation_keeps_413(owned_store, monkeypatch):
    import app.api.native_patch_contracts as contracts

    private = prepare_owned_candidate(owned_store)
    records = NativePatchRecords(owned_store)
    assert records.save(private)[1]
    monkeypatch.setattr(contracts, "MAX_NATIVE_PATCH_REVIEW_BYTES", 1)
    with pytest.raises(NativePatchTooLarge):
        records.save(private)
    with pytest.raises(StorageIntegrityError):
        records.get(private.public.candidate_id)
    assert counts(owned_store) == (1, 1)


def test_sql_utc_boundary_and_tied_uuid_sort(owned_store):
    private = prepare_owned_candidate(owned_store)
    local_time = private.public.created_at.astimezone(timezone(timedelta(hours=3)))
    first = rebuilt(private, owned_store, created_at=local_time, candidate_id=UUID(int=1))
    second = rebuilt(private, owned_store, created_at=local_time, candidate_id=UUID(int=2))
    records = NativePatchRecords(owned_store)
    assert records.save(first)[1] and records.save(second)[1]
    assert records.get(first.public.candidate_id) == first
    with owned_store._sessions() as session:
        row = session.get(NativePatchCandidateRow, str(first.public.candidate_id))
        assert row is not None
        assert row.created_at.replace(tzinfo=UTC) == local_time
    assert records.list_ids(private.public.configuration_id, limit=1, offset=0) == [UUID(int=2)]
    assert records.list_ids(private.public.configuration_id, limit=1, offset=1) == [UUID(int=1)]
    assert records.list_ids(private.public.configuration_id, limit=1, offset=2) == []
    assert records.list_ids(uuid4(), limit=1, offset=0) == []


def test_global_sql_uuid_and_foreign_keys_restrict_parent_deletion(owned_store):
    private = prepare_owned_candidate(owned_store)
    records = NativePatchRecords(owned_store)
    assert records.save(private)[1]
    with owned_store.engine.connect() as connection:
        row = dict(
            connection.execute(text("SELECT * FROM native_patch_candidates")).mappings().one()
        )
    for table in ("analyses", "configurations"):
        with pytest.raises(IntegrityError), owned_store.engine.begin() as connection:
            connection.execute(text(f"DELETE FROM {table}"))
    for changed in ({}, {"id": str(uuid4()), "analysis_id": str(uuid4())}):
        data = row | changed
        with pytest.raises(IntegrityError), owned_store.engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO native_patch_candidates "
                    "(id,configuration_id,analysis_id,created_at,public_sha256,payload) "
                    "VALUES (:id,:configuration_id,:analysis_id,"
                    ":created_at,:public_sha256,:payload)"
                ),
                data,
            )
    assert counts(owned_store) == (1, 1)


def test_populated_17_to_18_upgrade_keeps_old_rows_exactly_and_is_repeatable(owned_store):
    private = prepare_owned_candidate(owned_store)
    with owned_store.engine.begin() as connection:
        connection.exec_driver_sql("DROP TABLE native_patch_candidates")
        connection.execute(
            text("UPDATE alembic_version SET version_num='0017_source_risk_assessments'")
        )
    names = set(inspect(owned_store.engine).get_table_names()) - {"alembic_version"}

    def physical():
        with owned_store.engine.connect() as connection:
            return {
                name: sorted(map(repr, connection.execute(text(f'SELECT * FROM "{name}"')).all()))
                for name in names
            }

    old = physical()
    assert not owned_store.ready()
    upgrade_database(owned_store.engine)
    upgrade_database(owned_store.engine)
    assert SCHEMA_REVISION == "0018_native_patch_candidates"
    assert owned_store.ready() and physical() == old
    assert NativePatchRecords(owned_store).save(private)[1]
