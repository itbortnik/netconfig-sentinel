"""Explicit profile persistence and old bindings, without activating an upload profile."""

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from app.api.contracts import ConfigurationSnapshot
from app.comparison.snapshots import compare_snapshots
from app.core.settings import ApiSettings
from app.db.migrate import upgrade_database
from app.db.source_records import SourceRecords
from app.db.store import Store
from app.ingestion.source_retention import canonical_fingerprint, prepare_original_source
from app.parsers import parse_configuration
from cryptography.fernet import Fernet

SOURCE = (
    "hostname owned\nusername engineer privilege 5\nroute-map Export permit 10\n"
    " match ip address prefix-list TRUSTED\n!\nroute-map Export permit 20\n set metric 50\n!\n"
)
AT = datetime(2020, 1, 1, tzinfo=UTC)


def snapshot(text=SOURCE, *, version="1.2", seconds=0):
    return ConfigurationSnapshot(
        configuration_id=uuid4(),
        device_id=UUID(int=1),
        created_at=AT + timedelta(seconds=seconds),
        canonical=parse_configuration(
            text, filename="owned.cfg", collected_at=AT, schema_version=version
        ),
    )


def test_both_explicit_and_legacy_source_bindings_survive_encrypted_restart(tmp_path):
    settings = ApiSettings(
        f"sqlite:///{tmp_path / 'route-map.sqlite3'}",
        "owned-route-map-service-token-32-characters-001",
        Fernet.generate_key().decode(),
    )
    legacy, current = snapshot(version="1.1"), snapshot()
    expected = [
        (item, item.model_dump_json(), canonical_fingerprint(item)) for item in (legacy, current)
    ]
    store = Store(settings)
    upgrade_database(store.engine)
    try:
        for item in (legacy, current):
            store.add_configuration(item, retain_original_source=True, original_source=SOURCE)
    finally:
        store.close()
    restarted = Store(settings)
    try:
        for original, raw_json, pin in expected:
            loaded = restarted.get_configuration(original.configuration_id)
            assert loaded is not None and loaded.model_dump_json() == raw_json
            assert canonical_fingerprint(loaded) == pin
            source = SourceRecords(restarted).get(
                loaded.configuration_id,
                expected_source_sha256=loaded.canonical.source.sha256,
                allow_local_read=True,
            )
            assert source.content == SOURCE and source.canonical_sha256 == pin
            assert prepare_original_source(loaded, SOURCE) == source
        assert "route_maps" not in legacy.canonical.model_dump()
        assert current.canonical.route_maps[0].name == "Export"
    finally:
        restarted.close()


def test_normalized_diff_observes_clause_order_and_preserves_device_account_limitations():
    before = snapshot()
    changed = (
        SOURCE.replace("permit 10", "permit 21")
        .replace("permit 20", "permit 10")
        .replace("permit 21", "permit 20")
    )
    after = snapshot(changed, seconds=1)
    report = compare_snapshots(before, after)
    assert report.modified_count == 1 and report.added_count == report.removed_count == 0
    item = report.changes[0]
    assert item.section == "route_maps" and item.object_key == ("Export",)
    assert item.before_value["clauses"][0]["match_ipv4_prefix_lists"] == ["TRUSTED"]
    assert item.after_value["clauses"][0]["set_metric"] == 50
    assert item.before_locations and item.after_locations
    assert any("credential" in text.lower() for text in report.limitations)


def test_provenance_only_line_shifts_do_not_change_route_map_object_values():
    before, after = snapshot(), snapshot("! moved\n" + SOURCE, seconds=1)
    assert compare_snapshots(before, after).changes == ()


def test_modified_normalized_facts_cannot_be_retained_as_the_same_raw_source():
    item = snapshot()
    item.canonical.route_maps[0].clauses[1].set_metric = 99
    with pytest.raises(ValueError, match="reproduce"):
        prepare_original_source(item, SOURCE)
