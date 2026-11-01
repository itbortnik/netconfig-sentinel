"""Fresh owned native preparation without storage, policy rerun or application."""

from dataclasses import FrozenInstanceError
from datetime import timedelta
from uuid import UUID

import pytest
from app.api.native_patch_contracts import NativePatchPrivate, native_patch_candidate
from app.comparison.snapshots import DiffLimitExceeded
from app.ingestion.source_retention import canonical_fingerprint, prepare_original_source
from app.parsers.coverage import ParsedConfiguration
from app.patching.native_materialization_preparation import prepare_native_materialization
from test_native_patch_contracts import CISCO, CREATED, JUNOS, make_case

AFTER = UUID("5dc6b54f-e330-409c-8ba3-e277c2883996")
PATCH = UUID("c946ae34-5f74-4d17-adb2-9867d77860d0")
TIME = CREATED + timedelta(seconds=3)


def inputs(source=CISCO, schema="1.1"):
    before, analysis, generated, request, _, _ = make_case(source)
    canonical = before.canonical.model_copy(
        update={
            "schema_version": schema,
            "device": before.canonical.device.model_copy(
                update={
                    "role": "edge",
                    "site_class": "branch",
                    "service_profile": "management",
                }
            ),
        }
    )
    before = before.model_copy(update={"canonical": canonical})
    request = request.model_copy(update={"canonical_sha256": canonical_fingerprint(before)})
    public = native_patch_candidate(
        before.configuration_id,
        request,
        before,
        analysis,
        generated.metadata,
        created_at=CREATED + timedelta(seconds=2),
        service_role="engineer",
    )
    native = NativePatchPrivate(
        public=public,
        generated_metadata=generated.metadata,
        before_text=source,
        candidate_text=generated.candidate_text,
    )
    return native, before, analysis, prepare_original_source(before, source)


def prepare(values, **overrides):
    return prepare_native_materialization(
        *values,
        **{"after_configuration_id": AFTER, "patch_id": PATCH, "created_at": TIME, **overrides},
    )


@pytest.mark.parametrize("source,schema", [(CISCO, "1.1"), (JUNOS, "1.1"), (CISCO, "1.2")])
def test_both_vendors_preserve_exact_bytes_schema_inventory_and_create_only_ordinary_draft(
    source,
    schema,
):
    values = inputs(source, schema)
    originals = tuple(item.model_dump_json() for item in values)
    result = prepare(values)
    assert tuple(item.model_dump_json() for item in values) == originals
    assert result.after.configuration_id == AFTER
    assert result.after.device_id == values[1].device_id
    assert result.after.created_at == result.draft.created_at == TIME
    assert result.after.canonical.schema_version == schema
    assert result.after.canonical.source.filename == "native-candidate.cfg"
    assert result.after.canonical.source.collected_at == TIME
    assert (
        result.after.canonical.source.sha256
        == values[0].generated_metadata.review.proposal.after_sha256
    )
    assert result.after.parser_coverage.unparsed_units == 0
    assert result.after.canonical.management.telnet_enabled is False
    assert result.after.canonical.device.role == "edge"
    assert result.after.canonical.device.site_class == "branch"
    assert result.after.canonical.device.service_profile == "management"
    assert result.retained_after.content.encode() == values[0].candidate_text.encode()
    assert result.retained_after == prepare_original_source(result.after, values[0].candidate_text)
    assert "private-password" not in repr(result)
    assert result.draft.patch_id == PATCH and result.draft.status == "draft"
    assert result.draft.representation == "normalized_objects"
    assert result.draft.requires_human_review is True
    diff = result.draft.diff
    assert diff.coverage == "supported_complete" and diff.source_changed is True
    assert (diff.added_count, diff.removed_count, diff.modified_count) == (0, 0, 1)
    assert (diff.changes[0].section, diff.changes[0].kind) == ("management", "modified")
    with pytest.raises(FrozenInstanceError):
        result.draft = None


def test_preparation_never_calls_policy_generator_model_engine_or_source_record_lookup(monkeypatch):
    values = inputs()

    def forbidden(*args, **kwargs):
        pytest.fail("fresh preparation crossed a policy/generator/storage execution boundary")

    for name in (
        "app.detection.policy_engine.evaluate_policies",
        "app.patching.vendor_drafts.evaluate_policies",
        "app.patching.vendor_drafts.create_vendor_draft",
        "app.patching.vendor_drafts.check_vendor_draft",
        "app.db.source_records.SourceRecords.get",
    ):
        monkeypatch.setattr(name, forbidden)
    assert prepare(values).draft.status == "draft"


@pytest.mark.parametrize("change", ["text", "canonical", "binding", "native", "parent"])
def test_stale_original_native_and_real_parent_bindings_reject(change):
    values = list(inputs())
    if change == "text":
        values[3] = values[3].model_copy(update={"content": values[3].content + "!\n"})
    elif change == "canonical":
        values[3] = values[3].model_copy(update={"canonical_sha256": "f" * 64})
    elif change == "binding":
        values[3] = values[3].model_copy(
            update={
                "snapshot": values[3].snapshot.model_copy(update={"configuration_id": UUID(int=99)})
            }
        )
    elif change == "native":
        values[0] = values[0].model_copy(
            update={"candidate_text": values[0].candidate_text + "!\n"}
        )
    else:
        values[1] = values[1].model_copy(update={"device_id": UUID(int=99)})
    with pytest.raises(ValueError):
        prepare(values)


@pytest.mark.parametrize("created_at", [CREATED + timedelta(seconds=1), TIME.replace(tzinfo=None)])
def test_times_must_be_aware_and_no_earlier_than_native_and_parents(created_at):
    with pytest.raises(ValueError):
        prepare(inputs(), created_at=created_at)


def test_original_id_cannot_be_reused_as_the_after_id():
    values = inputs()
    with pytest.raises(ValueError):
        prepare(values, after_configuration_id=values[1].configuration_id)


@pytest.mark.parametrize("mutation", ["partial", "identity", "unrelated", "source_hash"])
def test_current_candidate_parser_drift_is_rejected(monkeypatch, mutation):
    import app.patching.native_materialization_preparation as preparation

    values = inputs()
    original = preparation.parse_configuration_with_coverage

    def drift(*args, **kwargs):
        parsed = original(*args, **kwargs)
        canonical = parsed.canonical
        if mutation == "partial":
            canonical = canonical.model_copy(update={"parser_confidence": 0.9})
        elif mutation == "identity":
            canonical = canonical.model_copy(
                update={"device": canonical.device.model_copy(update={"hostname": "foreign"})}
            )
        elif mutation == "unrelated":
            canonical = canonical.model_copy(
                update={"management": canonical.management.model_copy(update={"ssh_version": "1"})}
            )
        else:
            canonical = canonical.model_copy(
                update={"source": canonical.source.model_copy(update={"sha256": "f" * 64})}
            )
        return ParsedConfiguration(canonical, parsed.coverage)

    monkeypatch.setattr(preparation, "parse_configuration_with_coverage", drift)
    with pytest.raises(ValueError):
        prepare(values)


def test_fresh_before_reparse_must_reproduce_the_entire_saved_canonical(monkeypatch):
    import app.ingestion.source_retention as retention

    values = inputs()
    original = retention.parse_configuration

    def drift(*args, **kwargs):
        parsed = original(*args, **kwargs)
        return parsed.model_copy(
            update={"management": parsed.management.model_copy(update={"ssh_version": "1"})}
        )

    monkeypatch.setattr(retention, "parse_configuration", drift)
    with pytest.raises(ValueError, match="reproduce"):
        prepare(values)


@pytest.mark.parametrize("limit", ["MAX_RECORD_BYTES", "MAX_PREPARED_PLAINTEXT_BYTES"])
def test_prepared_draft_and_aggregate_budgets_reject_without_any_persistence(monkeypatch, limit):
    import app.patching.native_materialization_preparation as preparation

    values = inputs()
    monkeypatch.setattr(preparation, limit, 1)
    with pytest.raises(DiffLimitExceeded, match="budget"):
        prepare(values)
