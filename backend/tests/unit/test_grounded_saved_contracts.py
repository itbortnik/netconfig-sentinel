"""Persisted version/fact/projection contracts preserve legacy serialization."""

import json
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from app.api.contracts import SnapshotBinding
from app.api.grounded_patch_contracts import (
    GROUNDED_PROTOCOL,
    INTENT_ADAPTER,
    LEGACY_PROTOCOL,
    OUTCOME_ADAPTER,
    GroundedModelPatchIntent,
    GroundedModelPatchOutcome,
    GroundedModelPatchProposal,
    presentation_digest,
    protocol_for,
)
from app.api.model_patch_contracts import (
    GenerateModelPatch,
    ModelPatchIntent,
    ModelPatchOutcome,
    fingerprint,
)
from app.explanation.grounded_patch import renderer_policy_sha256, validate_grounded_patch_answer
from app.explanation.knowledge import text_sha256
from test_grounded_patch import prepared_answer


def records(*, null=False, failed=False):
    prepared, wire = prepared_answer(null=null)
    generated = validate_grounded_patch_answer(json.dumps(wire).encode(), prepared)
    stamp = datetime(2026, 10, 15, tzinfo=UTC)
    source = SnapshotBinding(
        configuration_id=UUID(int=10),
        device_id=prepared.legacy.finding.device_id,
        source_sha256=prepared.legacy.source_sha256,
        created_at=stamp,
    )
    baseline = SnapshotBinding(
        configuration_id=UUID(int=9),
        device_id=source.device_id,
        source_sha256=prepared.source_facts.baseline_source_sha256,
        created_at=stamp - timedelta(seconds=1),
    )
    intent = GroundedModelPatchIntent(
        request=GenerateModelPatch(
            patch_id=UUID(int=1),
            analysis_id=UUID(int=2),
            finding_id=prepared.legacy.finding.finding_id,
            finding_sha256=prepared.source_facts.finding_sha256,
            source_sha256=source.source_sha256,
            baseline_configuration_id=baseline.configuration_id,
            baseline_source_sha256=baseline.source_sha256,
            allow_local_model_context=True,
        ),
        source=source,
        baseline=baseline,
        created_at=stamp + timedelta(seconds=1),
        context_sha256=prepared.prompt.context_sha256,
        edit_context_sha256=prepared.legacy.prompt.context_sha256,
        knowledge_version="project-knowledge-0.2.0",
        knowledge_sha256=prepared.source_facts.knowledge_sha256,
        model_alias_sha256="a" * 64,
        instructions_sha256=text_sha256(prepared.prompt.instructions),
        answer_schema_sha256=text_sha256(prepared.prompt.answer_schema_json),
        source_facts=prepared.source_facts,
        facts_binding_sha256=prepared.facts_binding_sha256,
        renderer_policy_sha256=renderer_policy_sha256(),
    )
    result = generated.generated
    outcome = GroundedModelPatchOutcome(
        patch_id=intent.request.patch_id,
        intent_sha256=fingerprint(intent),
        completed_at=stamp + timedelta(seconds=2),
        status="failed" if failed else "declined" if null else "draft",
        answer=None if failed else result.answer,
        model_answer=None if failed else generated.model_answer,
        projection_sha256=None if failed else presentation_digest(result.answer),
        candidate_sha256=None if failed or null else text_sha256(result.candidate_text),
    )
    return prepared, intent, outcome


@pytest.mark.parametrize("state", ["generating", "failed", "declined", "draft"])
def test_closed_wire_choices_and_server_projection_are_separate_and_bound(state):
    prepared, intent, outcome = records(null=state == "declined", failed=state == "failed")
    if state == "generating":
        outcome = None
    proposal = GroundedModelPatchProposal.from_records(intent, outcome)
    assert proposal.projection.status == state
    assert proposal.presentation_kind == "server_derived"
    assert proposal.context_sha256 == prepared.prompt.context_sha256
    assert proposal.edit_context_sha256 == prepared.legacy.prompt.context_sha256
    assert proposal.projection.context_sha256 == proposal.edit_context_sha256
    assert proposal.context_sha256 != proposal.edit_context_sha256
    assert proposal.projection.approved is False
    assert proposal.projection.applied is False
    assert proposal.projection.formal_verification == "not_run"
    assert GroundedModelPatchProposal.model_validate_json(proposal.model_dump_json()) == proposal
    assert INTENT_ADAPTER.validate_json(intent.model_dump_json()) == intent
    if outcome:
        assert OUTCOME_ADAPTER.validate_json(outcome.model_dump_json()) == outcome


def test_legacy_adapter_round_trip_preserves_exact_json_and_fingerprint():
    _, intent, _ = records()
    values = intent.model_dump()
    old = ModelPatchIntent.model_validate(
        {key: values[key] for key in ModelPatchIntent.model_fields if key != "version"}
    )
    outcome = ModelPatchOutcome(
        patch_id=old.request.patch_id,
        intent_sha256=fingerprint(old),
        completed_at=old.created_at + timedelta(seconds=1),
        status="failed",
    )
    for adapter, model in ((INTENT_ADAPTER, old), (OUTCOME_ADAPTER, outcome)):
        restored = adapter.validate_json(model.model_dump_json())
        assert type(restored) is type(model)
        assert restored.model_dump_json() == model.model_dump_json()
        assert fingerprint(restored) == fingerprint(model)
    assert protocol_for(old) == LEGACY_PROTOCOL
    assert protocol_for(intent) == GROUNDED_PROTOCOL


@pytest.mark.parametrize("kind", ["missing", "unknown", "downgrade"])
def test_discriminator_is_required_and_does_not_guess_or_fallback(kind):
    _, intent, _ = records()
    values = intent.model_dump(mode="json")
    if kind == "missing":
        values.pop("version")
    else:
        values["version"] = "unknown" if kind == "unknown" else "model-patch-intent-0.1.0"
    with pytest.raises(ValueError):
        INTENT_ADAPTER.validate_python(values)


@pytest.mark.parametrize("field", ["source_sha256", "finding_sha256", "knowledge_sha256"])
def test_fact_ledger_cannot_bind_different_source_finding_or_knowledge(field):
    _, intent, _ = records()
    values = intent.model_dump(mode="json")
    values["source_facts"][field] = "f" * 64
    with pytest.raises(ValueError):
        GroundedModelPatchIntent.model_validate(values)


def test_unvalidated_fact_bool_integer_is_rejected_without_private_warning():
    _, intent, _ = records()
    values = intent.model_dump()
    values["source_facts"]["observed_ssh_enabled"] = 1
    with pytest.raises(ValueError):
        GroundedModelPatchIntent.model_validate(values)


def test_whole_record_fingerprint_binds_new_renderer_and_not_converted_legacy_bytes():
    _, intent, outcome = records()
    first = GroundedModelPatchProposal.from_records(intent, outcome)
    changed = intent.model_copy(update={"renderer_policy_sha256": "0" * 64})
    rebound = outcome.model_copy(update={"intent_sha256": fingerprint(changed)})
    second = GroundedModelPatchProposal.from_records(changed, rebound)
    assert first.projection.proposal_sha256 != second.projection.proposal_sha256


def test_projection_tamper_or_wrong_edit_context_not_accepted():
    _, intent, outcome = records()
    proposal = GroundedModelPatchProposal.from_records(intent, outcome)
    for change in ("projection", "context"):
        values = proposal.model_dump(mode="json")
        if change == "projection":
            values["projection"]["answer"]["summary"] = "Approved and safe."
        else:
            values["edit_context_sha256"] = values["context_sha256"]
        with pytest.raises(ValueError):
            GroundedModelPatchProposal.model_validate(values)


def test_grounded_audit_preserves_visible_ids_and_pins_without_raw_model_or_ledger():
    from app.audit.results import result_metadata

    _, intent, outcome = records()
    proposal = GroundedModelPatchProposal.from_records(intent, outcome)
    metadata = result_metadata(proposal)
    assert proposal.projection.patch_id in metadata.resource_ids
    assert set(metadata.resource_ids) == set(result_metadata(proposal.projection).resource_ids)
    assert metadata.source_sha256 == proposal.projection.source_sha256
    assert metadata.finding_sha256 == proposal.projection.finding_sha256
    assert metadata.context_sha256 == proposal.context_sha256
    assert metadata.model_alias_sha256 == proposal.projection.model_alias_sha256
    raw = metadata.model_dump_json()
    assert "model_answer" not in raw and "source_facts" not in raw
    assert "ip ssh version" not in raw and "BEFORE" not in raw
