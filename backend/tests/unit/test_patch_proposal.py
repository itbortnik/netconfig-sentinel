"""Drafts describe exact input versions and never contain configuration text."""

from uuid import UUID

import pytest
from app.domain import Vendor
from app.patching.proposal import PatchProposal, check_proposal_inputs, create_patch_proposal
from app.patching.review import review_patch_proposal

from ml.datasets.laboratory import laboratory_records
from ml.mutation import MutationType, mutate_configuration

DEVICE = UUID("7f64381c-fda8-48f9-8e8a-fb772b2f64dc")
BEFORE = "hostname edge\naaa new-model\n"
AFTER = "hostname edge\nno aaa new-model\n"


def test_draft_is_deterministic_bound_and_private() -> None:
    proposal = create_patch_proposal(BEFORE, AFTER, device_id=DEVICE, reference_id="v1")
    assert proposal == create_patch_proposal(BEFORE, AFTER, device_id=DEVICE, reference_id="v1")
    assert proposal.status == "draft"
    assert proposal.before_sha256 != proposal.after_sha256
    assert len(proposal.changes) == 1
    assert proposal.changes[0].operation == "replace"
    assert proposal.changes[0].before_start == 1
    assert proposal.changes[0].before_end == 2
    assert "aaa new-model" not in proposal.model_dump_json()
    check_proposal_inputs(proposal, BEFORE, AFTER, device_id=DEVICE)
    assert PatchProposal.model_validate_json(proposal.model_dump_json()) == proposal


@pytest.mark.parametrize("side", ["before", "after", "device"])
def test_stale_inputs_are_rejected(side: str) -> None:
    proposal = create_patch_proposal(BEFORE, AFTER, device_id=DEVICE, reference_id="v1")
    with pytest.raises(ValueError):
        check_proposal_inputs(
            proposal,
            BEFORE + ("! changed\n" if side == "before" else ""),
            AFTER + ("! changed\n" if side == "after" else ""),
            device_id=UUID(int=0) if side == "device" else DEVICE,
        )


@pytest.mark.parametrize(
    "after,operation",
    [
        (BEFORE + "ip ssh version 2\n", "insert"),
        ("hostname edge\n", "delete"),
        (BEFORE.replace("\n", "\r\n"), "replace"),
    ],
)
def test_insert_delete_and_line_endings(after: str, operation: str) -> None:
    proposal = create_patch_proposal(BEFORE, after, device_id=DEVICE, reference_id="v1")
    assert proposal.changes[0].operation == operation


@pytest.mark.parametrize("bad", ["", "hostname other\n", BEFORE])
def test_invalid_or_noop_draft_rejected(bad: str) -> None:
    with pytest.raises(ValueError):
        create_patch_proposal(BEFORE, bad, device_id=DEVICE, reference_id="v1")


@pytest.mark.parametrize("field,value", [("status", "validated"), ("after_sha256", "a" * 64)])
def test_serialized_draft_cannot_change_status_or_identity(field: str, value: str) -> None:
    proposal = create_patch_proposal(BEFORE, AFTER, device_id=DEVICE, reference_id="v1")
    data = proposal.model_dump()
    data[field] = value
    with pytest.raises(ValueError):
        PatchProposal.model_validate(data)


@pytest.mark.parametrize("vendor", [Vendor.CISCO, Vendor.JUNIPER])
@pytest.mark.parametrize(
    "scenario,mutation",
    [
        ("bgp-edge", MutationType.BGP_REMOTE_AS_MISMATCH),
        ("bgp-edge", MutationType.MISSING_BGP_NEIGHBOR),
        ("ospf-core", MutationType.OSPF_AREA_MISMATCH),
        ("ospf-core", MutationType.CONFLICTING_IP_ADDRESS),
        ("access-switch", MutationType.VLAN_MISMATCH),
        ("access-switch", MutationType.INCORRECT_ACCESS_TRUNK_MODE),
    ],
)
def test_structural_drafts_keep_exact_unchanged_line_regions(
    vendor: Vendor, scenario: str, mutation: MutationType
) -> None:
    record = next(
        item
        for item in laboratory_records()
        if item.vendor_hint is vendor and item.device_role == scenario
    )
    sample = mutate_configuration(record, (mutation,), seed=17)
    draft = create_patch_proposal(
        record.sanitized_text, sample.mutated_text, device_id=DEVICE, reference_id="lab"
    )
    old, new = (
        record.sanitized_text.splitlines(keepends=True),
        sample.mutated_text.splitlines(keepends=True),
    )
    old_end = new_end = 0
    for change in draft.changes:
        assert old[old_end : change.before_start] == new[new_end : change.after_start]
        assert (
            old[change.before_start : change.before_end]
            != new[change.after_start : change.after_end]
        )
        old_end, new_end = change.before_end, change.after_end
    assert old[old_end:] == new[new_end:]
    review = review_patch_proposal(
        draft, record.sanitized_text, sample.mutated_text, device_id=DEVICE
    )
    assert review.preflight.reference_findings
    assert "formal_verification_not_run" in review.validation_blockers
    assert review.proposal.status == "draft"
