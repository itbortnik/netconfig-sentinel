"""Review artifacts bind draft and preflight to the same inputs."""

from uuid import UUID

import pytest
from app.patching.proposal import create_patch_proposal
from app.patching.review import PatchReview, review_patch_proposal

DEVICE = UUID("7f64381c-fda8-48f9-8e8a-fb772b2f64dc")
BEFORE = "hostname edge\naaa new-model\n"
AFTER = "hostname edge\nno aaa new-model\n"


def test_review_remains_blocked_even_with_complete_parsing() -> None:
    draft = create_patch_proposal(BEFORE, AFTER, device_id=DEVICE, reference_id="v1")
    review = review_patch_proposal(draft, BEFORE, AFTER, device_id=DEVICE)
    assert review.status == "needs_review"
    assert "formal_verification_not_run" in review.validation_blockers
    assert "introduced_policy_findings" in review.validation_blockers
    assert review.preflight.before.source_sha256 == draft.before_sha256
    assert review.preflight.after.source_sha256 == draft.after_sha256
    assert PatchReview.model_validate_json(review.model_dump_json()) == review


def test_unknown_syntax_blocks_review_without_exposing_raw_text() -> None:
    after = AFTER + "unsupported-command private-secret\n"
    draft = create_patch_proposal(BEFORE, after, device_id=DEVICE, reference_id="v1")
    review = review_patch_proposal(draft, BEFORE, after, device_id=DEVICE)
    assert "incomplete_parsing" in review.validation_blockers
    assert "private-secret" not in review.model_dump_json()


@pytest.mark.parametrize("field", ["hash", "device", "reference", "status", "blockers"])
def test_review_rejects_mismatched_or_fake_approval(field: str) -> None:
    draft = create_patch_proposal(BEFORE, AFTER, device_id=DEVICE, reference_id="v1")
    review = review_patch_proposal(draft, BEFORE, AFTER, device_id=DEVICE)
    data = review.model_dump(mode="json")
    if field == "hash":
        data["preflight"]["after"]["source_sha256"] = "a" * 64
    elif field == "device":
        data["proposal"]["device_id"] = str(UUID(int=0))
    elif field == "reference":
        data["preflight"]["reference_id"] = "different"
    elif field == "blockers":
        data["validation_blockers"] = []
    else:
        data["status"] = "approved"
    with pytest.raises(ValueError):
        PatchReview.model_validate(data)
