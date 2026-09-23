"""Network evidence must belong to the exact reviewed single-device proposal."""

from uuid import UUID

import pytest
from app.patching.network_review import NetworkPatchReview, review_patch_network
from app.patching.proposal import create_patch_proposal
from app.patching.review import review_patch_proposal
from app.verification.batfish import ReachabilityScope
from app.verification.snapshots import prepare_snapshot

DEVICE, PEER = UUID(int=1), UUID(int=2)
BEFORE, AFTER = "hostname edge\naaa new-model\n", "hostname edge\nno aaa new-model\n"


def test_offline_network_review_is_bound_without_promotion() -> None:
    draft = create_patch_proposal(BEFORE, AFTER, device_id=DEVICE, reference_id="v1")
    local = review_patch_proposal(draft, BEFORE, AFTER, device_id=DEVICE)
    before = prepare_snapshot({DEVICE: BEFORE, PEER: "hostname peer\n"})
    after = prepare_snapshot({DEVICE: AFTER, PEER: "hostname peer\n"})
    report = review_patch_network(
        local, before, after, ReachabilityScope(start_node="edge", destination="192.0.2.0/24")
    )
    assert report.network_result.status == "unavailable"
    assert report.network_result.before_sha256 == before.digest
    assert report.local_review == local
    assert report.status == "needs_review"
    assert NetworkPatchReview.model_validate_json(report.model_dump_json()) == report
    assert "aaa new-model" not in report.model_dump_json()
    data = report.model_dump(mode="json")
    data["after_members"][0]["sha256"] = "a" * 64
    with pytest.raises(ValueError):
        NetworkPatchReview.model_validate(data)


@pytest.mark.parametrize("change", ["target", "peer", "missing"])
def test_network_review_rejects_stale_or_unrelated_inputs(change: str) -> None:
    draft = create_patch_proposal(BEFORE, AFTER, device_id=DEVICE, reference_id="v1")
    local = review_patch_proposal(draft, BEFORE, AFTER, device_id=DEVICE)
    before = prepare_snapshot({DEVICE: BEFORE, PEER: "hostname peer\n"})
    texts = {DEVICE: AFTER, PEER: "hostname peer\n"}
    if change == "missing":
        del texts[DEVICE]
    else:
        texts[DEVICE if change == "target" else PEER] += "! stale\n"
    with pytest.raises(ValueError):
        review_patch_network(
            local,
            before,
            prepare_snapshot(texts),
            ReachabilityScope(start_node="edge", destination="192.0.2.0/24"),
        )


def test_scoped_no_difference_result_still_cannot_approve(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.patching import network_review
    from app.verification.batfish import BatfishResult

    draft = create_patch_proposal(BEFORE, AFTER, device_id=DEVICE, reference_id="v1")
    local = review_patch_proposal(draft, BEFORE, AFTER, device_id=DEVICE)
    before, after = prepare_snapshot({DEVICE: BEFORE}), prepare_snapshot({DEVICE: AFTER})
    scope = ReachabilityScope(start_node="edge", destination="192.0.2.0/24")
    result = BatfishResult(
        before_sha256=before.digest,
        after_sha256=after.digest,
        scope=scope,
        status="no_differences_in_scope",
        reason="query_completed",
        engine_version="test-double",
        difference_count=0,
        before_reachable_count=1,
        after_reachable_count=1,
    )
    monkeypatch.setattr(network_review, "check_with_batfish", lambda *args, **kwargs: result)
    report = review_patch_network(local, before, after, scope)
    assert report.status == "needs_review"
    assert report.local_review.proposal.status == "draft"
    assert report.local_review.preflight.formal_verification == "not_run"
    data = report.model_dump(mode="json")
    data["status"] = "approved"
    with pytest.raises(ValueError):
        NetworkPatchReview.model_validate(data)


def test_stale_local_evidence_is_rejected_before_upload(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.patching import network_review
    from app.patching.review import PatchReview

    draft = create_patch_proposal(BEFORE, AFTER, device_id=DEVICE, reference_id="v1")
    local = review_patch_proposal(draft, BEFORE, AFTER, device_id=DEVICE)
    data = local.model_dump()
    data["preflight"]["report_id"] = UUID(int=0)
    local = PatchReview.model_validate(data)
    monkeypatch.setattr(
        network_review,
        "check_with_batfish",
        lambda *args, **kwargs: pytest.fail("stale review reached the network"),
    )
    with pytest.raises(ValueError, match="stale"):
        review_patch_network(
            local,
            prepare_snapshot({DEVICE: BEFORE}),
            prepare_snapshot({DEVICE: AFTER}),
            ReachabilityScope(start_node="edge", destination="192.0.2.0/24"),
            allow_local_upload=True,
        )
