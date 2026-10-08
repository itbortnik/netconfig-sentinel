"""Real engine check of actual recorded owned edits, not fresh CI model inference.

Only edits/measurements were projected from a private actual GPU receipt. Fixed
review prose below is a test envelope, NOT the model's undisclosed explanation.
The declared answer hash cannot independently authenticate model execution.
"""

import json
import os
from hashlib import sha256
from pathlib import Path

import pytest
from app.domain.fingerprints import finding_fingerprint
from app.explanation.knowledge import text_sha256
from app.explanation.patch_provider import validate_patch_answer
from app.verification.batfish import ReachabilityScope
from app.verification.model_patch import (
    ModelPatchVerificationUnavailable,
    check_model_patch_with_batfish,
    prepare_model_patch_snapshots,
)

from ml.instruct.network_cases import authored_network_patch_cases


def _projected_case(vendor):
    path = Path(__file__).parents[1] / "fixtures/owned_model_network_edits.json"
    raw = path.read_bytes()
    assert (
        sha256(raw).hexdigest()
        == "bd3af3b2baec947a93d98f108447b060bf7fed62e4976c2de4d254487e05a4de"
    )
    projection = json.loads(raw)
    assert projection["actual_generations"] == 2 and projection["raw_answers_disclosed"] is False
    case = next(row for row in authored_network_patch_cases() if row.patch.vendor == vendor)
    row = next(row for row in projection["cases"] if row["vendor"] == vendor)
    prepared = case.patch.prepared
    assert row["source_sha256"] == prepared.source_sha256
    assert row["context_sha256"] == prepared.prompt.context_sha256
    assert row["finding_sha256"] == finding_fingerprint(prepared.finding)
    assert row["before_snapshot_sha256"] == case.before.digest
    # Only actual model edits are replayed, no suggested template fills a decline.
    wire = {
        "summary": "Recorded owned edit replay for scoped network checking.",
        "technical_explanation": "The original private model prose is not replayed here.",
        "possible_impact": [],
        "recommendation": "An engineer must review all unverified gates.",
        "patch_draft": row["patch_draft"],
        "assumptions": [],
        "missing_information": ["Vendor syntax, SSH access, rollback and approval are unverified."],
        "citations": [prepared.chunks[0].citation],
        "requires_human_review": True,
    }
    generated = validate_patch_answer(json.dumps(wire).encode(), prepared)
    if generated.candidate_text is not None:
        assert text_sha256(generated.candidate_text) == row["candidate_sha256"]
        pair = prepare_model_patch_snapshots(generated, prepared=prepared, before=case.before)
        assert pair.after.digest == row["after_snapshot_sha256"]
    else:
        assert row["status"] == "no_candidate" and row["after_snapshot_sha256"] is None
    return case, generated


@pytest.mark.parametrize("vendor", ["cisco", "juniper"])
def test_recorded_owned_network_edits_have_exact_local_binding(vendor):
    case, generated = _projected_case(vendor)
    if vendor == "juniper":
        assert generated.candidate_text is None
        with pytest.raises(ModelPatchVerificationUnavailable):
            prepare_model_patch_snapshots(
                generated, prepared=case.patch.prepared, before=case.before
            )
    else:
        assert generated.metadata.review.status == "needs_review"
        assert generated.metadata.review.preflight.formal_verification == "not_run"


@pytest.mark.skipif(
    os.environ.get("NETCONFIG_LIVE_BATFISH") != "1",
    reason="requires explicit owned upload opt-in and loopback Batfish",
)
@pytest.mark.parametrize("scenario", ["reachable", "empty_scope"])
def test_actual_recorded_candidate_with_real_engine_and_unchanged_review(scenario):
    case, generated = _projected_case("cisco")
    previous = generated.metadata.review
    result = check_model_patch_with_batfish(
        generated,
        prepared=case.patch.prepared,
        before=case.before,
        scope=ReachabilityScope(
            start_node="edge",
            destination=("198.51.100.1/32" if scenario == "reachable" else "203.0.113.1/32"),
        ),
        allow_local_upload=True,
        timeout_seconds=120,
    )
    print(
        "OWNED_MODEL_PATCH_BATFISH_RESULT="
        + json.dumps(
            {
                "vendor": "cisco",
                "scenario": scenario,
                "status": result.batfish.status,
                "reason": result.batfish.reason,
                "engine_version": result.batfish.engine_version,
                "before_reachable_count": result.batfish.before_reachable_count,
                "after_reachable_count": result.batfish.after_reachable_count,
                "difference_count": result.batfish.difference_count,
                "cleanup_complete": result.batfish.cleanup_complete,
                "patch_status": result.status,
                "requires_human_review": result.requires_human_review,
                "candidate_sha256": result.candidate_sha256,
                "new_llm_generations": 0,
                "model_execution_authenticated": False,
                "device_syntax_verified": False,
                "management_access_verified": False,
            },
            sort_keys=True,
        )
    )
    assert result.batfish.cleanup_complete is True and result.batfish.engine_version
    assert result.batfish.difference_count == 0
    assert result.status == "needs_review" and result.approved is False
    assert generated.metadata.review == previous
    if scenario == "reachable":
        assert result.batfish.status == "no_differences_in_scope"
        assert result.batfish.before_reachable_count == result.batfish.after_reachable_count == 1
    else:
        assert result.batfish.status == "inconclusive"
        assert result.batfish.before_reachable_count == result.batfish.after_reachable_count == 0
