"""Binding tests use declared answers, never claim actual model or engine runs."""

from dataclasses import replace
from uuid import UUID

import pytest
from app.detection.policy_engine import evaluate_policies
from app.explanation.knowledge import text_sha256
from app.explanation.patch_provider import build_patch_prompt, validate_patch_answer
from app.verification.batfish import BatfishResult, ReachabilityScope
from app.verification.model_patch import (
    ModelPatchVerificationUnavailable,
    check_model_patch_with_batfish,
    prepare_model_patch_snapshots,
)
from app.verification.snapshots import NetworkSnapshot, prepare_snapshot

SOURCE = (
    "version 17.9\nhostname edge\nip ssh version 1\n"
    "interface GigabitEthernet0/0\n ip address 192.0.2.1 255.255.255.252\n"
    " no shutdown\n!\nip route 198.51.100.0 255.255.255.0 192.0.2.2\nend\n"
)
CORE = (
    "version 17.9\nhostname core\ninterface GigabitEthernet0/0\n"
    " ip address 192.0.2.2 255.255.255.252\n no shutdown\n!\n"
    "interface Loopback0\n ip address 198.51.100.1 255.255.255.0\nend\n"
)


def inputs():
    from app.parsers import parse_configuration

    finding = next(
        row
        for row in evaluate_policies(
            parse_configuration(SOURCE, filename="owned.cfg"), device_id=UUID(int=1)
        )
        if row.category == "management.ssh_version_1"
    )
    prepared = build_patch_prompt(
        SOURCE,
        finding=finding,
        source_sha256=text_sha256(SOURCE),
        reference_id="owned-test",
        baseline=SOURCE.replace("version 1", "version 2"),
        allow_local_context=True,
    )
    import json

    answer = {
        "summary": "The supplied source explicitly selects SSHv1.",
        "technical_explanation": "The proposed line selects SSHv2 instead.",
        "possible_impact": [],
        "recommendation": "Review the candidate on the device.",
        "patch_draft": {"edits": [{"source_line": 3, "replacement": "ip ssh version 2"}]},
        "assumptions": [],
        "missing_information": ["Access and vendor syntax are unverified."],
        "citations": [prepared.chunks[0].citation],
        "requires_human_review": True,
    }
    generated = validate_patch_answer(json.dumps(answer).encode(), prepared)
    return prepared, generated, prepare_snapshot({UUID(int=1): SOURCE, UUID(int=2): CORE})


def test_builds_only_exact_candidate_and_preserves_other_devices() -> None:
    prepared, generated, before = inputs()
    pair = prepare_model_patch_snapshots(generated, prepared=prepared, before=before)
    assert pair.before == before
    assert pair.after.configs[0].text == generated.candidate_text
    assert pair.after.configs[1] == before.configs[1]
    assert pair.before.digest != pair.after.digest
    assert SOURCE not in repr(pair)


@pytest.mark.parametrize(
    "mutation",
    [
        "source",
        "missing",
        "metadata",
        "candidate",
        "null",
        "prepared",
        "snapshot_metadata",
        "duplicate",
    ],
)
def test_rejects_unbound_inputs_before_any_engine_lookup(mutation: str, monkeypatch) -> None:
    prepared, generated, before = inputs()
    if mutation == "source":
        before = prepare_snapshot({UUID(int=1): SOURCE + "!\n", UUID(int=2): CORE})
    elif mutation == "missing":
        before = prepare_snapshot({UUID(int=2): CORE})
    elif mutation == "metadata":
        generated = replace(generated, metadata=None)
    elif mutation == "candidate":
        generated = replace(generated, candidate_text=generated.candidate_text + "!\n")
    elif mutation == "null":
        generated = replace(
            generated,
            answer=generated.answer.model_copy(update={"patch_draft": None}),
            metadata=None,
            candidate_text=None,
        )
    elif mutation == "prepared":
        prepared = replace(prepared, source_sha256="f" * 64)
    elif mutation == "snapshot_metadata":
        before = replace(
            before, configs=(replace(before.configs[0], hostname="other"), before.configs[1])
        )
    else:
        before = NetworkSnapshot((*before.configs, before.configs[0]))
    monkeypatch.setattr(
        "app.verification.model_patch.check_with_batfish",
        lambda *args, **kwargs: pytest.fail("engine invoked for invalid binding"),
    )
    with pytest.raises(
        ModelPatchVerificationUnavailable, match=r"^Model patch verification is unavailable\.$"
    ):
        check_model_patch_with_batfish(
            generated,
            prepared=prepared,
            before=before,
            scope=ReachabilityScope(start_node="edge", destination="198.51.100.1/32"),
            allow_local_upload=True,
        )


def test_default_permission_does_not_upload_or_promote(monkeypatch) -> None:
    prepared, generated, before = inputs()
    monkeypatch.setattr(
        "app.verification.batfish.importlib.util.find_spec",
        lambda *args: pytest.fail("SDK lookup without upload consent"),
    )
    result = check_model_patch_with_batfish(
        generated,
        prepared=prepared,
        before=before,
        scope=ReachabilityScope(start_node="edge", destination="198.51.100.1/32"),
    )
    assert result.batfish.reason == "upload_not_authorized"
    assert result.status == generated.metadata.review.status == "needs_review"
    assert result.application_supported is result.management_access_verified is False
    assert result.requires_human_review is True


def test_scoped_result_is_bound_but_never_promotes_patch(monkeypatch) -> None:
    prepared, generated, before = inputs()

    def fake_check(old, new, scope, **kwargs):
        assert kwargs == {"allow_local_upload": True, "timeout_seconds": 120}
        assert new.configs[0].text == generated.candidate_text
        return BatfishResult(
            before_sha256=old.digest,
            after_sha256=new.digest,
            scope=scope,
            status="no_differences_in_scope",
            reason="query_completed",
            engine_version="unit-test",
            difference_count=0,
            before_reachable_count=1,
            after_reachable_count=1,
            cleanup_complete=True,
        )

    monkeypatch.setattr("app.verification.model_patch.check_with_batfish", fake_check)
    result = check_model_patch_with_batfish(
        generated,
        prepared=prepared,
        before=before,
        scope=ReachabilityScope(start_node="edge", destination="198.51.100.1/32"),
        allow_local_upload=True,
        timeout_seconds=120,
    )
    assert result.source_sha256 == text_sha256(SOURCE)
    assert result.candidate_sha256 == text_sha256(generated.candidate_text)
    assert result.status == "needs_review"
    assert result.device_syntax_verified is result.approved is False
    assert generated.metadata.review.preflight.formal_verification == "not_run"


@pytest.mark.parametrize("field", ["before_sha256", "after_sha256", "scope"])
def test_rejects_result_from_a_different_query(field: str, monkeypatch) -> None:
    prepared, generated, before = inputs()

    def wrong(old, new, scope, **kwargs):
        data = dict(
            before_sha256=old.digest,
            after_sha256=new.digest,
            scope=scope,
            status="unavailable",
            reason="sdk_missing",
        )
        data[field] = (
            "f" * 64
            if field != "scope"
            else ReachabilityScope(start_node="core", destination="203.0.113.1/32")
        )
        return BatfishResult.model_validate(data)

    monkeypatch.setattr("app.verification.model_patch.check_with_batfish", wrong)
    with pytest.raises(ModelPatchVerificationUnavailable):
        check_model_patch_with_batfish(
            generated,
            prepared=prepared,
            before=before,
            scope=ReachabilityScope(start_node="edge", destination="198.51.100.1/32"),
        )


@pytest.mark.parametrize(
    "status,reason,counts",
    [
        ("unavailable", "sdk_missing", None),
        ("error", "engine_error", None),
        ("incomplete", "initialization_issues", None),
        ("inconclusive", "empty_reachable_scope", (0, 0, 0)),
        ("differences_found", "query_completed", (1, 1, 0)),
        ("no_differences_in_scope", "query_completed", (0, 1, 1)),
    ],
)
def test_retains_all_engine_outcomes_without_promoting(status, reason, counts, monkeypatch):
    prepared, generated, before = inputs()

    def outcome(old, new, scope, **kwargs):
        return BatfishResult(
            before_sha256=old.digest,
            after_sha256=new.digest,
            scope=scope,
            status=status,
            reason=reason,
            engine_version="declared-unit-test" if counts else None,
            difference_count=counts[0] if counts else None,
            before_reachable_count=counts[1] if counts else None,
            after_reachable_count=counts[2] if counts else None,
        )

    monkeypatch.setattr("app.verification.model_patch.check_with_batfish", outcome)
    result = check_model_patch_with_batfish(
        generated,
        prepared=prepared,
        before=before,
        scope=ReachabilityScope(start_node="edge", destination="198.51.100.1/32"),
    )
    assert result.batfish.status == status and result.batfish.reason == reason
    assert result.status == "needs_review" and result.approved is False
    assert generated.metadata.review.preflight.formal_verification == "not_run"


@pytest.mark.parametrize("value", [None, 1, "true"])
def test_non_boolean_upload_permission_never_reaches_sdk(value, monkeypatch):
    prepared, generated, before = inputs()
    monkeypatch.setattr(
        "app.verification.batfish.importlib.util.find_spec",
        lambda *args: pytest.fail("SDK lookup with invalid consent"),
    )
    with pytest.raises(ModelPatchVerificationUnavailable):
        check_model_patch_with_batfish(
            generated,
            prepared=prepared,
            before=before,
            scope=ReachabilityScope(start_node="edge", destination="198.51.100.1/32"),
            allow_local_upload=value,
        )


def test_owned_full_network_cases_are_bound_before_generation():
    from ml.instruct.network_cases import authored_network_patch_cases

    cases = authored_network_patch_cases()
    assert len(cases) == 2 and {case.patch.vendor for case in cases} == {"cisco", "juniper"}
    for case in cases:
        assert len(case.before.configs) == 2
        assert case.before.configs[0].text == case.patch.prepared.before
        assert "192.0.2.1" in case.patch.prepared.before
        # Raw topology is bound through the source hash, not leaked into model context.
        assert "192.0.2.1" not in case.patch.prepared.prompt.context_json
