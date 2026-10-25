"""Partial policy diagnostics preserve findings without a change or safety verdict."""

from datetime import UTC, datetime, timedelta
from hashlib import sha256
from uuid import uuid4

import pytest
from app.api.contracts import AnalysisResult, ConfigurationSnapshot, SnapshotBinding
from app.api.model_patch_contracts import fingerprint
from app.api.source_deterministic_contracts import (
    OriginalDeterministicContext,
    SourceDeterministicMember,
    SourceDeterministicSelection,
)
from app.api.source_ml_contracts import ml_json, source_ml_fingerprint
from app.api.source_partial_contracts import (
    PolicyDiagnosticParse,
    RunSourcePartialDiagnostic,
    SourcePartialDiagnostic,
    SourcePartialIntent,
    SourcePartialOutcome,
    SourcePartialReport,
    SourcePartialSummary,
    parse_source_deterministic_record_json,
    parse_source_deterministic_request,
    parse_source_deterministic_summary_json,
)
from app.detection.fusion import RiskSource, fuse_risk
from app.detection.policy_diagnostic import prepare_partial_policy, recheck_partial_policy
from app.detection.policy_engine import evaluate_policies
from app.explanation.local import explain_finding
from app.ingestion.source_retention import canonical_fingerprint, prepare_original_source
from app.parsers import parse_configuration
from app.policies import POLICY_CATALOG_VERSION

MARKER = "owned-unknown-password-never-a-real-credential"


def text(vendor, telnet, unknown=0, critical=False):
    if vendor == "cisco":
        base = (
            "hostname target\nip ssh version 2\nline vty 0 4\n transport input "
            + ("telnet ssh" if telnet else "ssh")
            + "\n!\n"
        )
        if critical:
            base += "ip route 0.0.0.0 0.0.0.0 Null0\n"
        return base + ("unsupported-owned password " + MARKER + "\n") * unknown
    base = "set system host-name target\nset system services ssh\n"
    if telnet:
        base += "set system services telnet\n"
    if critical:
        base += "set routing-options static route 0.0.0.0/0 discard\n"
    return base + ("set unsupported-owned password " + MARKER + "\n") * unknown


def prepared(vendor="cisco", partial="after", *, critical=False, unknown_count=1):
    device = uuid4()
    stamp = datetime(2026, 1, 2, tzinfo=UTC)
    sources = [
        text(vendor, True, unknown_count if partial in {"before", "both"} else 0),
        text(vendor, False, unknown_count if partial in {"after", "both"} else 0, critical),
    ]
    snapshots = [
        ConfigurationSnapshot(
            configuration_id=uuid4(),
            device_id=device,
            created_at=stamp + timedelta(seconds=i),
            canonical=parse_configuration(source, filename="owned.cfg", collected_at=stamp),
        )
        for i, source in enumerate(sources)
    ]
    for snapshot, source in zip(snapshots, sources, strict=True):
        assert prepare_original_source(snapshot, source).content == source
    before, after = snapshots
    findings = tuple(evaluate_policies(before.canonical, device_id=device))
    complete = PolicyDiagnosticParse.from_config(before.canonical).summary.complete
    analysis = AnalysisResult(
        analysis_id=uuid4(),
        configuration_id=before.configuration_id,
        device_id=device,
        source_sha256=before.canonical.source.sha256,
        created_at=stamp + timedelta(seconds=2),
        status="completed" if complete else "partial",
        policy_catalog_version=POLICY_CATALOG_VERSION,
        findings=findings,
        explanations=tuple(explain_finding(row, before.canonical) for row in findings),
        risk=fuse_risk(findings, device_id=device, completed_detectors=[RiskSource.POLICY])
        if complete
        else None,
        limitations=(),
    )
    return before, after, analysis


def records(vendor="cisco", partial="after", *, selected=None, **options):
    before, after, analysis = (
        selected if selected is not None else prepared(vendor, partial, **options)
    )
    computed = prepare_partial_policy(before, after, analysis)
    pair = recheck_partial_policy(computed)

    def member(snapshot):
        return SourceDeterministicMember.model_validate(
            SnapshotBinding.from_snapshot(snapshot).model_dump()
            | {"canonical_sha256": canonical_fingerprint(snapshot)}
        )

    request = RunSourcePartialDiagnostic(
        mode="policy_only_partial_diagnostic",
        recheck_id=uuid4(),
        draft_sha256="a" * 64,
        before_analysis_id=analysis.analysis_id,
        before_analysis_sha256=fingerprint(analysis),
        reference_canonical_sha256=None,
        allow_local_analysis_context=True,
    )
    selection = SourceDeterministicSelection(
        patch_id=uuid4(),
        draft_sha256=request.draft_sha256,
        before=SnapshotBinding.from_snapshot(before),
        before_analysis_id=analysis.analysis_id,
        before_analysis_sha256=request.before_analysis_sha256,
        before_analysis_created_at=analysis.created_at,
        original=OriginalDeterministicContext.from_analysis(analysis),
        reference=None,
    )
    intent = SourcePartialIntent(
        patch_id=selection.patch_id,
        request=request,
        before=member(before),
        after=member(after),
        selection=selection,
        before_analysis_status=analysis.status,
        before_parse=pair.before.parse,
        after_parse=pair.after.parse,
        reference_projection=None,
        created_at=analysis.created_at + timedelta(seconds=1),
    )
    outcome = SourcePartialOutcome(
        recheck_id=request.recheck_id,
        intent_sha256=source_ml_fingerprint(intent),
        completed_at=intent.created_at + timedelta(seconds=1),
        execution_status="completed",
        report=SourcePartialReport.from_pair(intent, pair),
    )
    return intent, outcome


def rehash(body):
    proof = ml_json({k: v for k, v in body.items() if k not in {"review_json", "review_sha256"}})
    return body | {"review_json": proof, "review_sha256": sha256(proof.encode()).hexdigest()}


@pytest.mark.parametrize("vendor", ["cisco", "juniper"])
@pytest.mark.parametrize("partial", ["before", "after", "both"])
def test_real_policy_execution_preserves_partial_source_findings(vendor, partial):
    intent, outcome = records(vendor, partial)
    value = SourcePartialDiagnostic.from_records(intent, outcome)
    assert parse_source_deterministic_record_json(value.model_dump_json()) == value
    assert SourcePartialSummary.from_recheck(value).coverage == "partial"
    assert parse_source_deterministic_summary_json(
        SourcePartialSummary.from_recheck(value).model_dump_json()
    ) == SourcePartialSummary.from_recheck(value)
    assert "partial_comparison_unavailable" in value.validation_blockers
    assert value.outcome.report.policy_changes is None
    assert value.outcome.report.policy_changes_reason == "partial_parsing"
    assert MARKER not in value.model_dump_json()
    assert value.intent.before_analysis_status == ("completed" if partial == "after" else "partial")
    assert value.outcome.report.before.policy_findings == intent.selection.original.findings
    assert any(
        row.category == "management.telnet_enabled"
        for row in value.outcome.report.before.policy_findings
    )
    assert all(
        row.category != "management.telnet_enabled"
        for row in value.outcome.report.after.policy_findings
    )


@pytest.mark.parametrize("vendor", ["cisco", "juniper"])
def test_actual_critical_adverse_finding_survives_partial_after(vendor):
    intent, outcome = records(vendor, "after", critical=True)
    value = SourcePartialDiagnostic.from_records(intent, outcome)
    assert any(
        row.category == "routing.default_route_discarded" and row.severity.value == "critical"
        for row in value.outcome.report.after.policy_findings
    )
    assert value.formal_verification == "not_run"
    assert value.risk_fused is value.quality_proven is value.approved is value.applied is False


@pytest.mark.parametrize("count", [0, 1, 257])
def test_unknown_provenance_is_bounded_without_raw_fragment_disclosure(count):
    config = parse_configuration(text("cisco", False, count), filename="owned.cfg")
    parsed = PolicyDiagnosticParse.from_config(config)
    assert len(parsed.unknown_locations) == min(count, 256)
    assert parsed.locations_truncated == (count > 256)
    assert MARKER not in parsed.model_dump_json()
    if count:
        assert parsed.unknown_locations[0] == config.unparsed_fragments[0].location


@pytest.mark.parametrize(
    "flag", ["risk_fused", "calibrated", "quality_proven", "approved", "applied"]
)
@pytest.mark.parametrize("bad", [0, True])
def test_resealed_and_typed_copied_qualification_flags_refused(flag, bad):
    intent, outcome = records()
    value = SourcePartialDiagnostic.from_records(intent, outcome)
    body = rehash(value.model_dump(mode="json") | {flag: bad})
    with pytest.raises(ValueError):
        SourcePartialDiagnostic.model_validate(body)
    with pytest.raises(ValueError):
        SourcePartialDiagnostic.model_validate(value.model_copy(update={flag: bad}))


def test_mode_cannot_silently_activate_new_path_or_drop_reference():
    intent, _ = records()
    body = intent.request.model_dump(mode="json")
    assert parse_source_deterministic_request(body) == intent.request
    for change in ({"mode": None}, {"reference_canonical_sha256": "b" * 64}):
        with pytest.raises(ValueError):
            parse_source_deterministic_request(body | change)
    body.pop("version")
    with pytest.raises(ValueError):
        parse_source_deterministic_request(body)


def test_original_finding_change_refuses_before_terminal_execution(monkeypatch):
    before, after, analysis = prepared()
    first, *rest = analysis.findings
    changed = first.model_copy(update={"observed": {"different": "owned"}})
    analysis = analysis.model_copy(update={"findings": (changed, *rest)})
    # Explanations are unchanged, as they would be in corrupted historical context.
    with pytest.raises(ValueError):
        prepare_partial_policy(before, after, analysis)


def test_prepared_binding_mutation_refuses_before_after_policy_call(monkeypatch):
    from dataclasses import replace

    prepared_pair = prepare_partial_policy(*prepared())
    monkeypatch.setattr(
        "app.detection.policy_diagnostic.evaluate_policies",
        lambda *a, **k: pytest.fail("after execution"),
    )
    with pytest.raises(ValueError):
        recheck_partial_policy(replace(prepared_pair, after_canonical_sha256="f" * 64))


def test_pending_failed_terminal_and_summary_states():
    intent, outcome = records()
    pending = SourcePartialDiagnostic.from_records(intent, None)
    assert pending.execution_status == "pending_unknown"
    assert "deterministic_execution_unknown" in pending.validation_blockers
    failed = SourcePartialOutcome(
        recheck_id=outcome.recheck_id,
        intent_sha256=outcome.intent_sha256,
        completed_at=outcome.completed_at,
        execution_status="failed",
        failure_reason="original_context_or_deterministic_result_unavailable",
    )
    value = SourcePartialDiagnostic.from_records(intent, failed)
    assert value.outcome.report is None
    assert SourcePartialSummary.from_recheck(value).execution_status == "failed"


@pytest.mark.parametrize("case", ["partition", "parse", "finding", "analysis_status"])
def test_resealed_inner_tampering_is_refused(case):
    intent, outcome = records()
    body = SourcePartialDiagnostic.from_records(intent, outcome).model_dump(mode="json")
    if case == "partition":
        body["outcome"]["report"]["policy_changes"] = {
            "resolved": [],
            "introduced": [],
            "persistent": [],
        }
    elif case == "parse":
        body["outcome"]["report"]["after"]["parse"]["unknown_locations"] = []
    elif case == "finding":
        body["outcome"]["report"]["before"]["policy_findings"] = []
    else:
        body["intent"]["before_analysis_status"] = "partial"
    with pytest.raises(ValueError):
        SourcePartialDiagnostic.model_validate(rehash(body))


def test_nested_legacy_typed_parser_values_are_normalized_before_new_validation():
    intent, outcome = records()
    parsed = intent.after_parse
    copied = parsed.model_copy(
        update={
            "summary": parsed.summary.model_copy(update={"complete": 0}),
            "unknown_locations": tuple(
                item.model_copy(update={"source_lines": [str(line) for line in item.source_lines]})
                for item in parsed.unknown_locations
            ),
        }
    )
    normalized = PolicyDiagnosticParse.model_validate(copied)
    assert normalized.summary.complete is False
    assert all(
        type(line) is int for item in normalized.unknown_locations for line in item.source_lines
    )
    assert PolicyDiagnosticParse.model_validate_json(normalized.model_dump_json()) == normalized
    value = SourcePartialDiagnostic.from_records(intent, outcome)
    bad_intent = intent.model_copy(update={"after_parse": copied})
    bad = value.model_copy(update={"intent": bad_intent})
    proof = rehash(bad.model_dump(mode="json"))
    bad = bad.model_copy(
        update={"review_json": proof["review_json"], "review_sha256": proof["review_sha256"]}
    )
    # A proof over unnormalized legacy values must not become an accepted unreadable DTO.
    with pytest.raises(ValueError):
        SourcePartialDiagnostic.model_validate(bad)


@pytest.mark.parametrize("which", ["before", "after", "analysis", "all"])
def test_naive_context_refuses_before_policy_execution(which, monkeypatch):
    before, after, analysis = prepared()
    if which in {"before", "all"}:
        before = before.model_copy(update={"created_at": before.created_at.replace(tzinfo=None)})
    if which in {"after", "all"}:
        after = after.model_copy(update={"created_at": after.created_at.replace(tzinfo=None)})
    if which in {"analysis", "all"}:
        analysis = analysis.model_copy(
            update={"created_at": analysis.created_at.replace(tzinfo=None)}
        )
    monkeypatch.setattr(
        "app.detection.policy_diagnostic.evaluate_policies",
        lambda *args, **kwargs: pytest.fail("policy evaluation before timestamp admission"),
    )
    with pytest.raises(ValueError, match="timezone-aware"):
        prepare_partial_policy(before, after, analysis)
