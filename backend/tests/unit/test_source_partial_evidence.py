"""Exact saved partial child projections; no detector execution on report replay."""

from datetime import timedelta
from uuid import uuid4

import pytest
from app.api.patch_contracts import PatchDraft, draft_fingerprint
from app.api.source_evidence_contracts import SelectedEvidenceRef
from app.api.source_evidence_partial_contracts import (
    CreateSourceEvidenceReportV5,
    SourceEvidenceReportV5,
    SourceEvidenceSummaryV5,
    parse_source_evidence_report_json,
    parse_source_evidence_request,
    source_evidence_report,
    validate_source_evidence_report,
)
from app.api.source_evidence_scope_contracts import CreateSourceEvidenceReportV4
from app.api.source_ml_contracts import source_ml_fingerprint
from app.api.source_partial_contracts import SourcePartialDiagnostic
from app.comparison.snapshots import compare_snapshots
from test_partial_policy_diagnostic import MARKER, prepared, records, rehash


def joint_records(vendor="cisco", partial="after", **options):
    selected = prepared(vendor, partial, **options)
    before, after, analysis = selected
    diff = compare_snapshots(before, after)
    draft = PatchDraft(
        patch_id=uuid4(),
        created_at=analysis.created_at + timedelta(microseconds=1),
        draft_sha256=draft_fingerprint(diff),
        diff=diff,
    )
    intent, outcome = records(selected=selected)
    intent = intent.model_copy(
        update={
            "patch_id": draft.patch_id,
            "request": intent.request.model_copy(update={"draft_sha256": draft.draft_sha256}),
            "selection": intent.selection.model_copy(
                update={
                    "patch_id": draft.patch_id,
                    "draft_sha256": draft.draft_sha256,
                }
            ),
        }
    )
    outcome = outcome.model_copy(update={"intent_sha256": source_ml_fingerprint(intent)})
    child = SourcePartialDiagnostic.from_records(intent, outcome)
    request = CreateSourceEvidenceReportV5(
        mode="policy_only_partial_diagnostic",
        report_id=uuid4(),
        draft_sha256=draft.draft_sha256,
        deterministic=SelectedEvidenceRef(
            record_id=child.recheck_id, review_sha256=child.review_sha256
        ),
        forest=None,
        neural=None,
        network=None,
    )
    report = SourceEvidenceReportV5.from_evidence(
        draft,
        request,
        child,
        created_at=child.outcome.completed_at + timedelta(seconds=1),
    )
    return draft, child, report


@pytest.mark.parametrize("vendor", ["cisco", "juniper"])
@pytest.mark.parametrize("partial", ["before", "after", "both"])
def test_partial_projection_preserves_full_exact_child(vendor, partial):
    draft, child, report = joint_records(vendor, partial)
    validate_source_evidence_report(report, draft, child)
    assert parse_source_evidence_report_json(report.model_dump_json()) == report
    assert report.deterministic.report == child.outcome.report
    assert report.deterministic.selection == child.intent.selection
    assert report.deterministic.validation_blockers == child.validation_blockers
    assert report.coverage == "partial"
    assert report.deterministic.report.policy_changes is None
    assert MARKER not in report.model_dump_json()
    assert SourceEvidenceSummaryV5.from_report(report).selected_kinds == ("deterministic",)


def test_replay_and_validation_need_no_parser_policy_or_catalog_lookup(monkeypatch):
    draft, child, report = joint_records()

    def forbidden(*args, **kwargs):
        pytest.fail("history must use saved values only")

    for name in (
        "app.detection.policy_diagnostic.prepare_partial_policy",
        "app.detection.policy_diagnostic.recheck_partial_policy",
        "app.detection.policy_diagnostic.evaluate_policies",
        "app.ingestion.source_retention.prepare_original_source",
        "app.parsers.parse_configuration",
    ):
        monkeypatch.setattr(name, forbidden)
    monkeypatch.setattr("app.detection.policy_engine.POLICY_CATALOGS", {})
    validate_source_evidence_report(report, draft, child)


@pytest.mark.parametrize("kind", ["forest", "neural", "network"])
def test_partial_request_prohibits_optional_selection(kind):
    _, _, report = joint_records()
    body = report.request.model_dump(mode="json")
    body[kind] = {"record_id": str(uuid4()), "review_sha256": "a" * 64}
    with pytest.raises(ValueError):
        parse_source_evidence_request(body)


def test_old_report_request_does_not_silently_accept_partial_child():
    draft, child, report = joint_records()
    request = CreateSourceEvidenceReportV4(
        report_id=uuid4(),
        draft_sha256=draft.draft_sha256,
        deterministic=report.request.deterministic,
        forest=None,
        neural=None,
        network=None,
    )
    with pytest.raises(ValueError, match="explicit report protocol"):
        source_evidence_report(draft, request, child, created_at=report.created_at)
    body = report.request.model_dump(mode="json")
    body.pop("version")
    with pytest.raises(ValueError):
        parse_source_evidence_request(body)


@pytest.mark.parametrize(
    "field",
    [
        "original_statistical_present",
        "risk_fused",
        "calibrated",
        "quality_proven",
        "approved",
        "applied",
    ],
)
@pytest.mark.parametrize("bad", [0, True])
def test_resealed_typed_copies_cannot_promote_qualification(field, bad):
    _, _, report = joint_records()
    body = rehash(report.model_dump(mode="json") | {field: bad})
    with pytest.raises(ValueError):
        SourceEvidenceReportV5.model_validate(body)
    with pytest.raises(ValueError):
        SourceEvidenceReportV5.model_validate(report.model_copy(update={field: bad}))


def test_self_consistent_changed_after_finding_refused_against_saved_child():
    draft, child, report = joint_records()
    body = report.model_dump(mode="json")
    body["deterministic"]["report"]["after"]["policy_findings"] = []
    altered = SourceEvidenceReportV5.model_validate(rehash(body))
    with pytest.raises(ValueError, match="full saved child projection"):
        validate_source_evidence_report(altered, draft, child)


def test_changed_parser_summary_refused_against_saved_child():
    draft, child, report = joint_records()
    body = report.model_dump(mode="json")
    body["deterministic"]["report"]["after"]["parse"]["summary"]["confidence"] = 0.25
    altered = SourceEvidenceReportV5.model_validate(rehash(body))
    with pytest.raises(ValueError):
        validate_source_evidence_report(altered, draft, child)
