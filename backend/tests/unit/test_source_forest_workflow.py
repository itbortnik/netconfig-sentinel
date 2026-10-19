"""Actual source-bound domain workflow only; HTTP/roles/UI are intentionally untested here."""

from uuid import uuid4

import app.patching.source_forest as workflow_module
import pytest
from app.db.patch_records import PatchConflict
from app.db.source_forest_records import SourceForestRecords
from app.db.source_records import OriginalSourceUnavailable, SourceRecords
from app.patching.source_forest import (
    SourceForestConsentRequired,
    SourceForestTooLarge,
    SourceForestWorkflow,
)
from test_original_forest_pair import selected_forest_pair as selected_forest_pair
from test_source_forest_records import counts
from test_source_forest_records import saved_pair as saved_pair


def test_actual_selected_original_forest_durable_replay_without_source_or_model(
    saved_pair, monkeypatch
):
    store, intent, _outcome = saved_pair
    workflow = SourceForestWorkflow(store)
    monkeypatch.setattr(
        "sklearn.ensemble.IsolationForest.fit", lambda *a, **k: pytest.fail("refit")
    )
    view, created = workflow.run(intent.patch_id, intent.request)
    assert created and view.execution_status == "completed"
    assert (
        view.outcome.report.scores.before_score_samples == intent.selection.original.score_samples
    )
    assert view.status == "needs_review" and not view.approved and not view.quality_proven
    assert counts(store) == (1, 1)

    def forbidden(*args, **kwargs):
        pytest.fail("identical replay or history ran source/model/scorer")

    monkeypatch.setattr(store, "get_model", forbidden)
    monkeypatch.setattr(SourceRecords, "get", forbidden)
    monkeypatch.setattr(workflow_module, "recheck_original_forest", forbidden)
    assert workflow.run(intent.patch_id, intent.request) == (view, False)
    assert workflow.get(intent.patch_id, intent.request.recheck_id) == view
    changed = intent.request.model_copy(update={"model_id": uuid4()})
    with pytest.raises(PatchConflict):
        workflow.run(intent.patch_id, changed)


def test_selection_read_is_analysis_metadata_not_model_or_source_probe(saved_pair, monkeypatch):
    store, intent, _outcome = saved_pair
    monkeypatch.setattr(store, "get_model", lambda *a: pytest.fail("model load"))
    monkeypatch.setattr(SourceRecords, "get", lambda *a, **k: pytest.fail("original read"))
    selected = SourceForestWorkflow(store).selection(
        intent.patch_id, intent.request.before_analysis_id
    )
    assert selected == intent.selection


@pytest.mark.parametrize("fault", ["consent", "analysis", "model", "artifact", "original"])
def test_invalid_selection_or_missing_original_has_no_reservation_or_scoring(
    saved_pair, monkeypatch, fault
):
    store, intent, _outcome = saved_pair
    request = intent.request
    if fault == "consent":
        request = request.model_copy(update={"allow_local_model_context": False})
    elif fault == "analysis":
        request = request.model_copy(update={"before_analysis_sha256": "b" * 64})
    elif fault == "model":
        request = request.model_copy(update={"model_id": uuid4()})
    elif fault == "artifact":
        request = request.model_copy(update={"artifact_sha256": "b" * 64})
    else:

        def missing(*args, **kwargs):
            raise OriginalSourceUnavailable()

        monkeypatch.setattr(SourceRecords, "get", missing)
    monkeypatch.setattr(
        workflow_module, "recheck_original_forest", lambda *a: pytest.fail("scorer")
    )
    with pytest.raises(SourceForestConsentRequired if fault == "consent" else PatchConflict):
        SourceForestWorkflow(store).run(intent.patch_id, request)
    assert counts(store) == (0, 0)


@pytest.mark.parametrize("budget", ["MAX_FOREST_INPUT_BYTES", "MAX_SOURCE_FOREST_BYTES"])
def test_pair_and_proof_budgets_refuse_before_reservation(saved_pair, monkeypatch, budget):
    store, intent, _outcome = saved_pair
    monkeypatch.setattr(workflow_module, budget, 1)
    monkeypatch.setattr(
        workflow_module, "recheck_original_forest", lambda *a: pytest.fail("scorer")
    )
    with pytest.raises(SourceForestTooLarge):
        SourceForestWorkflow(store).run(intent.patch_id, intent.request)
    assert counts(store) == (0, 0)


def test_unavailable_numeric_result_is_durable_failed_without_partial_scores(
    saved_pair, monkeypatch
):
    store, intent, _outcome = saved_pair

    def fail(*args):
        raise ValueError("private diagnostics must not escape")

    monkeypatch.setattr(workflow_module, "recheck_original_forest", fail)
    workflow = SourceForestWorkflow(store)
    view, created = workflow.run(intent.patch_id, intent.request)
    assert created and view.execution_status == "failed" and view.outcome.report is None
    assert "private diagnostics" not in view.model_dump_json()
    assert counts(store) == (1, 1) and workflow.run(intent.patch_id, intent.request) == (
        view,
        False,
    )


def test_completion_audit_failure_keeps_pending_replay_without_rerun(saved_pair, monkeypatch):
    store, intent, _outcome = saved_pair
    original = SourceForestRecords._audit

    def fail(session, action, key):
        if action == "patch.statistical_recheck_completed":
            raise RuntimeError("owned audit failure")
        original(session, action, key)

    monkeypatch.setattr(SourceForestRecords, "_audit", staticmethod(fail))
    workflow = SourceForestWorkflow(store)
    with pytest.raises(RuntimeError, match="owned audit failure"):
        workflow.run(intent.patch_id, intent.request)
    assert counts(store) == (1, 0)
    monkeypatch.setattr(store, "get_model", lambda *a: pytest.fail("load model"))
    monkeypatch.setattr(workflow_module, "recheck_original_forest", lambda *a: pytest.fail("rerun"))
    view, created = workflow.run(intent.patch_id, intent.request)
    assert not created and view.execution_status == "pending_unknown" and view.outcome is None
