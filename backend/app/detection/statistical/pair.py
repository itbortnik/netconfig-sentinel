"""Reexecute the explicitly selected original numeric Forest on a genuine source pair."""

from app.api.contracts import AnalysisResult, ConfigurationSnapshot, ModelSummary, RegisteredModel
from app.api.model_patch_review_contracts import StatisticalRecheck
from app.detection.baseline import PeerGroupKey
from app.detection.config_model_contracts import require_complete
from app.detection.statistical.features import extract_structured_features


def require_forest_target(snapshot: ConfigurationSnapshot, summary: ModelSummary) -> None:
    """Metadata-only admission usable for immutable history without loading a model."""
    require_complete(snapshot)
    config = snapshot.canonical
    if (
        PeerGroupKey.from_config(config) != summary.metadata.group
        or not config.device.hostname
        or config.device.hostname in summary.training_hostnames
        or any(
            item.device_id == snapshot.device_id
            or item.source_sha256 == config.source.sha256
            or item.created_at > snapshot.created_at
            for item in summary.training
        )
    ):
        raise ValueError("statistical target group or training exclusion differs")


def recheck_original_forest(
    before: ConfigurationSnapshot,
    after: ConfigurationSnapshot,
    analysis: AnalysisResult,
    registered: RegisteredModel,
) -> StatisticalRecheck:
    """No fit, persistence or history reads; the caller binds exact retained originals."""
    before = ConfigurationSnapshot.model_validate(before.model_dump(warnings=False))
    after = ConfigurationSnapshot.model_validate(after.model_dump(warnings=False))
    analysis = AnalysisResult.model_validate(analysis.model_dump(warnings=False))
    registered = RegisteredModel.model_validate(registered.model_dump(warnings=False))
    original = analysis.statistical
    if original is None or (
        analysis.configuration_id != before.configuration_id
        or analysis.device_id != before.device_id
        or analysis.source_sha256 != before.canonical.source.sha256
        or original.model != registered.summary
        or before.device_id != after.device_id
        or before.configuration_id == after.configuration_id
        or before.canonical.source.sha256 == after.canonical.source.sha256
        or before.created_at > after.created_at
        or (before.canonical.device.vendor, before.canonical.device.platform)
        != (after.canonical.device.vendor, after.canonical.device.platform)
    ):
        raise ValueError("original statistical analysis or selected pair differs")
    summary = registered.summary
    for snapshot in (before, after):
        require_forest_target(snapshot, summary)
    rows = [
        extract_structured_features(snapshot.canonical).as_row() for snapshot in (before, after)
    ]
    scores = registered.artifact.score_samples(rows)
    decisions = registered.artifact.decision_function(rows)
    predictions = registered.artifact.predict(rows)
    if (scores[0], decisions[0], predictions[0]) != (
        original.score_samples,
        original.decision_function,
        original.prediction,
    ):
        raise ValueError("original statistical baseline differs from frozen artifact")
    return StatisticalRecheck(
        model_id=summary.model_id,
        artifact_sha256=summary.artifact_sha256,
        before_score_samples=scores[0],
        after_score_samples=scores[1],
        before_decision_function=decisions[0],
        after_decision_function=decisions[1],
        before_prediction=predictions[0],
        after_prediction=predictions[1],
    )
