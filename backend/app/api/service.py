"""Persistent upload-to-analysis workflow using the supported local detector."""

from datetime import UTC, datetime
from threading import BoundedSemaphore
from uuid import UUID, uuid4

from app.api.contracts import (
    AnalysisOptions,
    AnalysisResult,
    ComparisonContext,
    ConfigurationSnapshot,
    ModelSummary,
    RegisteredModel,
    SnapshotBinding,
    StatisticalContext,
    TrainModelOptions,
    UploadConfiguration,
)
from app.api.feedback_contracts import FeedbackRecord, SubmitFeedback
from app.db.store import FeedbackConflict, StorageIntegrityError, Store
from app.detection.baseline import (
    PeerGroupKey,
    build_peer_baseline,
    compare_expected_configuration,
    create_expected_configuration,
    evaluate_peer_baseline,
)
from app.detection.fusion import RiskSource, fuse_risk
from app.detection.policy_engine import evaluate_policies
from app.detection.statistical.artifact import export_forest
from app.detection.statistical.features import extract_structured_features
from app.detection.statistical.isolation_forest import (
    evaluate_isolation_forest,
    fit_isolation_forest,
)
from app.domain import Finding
from app.domain.fingerprints import finding_fingerprint
from app.explanation.local import explain_finding
from app.ingestion.local import validate_configuration_text
from app.parsers import parse_configuration
from app.policies import POLICY_CATALOG_VERSION


class ModelTrainingBusy(Exception):
    """Only one bounded training operation is allowed per application process."""


class FeedbackTargetNotFound(Exception):
    """The selected analysis/finding pair is unavailable."""


class AnalysisService:
    def __init__(self, store: Store) -> None:
        self.store = store
        self._training_slot = BoundedSemaphore(1)

    def feedback_target(
        self, analysis_id: UUID, finding_id: UUID
    ) -> tuple[AnalysisResult, Finding]:
        analysis = self.store.get_analysis(analysis_id)
        if analysis is None:
            raise FeedbackTargetNotFound()
        for finding, explanation in zip(analysis.findings, analysis.explanations, strict=True):
            if finding.finding_id == finding_id:
                if finding_fingerprint(finding) != explanation.finding_sha256:
                    raise StorageIntegrityError("Stored data is unavailable.")
                return analysis, finding
        raise FeedbackTargetNotFound()

    def submit_feedback(
        self, finding_id: UUID, submission: SubmitFeedback
    ) -> tuple[FeedbackRecord, bool]:
        analysis, finding = self.feedback_target(submission.analysis_id, finding_id)
        if submission.finding_sha256 != finding_fingerprint(finding):
            raise FeedbackConflict("finding content differs from the selected analysis")
        record = FeedbackRecord(
            **submission.model_dump(),
            finding_id=finding_id,
            device_id=analysis.device_id,
            configuration_id=analysis.configuration_id,
            source_sha256=analysis.source_sha256,
            created_at=datetime.now(UTC),
        )
        return self.store.add_feedback(record)

    def train_model(self, options: TrainModelOptions) -> ModelSummary:
        if not self._training_slot.acquire(blocking=False):
            raise ModelTrainingBusy()
        try:
            snapshots: list[ConfigurationSnapshot] = []
            total_size = 0
            for configuration_id in sorted(options.configuration_ids, key=str):
                snapshot = self.store.get_configuration(configuration_id)
                if snapshot is None:
                    raise ValueError("training snapshot is missing")
                config = snapshot.canonical
                if (
                    config.parse_warnings
                    or config.unparsed_fragments
                    or (config.parser_confidence != 1 or not config.device.hostname)
                ):
                    raise ValueError("training requires complete, identified configurations")
                total_size += len(config.model_dump_json().encode("utf-8"))
                if total_size > 16 * 1024 * 1024:
                    raise ValueError("training population exceeds size limit")
                snapshots.append(snapshot)
            for values in (
                [item.device_id for item in snapshots],
                [item.canonical.device.hostname for item in snapshots],
                [item.canonical.source.sha256 for item in snapshots],
            ):
                if len(set(values)) != len(values):
                    raise ValueError("training requires different devices and source snapshots")
            fitted = fit_isolation_forest(
                [item.canonical for item in snapshots],
                contamination=options.contamination,
            )
            artifact = export_forest(fitted)
            rows = [extract_structured_features(item.canonical).as_row() for item in snapshots]
            if list(fitted.estimator.predict(rows)) != artifact.predict(rows) or any(
                abs(float(expected) - actual) > 1e-14
                for expected, actual in zip(
                    fitted.estimator.score_samples(rows),
                    artifact.score_samples(rows),
                    strict=True,
                )
            ):
                raise ValueError("numeric export differs from the fitted model")
            summary = ModelSummary(
                model_id=uuid4(),
                created_at=datetime.now(UTC),
                artifact_sha256=artifact.fingerprint(),
                decision_offset=artifact.offset,
                metadata=artifact.metadata,
                training=tuple(SnapshotBinding.from_snapshot(item) for item in snapshots),
                training_hostnames=tuple(
                    item.canonical.device.hostname or "" for item in snapshots
                ),
            )
            self.store.add_model(RegisteredModel(summary=summary, artifact=artifact))
            return summary
        finally:
            self._training_slot.release()

    def upload(self, upload: UploadConfiguration) -> ConfigurationSnapshot:
        validate_configuration_text(upload.content)
        config = parse_configuration(upload.content, filename=upload.filename)
        if upload.inventory is not None:
            config = config.model_copy(
                update={
                    "device": config.device.model_copy(
                        update={
                            "role": upload.inventory.device_role,
                            "site_class": upload.inventory.site_class,
                            "service_profile": upload.inventory.service_profile,
                        }
                    )
                }
            )
        snapshot = ConfigurationSnapshot(
            configuration_id=uuid4(),
            device_id=upload.device_id,
            created_at=datetime.now(UTC),
            canonical=config,
        )
        self.store.add_configuration(snapshot)
        return snapshot

    def analyze(
        self, configuration_id: UUID, options: AnalysisOptions | None = None
    ) -> AnalysisResult | None:
        snapshot = self.store.get_configuration(configuration_id)
        if snapshot is None:
            return None
        config = snapshot.canonical
        complete = (
            not config.unparsed_fragments
            and not config.parse_warnings
            and config.parser_confidence == 1
        )
        findings = evaluate_policies(config, device_id=snapshot.device_id)
        options = options or AnalysisOptions()
        reference = None
        reference_binding = None
        baseline = None
        statistical = None
        statistical_model = None
        peers: list[ConfigurationSnapshot] = []
        if options.reference_configuration_id is not None:
            selected = self.store.get_configuration(options.reference_configuration_id)
            if (
                selected is None
                or selected.configuration_id == configuration_id
                or (selected.created_at > snapshot.created_at)
            ):
                raise ValueError("reference snapshot is missing, current or newer than the target")
            reference = create_expected_configuration(
                selected.canonical,
                device_id=selected.device_id,
                reference_id=str(selected.configuration_id),
            )
            findings.extend(
                compare_expected_configuration(config, reference, device_id=snapshot.device_id)
            )
            reference_binding = SnapshotBinding.from_snapshot(selected)
        if options.peer_configuration_ids:
            group = PeerGroupKey.from_config(config)
            for peer_id in sorted(options.peer_configuration_ids, key=str):
                peer = self.store.get_configuration(peer_id)
                if (
                    peer is None
                    or peer.device_id == snapshot.device_id
                    or (peer.created_at > snapshot.created_at)
                ):
                    raise ValueError("peer snapshot is missing, from the target or newer")
                candidate = peer.canonical
                if PeerGroupKey.from_config(candidate) != group or (
                    candidate.parse_warnings
                    or candidate.unparsed_fragments
                    or candidate.parser_confidence < 1
                ):
                    raise ValueError("peer group or parsing is incompatible")
                peers.append(peer)
            if len({peer.device_id for peer in peers}) != len(peers) or (
                len({peer.canonical.device.hostname for peer in peers}) != len(peers)
            ):
                raise ValueError("each peer must be a different identified device")
            if any(peer.canonical.device.hostname == config.device.hostname for peer in peers):
                raise ValueError("the target hostname cannot be selected as a peer")
            if config.device.hostname is None or any(
                peer.canonical.device.hostname is None for peer in peers
            ):
                raise ValueError("peer comparisons require explicit device hostnames")
            baseline = build_peer_baseline([peer.canonical for peer in peers])
            findings.extend(evaluate_peer_baseline(config, baseline, device_id=snapshot.device_id))
        comparison = (
            ComparisonContext(
                reference=reference_binding,
                peers=tuple(SnapshotBinding.from_snapshot(peer) for peer in peers),
                peer_baseline=baseline,
            )
            if reference_binding is not None or peers
            else None
        )
        completed = [RiskSource.POLICY]
        if baseline is not None:
            completed.append(RiskSource.PEER_GROUP)
        if options.statistical_model_id is not None:
            registered = self.store.get_model(options.statistical_model_id)
            if registered is None:
                raise ValueError("selected model is unavailable")
            summary = registered.summary
            if not complete or PeerGroupKey.from_config(config) != summary.metadata.group:
                raise ValueError("selected model requires complete parsing and matching group")
            if not config.device.hostname or config.device.hostname in summary.training_hostnames:
                raise ValueError("target hostname belongs to training or is missing")
            if any(
                item.device_id == snapshot.device_id
                or item.source_sha256 == config.source.sha256
                or item.created_at > snapshot.created_at
                for item in summary.training
            ):
                raise ValueError("training population contains the target or future snapshots")
            statistical_model = registered.artifact.fitted(registry_id=summary.model_id)
            row = [extract_structured_features(config).as_row()]
            statistical = StatisticalContext(
                model=summary,
                score_samples=registered.artifact.score_samples(row)[0],
                decision_function=registered.artifact.decision_function(row)[0],
                prediction=registered.artifact.predict(row)[0],
            )
            findings.extend(
                evaluate_isolation_forest(
                    config,
                    statistical_model,
                    device_id=snapshot.device_id,
                )
            )
            completed.append(RiskSource.STATISTICAL)
        result = AnalysisResult(
            version="analysis-api-0.3.0"
            if statistical is not None
            else ("analysis-api-0.2.0" if comparison is not None else "analysis-api-0.1.0"),
            analysis_id=uuid4(),
            configuration_id=configuration_id,
            device_id=snapshot.device_id,
            source_sha256=config.source.sha256,
            created_at=datetime.now(UTC),
            status="completed" if complete else "partial",
            policy_catalog_version=POLICY_CATALOG_VERSION,
            findings=tuple(findings),
            explanations=tuple(
                explain_finding(
                    finding,
                    config,
                    reference=reference,
                    peer_baseline=baseline,
                    statistical_model=statistical_model,
                )
                for finding in findings
            ),
            risk=fuse_risk(
                [item for item in findings if item.detector != "expected_configuration"],
                device_id=snapshot.device_id,
                completed_detectors=completed,
            )
            if complete
            else None,
            limitations=(
                "Only the recorded detectors were run; Transformer and formal verification "
                "were not run."
                if statistical is not None
                else (
                    "Only the recorded deterministic detectors were run; "
                    "ML and formal verification were not run."
                ),
                *(
                    (
                        "Isolation Forest is an experimental control model, not a calibrated "
                        "or independently validated production model.",
                    )
                    if statistical is not None
                    else ()
                ),
                "Reference differences are review information and are excluded from risk fusion.",
                "Inventory labels and comparison inputs were explicitly selected by the operator; "
                "they are not independently verified or approved security baselines.",
                "Scores are uncalibrated; the result requires engineer review.",
                *(
                    ()
                    if complete
                    else ("Parsing is incomplete; findings are partial and risk is unavailable.",)
                ),
            ),
            comparison=comparison,
            statistical=statistical,
        )
        self.store.add_analysis(result)
        return result
