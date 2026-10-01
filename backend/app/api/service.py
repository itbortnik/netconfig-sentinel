"""Persistent upload-to-analysis workflow using the supported local detector."""

from datetime import UTC, datetime
from uuid import UUID, uuid4

from app.api.contracts import AnalysisResult, ConfigurationSnapshot, UploadConfiguration
from app.db.store import Store
from app.detection.fusion import RiskSource, fuse_risk
from app.detection.policy_engine import evaluate_policies
from app.explanation.local import explain_finding
from app.ingestion.local import validate_configuration_text
from app.parsers import parse_configuration
from app.policies import POLICY_CATALOG_VERSION


class AnalysisService:
    def __init__(self, store: Store) -> None:
        self.store = store

    def upload(self, upload: UploadConfiguration) -> ConfigurationSnapshot:
        validate_configuration_text(upload.content)
        config = parse_configuration(upload.content, filename=upload.filename)
        snapshot = ConfigurationSnapshot(
            configuration_id=uuid4(),
            device_id=upload.device_id,
            created_at=datetime.now(UTC),
            canonical=config,
        )
        self.store.add_configuration(snapshot)
        return snapshot

    def analyze(self, configuration_id: UUID) -> AnalysisResult | None:
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
        result = AnalysisResult(
            analysis_id=uuid4(),
            configuration_id=configuration_id,
            device_id=snapshot.device_id,
            source_sha256=config.source.sha256,
            created_at=datetime.now(UTC),
            status="completed" if complete else "partial",
            policy_catalog_version=POLICY_CATALOG_VERSION,
            findings=tuple(findings),
            explanations=tuple(explain_finding(finding, config) for finding in findings),
            risk=fuse_risk(
                findings, device_id=snapshot.device_id, completed_detectors=[RiskSource.POLICY]
            )
            if complete
            else None,
            limitations=(
                "Only deterministic policies were run; "
                "baseline, ML and formal verification were not run.",
                "Scores are uncalibrated; the result requires engineer review.",
                *(
                    ()
                    if complete
                    else ("Parsing is incomplete; findings are partial and risk is unavailable.",)
                ),
            ),
        )
        self.store.add_analysis(result)
        return result
