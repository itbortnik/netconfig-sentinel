"""Persistent upload-to-analysis workflow using the supported local detector."""

from datetime import UTC, datetime
from uuid import UUID, uuid4

from app.api.contracts import (
    AnalysisOptions,
    AnalysisResult,
    ComparisonContext,
    ConfigurationSnapshot,
    SnapshotBinding,
    UploadConfiguration,
)
from app.db.store import Store
from app.detection.baseline import (
    PeerGroupKey,
    build_peer_baseline,
    compare_expected_configuration,
    create_expected_configuration,
    evaluate_peer_baseline,
)
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
        result = AnalysisResult(
            version="analysis-api-0.2.0" if comparison is not None else "analysis-api-0.1.0",
            analysis_id=uuid4(),
            configuration_id=configuration_id,
            device_id=snapshot.device_id,
            source_sha256=config.source.sha256,
            created_at=datetime.now(UTC),
            status="completed" if complete else "partial",
            policy_catalog_version=POLICY_CATALOG_VERSION,
            findings=tuple(findings),
            explanations=tuple(
                explain_finding(finding, config, reference=reference, peer_baseline=baseline)
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
                "Only the recorded deterministic detectors were run; "
                "ML and formal verification were not run.",
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
        )
        self.store.add_analysis(result)
        return result
