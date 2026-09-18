"""Detector and risk-fusion boundary."""

from app.detection.baseline import (
    PEER_BASELINE_NAMESPACE,
    ConsensusFeature,
    PeerBaseline,
    PeerFeature,
    PeerGroupKey,
    build_peer_baseline,
    evaluate_peer_baseline,
)
from app.detection.policy_engine import POLICY_FINDING_NAMESPACE, evaluate_policies
from app.detection.statistical import (
    FEATURE_NAMES,
    FEATURE_SCHEMA_VERSION,
    ISOLATION_FOREST_MODEL_VERSION,
    ISOLATION_FOREST_NAMESPACE,
    FittedIsolationForest,
    IsolationForestMetadata,
    StructuredFeatureVector,
    evaluate_isolation_forest,
    extract_structured_features,
    fit_isolation_forest,
)

__all__ = [
    "FEATURE_NAMES",
    "FEATURE_SCHEMA_VERSION",
    "ISOLATION_FOREST_MODEL_VERSION",
    "ISOLATION_FOREST_NAMESPACE",
    "PEER_BASELINE_NAMESPACE",
    "POLICY_FINDING_NAMESPACE",
    "ConsensusFeature",
    "FittedIsolationForest",
    "IsolationForestMetadata",
    "PeerBaseline",
    "PeerFeature",
    "PeerGroupKey",
    "StructuredFeatureVector",
    "build_peer_baseline",
    "evaluate_isolation_forest",
    "evaluate_peer_baseline",
    "evaluate_policies",
    "extract_structured_features",
    "fit_isolation_forest",
]
