"""Peer-group baseline construction and evaluation."""

from app.detection.baseline.expanded import (
    ExpandedFact,
    ExpandedField,
    ExpandedReference,
    compare_expanded_reference,
    create_expanded_reference,
    project_expanded_facts,
)
from app.detection.baseline.expected import (
    ExpectedConfiguration,
    compare_expected_configuration,
    create_expected_configuration,
)
from app.detection.baseline.models import (
    ConsensusFeature,
    PeerBaseline,
    PeerFeature,
    PeerGroupKey,
)
from app.detection.baseline.peer import (
    PEER_BASELINE_NAMESPACE,
    build_peer_baseline,
    evaluate_peer_baseline,
)
from app.detection.baseline.peer_v2 import (
    ExpandedPeerBaseline,
    ExpandedPeerEvaluation,
    ExpandedPeerFeature,
    build_expanded_peer_baseline,
    evaluate_expanded_peer_baseline,
)
from app.detection.baseline.peer_v3 import (
    MeasuredPeerBaseline,
    MeasuredPeerEvaluation,
    build_measured_peer_baseline,
    evaluate_measured_peer_baseline,
)

__all__ = [
    "PEER_BASELINE_NAMESPACE",
    "ConsensusFeature",
    "ExpandedFact",
    "ExpandedField",
    "ExpandedPeerBaseline",
    "ExpandedPeerEvaluation",
    "ExpandedPeerFeature",
    "ExpandedReference",
    "ExpectedConfiguration",
    "MeasuredPeerBaseline",
    "MeasuredPeerEvaluation",
    "PeerBaseline",
    "PeerFeature",
    "PeerGroupKey",
    "build_expanded_peer_baseline",
    "build_measured_peer_baseline",
    "build_peer_baseline",
    "compare_expanded_reference",
    "compare_expected_configuration",
    "create_expanded_reference",
    "create_expected_configuration",
    "evaluate_expanded_peer_baseline",
    "evaluate_measured_peer_baseline",
    "evaluate_peer_baseline",
    "project_expanded_facts",
]
