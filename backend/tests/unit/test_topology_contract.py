"""Synthetic graph contracts; no neural model, live discovery or quality measurements."""

from uuid import UUID, uuid4

import pytest
from app.detection.policy_engine import evaluate_policies
from app.detection.topology import TopologyReport, analyze_topology
from app.domain.topology import TopologyInput, TopologyNode, topology_fingerprint
from app.parsers import parse_configuration


def graph():
    devices = [
        {
            "device_id": str(UUID(int=i)),
            "source_sha256": str(i) * 64,
            "vendor": "cisco" if i == 1 else "juniper",
            "platform": "ios" if i == 1 else "junos",
            "parser_confidence": 1.0,
            "unparsed_count": 0,
        }
        for i in (1, 2)
    ]
    nodes = [
        {
            "node_id": device["device_id"],
            "device_id": device["device_id"],
            "kind": "device",
            "entity_key": "",
            "features": [1.0, 0.0],
        }
        for device in devices
    ]
    nodes.extend(
        [
            {
                "node_id": str(UUID(int=i + 2)),
                "device_id": str(UUID(int=i)),
                "kind": "interface",
                "entity_key": "port-1",
                "features": [0.0, 1.0],
            }
            for i in (1, 2)
        ]
    )
    return {
        "topology_id": str(UUID(int=10)),
        "devices": devices,
        "feature_schema": "synthetic-0.1",
        "feature_names": ["present", "interface"],
        "nodes": nodes,
        "edges": [
            {
                "edge_id": str(UUID(int=20)),
                "source_node_id": str(UUID(int=3)),
                "target_node_id": str(UUID(int=4)),
                "kind": "physical",
                "directed": False,
                "basis": "declared_inventory",
            }
        ],
    }


def valid_graph():
    return TopologyInput.model_validate(graph())


def test_graph_roundtrip_is_bound_but_default_detector_is_honestly_unavailable():
    inputs = valid_graph()
    assert TopologyInput.model_validate_json(inputs.model_dump_json()) == inputs
    before = inputs.model_dump_json()
    result = analyze_topology(inputs)
    assert result.status == "unavailable" and not result.findings
    assert result.model_version is None and result.model_sha256 is None
    assert result.input_sha256 == topology_fingerprint(inputs)
    assert result.formal_verification == "not_run" and result.risk_fusion_enabled is False
    assert inputs.model_dump_json() == before
    with pytest.raises(ValueError):
        inputs.scope = "complete"


@pytest.mark.parametrize(
    "damage",
    [
        "device",
        "node",
        "edge",
        "foreign",
        "root",
        "entity",
        "dangling",
        "self",
        "direction",
        "physical-device",
        "duplicate-connection",
        "features",
        "feature-names",
        "embedding",
        "nan",
        "infinity",
        "boolean",
        "vendor",
        "scope",
        "extra",
        "snapshot",
    ],
)
def test_ambiguous_unbound_unbounded_or_unsupported_graphs_fail_closed(damage):
    value = graph()
    if damage in {"device", "node", "edge"}:
        field = {"device": "devices", "node": "nodes", "edge": "edges"}[damage]
        value[field].append(value[field][0])
    elif damage == "foreign":
        value["nodes"][2]["device_id"] = str(UUID(int=99))
    elif damage == "root":
        value["nodes"].pop(0)
    elif damage == "entity":
        value["nodes"].append(value["nodes"][2] | {"node_id": str(UUID(int=99))})
    elif damage == "dangling":
        value["edges"][0]["target_node_id"] = str(UUID(int=99))
    elif damage == "self":
        value["edges"][0]["target_node_id"] = str(UUID(int=3))
    elif damage == "direction":
        value["edges"][0]["directed"] = True
    elif damage == "physical-device":
        value["edges"][0]["source_node_id"] = str(UUID(int=1))
    elif damage == "duplicate-connection":
        value["edges"].append(
            value["edges"][0]
            | {
                "edge_id": str(UUID(int=21)),
                "source_node_id": str(UUID(int=4)),
                "target_node_id": str(UUID(int=3)),
            }
        )
    elif damage == "features":
        value["nodes"][0]["features"] = [1.0]
    elif damage == "feature-names":
        value["feature_names"] = ["present", "present"]
    elif damage == "embedding":
        for i, node in enumerate(value["nodes"][:2]):
            node["embedding"] = {
                "checkpoint_sha256": "a" * 64,
                "tokenizer_sha256": "b" * 64,
                "values": [1.0] * (i + 1),
            }
    elif damage == "nan":
        value["nodes"][0]["features"][0] = float("nan")
    elif damage == "infinity":
        value["nodes"][0]["features"][0] = float("inf")
    elif damage == "boolean":
        value["nodes"][0]["features"][0] = True
    elif damage == "vendor":
        value["devices"][0]["platform"] = "junos"
    elif damage == "scope":
        value["scope"] = "complete"
    elif damage == "extra":
        value["raw_configuration"] = "private text"
    elif damage == "snapshot":
        for device in value["devices"]:
            device["configuration_id"] = str(UUID(int=30))
    with pytest.raises(ValueError):
        TopologyInput.model_validate(value)


def test_entity_order_and_undirected_endpoint_order_do_not_change_fingerprint():
    value = graph()
    before = topology_fingerprint(TopologyInput.model_validate(value))
    value["devices"].reverse()
    value["nodes"].reverse()
    edge = value["edges"][0]
    edge["source_node_id"], edge["target_node_id"] = edge["target_node_id"], edge["source_node_id"]
    assert topology_fingerprint(TopologyInput.model_validate(value)) == before
    value["nodes"][0]["features"][0] = 2.0
    assert topology_fingerprint(TopologyInput.model_validate(value)) != before


def test_embedding_budget_is_enforced_before_running_an_adapter():
    value = graph()
    value["nodes"] = value["nodes"][:2]
    value["edges"] = []
    embedding = {
        "checkpoint_sha256": "a" * 64,
        "tokenizer_sha256": "b" * 64,
        "values": [0.0] * 1024,
    }
    for index in range(260):
        value["nodes"].append(
            {
                "node_id": str(uuid4()),
                "device_id": str(UUID(int=1)),
                "kind": "interface",
                "entity_key": str(index),
                "features": [0.0, 1.0],
                "embedding": embedding,
            }
        )
    with pytest.raises(ValueError, match="numeric budget"):
        TopologyInput.model_validate(value)


class SyntheticDetector:
    model_version = "synthetic-topology-0.1.0"
    model_sha256 = "a" * 64

    def __init__(self):
        finding = evaluate_policies(
            parse_configuration("hostname test\n", filename="synthetic.cfg"), device_id=UUID(int=1)
        )[0]
        self.finding = finding.model_copy(
            update={"detector": "topology_gnn", "model_version": self.model_version}
        )
        self.calls = 0

    def detect(self, inputs):
        self.calls += 1
        return (self.finding,)


def test_explicit_synthetic_adapter_produces_only_partial_unfused_findings():
    adapter = SyntheticDetector()
    result = analyze_topology(valid_graph(), adapter)
    assert adapter.calls == 1 and result.status == "partial"
    assert result.findings[0] == adapter.finding
    assert not result.risk_fusion_enabled and result.formal_verification == "not_run"


@pytest.mark.parametrize(
    "update",
    [
        {"device_id": UUID(int=99)},
        {"detector": "policy_engine"},
        {"model_version": "other"},
        {"evidence": []},
    ],
)
def test_adapter_cannot_inject_foreign_unbound_or_evidence_free_findings(update):
    adapter = SyntheticDetector()
    adapter.finding = adapter.finding.model_copy(update=update)
    with pytest.raises(ValueError, match="unbound"):
        analyze_topology(valid_graph(), adapter)


def test_bad_adapter_metadata_is_rejected_before_call_and_report_cannot_be_promoted():
    adapter = SyntheticDetector()
    adapter.model_sha256 = "invalid"
    with pytest.raises(ValueError):
        analyze_topology(valid_graph(), adapter)
    assert adapter.calls == 0
    value = analyze_topology(valid_graph()).model_dump()
    for update in (
        {"status": "completed"},
        {"formal_verification": "passed"},
        {"risk_fusion_enabled": True},
        {"risk_fusion_enabled": 0},
        {"approved": True},
    ):
        with pytest.raises(ValueError):
            TopologyReport.model_validate(value | update)


def test_mutated_model_copy_is_revalidated_before_fingerprinting_or_inference():
    invalid = valid_graph().model_copy(update={"nodes": ()})
    adapter = SyntheticDetector()
    with pytest.raises(ValueError):
        analyze_topology(invalid, adapter)
    assert adapter.calls == 0
    with pytest.raises(ValueError):
        topology_fingerprint(invalid)


@pytest.mark.parametrize("key", ["", " hidden", "private\nline", "x" * 129])
def test_entity_keys_cannot_be_empty_unbounded_or_invisible(key):
    with pytest.raises(ValueError):
        TopologyNode(node_id=uuid4(), device_id=uuid4(), kind="interface", entity_key=key)
