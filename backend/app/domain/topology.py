"""Bounded explicit-subset graph input; structural validity never proves a real topology."""

import json
from hashlib import sha256
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.domain.models import SHA256_PATTERN, Vendor

FiniteNumber = Annotated[float, Field(strict=True, allow_inf_nan=False)]
Identifier = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")]


class GraphModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class TopologyLocation(GraphModel):
    source_lines: tuple[Annotated[int, Field(strict=True, ge=1)], ...] = Field(
        min_length=1, max_length=256
    )
    raw_text_hash: str = Field(pattern=SHA256_PATTERN)
    parser_confidence: FiniteNumber = Field(ge=0, le=1)

    @field_validator("source_lines")
    @classmethod
    def ordered_lines(cls, values: tuple[int, ...]) -> tuple[int, ...]:
        if values != tuple(sorted(set(values))):
            raise ValueError("invalid topology anchor lines")
        return values


class TopologyDevice(GraphModel):
    device_id: UUID
    configuration_id: UUID | None = None
    source_sha256: str = Field(pattern=SHA256_PATTERN)
    vendor: Vendor
    platform: Literal["ios", "ios-xe", "junos"]
    parser_confidence: FiniteNumber = Field(ge=0, le=1)
    unparsed_count: int = Field(strict=True, ge=0, le=10000)

    @model_validator(mode="after")
    def supported_platform(self) -> "TopologyDevice":
        if (self.vendor == Vendor.CISCO) != (self.platform in {"ios", "ios-xe"}):
            raise ValueError("inconsistent topology platform")
        return self


class TopologyEmbedding(GraphModel):
    checkpoint_sha256: str = Field(pattern=SHA256_PATTERN)
    tokenizer_sha256: str = Field(pattern=SHA256_PATTERN)
    values: tuple[FiniteNumber, ...] = Field(min_length=1, max_length=1024)


class TopologyNode(GraphModel):
    node_id: UUID
    device_id: UUID
    kind: Literal["device", "interface", "vrf", "vlan"]
    entity_key: str = Field(max_length=128)
    features: tuple[FiniteNumber, ...] = Field(default=(), max_length=256)
    embedding: TopologyEmbedding | None = None
    anchors: tuple[TopologyLocation, ...] = Field(default=(), max_length=16)

    @model_validator(mode="after")
    def explicit_entity(self) -> "TopologyNode":
        if self.kind == "device":
            if self.node_id != self.device_id or self.entity_key:
                raise ValueError("device vertex must use its device identity")
        elif not self.entity_key.strip() or self.entity_key != self.entity_key.strip():
            raise ValueError("non-device vertex needs an explicit entity key")
        if any(not character.isprintable() for character in self.entity_key):
            raise ValueError("invalid topology entity key")
        return self


class TopologyEdge(GraphModel):
    edge_id: UUID
    source_node_id: UUID
    target_node_id: UUID
    kind: Literal["physical", "logical"]
    directed: bool = Field(strict=True)
    basis: Literal["declared_inventory", "configuration"]

    @model_validator(mode="after")
    def distinct_endpoints(self) -> "TopologyEdge":
        if self.source_node_id == self.target_node_id or (
            self.kind == "physical" and self.directed
        ):
            raise ValueError("invalid topology edge endpoints or direction")
        return self


class TopologyInput(GraphModel):
    version: Literal["topology-input-0.1.0"] = "topology-input-0.1.0"
    topology_id: UUID
    scope: Literal["explicit_subset"] = "explicit_subset"
    devices: tuple[TopologyDevice, ...] = Field(min_length=1, max_length=512)
    feature_schema: Identifier
    feature_names: tuple[Identifier, ...] = Field(max_length=256)
    nodes: tuple[TopologyNode, ...] = Field(min_length=1, max_length=2048)
    edges: tuple[TopologyEdge, ...] = Field(default=(), max_length=8192)

    @model_validator(mode="after")
    def graph_is_bound(self) -> "TopologyInput":
        devices = {device.device_id: device for device in self.devices}
        nodes = {node.node_id: node for node in self.nodes}
        if len(devices) != len(self.devices) or len(nodes) != len(self.nodes):
            raise ValueError("duplicate topology device or vertex identity")
        if len({edge.edge_id for edge in self.edges}) != len(self.edges):
            raise ValueError("duplicate topology edge identity")
        snapshots = [device.configuration_id for device in self.devices if device.configuration_id]
        if len(set(snapshots)) != len(snapshots):
            raise ValueError("snapshot cannot represent multiple topology devices")
        if len(set(self.feature_names)) != len(self.feature_names):
            raise ValueError("duplicate topology feature names")
        entities = set()
        signatures = set()
        numeric_count = 0
        for device_id in devices:
            if device_id not in nodes or nodes[device_id].kind != "device":
                raise ValueError("each selected device needs one device vertex")
        for node in self.nodes:
            if node.device_id not in devices or len(node.features) != len(self.feature_names):
                raise ValueError("foreign device or incompatible numeric features")
            entity = (node.device_id, node.kind, node.entity_key)
            if entity in entities:
                raise ValueError("duplicate topology entity")
            entities.add(entity)
            numeric_count += len(node.features)
            if node.embedding is not None:
                vector = node.embedding
                numeric_count += len(vector.values)
                signatures.add(
                    (vector.checkpoint_sha256, vector.tokenizer_sha256, len(vector.values))
                )
        if len(signatures) > 1 or numeric_count > 262144:
            raise ValueError("incompatible embeddings or numeric budget exceeded")
        connections = set()
        for edge in self.edges:
            if edge.source_node_id not in nodes or edge.target_node_id not in nodes:
                raise ValueError("dangling topology edge")
            endpoints: tuple[UUID, ...] = (edge.source_node_id, edge.target_node_id)
            if not edge.directed:
                endpoints = tuple(sorted(endpoints))
            key = (edge.kind, edge.directed, *endpoints)
            if key in connections:
                raise ValueError("duplicate topology connection")
            connections.add(key)
            if edge.kind == "physical" and any(
                nodes[node_id].kind != "interface" for node_id in endpoints
            ):
                raise ValueError("physical links require interface vertices")
        if len(self.model_dump_json().encode("utf-8")) > 8 * 1024 * 1024:
            raise ValueError("topology input byte budget exceeded")
        return self


def topology_fingerprint(inputs: TopologyInput) -> str:
    """Revalidate and ignore entity enumeration order, not vector/feature semantics."""
    checked = TopologyInput.model_validate_json(inputs.model_dump_json())
    content = checked.model_dump(mode="json")
    for field, identity in (("devices", "device_id"), ("nodes", "node_id"), ("edges", "edge_id")):
        content[field].sort(key=lambda item: item[identity])
    for edge in content["edges"]:
        if not edge["directed"] and edge["source_node_id"] > edge["target_node_id"]:
            edge["source_node_id"], edge["target_node_id"] = (
                edge["target_node_id"],
                edge["source_node_id"],
            )
    serialized = json.dumps(content, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return sha256(serialized.encode("utf-8")).hexdigest()
