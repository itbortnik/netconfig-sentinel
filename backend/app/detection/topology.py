"""Future graph-detector boundary; no GNN, discovery, model loading or production fusion."""

from typing import Literal, Protocol
from uuid import UUID

from pydantic import ConfigDict, Field, field_validator, model_validator

from app.domain.models import SHA256_PATTERN, Finding
from app.domain.topology import GraphModel, Identifier, TopologyInput, topology_fingerprint


class TopologyDetector(Protocol):
    model_version: str
    model_sha256: str

    def detect(self, inputs: TopologyInput) -> tuple[Finding, ...]: ...


class TopologyReport(GraphModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["topology-report-0.1.0"] = "topology-report-0.1.0"
    topology_id: UUID
    input_sha256: str = Field(pattern=SHA256_PATTERN)
    scope: Literal["explicit_subset"] = "explicit_subset"
    status: Literal["unavailable", "partial"]
    model_version: Identifier | None = None
    model_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    findings: tuple[Finding, ...] = Field(default=(), max_length=500)
    formal_verification: Literal["not_run"] = "not_run"
    risk_fusion_enabled: Literal[False] = False
    limitations: tuple[str, ...] = Field(min_length=1)

    @field_validator("risk_fusion_enabled", mode="before")
    @classmethod
    def fusion_disabled(cls, value: object) -> bool:
        if value is not False:
            raise ValueError("topology fusion is disabled")
        return False

    @model_validator(mode="after")
    def unavailable_is_not_a_clean_result(self) -> "TopologyReport":
        if self.status == "unavailable":
            if self.findings or self.model_version is not None or self.model_sha256 is not None:
                raise ValueError("unavailable topology report cannot carry model findings")
        elif self.model_version is None or self.model_sha256 is None:
            raise ValueError("executed subset needs explicit model metadata")
        if len(self.model_dump_json().encode("utf-8")) > 512 * 1024:
            raise ValueError("topology report exceeds byte budget")
        return self


def analyze_topology(
    inputs: TopologyInput, detector: TopologyDetector | None = None
) -> TopologyReport:
    checked = TopologyInput.model_validate_json(inputs.model_dump_json())
    digest = topology_fingerprint(checked)
    limits = (
        "Only an explicitly supplied subset is considered, never the complete real network.",
        "Graph structure, identities, source hashes and declared links "
        "are not independently attested.",
        "Partial parser coverage and unsupported VRF/other constructs are not repaired by a graph.",
        "Embeddings and numeric features require separate provenance and quality evaluation.",
        "No built-in GNN is supplied; graph findings are uncalibrated, "
        "outside risk fusion and not formal verification.",
    )
    if detector is None:
        return TopologyReport(
            topology_id=checked.topology_id,
            input_sha256=digest,
            status="unavailable",
            limitations=limits,
        )
    model_version, model_sha = detector.model_version, detector.model_sha256
    # Validate metadata before calling any explicitly supplied in-process adapter.
    TopologyReport(
        topology_id=checked.topology_id,
        input_sha256=digest,
        status="partial",
        model_version=model_version,
        model_sha256=model_sha,
        limitations=limits,
    )
    produced = detector.detect(checked)
    if (
        not isinstance(produced, tuple)
        or len(produced) > 500
        or any(not isinstance(item, Finding) for item in produced)
    ):
        raise ValueError("invalid topology finding inventory")
    findings = tuple(Finding.model_validate_json(item.model_dump_json()) for item in produced)
    device_ids = {device.device_id for device in checked.devices}
    if len({finding.finding_id for finding in findings}) != len(findings) or any(
        finding.device_id not in device_ids
        or finding.detector != "topology_gnn"
        or finding.model_version != model_version
        or not finding.evidence
        for finding in findings
    ):
        raise ValueError("unbound topology finding")
    return TopologyReport(
        topology_id=checked.topology_id,
        input_sha256=digest,
        status="partial",
        model_version=model_version,
        model_sha256=model_sha,
        findings=findings,
        limitations=limits,
    )
