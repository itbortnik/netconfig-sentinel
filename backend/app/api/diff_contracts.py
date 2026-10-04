"""Read-only normalized-object comparison, not a raw-file or network verification."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator

from app.api.contracts import SnapshotBinding
from app.domain import SourceLocation, Vendor

DiffSection = Literal[
    "device",
    "management",
    "local_users",
    "interfaces",
    "vlans",
    "acls",
    "prefix_lists",
    "static_routes",
    "bgp",
    "bgp_neighbors",
    "ospf",
]


class DiffSnapshot(SnapshotBinding):
    vendor: Vendor
    platform: str
    hostname: str | None
    projection_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    parser_confidence: float = Field(ge=0, le=1)
    warning_count: int = Field(ge=0)
    unparsed_count: int = Field(ge=0)

    @property
    def complete(self) -> bool:
        return self.parser_confidence == 1 and self.warning_count == self.unparsed_count == 0


class ObjectChange(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)
    section: DiffSection
    object_key: tuple[str, ...] = Field(min_length=1, max_length=3)
    kind: Literal["added", "removed", "modified"]
    before_value: dict[str, JsonValue] | None
    after_value: dict[str, JsonValue] | None
    before_locations: tuple[SourceLocation, ...] = ()
    after_locations: tuple[SourceLocation, ...] = ()

    @model_validator(mode="after")
    def consistent_change(self) -> "ObjectChange":
        expected = (
            "added"
            if self.before_value is None
            else ("removed" if self.after_value is None else "modified")
        )
        if self.kind != expected or self.before_value == self.after_value:
            raise ValueError("inconsistent object change")
        if (self.before_value is None and self.before_locations) or (
            self.after_value is None and self.after_locations
        ):
            raise ValueError("absent objects cannot have source locations")
        return self


class SnapshotDiff(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["snapshot-diff-0.1.0"] = "snapshot-diff-0.1.0"
    representation: Literal["normalized_objects"] = "normalized_objects"
    before: DiffSnapshot
    after: DiffSnapshot
    coverage: Literal["supported_complete", "partial"]
    source_changed: bool
    added_count: int = Field(ge=0)
    removed_count: int = Field(ge=0)
    modified_count: int = Field(ge=0)
    changes: tuple[ObjectChange, ...] = Field(max_length=500)
    limitations: tuple[str, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def bound_result(self) -> "SnapshotDiff":
        if (
            self.before.configuration_id == self.after.configuration_id
            or (
                self.before.device_id,
                self.before.vendor,
                self.before.platform,
                self.before.hostname,
            )
            != (self.after.device_id, self.after.vendor, self.after.platform, self.after.hostname)
            or self.before.created_at > self.after.created_at
        ):
            raise ValueError("incompatible diff snapshots")
        coverage = (
            "supported_complete" if self.before.complete and self.after.complete else "partial"
        )
        if self.coverage != coverage or self.source_changed != (
            self.before.source_sha256 != self.after.source_sha256
        ):
            raise ValueError("inconsistent diff coverage")
        counts = tuple(
            sum(item.kind == kind for item in self.changes)
            for kind in ("added", "removed", "modified")
        )
        if counts != (self.added_count, self.removed_count, self.modified_count):
            raise ValueError("inconsistent diff counts")
        keys = [(item.section, item.object_key) for item in self.changes]
        if keys != sorted(set(keys)):
            raise ValueError("diff changes must be unique and ordered")
        if (self.before.projection_sha256 == self.after.projection_sha256) != (not self.changes):
            raise ValueError("inconsistent projection hash")
        return self
