"""Content-bound draft metadata; no commands, secrets or application capability."""

from __future__ import annotations

import json
from difflib import SequenceMatcher
from hashlib import sha256
from typing import Literal
from uuid import UUID, uuid5

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.domain import Vendor
from app.ingestion.local import validate_configuration_text
from app.parsers import parse_configuration

PROPOSAL_NAMESPACE = UUID("2fbda00a-e6a4-4e89-9666-c961c61b3a18")


class ChangeSpan(BaseModel):
    """Zero-based half-open line ranges on each side, without raw content."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    operation: Literal["insert", "delete", "replace"]
    before_start: int = Field(ge=0)
    before_end: int = Field(ge=0)
    after_start: int = Field(ge=0)
    after_end: int = Field(ge=0)

    @model_validator(mode="after")
    def valid_ranges(self) -> ChangeSpan:
        old, new = self.before_end - self.before_start, self.after_end - self.after_start
        if old < 0 or new < 0 or (old == 0 and new == 0):
            raise ValueError("invalid change span")
        if self.operation != ("insert" if old == 0 else "delete" if new == 0 else "replace"):
            raise ValueError("operation conflicts with change ranges")
        return self


class PatchProposal(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["patch-proposal-0.1.0"] = "patch-proposal-0.1.0"
    proposal_id: UUID
    device_id: UUID
    reference_id: str = Field(min_length=1, max_length=256)
    vendor: Vendor
    platform: str
    before_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    after_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    before_line_count: int = Field(ge=1, le=10_000)
    after_line_count: int = Field(ge=1, le=10_000)
    changes: tuple[ChangeSpan, ...] = Field(min_length=1)
    status: Literal["draft"] = "draft"

    @model_validator(mode="after")
    def valid_draft(self) -> PatchProposal:
        if not self.reference_id.strip() or self.before_sha256 == self.after_sha256:
            raise ValueError("draft requires a reference ID and different input versions")
        old_end = new_end = 0
        for span in self.changes:
            if (
                span.before_start < old_end
                or span.after_start < new_end
                or span.before_start - old_end != span.after_start - new_end
                or span.before_end > self.before_line_count
                or span.after_end > self.after_line_count
            ):
                raise ValueError("change spans are inconsistent or out of bounds")
            old_end, new_end = span.before_end, span.after_end
        if self.before_line_count - old_end != self.after_line_count - new_end:
            raise ValueError("unchanged trailing line counts differ")
        if self.proposal_id != _proposal_id(self.model_dump(mode="json", exclude={"proposal_id"})):
            raise ValueError("proposal identity does not match its content")
        return self


def _proposal_id(payload: dict[str, object]) -> UUID:
    return uuid5(PROPOSAL_NAMESPACE, json.dumps(payload, sort_keys=True, separators=(",", ":")))


def create_patch_proposal(
    before: str, after: str, *, device_id: UUID, reference_id: str
) -> PatchProposal:
    """Describe two caller-supplied snapshots, without generating or applying commands."""
    validate_configuration_text(before)
    validate_configuration_text(after)
    previous = parse_configuration(before, filename="before.cfg")
    candidate = parse_configuration(after, filename="after.cfg")
    if (previous.device.vendor, previous.device.platform, previous.device.hostname) != (
        candidate.device.vendor,
        candidate.device.platform,
        candidate.device.hostname,
    ):
        raise ValueError("configuration identity differs")
    old, new = before.splitlines(keepends=True), after.splitlines(keepends=True)
    spans = [
        ChangeSpan(operation=tag, before_start=i, before_end=j, after_start=k, after_end=end)
        for tag, i, j, k, end in SequenceMatcher(a=old, b=new, autojunk=True).get_opcodes()
        if tag in {"insert", "delete", "replace"}
    ]
    payload: dict[str, object] = {
        "version": "patch-proposal-0.1.0",
        "device_id": str(device_id),
        "reference_id": reference_id,
        "vendor": previous.device.vendor.value,
        "platform": previous.device.platform,
        "before_sha256": sha256(before.encode("utf-8")).hexdigest(),
        "after_sha256": sha256(after.encode("utf-8")).hexdigest(),
        "before_line_count": len(old),
        "after_line_count": len(new),
        "changes": [span.model_dump(mode="json") for span in spans],
        "status": "draft",
    }
    return PatchProposal.model_validate({**payload, "proposal_id": _proposal_id(payload)})


def check_proposal_inputs(
    proposal: PatchProposal, before: str, after: str, *, device_id: UUID
) -> None:
    """Reject stale files, mismatched devices or modified draft metadata."""
    proposal = PatchProposal.model_validate(proposal.model_dump())
    rebuilt = create_patch_proposal(
        before, after, device_id=device_id, reference_id=proposal.reference_id
    )
    if rebuilt != proposal:
        raise ValueError("proposal no longer matches the selected inputs")
