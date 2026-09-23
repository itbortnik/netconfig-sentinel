"""Bind scoped network evidence to a reviewed proposal without status promotion."""

from __future__ import annotations

import json
from hashlib import sha256
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.patching.review import PatchReview, review_patch_proposal
from app.verification.batfish import BatfishResult, ReachabilityScope, check_with_batfish
from app.verification.snapshots import NetworkSnapshot, validate_snapshot_pair


class SnapshotMember(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    device_id: UUID
    hostname: str = Field(pattern=r"^[A-Za-z0-9_-]{1,128}$")
    platform: Literal["ios", "junos"]
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


def _digest(members: tuple[SnapshotMember, ...]) -> str:
    payload = [(str(item.device_id), item.hostname, item.platform, item.sha256) for item in members]
    return sha256(json.dumps(payload, separators=(",", ":")).encode("utf-8")).hexdigest()


class NetworkPatchReview(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["network-patch-review-0.1.0"] = "network-patch-review-0.1.0"
    local_review: PatchReview
    before_members: tuple[SnapshotMember, ...] = Field(min_length=1, max_length=32)
    after_members: tuple[SnapshotMember, ...] = Field(min_length=1, max_length=32)
    network_result: BatfishResult
    status: Literal["needs_review"] = "needs_review"
    requires_human_review: Literal[True] = True
    limitations: tuple[str, ...] = (
        "The network query covers only its explicit scope, not all patch acceptance criteria.",
        "Local preflight is historical and retains its original not_run formal status.",
        "The experimental adapter still requires live qualification; no promotion is allowed.",
        "Serialized evidence is not signed and is not approval authority.",
    )

    @model_validator(mode="after")
    def bound_snapshots(self) -> NetworkPatchReview:
        for members in (self.before_members, self.after_members):
            ids = [str(item.device_id) for item in members]
            hosts = [item.hostname.casefold() for item in members]
            if ids != sorted(set(ids)) or len(hosts) != len(set(hosts)):
                raise ValueError("network members must be unique and sorted by device ID")
        old, new = self.before_members, self.after_members
        if [(item.device_id, item.hostname, item.platform) for item in old] != [
            (item.device_id, item.hostname, item.platform) for item in new
        ]:
            raise ValueError("network identity changed")
        if (_digest(old), _digest(new)) != (
            self.network_result.before_sha256,
            self.network_result.after_sha256,
        ):
            raise ValueError("network result does not match member fingerprints")
        proposal = self.local_review.proposal
        target = next((item for item in old if item.device_id == proposal.device_id), None)
        if target is None or target.platform != proposal.platform:
            raise ValueError("proposal device is absent or incompatible")
        if self.network_result.scope.start_node not in {item.hostname for item in old}:
            raise ValueError("network scope starts outside the supplied snapshots")
        for previous, current in zip(old, new, strict=True):
            if previous.device_id == proposal.device_id:
                if (previous.sha256, current.sha256) != (
                    proposal.before_sha256,
                    proposal.after_sha256,
                ):
                    raise ValueError("network target differs from the reviewed proposal")
            elif previous.sha256 != current.sha256:
                raise ValueError("network review permits changes only on the proposal device")
        return self


def _members(snapshot: NetworkSnapshot) -> tuple[SnapshotMember, ...]:
    return tuple(
        SnapshotMember.model_validate(
            {
                "device_id": item.device_id,
                "hostname": item.hostname,
                "platform": item.platform,
                "sha256": item.digest,
            }
        )
        for item in snapshot.configs
    )


def review_patch_network(
    local_review: PatchReview,
    before: NetworkSnapshot,
    after: NetworkSnapshot,
    scope: ReachabilityScope,
    *,
    allow_local_upload: bool = False,
    timeout_seconds: int = 60,
) -> NetworkPatchReview:
    local_review = PatchReview.model_validate(local_review.model_dump())
    validate_snapshot_pair(before, after)
    members_before, members_after = _members(before), _members(after)
    # Bind and reject stale or unrelated snapshots before any SDK upload can occur.
    pending = BatfishResult(
        before_sha256=before.digest,
        after_sha256=after.digest,
        scope=scope,
        status="unavailable",
        reason="upload_not_authorized",
    )
    NetworkPatchReview(
        local_review=local_review,
        before_members=members_before,
        after_members=members_after,
        network_result=pending,
    )
    device_id = local_review.proposal.device_id
    old_text = next(item.text for item in before.configs if item.device_id == device_id)
    new_text = next(item.text for item in after.configs if item.device_id == device_id)
    fresh = review_patch_proposal(local_review.proposal, old_text, new_text, device_id=device_id)
    if fresh != local_review:
        raise ValueError("local review is stale or modified; recreate it before network checking")
    result = check_with_batfish(
        before, after, scope, allow_local_upload=allow_local_upload, timeout_seconds=timeout_seconds
    )
    return NetworkPatchReview(
        local_review=fresh,
        before_members=members_before,
        after_members=members_after,
        network_result=result,
    )
