"""Exclusive local review storage and fresh checks against caller-selected files."""

from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.patching.review import PatchReview, review_patch_proposal

MAX_ARTIFACT_BYTES = 16 * 1024 * 1024


def _checksum(review: PatchReview) -> str:
    payload = json.dumps(review.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    return sha256(payload.encode("utf-8")).hexdigest()


class _Envelope(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["patch-artifact-0.1.0"] = "patch-artifact-0.1.0"
    payload: PatchReview
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def verify_checksum(self) -> _Envelope:
        if self.sha256 != _checksum(self.payload):
            raise ValueError("artifact checksum mismatch")
        return self


def save_patch_review(review: PatchReview, path: Path) -> None:
    """Write one new JSON file; never overwrite an existing path or create parents."""
    if path.suffix.lower() != ".json":
        raise ValueError("review artifact must be a JSON file")
    review = PatchReview.model_validate(review.model_dump())
    envelope = _Envelope(payload=review, sha256=_checksum(review))
    encoded = (envelope.model_dump_json(indent=2) + "\n").encode("utf-8")
    if len(encoded) > MAX_ARTIFACT_BYTES:
        raise ValueError("review artifact exceeds size limit")
    with path.open("xb") as stream:
        stream.write(encoded)


def _unique_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def load_patch_review(path: Path) -> PatchReview:
    if path.suffix.lower() != ".json" or not path.is_file():
        raise ValueError("review artifact must be a JSON file")
    with path.open("rb") as stream:
        data = stream.read(MAX_ARTIFACT_BYTES + 1)
    if len(data) > MAX_ARTIFACT_BYTES:
        raise ValueError("review artifact exceeds size limit")
    try:
        parsed = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_keys)
    except RecursionError as error:
        raise ValueError("review artifact nesting exceeds limit") from error
    return _Envelope.model_validate(parsed).payload


def recheck_patch_review(path: Path, before: str, after: str, *, device_id: UUID) -> PatchReview:
    """Recompute evidence; neither a checksum nor stored metadata is approval authority."""
    saved = load_patch_review(path)
    fresh = review_patch_proposal(saved.proposal, before, after, device_id=device_id)
    if fresh != saved:
        raise ValueError("saved review is stale; create a new review with current checks")
    return fresh
