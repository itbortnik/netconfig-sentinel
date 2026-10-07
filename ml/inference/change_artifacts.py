"""Exclusive private numeric review artifacts; checksums are not authenticity/proof."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal, Self

from app.patching.artifacts import MAX_ARTIFACT_BYTES, _unique_keys
from pydantic import BaseModel, ConfigDict, model_validator

from ml.evaluation.contracts import Digest
from ml.evaluation.metrics import canonical_hash
from ml.inference.change_contracts import MLChangeReview


def safe_path(path: Path) -> None:
    selected = path.absolute()
    if any(item.is_symlink() or item.is_junction() for item in (selected, *selected.parents)):
        raise ValueError("linked inference path is not supported")


class Envelope(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["ml-change-artifact-0.1.0"] = "ml-change-artifact-0.1.0"
    payload: MLChangeReview
    sha256: Digest

    @model_validator(mode="after")
    def checksum(self) -> Self:
        if self.sha256 != canonical_hash(self.payload.model_dump(mode="json")):
            raise ValueError("ML review checksum differs")
        return self


def save_ml_change_review(review: MLChangeReview, path: Path) -> None:
    """Validate structure before a new file; fresh inference is the caller's job."""
    review = MLChangeReview.model_validate(review.model_dump())
    envelope = Envelope(payload=review, sha256=canonical_hash(review.model_dump(mode="json")))
    encoded = (envelope.model_dump_json(indent=2) + "\n").encode("utf-8")
    if path.suffix.lower() != ".json" or len(encoded) > MAX_ARTIFACT_BYTES:
        raise ValueError("ML review output must be a bounded JSON file")
    safe_path(path)
    with path.open("xb") as stream:
        stream.write(encoded)


def load_ml_change_review(path: Path) -> MLChangeReview:
    safe_path(path)
    if (
        path.suffix.lower() != ".json"
        or not path.is_file()
        or path.stat().st_size > MAX_ARTIFACT_BYTES
    ):
        raise ValueError("ML review input must be a bounded JSON file")
    with path.open("rb") as stream:
        encoded = stream.read(MAX_ARTIFACT_BYTES + 1)
    if len(encoded) > MAX_ARTIFACT_BYTES:
        raise ValueError("ML review grew past its budget")
    try:
        parsed = json.loads(encoded.decode("utf-8"), object_pairs_hook=_unique_keys)
    except RecursionError:
        raise ValueError("ML review nesting exceeds budget") from None
    return Envelope.model_validate(parsed).payload
