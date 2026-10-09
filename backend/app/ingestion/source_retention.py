"""Private original UTF-8 text bound to one saved snapshot, never IR reconstruction."""

from __future__ import annotations

import json
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.api.contracts import ConfigurationSnapshot, SnapshotBinding
from app.explanation.knowledge import text_sha256
from app.ingestion.local import MAX_INPUT_BYTES, validate_configuration_text
from app.parsers import parse_configuration

MAX_SOURCE_PAYLOAD_BYTES = 8 * 1024 * 1024
MAX_SOURCE_CIPHERTEXT_BYTES = 16 * 1024 * 1024


def canonical_fingerprint(snapshot: ConfigurationSnapshot) -> str:
    return text_sha256(
        json.dumps(
            snapshot.canonical.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    )


class StoredOriginalSource(BaseModel):
    """Confidential bytes-in-text-form. Never return this object from an HTTP route."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["configuration-source-0.1.0"] = "configuration-source-0.1.0"
    snapshot: SnapshotBinding
    canonical_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    filename: str = Field(min_length=1, max_length=255, repr=False)
    content: str = Field(min_length=1, max_length=MAX_INPUT_BYTES, repr=False, strict=True)

    @model_validator(mode="after")
    def exact_original(self) -> Self:
        validate_configuration_text(self.content)
        if text_sha256(self.content) != self.snapshot.source_sha256:
            raise ValueError("original source binding differs")
        return self


def prepare_original_source(snapshot: ConfigurationSnapshot, content: str) -> StoredOriginalSource:
    """Reparse the supplied exact original; never manufacture text from normalized IR."""
    snapshot = ConfigurationSnapshot.model_validate_json(snapshot.model_dump_json())
    validate_configuration_text(content)
    parsed = parse_configuration(
        content,
        filename=snapshot.canonical.source.filename,
        collected_at=snapshot.canonical.source.collected_at,
    )
    # These three labels are declared inventory metadata, not source statements.
    parsed = parsed.model_copy(
        update={
            "device": parsed.device.model_copy(
                update={
                    name: getattr(snapshot.canonical.device, name)
                    for name in ("role", "site_class", "service_profile")
                }
            )
        }
    )
    if parsed != snapshot.canonical:
        raise ValueError("original text does not reproduce the selected snapshot")
    result = StoredOriginalSource(
        snapshot=SnapshotBinding.from_snapshot(snapshot),
        canonical_sha256=canonical_fingerprint(snapshot),
        filename=snapshot.canonical.source.filename,
        content=content,
    )
    if len(result.model_dump_json().encode()) > MAX_SOURCE_PAYLOAD_BYTES:
        raise ValueError("original source payload exceeds budget")
    return result


def validate_original_binding(
    record: StoredOriginalSource, snapshot: ConfigurationSnapshot
) -> None:
    if record.snapshot != SnapshotBinding.from_snapshot(snapshot) or (
        record.filename != snapshot.canonical.source.filename
        or record.canonical_sha256 != canonical_fingerprint(snapshot)
    ):
        raise ValueError("saved original source metadata differs")
