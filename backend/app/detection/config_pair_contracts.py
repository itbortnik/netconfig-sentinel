"""Private two-source worker input, never an HTTP request contract."""

from typing import Self

from pydantic import Field, model_validator

from app.api.contracts import ConfigurationSnapshot, SnapshotBinding
from app.detection.config_model_contracts import require_complete
from app.ingestion.source_retention import StoredOriginalSource
from ml.evaluation.contracts import Digest, Frozen

MAX_PAIR_JOB_BYTES = 32 * 1024 * 1024
MAX_PAIR_RESULT_BYTES = 2 * 1024 * 1024


class ConfigurationPairJob(Frozen):
    registry_root: str = Field(min_length=1, max_length=2048, repr=False)
    model_sha256: Digest
    foundation_source: str | None = Field(default=None, max_length=2048, repr=False)
    key_hex: str = Field(pattern=r"^[0-9a-f]{64}$", repr=False)
    before: ConfigurationSnapshot = Field(repr=False)
    after: ConfigurationSnapshot = Field(repr=False)
    before_source: StoredOriginalSource = Field(repr=False)
    after_source: StoredOriginalSource = Field(repr=False)

    @model_validator(mode="after")
    def bound_pair(self) -> Self:
        require_complete(self.before)
        require_complete(self.after)
        old, new = self.before.canonical.device, self.after.canonical.device
        if (
            self.before.device_id != self.after.device_id
            or (old.vendor, old.platform, old.hostname) != (new.vendor, new.platform, new.hostname)
            or self.before.created_at > self.after.created_at
            or self.before_source.snapshot != SnapshotBinding.from_snapshot(self.before)
            or self.after_source.snapshot != SnapshotBinding.from_snapshot(self.after)
        ):
            raise ValueError("paired worker input identity/source differs")
        return self
