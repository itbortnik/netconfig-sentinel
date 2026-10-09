"""Private bounded parent/worker envelope, not a public HTTP model selector."""

from pydantic import BaseModel, ConfigDict, Field

from app.api.model_patch_contracts import Digest
from app.patching.review import PatchReview

MAX_JOB_BYTES = 8 * 1024 * 1024
MAX_RESULT_BYTES = 4 * 1024 * 1024


class PatchMLJob(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    registry_root: str = Field(min_length=1, max_length=2048, repr=False)
    model_sha256: Digest
    foundation_source: str | None = Field(default=None, max_length=2048, repr=False)
    key_hex: str = Field(pattern=r"^[0-9a-f]{64}$", repr=False)
    local_review: PatchReview = Field(repr=False)
    before: str = Field(max_length=2 * 1024 * 1024, repr=False)
    after: str = Field(max_length=2 * 1024 * 1024, repr=False)
