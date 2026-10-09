"""Private bounded worker input. Model paths never come from HTTP callers."""

from pydantic import Field

from app.api.contracts import ConfigurationSnapshot
from app.ingestion.source_retention import StoredOriginalSource
from ml.evaluation.contracts import Digest, Frozen

MAX_JOB_BYTES = 16 * 1024 * 1024
MAX_RESULT_BYTES = 4 * 1024 * 1024


class ConfigurationModelJob(Frozen):
    registry_root: str = Field(min_length=1, max_length=2048, repr=False)
    model_sha256: Digest
    foundation_source: str | None = Field(default=None, max_length=2048, repr=False)
    key_hex: str = Field(pattern=r"^[0-9a-f]{64}$", repr=False)
    snapshot: ConfigurationSnapshot = Field(repr=False)
    source: StoredOriginalSource = Field(repr=False)


def require_complete(snapshot: ConfigurationSnapshot) -> None:
    config = snapshot.canonical
    if config.parser_confidence != 1 or config.parse_warnings or config.unparsed_fragments:
        raise ValueError("experimental configuration inference requires complete parsing")
