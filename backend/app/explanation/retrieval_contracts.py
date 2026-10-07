"""Typed, bounded local worker messages, containing public query metadata only."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.explanation.knowledge import KnowledgeVersion
from app.explanation.vector_index import EmbeddingIdentity, RetrievedDocument, validate_text

MAX_WORKER_REQUEST_BYTES = 16 * 1024
MAX_WORKER_RESULT_BYTES = 64 * 1024


class RetrievalJob(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    model_root: str = Field(min_length=1, max_length=2048)
    index_root: str = Field(min_length=1, max_length=2048)
    index_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    knowledge_version: KnowledgeVersion
    query: str = Field(min_length=1, max_length=4096)

    @model_validator(mode="after")
    def bound_query(self) -> "RetrievalJob":
        validate_text(self.query, 4096)
        return self


class RetrievalSelection(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    index_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    knowledge_version: KnowledgeVersion
    knowledge_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    query_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    encoder: EmbeddingIdentity
    matches: tuple[RetrievedDocument, ...] = Field(min_length=1, max_length=4)

    @model_validator(mode="after")
    def unique_matches(self) -> "RetrievalSelection":
        if len({item.document.citation for item in self.matches}) != len(self.matches):
            raise ValueError("duplicate retrieved citation")
        return self


class SemanticMatch(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)
    citation: str = Field(min_length=1, max_length=330)
    content_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    cosine_similarity: float = Field(ge=-1, le=1)


class SemanticRetrievalContext(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    index_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    encoder: EmbeddingIdentity
    query_source: Literal["public_detector_metadata"] = "public_detector_metadata"
    query_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    required_citations: tuple[str, ...] = Field(min_length=1, max_length=4)
    matches: tuple[SemanticMatch, ...] = Field(max_length=4)
