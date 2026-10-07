"""Bounded cosine retrieval of sealed sources, without model imports or risk changes."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Literal, Protocol

import numpy as np
from numpy.typing import NDArray
from pydantic import BaseModel, ConfigDict, Field, StrictInt, model_validator

from app.explanation.knowledge import (
    DocumentChunk,
    KnowledgeCatalog,
    KnowledgeVersion,
    load_knowledge_catalog,
)

MAX_INDEX_BYTES = 8 * 1024 * 1024
MAX_TEXT_BYTES = 16 * 1024
MAX_ROWS = 256
MAX_DIMENSIONS = 1024


class RetrievalUnavailable(Exception):
    """A model, index, source or query is unavailable or outside supported limits."""


class EmbeddingIdentity(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)
    model_id: str = Field(min_length=1, max_length=200)
    revision: str = Field(pattern=r"^[0-9a-f]{40}$")
    files_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    pipeline_version: str = Field(min_length=1, max_length=100)
    dimensions: StrictInt = Field(ge=1, le=MAX_DIMENSIONS)
    runtime_versions: tuple[str, ...] = Field(min_length=1, max_length=8)

    @model_validator(mode="after")
    def printable_metadata(self) -> EmbeddingIdentity:
        if any(
            not value or len(value) > 100 or not value.isprintable()
            for value in self.runtime_versions
        ) or not all(value.isprintable() for value in (self.model_id, self.pipeline_version)):
            raise ValueError("unsupported embedding metadata")
        return self


class DocumentEncoder(Protocol):
    @property
    def identity(self) -> EmbeddingIdentity: ...

    def encode(self, texts: tuple[str, ...]) -> NDArray[np.float32]: ...


class VectorRow(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)
    citation: str = Field(min_length=1, max_length=330)
    content_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    document_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    vector: tuple[float, ...] = Field(min_length=1, max_length=MAX_DIMENSIONS)


class DocumentIndex(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)
    format_version: Literal["sealed-document-vectors-0.1.0"] = "sealed-document-vectors-0.1.0"
    knowledge_version: KnowledgeVersion
    knowledge_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    encoder: EmbeddingIdentity
    rows: tuple[VectorRow, ...] = Field(min_length=1, max_length=MAX_ROWS)

    @model_validator(mode="after")
    def bound_vectors(self) -> DocumentIndex:
        citations = tuple(row.citation for row in self.rows)
        if citations != tuple(sorted(set(citations))) or any(
            len(row.vector) != self.encoder.dimensions for row in self.rows
        ):
            raise ValueError("duplicate, unordered or incompatible index rows")
        matrix = np.asarray([row.vector for row in self.rows], dtype=np.float64)
        if not np.isfinite(matrix).all() or not np.allclose(
            np.linalg.norm(matrix, axis=1), 1.0, atol=2e-5, rtol=0
        ):
            raise ValueError("index requires finite unit vectors")
        return self

    @property
    def sha256(self) -> str:
        return hashlib.sha256(_serialized(self)).hexdigest()


class RetrievedDocument(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)
    document: DocumentChunk
    cosine_similarity: float = Field(ge=-1, le=1)


def _serialized(index: DocumentIndex) -> bytes:
    return json.dumps(
        index.model_dump(mode="json"), ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _unique_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value
    return result


def validate_text(text: str, maximum: int = MAX_TEXT_BYTES) -> None:
    if (
        not isinstance(text, str)
        or not text.strip()
        or any(not char.isprintable() and char not in "\n\t" for char in text)
        or len(text.encode("utf-8")) > maximum
    ):
        raise RetrievalUnavailable("Document retrieval is unavailable.")


def _sealed_catalog(catalog: KnowledgeCatalog) -> None:
    if catalog != load_knowledge_catalog(catalog.version):
        raise RetrievalUnavailable("Document retrieval is unavailable.")


def _bound_catalog(index: DocumentIndex, catalog: KnowledgeCatalog) -> None:
    _sealed_catalog(catalog)
    if index.knowledge_version != catalog.version or index.knowledge_sha256 != catalog.sha256:
        raise RetrievalUnavailable("Document retrieval is unavailable.")
    expected = {
        chunk.citation: (chunk.content_sha256, chunk.document_sha256) for chunk in catalog.chunks
    }
    actual = {row.citation: (row.content_sha256, row.document_sha256) for row in index.rows}
    if expected != actual:
        raise RetrievalUnavailable("Document retrieval is unavailable.")


def _matrix(encoder: DocumentEncoder, texts: tuple[str, ...]) -> NDArray[np.float32]:
    for text in texts:
        validate_text(text)
    result = np.asarray(encoder.encode(texts))
    if (
        result.shape != (len(texts), encoder.identity.dimensions)
        or result.dtype.kind != "f"
        or not np.isfinite(result).all()
        or not np.allclose(np.linalg.norm(result, axis=1), 1.0, atol=2e-5, rtol=0)
    ):
        raise RetrievalUnavailable("Document retrieval is unavailable.")
    return np.asarray(result, dtype=np.float32)


def build_document_index(catalog: KnowledgeCatalog, encoder: DocumentEncoder) -> DocumentIndex:
    _sealed_catalog(catalog)
    chunks = tuple(sorted(catalog.chunks, key=lambda chunk: chunk.citation))
    if not 1 <= len(chunks) <= MAX_ROWS:
        raise RetrievalUnavailable("Document retrieval is unavailable.")
    matrix = _matrix(
        encoder,
        tuple(
            f"{chunk.document_title}\n{chunk.section_title}\n{chunk.content}" for chunk in chunks
        ),
    )
    return DocumentIndex(
        knowledge_version=catalog.version,
        knowledge_sha256=catalog.sha256,
        encoder=encoder.identity,
        rows=tuple(
            VectorRow(
                citation=chunk.citation,
                content_sha256=chunk.content_sha256,
                document_sha256=chunk.document_sha256,
                vector=tuple(float(value) for value in matrix[position]),
            )
            for position, chunk in enumerate(chunks)
        ),
    )


def search_documents(
    index: DocumentIndex,
    catalog: KnowledgeCatalog,
    encoder: DocumentEncoder,
    query: str,
    *,
    limit: int = 4,
    minimum_similarity: float = -1.0,
) -> tuple[RetrievedDocument, ...]:
    """Similarity ranks citations only; it is not confidence, truth or anomaly risk."""
    validate_text(query, 4096)
    if (
        type(limit) is not int
        or not 1 <= limit <= 4
        or not np.isfinite(minimum_similarity)
        or not -1 <= minimum_similarity <= 1
        or index.encoder != encoder.identity
    ):
        raise RetrievalUnavailable("Document retrieval is unavailable.")
    _bound_catalog(index, catalog)
    vector = _matrix(encoder, (query,))[0]
    scores = np.clip(np.asarray([row.vector for row in index.rows]) @ vector, -1.0, 1.0)
    ranked = sorted(
        range(len(index.rows)), key=lambda i: (-float(scores[i]), index.rows[i].citation)
    )
    chunks = {chunk.citation: chunk for chunk in catalog.chunks}
    return tuple(
        RetrievedDocument(
            document=chunks[index.rows[position].citation],
            cosine_similarity=float(scores[position]),
        )
        for position in ranked
        if scores[position] >= minimum_similarity
    )[:limit]


def _no_links(path: Path) -> None:
    if any(item.is_symlink() or item.is_junction() for item in (path, *path.parents)):
        raise RetrievalUnavailable("Document retrieval is unavailable.")


def save_document_index(index: DocumentIndex, root: Path) -> None:
    """Create a new numeric-only artifact; never overwrite an existing directory."""
    try:
        _bound_catalog(index, load_knowledge_catalog(index.knowledge_version))
        _no_links(root)
        raw = _serialized(index)
        if len(raw) > MAX_INDEX_BYTES:
            raise ValueError("index exceeds budget")
        root.mkdir()
        with (root / "index.json").open("xb") as target:
            target.write(raw)
        manifest = json.dumps(
            {"sha256": index.sha256, "bytes": len(raw)}, separators=(",", ":")
        ).encode("ascii")
        with (root / "manifest.json").open("xb") as target:
            target.write(manifest)
    except (OSError, ValueError):
        raise RetrievalUnavailable("Document retrieval is unavailable.") from None


def load_document_index(
    root: Path, catalog: KnowledgeCatalog, *, expected_sha256: str | None = None
) -> DocumentIndex:
    try:
        for path in (root, root / "index.json", root / "manifest.json"):
            _no_links(path)
        if not root.is_dir() or {path.name for path in root.iterdir()} != {
            "index.json",
            "manifest.json",
        }:
            raise ValueError("unexpected index inventory")
        with (root / "manifest.json").open("rb") as source:
            manifest_raw = source.read(513)
        if len(manifest_raw) > 512:
            raise ValueError("manifest exceeds budget")
        manifest = json.loads(manifest_raw, object_pairs_hook=_unique_keys)
        with (root / "index.json").open("rb") as source:
            raw = source.read(MAX_INDEX_BYTES + 1)
        if (
            len(raw) > MAX_INDEX_BYTES
            or set(manifest) != {"bytes", "sha256"}
            or type(manifest["bytes"]) is not int
            or manifest["bytes"] != len(raw)
            or manifest["sha256"] != hashlib.sha256(raw).hexdigest()
            or (expected_sha256 is not None and manifest["sha256"] != expected_sha256)
        ):
            raise ValueError("index checksum mismatch")
        index = DocumentIndex.model_validate(json.loads(raw, object_pairs_hook=_unique_keys))
        if _serialized(index) != raw:
            raise ValueError("noncanonical index")
        _bound_catalog(index, catalog)
        return index
    except (OSError, ValueError, TypeError, RecursionError):
        raise RetrievalUnavailable("Document retrieval is unavailable.") from None
