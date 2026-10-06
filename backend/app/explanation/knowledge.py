"""Bounded ingestion and explicit-reference retrieval of reviewed project documents."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.domain import Finding
from app.policies import POLICY_CATALOGS

KNOWLEDGE_VERSION = "project-knowledge-0.1.0"
DOCUMENT_IDS = (
    "docs/policies/management-plane.md",
    "docs/policies/observability.md",
    "docs/policies/access-control.md",
    "docs/policies/routing.md",
    "docs/policies/layer2.md",
    "docs/expected-configuration.md",
    "docs/baseline.md",
    "docs/statistical-baseline.md",
)
MAX_DOCUMENT_BYTES = 64 * 1024
MAX_CHUNK_BYTES = 8 * 1024


class KnowledgeUnavailable(Exception):
    """A reviewed source is missing, ambiguous, incompatible or exceeds its budget."""


def text_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class DocumentChunk(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    document_id: str = Field(min_length=1, max_length=128)
    document_title: str = Field(min_length=1, max_length=200)
    section: str = Field(min_length=1, max_length=200)
    section_title: str = Field(min_length=1, max_length=200)
    citation: str = Field(min_length=1, max_length=330)
    document_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    content_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    content: str = Field(min_length=1, max_length=MAX_CHUNK_BYTES)
    authority: Literal["internal_project_document"] = "internal_project_document"

    @model_validator(mode="after")
    def bound_content(self) -> DocumentChunk:
        if self.document_id not in DOCUMENT_IDS or self.citation != (
            f"{self.document_id}#{self.section}"
        ):
            raise ValueError("unknown document or inconsistent citation")
        if len(self.content.encode("utf-8")) > MAX_CHUNK_BYTES or (
            text_sha256(self.content) != self.content_sha256
        ):
            raise ValueError("document chunk exceeds budget or differs from its hash")
        if self.section != heading_anchor(self.section_title) or any(
            not char.isprintable() and char not in "\n\t"
            for value in (self.document_title, self.section_title, self.content)
            for char in value
        ):
            raise ValueError("unsupported section metadata or text")
        return self


def heading_anchor(heading: str) -> str:
    """Only the simple, unique headings in the bundled catalog are supported."""
    return re.sub(r"\s", "-", re.sub(r"[^\w\s-]", "", heading.lower()))


def ingest_document(document_id: str, raw: bytes) -> tuple[DocumentChunk, ...]:
    """Ingest an explicitly reviewed UTF-8 Markdown source, never a URL or user path."""
    try:
        if document_id not in DOCUMENT_IDS or len(raw) > MAX_DOCUMENT_BYTES:
            raise ValueError("unsupported document")
        text = raw.decode("utf-8").replace("\r\n", "\n")
        if any(not char.isprintable() and char not in "\n\t" for char in text):
            raise ValueError("unsupported source characters")
        title = ""
        section_title = ""
        section_lines: list[str] = []
        sections: list[tuple[str, str]] = []
        fence = ""
        for line in text.splitlines():
            stripped = line.lstrip()
            if stripped.startswith(("```", "~~~")):
                marker = stripped[:3]
                fence = "" if fence == marker else (fence or marker)
            if not fence and line.startswith("# "):
                if title:
                    raise ValueError("multiple document titles")
                title = line[2:].strip()
            if not fence and line.startswith("## "):
                if section_title:
                    sections.append((section_title, "\n".join(section_lines).strip()))
                section_title = line[3:].strip()
                section_lines = []
            elif section_title:
                section_lines.append(line)
        if fence or not title:
            raise ValueError("incomplete Markdown source")
        if section_title:
            sections.append((section_title, "\n".join(section_lines).strip()))
        chunks = tuple(
            DocumentChunk(
                document_id=document_id,
                document_title=title,
                section=heading_anchor(heading),
                section_title=heading,
                citation=f"{document_id}#{heading_anchor(heading)}",
                document_sha256=hashlib.sha256(raw).hexdigest(),
                content_sha256=text_sha256(content),
                content=content,
            )
            for heading, content in sections
        )
        if (
            not chunks
            or len(chunks) > 32
            or (len({chunk.citation for chunk in chunks}) != len(chunks))
        ):
            raise ValueError("empty or ambiguous source")
        return chunks
    except (ValueError, RecursionError):
        raise KnowledgeUnavailable("Reviewed knowledge is unavailable.") from None


@dataclass(frozen=True)
class KnowledgeCatalog:
    chunks: tuple[DocumentChunk, ...]
    sha256: str

    def retrieve(self, finding: Finding) -> tuple[DocumentChunk, ...]:
        if finding.detector == "policy_engine":
            catalog = POLICY_CATALOGS.get(finding.model_version, ())
            rule = next((item for item in catalog if item.rule_id == finding.category), None)
            if rule is None:
                raise KnowledgeUnavailable("Reviewed knowledge is unavailable.")
            citations = rule.references
        else:
            references = {
                "expected_configuration": (
                    "expected-config-0.1.0",
                    ("docs/expected-configuration.md#доказательства-и-ограничения",),
                ),
                "peer_baseline": (
                    "peer-baseline-0.1.0",
                    ("docs/baseline.md#exact-consensus-features", "docs/baseline.md#limitations"),
                ),
                "isolation_forest": (
                    "isolation-forest-0.1.0",
                    (
                        "docs/statistical-baseline.md#finding-interpretation",
                        "docs/statistical-baseline.md#current-limitations",
                    ),
                ),
            }
            selection = references.get(finding.detector)
            if selection is None or finding.model_version != selection[0]:
                raise KnowledgeUnavailable("Reviewed knowledge is unavailable.")
            citations = selection[1]
        indexed = {chunk.citation: chunk for chunk in self.chunks}
        try:
            selected = tuple(indexed[citation] for citation in citations)
        except KeyError:
            raise KnowledgeUnavailable("Reviewed knowledge is unavailable.") from None
        if not selected or len(selected) > 4:
            raise KnowledgeUnavailable("Reviewed knowledge is unavailable.")
        return selected


def load_knowledge_catalog() -> KnowledgeCatalog:
    """Use wheel-bundled sources, or this checkout's allowlisted docs in development."""
    app_root = Path(__file__).resolve().parents[1]
    packaged = app_root / "knowledge"
    root = packaged if packaged.is_dir() else app_root.parent.parent
    if root != packaged and not (root / "pyproject.toml").is_file():
        raise KnowledgeUnavailable("Reviewed knowledge is unavailable.")
    chunks: list[DocumentChunk] = []
    manifest: list[tuple[str, str]] = []
    try:
        for document_id in DOCUMENT_IDS:
            path = root / document_id
            if (
                path.is_symlink()
                or not path.is_file()
                or (not path.resolve().is_relative_to(root.resolve()))
            ):
                raise KnowledgeUnavailable("Reviewed knowledge is unavailable.")
            with path.open("rb") as source:
                raw = source.read(MAX_DOCUMENT_BYTES + 1)
            ingested = ingest_document(document_id, raw)
            chunks.extend(ingested)
            manifest.append((document_id, ingested[0].document_sha256))
    except OSError:
        raise KnowledgeUnavailable("Reviewed knowledge is unavailable.") from None
    digest = text_sha256(
        json.dumps([KNOWLEDGE_VERSION, sorted(manifest)], ensure_ascii=False, separators=(",", ":"))
    )
    return KnowledgeCatalog(tuple(chunks), digest)
