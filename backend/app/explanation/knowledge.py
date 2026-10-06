"""Bounded ingestion and explicit-reference retrieval of reviewed project documents."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Literal, cast

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.domain import Finding
from app.policies import POLICY_CATALOGS

type KnowledgeVersion = Literal["project-knowledge-0.1.0", "project-knowledge-0.2.0"]
KNOWLEDGE_VERSION: KnowledgeVersion = "project-knowledge-0.2.0"
ARCHIVE_MANIFESTS = MappingProxyType(
    {
        "project-knowledge-0.1.0": (
            "454eab77e7233bd69e570b159dc96d9639e176b633cfbfb2a80d0cc531f3ef74"
        ),
        "project-knowledge-0.2.0": (
            "73434e471171d10016e6cb7e43c4c970128e9b086667e8634e60498b76785eb7"
        ),
    }
)
RELEASE_BY_DETECTOR_VERSION: MappingProxyType[str, KnowledgeVersion] = MappingProxyType(
    {
        "policy-rules-0.6.0": "project-knowledge-0.1.0",
        "policy-rules-0.7.0": "project-knowledge-0.2.0",
        "expected-config-0.1.0": "project-knowledge-0.1.0",
        "peer-baseline-0.1.0": "project-knowledge-0.1.0",
        "isolation-forest-0.1.0": "project-knowledge-0.1.0",
    }
)
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
    version: KnowledgeVersion = KNOWLEDGE_VERSION

    def retrieve(self, finding: Finding) -> tuple[DocumentChunk, ...]:
        if knowledge_version_for_finding(finding) != self.version:
            raise KnowledgeUnavailable("Reviewed knowledge is unavailable.")
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


def knowledge_version_for_finding(finding: Finding) -> KnowledgeVersion:
    """Pin supported detector versions to released sources, never to a current file."""
    if finding.detector == "policy_engine":
        if finding.model_version == "policy-rules-0.6.0":
            return "project-knowledge-0.1.0"
        if finding.model_version == "policy-rules-0.7.0":
            return "project-knowledge-0.2.0"
    elif (finding.detector, finding.model_version) in {
        ("expected_configuration", "expected-config-0.1.0"),
        ("peer_baseline", "peer-baseline-0.1.0"),
        ("isolation_forest", "isolation-forest-0.1.0"),
    }:
        return "project-knowledge-0.1.0"
    raise KnowledgeUnavailable("Reviewed knowledge is unavailable.")


def _archive_file(root: Path, relative: str, limit: int) -> bytes:
    path = root / relative
    for candidate in (root, *path.parents[: len(Path(relative).parts) - 1], path):
        if candidate.is_symlink() or candidate.is_junction():
            raise KnowledgeUnavailable("Reviewed knowledge is unavailable.")
    if not path.is_file() or not path.resolve().is_relative_to(root.resolve()):
        raise KnowledgeUnavailable("Reviewed knowledge is unavailable.")
    with path.open("rb") as source:
        raw = source.read(limit + 1)
    if len(raw) > limit:
        raise KnowledgeUnavailable("Reviewed knowledge is unavailable.")
    return raw


def load_knowledge_catalog(version: str = KNOWLEDGE_VERSION) -> KnowledgeCatalog:
    """Load one sealed release from the package; no current-document fallback."""
    if version not in ARCHIVE_MANIFESTS:
        raise KnowledgeUnavailable("Reviewed knowledge is unavailable.")
    app_root = Path(__file__).resolve().parents[1]
    root = app_root / "knowledge" / "versions" / version
    chunks: list[DocumentChunk] = []
    manifest: list[tuple[str, str]] = []
    try:
        if (
            any(
                path.is_symlink() or path.is_junction()
                for path in (app_root / "knowledge", root.parent, root)
            )
            or not root.is_dir()
        ):
            raise KnowledgeUnavailable("Reviewed knowledge is unavailable.")
        expected_inventory = {
            root: {"manifest.json", "docs"},
            root / "docs": {
                "policies",
                "expected-configuration.md",
                "baseline.md",
                "statistical-baseline.md",
            },
            root / "docs" / "policies": {
                "management-plane.md",
                "observability.md",
                "access-control.md",
                "routing.md",
                "layer2.md",
            },
        }
        for directory, names in expected_inventory.items():
            if (
                directory.is_symlink()
                or directory.is_junction()
                or ({item.name for item in directory.iterdir()} != names)
            ):
                raise KnowledgeUnavailable("Reviewed knowledge is unavailable.")
        raw_manifest = _archive_file(root, "manifest.json", 4096)
        if hashlib.sha256(raw_manifest).hexdigest() != ARCHIVE_MANIFESTS[version]:
            raise KnowledgeUnavailable("Reviewed knowledge is unavailable.")
        release = json.loads(raw_manifest)
        if (
            set(release) != {"version", "source_commit", "authority", "documents"}
            or release["version"] != version
            or release["authority"] != "internal_project_document"
            or not re.fullmatch(r"[0-9a-f]{40}", release["source_commit"])
            or set(release["documents"]) != set(DOCUMENT_IDS)
        ):
            raise KnowledgeUnavailable("Reviewed knowledge is unavailable.")
        for document_id in DOCUMENT_IDS:
            raw = _archive_file(root, document_id, MAX_DOCUMENT_BYTES)
            if hashlib.sha256(raw).hexdigest() != release["documents"][document_id]:
                raise KnowledgeUnavailable("Reviewed knowledge is unavailable.")
            ingested = ingest_document(document_id, raw)
            chunks.extend(ingested)
            manifest.append((document_id, ingested[0].document_sha256))
    except (OSError, ValueError, TypeError, RecursionError):
        raise KnowledgeUnavailable("Reviewed knowledge is unavailable.") from None
    digest = text_sha256(
        json.dumps([version, sorted(manifest)], ensure_ascii=False, separators=(",", ":"))
    )
    return KnowledgeCatalog(tuple(chunks), digest, cast(KnowledgeVersion, version))
