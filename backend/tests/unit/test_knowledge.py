"""Reviewed sources resolve exactly; arbitrary documents and ambiguous chunks fail closed."""

from pathlib import Path
from uuid import UUID

import pytest
from app.detection.policy_engine import evaluate_policies
from app.domain import Finding
from app.explanation.knowledge import (
    DOCUMENT_IDS,
    MAX_CHUNK_BYTES,
    MAX_DOCUMENT_BYTES,
    DocumentChunk,
    KnowledgeUnavailable,
    ingest_document,
    load_knowledge_catalog,
    text_sha256,
)
from app.parsers import parse_configuration
from app.policies import POLICY_CATALOG_VERSION, POLICY_RULES


def finding(**updates) -> Finding:
    config = parse_configuration("hostname edge\n", filename="test.cfg")
    value = evaluate_policies(config, device_id=UUID(int=1))[0].model_dump()
    return Finding.model_validate(value | updates)


def test_catalog_all_policy_references_and_content_hashes() -> None:
    catalog = load_knowledge_catalog()
    assert catalog == load_knowledge_catalog()
    assert len(catalog.chunks) == 31
    assert {chunk.document_id for chunk in catalog.chunks} == set(DOCUMENT_IDS)
    for rule in POLICY_RULES:
        selected = catalog.retrieve(
            finding(category=rule.rule_id, model_version=POLICY_CATALOG_VERSION)
        )
        assert tuple(chunk.citation for chunk in selected) == rule.references
        for chunk in selected:
            assert chunk.content_sha256 == text_sha256(chunk.content)
            assert chunk.authority == "internal_project_document"


@pytest.mark.parametrize(
    "detector,version,count",
    [
        ("expected_configuration", "expected-config-0.1.0", 1),
        ("peer_baseline", "peer-baseline-0.1.0", 2),
        ("isolation_forest", "isolation-forest-0.1.0", 2),
    ],
)
def test_non_policy_sources_use_explicit_versioned_selection(detector, version, count) -> None:
    catalog = load_knowledge_catalog()
    assert len(catalog.retrieve(finding(detector=detector, model_version=version))) == count
    with pytest.raises(KnowledgeUnavailable):
        catalog.retrieve(finding(detector=detector, model_version="future-version"))


@pytest.mark.parametrize(
    "updates",
    [
        {"detector": "unsupported"},
        {"model_version": "future-catalog"},
        {"category": "invented.policy"},
    ],
)
def test_unknown_or_changed_catalog_is_not_guessed(updates) -> None:
    with pytest.raises(KnowledgeUnavailable):
        load_knowledge_catalog().retrieve(finding(**updates))


@pytest.mark.parametrize(
    "raw",
    [
        b"not a document",
        b"\xff",
        b"# Title\n## Empty\n",
        b"# Title\n## One\ntext\n## One\nother",
        b"# Title\n## One!\ntext\n## One\nother",
        b"# Title\n## One\nsecret\x00value",
        b"# Title\n## One\n```\nunclosed",
        b"# First\n# Second\n## One\ntext",
        b"x" * (MAX_DOCUMENT_BYTES + 1),
        ("# Title\n## One\n" + "я" * (MAX_CHUNK_BYTES // 2 + 1)).encode(),
    ],
    ids=[
        "no-title",
        "non-utf8",
        "empty",
        "duplicate",
        "anchor-collision",
        "control",
        "unclosed-fence",
        "two-titles",
        "oversized-document",
        "oversized-unicode-chunk",
    ],
)
def test_invalid_documents_are_rejected_without_reflecting_contents(raw) -> None:
    with pytest.raises(KnowledgeUnavailable, match=r"^Reviewed knowledge is unavailable\.$"):
        ingest_document(DOCUMENT_IDS[0], raw)


def test_fenced_headings_are_data_and_raw_document_hash_keeps_line_endings() -> None:
    raw = b"# Title\r\n## One\r\n~~~text\r\n## Not a section\r\n~~~\r\ntext\r\n"
    chunks = ingest_document(DOCUMENT_IDS[0], raw)
    assert len(chunks) == 1
    assert "## Not a section" in chunks[0].content
    normalized = ingest_document(DOCUMENT_IDS[0], raw.replace(b"\r\n", b"\n"))
    assert chunks[0].content_sha256 == normalized[0].content_sha256
    assert chunks[0].document_sha256 != normalized[0].document_sha256


def test_arbitrary_paths_urls_and_modified_chunk_contents_are_rejected() -> None:
    for document_id in ("../PROJECT_BRIEF.md", "https://outside.invalid/doc", "user.cfg"):
        with pytest.raises(KnowledgeUnavailable):
            ingest_document(document_id, b"# Title\n## One\ntext")
    chunk = load_knowledge_catalog().chunks[0].model_dump()
    with pytest.raises(ValueError):
        DocumentChunk.model_validate(chunk | {"content": "changed contents"})
    with pytest.raises(ValueError):
        DocumentChunk.model_validate(chunk | {"citation": "fabricated#section"})


def test_packaged_sources_are_self_contained_and_never_fall_back_when_missing(
    tmp_path, monkeypatch
):
    import app.explanation.knowledge as knowledge

    checkout = load_knowledge_catalog()
    project = Path(__file__).resolve().parents[3]
    package = tmp_path / "app"
    for document_id in DOCUMENT_IDS:
        target = package / "knowledge" / document_id
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((project / document_id).read_bytes())
    monkeypatch.setattr(knowledge, "__file__", str(package / "explanation" / "knowledge.py"))
    assert load_knowledge_catalog() == checkout
    (package / "knowledge" / DOCUMENT_IDS[0]).unlink()
    with pytest.raises(KnowledgeUnavailable):
        load_knowledge_catalog()
