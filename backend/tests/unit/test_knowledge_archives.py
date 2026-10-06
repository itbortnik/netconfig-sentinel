"""Sealed historical releases cannot be replaced by current or newly hashed documents."""

import hashlib
import json
from shutil import copytree
from uuid import UUID

import pytest
from app.api.explanation_contracts import ExplanationBundle
from app.detection.policy_engine import evaluate_policies
from app.explanation.knowledge import (
    ARCHIVE_MANIFESTS,
    DOCUMENT_IDS,
    KNOWLEDGE_VERSION,
    KnowledgeUnavailable,
    knowledge_version_for_finding,
    load_knowledge_catalog,
)
from app.explanation.local import explain_finding
from app.parsers import parse_configuration

OLD = "project-knowledge-0.1.0"
NEW = "project-knowledge-0.2.0"


def old_finding():
    config = parse_configuration("hostname test\n", filename="synthetic.cfg")
    finding = evaluate_policies(
        config, device_id=UUID(int=1), catalog_version="policy-rules-0.6.0"
    )[0]
    return finding, config


def test_releases_have_distinct_bound_hashes_and_never_guess_from_current_catalog():
    old, current = load_knowledge_catalog(OLD), load_knowledge_catalog()
    assert old.version == OLD and current.version == NEW == KNOWLEDGE_VERSION
    assert old.sha256 != current.sha256
    assert {chunk.document_id for chunk in old.chunks} == set(DOCUMENT_IDS)
    assert len(old.chunks) < len(current.chunks)
    assert "local-accounts-must-require-authentication" not in {
        chunk.section for chunk in old.chunks
    }
    finding, _ = old_finding()
    assert knowledge_version_for_finding(finding) == OLD
    assert old.retrieve(finding)
    with pytest.raises(KnowledgeUnavailable):
        current.retrieve(finding)
    with pytest.raises(KnowledgeUnavailable):
        load_knowledge_catalog("project-knowledge-0.99.0")
    with pytest.raises(TypeError):
        ARCHIVE_MANIFESTS["future"] = "f" * 64


@pytest.fixture
def archive_copy(tmp_path, monkeypatch):
    from pathlib import Path

    import app.explanation.knowledge as knowledge

    source = Path(knowledge.__file__).resolve().parents[1] / "knowledge"
    target = tmp_path / "app" / "knowledge"
    copytree(source, target)
    monkeypatch.setattr(knowledge, "__file__", str(target.parent / "explanation" / "knowledge.py"))
    return target


@pytest.mark.parametrize("case", ["missing", "changed", "extra", "manifest", "rehash", "oversized"])
def test_changed_or_missing_historical_sources_never_fall_back(archive_copy, case):
    root = archive_copy / "versions" / OLD
    path = root / DOCUMENT_IDS[0]
    if case == "missing":
        path.unlink()
    elif case == "extra":
        (root / "docs" / "unexpected.md").write_text("private marker", encoding="utf-8")
    elif case == "manifest":
        (root / "manifest.json").write_text('{"private": true}', encoding="utf-8")
    else:
        path.write_text(
            "# Modified\n## Section\nprivate marker\n" * (3000 if case == "oversized" else 1),
            encoding="utf-8",
        )
        if case == "rehash":
            manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
            manifest["documents"][DOCUMENT_IDS[0]] = hashlib.sha256(path.read_bytes()).hexdigest()
            (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(KnowledgeUnavailable, match=r"^Reviewed knowledge is unavailable\.$"):
        load_knowledge_catalog(OLD)
    assert load_knowledge_catalog(NEW).version == NEW


def test_unversioned_and_current_document_overlays_are_not_retrieval_sources(archive_copy):
    baseline = load_knowledge_catalog(OLD)
    raw = archive_copy / "docs" / "policies" / "management-plane.md"
    raw.parent.mkdir(parents=True)
    raw.write_text("# Private\n## Instructions\nprivate marker\n", encoding="utf-8")
    assert load_knowledge_catalog(OLD) == baseline


@pytest.mark.parametrize("kind", ["is_symlink", "is_junction"])
@pytest.mark.parametrize(
    "relative", [".", "docs", "docs/policies", "manifest.json", "docs/policies/management-plane.md"]
)
def test_link_gate_covers_archive_and_all_document_parents(
    archive_copy, monkeypatch, kind, relative
):
    from pathlib import Path

    root = archive_copy / "versions" / OLD
    target = root / relative
    original = getattr(Path, kind)

    def link(path):
        return path == target or original(path)

    monkeypatch.setattr(Path, kind, link)
    with pytest.raises(KnowledgeUnavailable):
        load_knowledge_catalog(OLD)


def test_context_cannot_bind_old_detector_to_new_documents():
    finding, config = old_finding()
    catalog = load_knowledge_catalog(OLD)
    values = dict(
        analysis_id=UUID(int=2),
        configuration_id=UUID(int=3),
        device_id=finding.device_id,
        source_sha256=config.source.sha256,
        finding_id=finding.finding_id,
        finding_sha256=explain_finding(finding, config).finding_sha256,
        knowledge_sha256=catalog.sha256,
        knowledge_version=OLD,
        explanation=explain_finding(finding, config),
        documents=catalog.retrieve(finding),
        limitations=("Internal sources only",),
    )
    assert ExplanationBundle(**values).knowledge_version == OLD
    with pytest.raises(ValueError, match="inconsistent"):
        ExplanationBundle(**(values | {"knowledge_version": NEW}))
