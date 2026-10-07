"""Test vector contracts with artificial vectors, separately from real-model diagnostics."""

import hashlib
import json
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import numpy as np
import pytest
from app.explanation.knowledge import load_knowledge_catalog
from app.explanation.vector_index import (
    DocumentIndex,
    EmbeddingIdentity,
    RetrievalUnavailable,
    build_document_index,
    load_document_index,
    save_document_index,
    search_documents,
)
from pydantic import ValidationError


class ArtificialEncoder:
    """Pure software fixture, never published as a semantic encoder."""

    identity = EmbeddingIdentity(
        model_id="unit-test-only",
        revision="a" * 40,
        files_sha256="b" * 64,
        pipeline_version="unit-test",
        dimensions=3,
        runtime_versions=("fixture=1",),
    )

    def encode(self, texts):
        return np.tile(np.array([[1.0, 0.0, 0.0]], dtype=np.float32), (len(texts), 1))


def test_default_api_and_vector_contracts_do_not_import_optional_model_libraries():
    command = (
        "import app.main; import app.explanation.vector_index; import sys; "
        "assert not any(name in sys.modules for name in ('torch', 'transformers', 'safetensors')); "
        "print('base-api-no-optional-model-imports')"
    )
    result = subprocess.run(
        [sys.executable, "-c", command], capture_output=True, text=True, timeout=20, check=True
    )
    assert result.stdout.strip() == "base-api-no-optional-model-imports"


@pytest.fixture
def vectors():
    catalog = load_knowledge_catalog()
    encoder = ArtificialEncoder()
    return catalog, encoder, build_document_index(catalog, encoder)


def test_complete_sealed_catalog_numeric_index_roundtrip_and_deterministic_ties(vectors, tmp_path):
    catalog, encoder, index = vectors
    assert len(index.rows) == len(catalog.chunks) == 41
    assert index.encoder == encoder.identity
    root = tmp_path / "index"
    save_document_index(index, root)
    assert load_document_index(root, catalog, expected_sha256=index.sha256) == index
    raw = (root / "index.json").read_text(encoding="utf-8")
    assert '"content":' not in raw
    results = search_documents(index, catalog, encoder, "public query", limit=2)
    assert [item.document.citation for item in results] == sorted(
        chunk.citation for chunk in catalog.chunks
    )[:2]
    assert all(item.cosine_similarity == 1 for item in results)
    assert all(item.document in catalog.chunks for item in results)
    with pytest.raises(RetrievalUnavailable):
        save_document_index(index, root)
    assert load_document_index(root, catalog) == index


@pytest.mark.parametrize("case", ["version", "catalog_hash", "missing", "content", "document"])
def test_mismatched_or_partial_sources_are_rejected_even_with_rehashed_artifact(
    vectors, tmp_path, case
):
    catalog, _, index = vectors
    payload = index.model_dump(mode="json")
    if case == "version":
        payload["knowledge_version"] = "project-knowledge-0.1.0"
    elif case == "catalog_hash":
        payload["knowledge_sha256"] = "0" * 64
    elif case == "missing":
        payload["rows"].pop()
    else:
        payload["rows"][0][f"{case}_sha256"] = "0" * 64
    invalid = DocumentIndex.model_validate(payload)
    with pytest.raises(RetrievalUnavailable):
        search_documents(invalid, catalog, ArtificialEncoder(), "query")
    with pytest.raises(RetrievalUnavailable):
        save_document_index(invalid, tmp_path / "index")


@pytest.mark.parametrize("case", ["duplicate", "order", "norm", "nan", "dimension", "infinity"])
def test_vector_payload_requires_unique_ordered_finite_unit_rows(vectors, case):
    _, _, index = vectors
    payload = index.model_dump(mode="json")
    if case == "duplicate":
        payload["rows"].append(payload["rows"][0])
    elif case == "order":
        payload["rows"].reverse()
    else:
        payload["rows"][0]["vector"] = {
            "norm": [0, 0, 0],
            "nan": [float("nan"), 0, 0],
            "dimension": [1, 0],
            "infinity": [float("inf"), 0, 0],
        }[case]
    with pytest.raises(ValidationError):
        DocumentIndex.model_validate(payload)


@pytest.mark.parametrize("case", ["shape", "norm", "nan", "integer"])
def test_encoder_contract_is_checked_before_build_or_search(vectors, case):
    catalog, _, index = vectors

    class BrokenEncoder(ArtificialEncoder):
        def encode(self, texts):
            return {
                "shape": np.ones((len(texts), 2), dtype=np.float32),
                "norm": np.zeros((len(texts), 3), dtype=np.float32),
                "nan": np.full((len(texts), 3), np.nan, dtype=np.float32),
                "integer": np.tile([1, 0, 0], (len(texts), 1)),
            }[case]

    with pytest.raises(RetrievalUnavailable):
        build_document_index(catalog, BrokenEncoder())
    with pytest.raises(RetrievalUnavailable):
        search_documents(index, catalog, BrokenEncoder(), "query")


def test_encoder_identity_and_sealed_catalog_cannot_be_substituted(vectors):
    catalog, encoder, index = vectors
    other = ArtificialEncoder()
    other.identity = encoder.identity.model_copy(update={"runtime_versions": ("fixture=2",)})
    with pytest.raises(RetrievalUnavailable):
        search_documents(index, catalog, other, "query")
    chunk = catalog.chunks[0]
    forged = replace(catalog, chunks=(chunk,))
    with pytest.raises(RetrievalUnavailable):
        build_document_index(forged, encoder)
    with pytest.raises(RetrievalUnavailable):
        search_documents(index, forged, encoder, "query")


@pytest.mark.parametrize("query", ["", " \n", "private\x00marker", "x" * 4097, "\ud800"])
def test_invalid_query_never_reaches_encoder(vectors, query):
    catalog, encoder, index = vectors
    with pytest.raises(RetrievalUnavailable):
        search_documents(index, catalog, encoder, query)


@pytest.mark.parametrize("limit,threshold", [(0, 0), (5, 0), (True, 0), (1, 2), (1, float("nan"))])
def test_invalid_search_budget(vectors, limit, threshold):
    catalog, encoder, index = vectors
    with pytest.raises(RetrievalUnavailable):
        search_documents(
            index, catalog, encoder, "query", limit=limit, minimum_similarity=threshold
        )


@pytest.mark.parametrize(
    "case", ["extra", "missing", "checksum", "duplicate_json", "oversize", "pin"]
)
def test_disk_tampering_and_wrong_operator_pin_are_rejected(vectors, tmp_path, case):
    catalog, _, index = vectors
    root = tmp_path / "index"
    save_document_index(index, root)
    if case == "extra":
        (root / "extra.json").write_text("private marker", encoding="utf-8")
    elif case == "missing":
        (root / "index.json").unlink()
    elif case == "checksum":
        (root / "index.json").write_text("private marker", encoding="utf-8")
    elif case == "duplicate_json":
        raw = (
            (root / "index.json")
            .read_bytes()
            .replace(b'{"encoder":', b'{"knowledge_sha256":"' + b"0" * 64 + b'","encoder":', 1)
        )
        (root / "index.json").write_bytes(raw)
        (root / "manifest.json").write_text(
            json.dumps({"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}),
            encoding="utf-8",
        )
    elif case == "oversize":
        (root / "manifest.json").write_bytes(b" " * 513)
    with pytest.raises(RetrievalUnavailable, match=r"^Document retrieval is unavailable\.$"):
        load_document_index(root, catalog, expected_sha256="0" * 64 if case == "pin" else None)


@pytest.mark.parametrize("kind", ["is_symlink", "is_junction"])
@pytest.mark.parametrize("name", ["root", "parent", "index.json", "manifest.json"])
def test_index_links_and_parent_links_rejected(vectors, tmp_path, monkeypatch, kind, name):
    catalog, _, index = vectors
    root = tmp_path / "index"
    save_document_index(index, root)
    target = root if name == "root" else root.parent if name == "parent" else root / name
    original = getattr(Path, kind)
    monkeypatch.setattr(Path, kind, lambda self: self == target or original(self))
    with pytest.raises(RetrievalUnavailable):
        load_document_index(root, catalog)
