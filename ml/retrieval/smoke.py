"""Build real local vectors and report small authored-query diagnostics, not RAG quality."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from time import perf_counter

import torch
from app.explanation.knowledge import load_knowledge_catalog
from app.explanation.vector_index import (
    build_document_index,
    load_document_index,
    save_document_index,
    search_documents,
)

from ml.retrieval.minilm import LocalDocumentEncoder

QUERIES = (
    (
        "Why should Telnet be disabled and SSH used for management?",
        "docs/policies/management-plane.md#telnet-must-be-disabled",
        "en",
    ),
    (
        "Почему следует отключить Telnet и использовать SSH для управления?",
        "docs/policies/management-plane.md#telnet-must-be-disabled",
        "ru",
    ),
    (
        "Configure NTP time synchronization on the network device.",
        "docs/policies/observability.md#time-synchronization-is-required",
        "en",
    ),
    (
        "На устройстве не настроена синхронизация времени NTP.",  # noqa: RUF001
        "docs/policies/observability.md#time-synchronization-is-required",
        "ru",
    ),
    (
        "What are the limitations of the peer configuration baseline?",
        "docs/baseline.md#limitations",
        "en",
    ),
    (
        "Ограничения сравнения конфигурации с похожими устройствами.",  # noqa: RUF001
        "docs/baseline.md#limitations",
        "ru",
    ),
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model-root", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument(
        "--knowledge-version",
        action="append",
        choices=(
            "project-knowledge-0.1.0",
            "project-knowledge-0.2.0",
            "project-knowledge-0.3.0",
            "project-knowledge-0.4.0",
        ),
        help="Explicit releases to build; omission preserves the original two-release diagnostic.",
    )
    arguments = parser.parse_args()
    versions = arguments.knowledge_version or ["project-knowledge-0.1.0", "project-knowledge-0.2.0"]
    if len(set(versions)) != len(versions):
        parser.error("knowledge releases must be distinct")
    if arguments.output_root.exists():
        parser.error("output root must not already exist")
    # This offline process owns its threads; library inference does not mutate global settings.
    torch.set_num_threads(1)
    began = perf_counter()
    encoder = LocalDocumentEncoder(arguments.model_root)
    load_seconds = perf_counter() - began
    arguments.output_root.mkdir()
    releases = []
    for release in versions:
        catalog = load_knowledge_catalog(release)
        if not all(
            expected in {chunk.citation for chunk in catalog.chunks} for _, expected, _ in QUERIES
        ):
            raise ValueError("authored query references are not in the sealed catalog")
        began = perf_counter()
        index = build_document_index(catalog, encoder)
        build_seconds = perf_counter() - began
        save_document_index(index, arguments.output_root / release)
        loaded = load_document_index(arguments.output_root / release, catalog)
        if loaded != index:
            raise ValueError("index round trip differs")
        queries = []
        for query, expected, language in QUERIES:
            began = perf_counter()
            matches = search_documents(loaded, catalog, encoder, query)
            elapsed = perf_counter() - began
            citations = [match.document.citation for match in matches]
            queries.append(
                {
                    "query": query,
                    "language": language,
                    "expected_citation": expected,
                    "matches": [
                        match.model_dump(mode="json", exclude={"document": {"content"}})
                        for match in matches
                    ],
                    "hit_at_1": bool(citations and citations[0] == expected),
                    "hit_at_4": expected in citations,
                    "seconds": elapsed,
                }
            )
        releases.append(
            {
                "knowledge_version": release,
                "knowledge_sha256": catalog.sha256,
                "index_sha256": index.sha256,
                "rows": len(index.rows),
                "build_seconds": build_seconds,
                "hit_at_1": sum(bool(item["hit_at_1"]) for item in queries) / len(queries),
                "hit_at_4": sum(bool(item["hit_at_4"]) for item in queries) / len(queries),
                "queries": queries,
            }
        )
    report = {
        "report_version": "document-retrieval-diagnostic-0.2.0"
        if arguments.knowledge_version
        else "document-retrieval-diagnostic-0.1.0",
        "scope": (
            f"six authored EN/RU queries over {len(versions)} sealed internal project releases"
        ),
        "independent_evaluation": False,
        "production_qualified": False,
        "uses_customer_configurations": False,
        "vendor_documentation_included": False,
        "encoder": encoder.identity.model_dump(mode="json"),
        "load_seconds": load_seconds,
        "releases": releases,
        "limitations": [
            "Queries and expected citations are authored by the implementation, "
            "not independent labels.",
            "Cosine similarity is not detector confidence, correctness or network impact.",
            "Only approved internal project sources are indexed, not licensed vendor manuals.",
            "All content windows are pooled; this differs from publisher short-text truncation.",
            "This diagnostic does not activate HTTP retrieval or an anomaly detector.",
        ],
    }
    with (arguments.output_root / "report.json").open("x", encoding="utf-8") as target:
        json.dump(report, target, ensure_ascii=False, indent=2)
        target.write("\n")
    print(
        json.dumps(
            {
                "rows": [item["rows"] for item in releases],
                "hit_at_4": [item["hit_at_4"] for item in releases],
            }
        )
    )


if __name__ == "__main__":
    main()
