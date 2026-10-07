"""Isolated real local document inference; stdout contains only a bounded validated result."""

import json
import sys
from pathlib import Path

# The worker is launched by this installed application, not by an input-selected script.
# -I drops CWD/PYTHONPATH. Restore only its own trusted package root for app/ml imports.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app.explanation.knowledge import load_knowledge_catalog, text_sha256
from app.explanation.retrieval_contracts import (
    MAX_WORKER_REQUEST_BYTES,
    MAX_WORKER_RESULT_BYTES,
    RetrievalJob,
    RetrievalSelection,
)
from app.explanation.vector_index import _unique_keys, load_document_index, search_documents


def main() -> None:
    try:
        raw = sys.stdin.buffer.read(MAX_WORKER_REQUEST_BYTES + 1)
        if len(raw) > MAX_WORKER_REQUEST_BYTES:
            raise ValueError("unsupported request")
        job = RetrievalJob.model_validate(json.loads(raw, object_pairs_hook=_unique_keys))
        catalog = load_knowledge_catalog(job.knowledge_version)
        index = load_document_index(
            Path(job.index_root) / catalog.version, catalog, expected_sha256=job.index_sha256
        )
        # Optional heavy dependencies exist only inside the explicitly invoked process.
        import torch

        from ml.retrieval.minilm import LocalDocumentEncoder

        torch.set_num_threads(1)
        encoder = LocalDocumentEncoder(Path(job.model_root))
        result = RetrievalSelection(
            index_sha256=index.sha256,
            knowledge_version=catalog.version,
            knowledge_sha256=catalog.sha256,
            query_sha256=text_sha256(job.query),
            encoder=encoder.identity,
            matches=search_documents(index, catalog, encoder, job.query),
        )
        output = result.model_dump_json().encode("utf-8")
        if len(output) > MAX_WORKER_RESULT_BYTES:
            raise ValueError("unsupported result")
        sys.stdout.buffer.write(output)
    except Exception:
        # Never expose a model exception, operator path or query in stdout/stderr.
        sys.exit(1)


if __name__ == "__main__":
    main()
