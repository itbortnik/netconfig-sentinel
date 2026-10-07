"""Single isolated worker with deadline; query derives exclusively from public metadata."""

import json
import os
import subprocess
import sys
from pathlib import Path
from threading import Lock

from app.core.document_retrieval import DocumentRetrievalSettings
from app.domain import Finding
from app.explanation.knowledge import KnowledgeCatalog, text_sha256
from app.explanation.retrieval_contracts import (
    MAX_WORKER_REQUEST_BYTES,
    MAX_WORKER_RESULT_BYTES,
    RetrievalJob,
    RetrievalSelection,
)
from app.explanation.vector_index import RetrievalUnavailable, _unique_keys, load_document_index
from app.policies import POLICY_CATALOGS


class RetrievalBusy(Exception):
    pass


def public_retrieval_query(finding: Finding) -> str:
    """Never use observed/expected values, evidence, source text or customer inventory."""
    if finding.detector == "policy_engine":
        rule = next(
            (
                item
                for item in POLICY_CATALOGS.get(finding.model_version, ())
                if item.rule_id == finding.category
            ),
            None,
        )
        if rule is not None:
            return f"{rule.title}\n{rule.remediation}"
    else:
        queries = {
            ("expected_configuration", "expected-config-0.1.0"): (
                "Expected configuration comparison: evidence and limitations."
            ),
            ("peer_baseline", "peer-baseline-0.1.0"): (
                "Peer configuration consensus baseline: interpretation and limitations."
            ),
            ("isolation_forest", "isolation-forest-0.1.0"): (
                "Experimental Isolation Forest outlier finding interpretation and limitations."
            ),
        }
        query = queries.get((finding.detector, finding.model_version))
        if query is not None:
            return query
    raise RetrievalUnavailable("Document retrieval is unavailable.")


class DocumentRetrievalRuntime:
    def __init__(self, settings: DocumentRetrievalSettings) -> None:
        self.settings = settings
        self._lock = Lock()

    def search(self, catalog: KnowledgeCatalog, query: str) -> RetrievalSelection:
        if not self._lock.acquire(blocking=False):
            raise RetrievalBusy()
        try:
            return self._search(catalog, query)
        except (OSError, ValueError, TypeError, RecursionError, subprocess.SubprocessError):
            raise RetrievalUnavailable("Document retrieval is unavailable.") from None
        finally:
            self._lock.release()

    def _search(self, catalog: KnowledgeCatalog, query: str) -> RetrievalSelection:
        pin = (
            self.settings.legacy_index_sha256
            if catalog.version == "project-knowledge-0.1.0"
            else self.settings.current_index_sha256
        )
        index = load_document_index(
            self.settings.index_root / catalog.version, catalog, expected_sha256=pin
        )
        job = RetrievalJob(
            model_root=str(self.settings.model_root),
            index_root=str(self.settings.index_root),
            index_sha256=pin,
            knowledge_version=catalog.version,
            query=query,
        )
        request = job.model_dump_json().encode("utf-8")
        if len(request) > MAX_WORKER_REQUEST_BYTES:
            raise RetrievalUnavailable("Document retrieval is unavailable.")
        environment = {
            key: value
            for key, value in os.environ.items()
            if key.upper() in {"SYSTEMROOT", "WINDIR", "PATH", "TMP", "TEMP", "LANG", "LC_ALL"}
        }
        process = subprocess.Popen(
            [sys.executable, "-I", str(Path(__file__).with_name("retrieval_worker.py"))],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=environment,
            creationflags=(
                int(getattr(subprocess, "CREATE_NO_WINDOW", 0)) if sys.platform == "win32" else 0
            ),
        )
        try:
            stdout, _ = process.communicate(request, timeout=self.settings.timeout_seconds)
        except BaseException as error:
            process.kill()
            process.communicate(timeout=5)
            if isinstance(error, subprocess.TimeoutExpired):
                raise RetrievalUnavailable("Document retrieval is unavailable.") from None
            raise
        if process.returncode != 0 or len(stdout) > MAX_WORKER_RESULT_BYTES:
            raise RetrievalUnavailable("Document retrieval is unavailable.")
        selected = RetrievalSelection.model_validate(
            json.loads(stdout, object_pairs_hook=_unique_keys)
        )
        chunks = {item.citation: item for item in catalog.chunks}
        if (
            selected.index_sha256 != pin
            or selected.knowledge_version != catalog.version
            or selected.knowledge_sha256 != catalog.sha256
            or selected.query_sha256 != text_sha256(query)
            or selected.encoder != index.encoder
            or any(chunks.get(item.document.citation) != item.document for item in selected.matches)
        ):
            raise RetrievalUnavailable("Document retrieval is unavailable.")
        return selected
