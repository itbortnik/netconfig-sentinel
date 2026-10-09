"""Read-only semantic workflow mechanics use a fake worker, not a retrieval-quality claim."""

import json
import subprocess
from pathlib import Path
from uuid import UUID, uuid4

import numpy as np
import pytest
from app.api.explanation_contracts import ExplanationBundle
from app.audit.contracts import metadata_hash
from app.core.document_retrieval import DocumentRetrievalSettings
from app.core.settings import ApiSettings
from app.db.migrate import upgrade_database
from app.explanation.knowledge import load_knowledge_catalog, text_sha256
from app.explanation.retrieval_contracts import RetrievalJob, RetrievalSelection
from app.explanation.retrieval_runtime import (
    DocumentRetrievalRuntime,
    RetrievalBusy,
    public_retrieval_query,
)
from app.explanation.vector_index import (
    EmbeddingIdentity,
    RetrievalUnavailable,
    RetrievedDocument,
    build_document_index,
    save_document_index,
)
from app.main import create_app
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import text

TOKEN = "semantic-api-synthetic-admin-token-00001"
READER = "semantic-api-synthetic-reader-token-0001"
HEADERS = {"Authorization": f"Bearer {TOKEN}"}
PRIVATE = "PRIVATE-CUSTOMER-CONFIGURATION-MARKER"


class ArtificialEncoder:
    identity = EmbeddingIdentity(
        model_id="artificial-software-test-not-real-weights",
        revision="a" * 40,
        files_sha256="b" * 64,
        pipeline_version="test-only",
        dimensions=3,
        runtime_versions=("fixture=1",),
    )

    def encode(self, texts):
        return np.tile(np.array([[1, 0, 0]], dtype=np.float32), (len(texts), 1))


@pytest.fixture
def semantic_api(tmp_path, monkeypatch):
    index_root = tmp_path / "vectors"
    index_root.mkdir()
    pins = []
    for version in ("project-knowledge-0.1.0", "project-knowledge-0.2.0"):
        index = build_document_index(load_knowledge_catalog(version), ArtificialEncoder())
        save_document_index(index, index_root / version)
        pins.append(index.sha256)
    configured = DocumentRetrievalSettings(tmp_path / "model", index_root, *pins)
    settings = ApiSettings(
        f"sqlite:///{tmp_path / 'semantic.sqlite3'}",
        TOKEN,
        Fernet.generate_key().decode(),
        reader_token=READER,
    )
    app = create_app(settings, document_retrieval=configured)
    upgrade_database(app.state.analysis_service.store.engine)
    state = {"jobs": [], "damage": None, "processes": []}

    class FakeProcess:
        returncode = 0

        def __init__(self, command, **kwargs):
            assert command[-2] == "-I" and command[-1].endswith("retrieval_worker.py")
            assert not any("NETCONFIG" in name or "HUGGING" in name for name in kwargs["env"])
            self.killed = False
            state["processes"].append(self)

        def communicate(self, request=None, timeout=None):
            if request is None:
                return b"", b""
            job = RetrievalJob.model_validate_json(request)
            state["jobs"].append(json.loads(request))
            assert PRIVATE.encode() not in request
            if state["damage"] == "timeout":
                raise subprocess.TimeoutExpired("private process path", timeout)
            catalog = load_knowledge_catalog(job.knowledge_version)
            selected = RetrievalSelection(
                index_sha256=job.index_sha256,
                knowledge_version=catalog.version,
                knowledge_sha256=catalog.sha256,
                query_sha256=text_sha256(job.query),
                encoder=ArtificialEncoder.identity,
                matches=tuple(
                    RetrievedDocument(document=chunk, cosine_similarity=0.5)
                    for chunk in catalog.chunks[-4:]
                ),
            ).model_dump(mode="json")
            damage = state["damage"]
            if damage in ("index_sha256", "knowledge_sha256", "query_sha256"):
                selected[damage] = "0" * 64
            elif damage == "version":
                selected["knowledge_version"] = "project-knowledge-0.1.0"
            elif damage == "encoder":
                selected["encoder"]["revision"] = "f" * 40
            elif damage == "duplicate":
                selected["matches"][1] = selected["matches"][0]
            elif damage == "content":
                chunk = selected["matches"][0]["document"]
                chunk["content"] = PRIVATE
                chunk["content_sha256"] = text_sha256(PRIVATE)
            elif damage == "nan":
                selected["matches"][0]["cosine_similarity"] = float("nan")
            elif damage == "exit":
                self.returncode = 1
            elif damage == "huge":
                return b"x" * 65537, b""
            elif damage == "json":
                return PRIVATE.encode(), b""
            return json.dumps(selected).encode(), b""

        def kill(self):
            self.killed = True

    monkeypatch.setattr("app.explanation.retrieval_runtime.subprocess.Popen", FakeProcess)
    with TestClient(app) as client:
        uploaded = client.post(
            "/api/v1/configurations",
            headers=HEADERS,
            json={
                "device_id": str(uuid4()),
                "filename": "private-edge.cfg",
                "content": f"hostname {PRIVATE}\nunsupported {PRIVATE}\n",
            },
        )
        result = client.post(
            f"/api/v1/configurations/{uploaded.json()['configuration_id']}/analyze", headers=HEADERS
        ).json()
        yield client, app, result, state, configured


def explain(client, result, headers=HEADERS, **update):
    return client.post(
        f"/api/v1/findings/{result['findings'][0]['finding_id']}/explain",
        headers=headers,
        json={
            "analysis_id": result["analysis_id"],
            "finding_sha256": result["explanations"][0]["finding_sha256"],
            "retrieval": "semantic_supplement",
        }
        | update,
    )


def test_semantic_sources_preserve_required_references_scores_history_and_reader_access(
    semantic_api,
):
    client, app, result, state, _ = semantic_api
    response = explain(client, result)
    assert response.status_code == 200, response.text
    bundle = response.json()
    assert bundle["version"] == "finding-context-0.2.0"
    assert bundle["explanation"] == result["explanations"][0]
    assert PRIVATE not in response.text
    metadata = bundle["semantic_retrieval"]
    operation = app.state.operation_journal.get(UUID(response.headers["X-Operation-Id"]))
    audit = operation.completion.result
    assert audit.document_index_sha256 == metadata["index_sha256"]
    assert audit.document_encoder_sha256 == metadata_hash(metadata["encoder"])
    assert audit.retrieval == "semantic_supplement"
    assert metadata["encoder"]["pipeline_version"] in audit.versions
    assert PRIVATE not in operation.model_dump_json()
    assert metadata["query_source"] == "public_detector_metadata"
    assert metadata["required_citations"] == result["explanations"][0]["citations"]
    assert bundle["documents"][0]["citation"] in metadata["required_citations"]
    assert 1 < len(bundle["documents"]) <= 4
    assert explain(client, result, headers={"Authorization": f"Bearer {READER}"}).json() == bundle
    assert client.get(f"/api/v1/analyses/{result['analysis_id']}", headers=HEADERS).json() == result
    with app.state.analysis_service.store.engine.connect() as connection:
        assert connection.execute(text("SELECT count(*) FROM analyses")).scalar_one() == 1
        assert connection.execute(text("SELECT count(*) FROM audit_events")).scalar_one() == 2
    assert len(state["jobs"]) == 2
    assert "SSH" in state["jobs"][0]["query"]
    assert "private-edge" not in str(state["jobs"])


def test_default_wire_shape_stays_legacy_without_starting_worker_and_health_is_not_claimed(
    semantic_api,
):
    client, _, result, state, _ = semantic_api
    response = explain(client, result, retrieval="explicit_reference")
    assert response.status_code == 200
    assert response.json()["version"] == "finding-context-0.1.0"
    assert "semantic_retrieval" not in response.json()
    assert response.json()["explanation"]["patch_draft"] is None
    assert not state["jobs"]
    capabilities = client.get("/api/v1/explanation-capabilities", headers=HEADERS).json()
    assert capabilities["semantic_retrieval"] == "configured"
    assert capabilities["retrieval_health_checked"] is False
    assert not state["jobs"]


def test_reader_cannot_use_semantic_selection_to_bypass_language_model_permission(semantic_api):
    client, _, result, state, _ = semantic_api
    response = explain(
        client,
        result,
        headers={"Authorization": f"Bearer {READER}"},
        provider="llm",
        allow_local_model_context=True,
    )
    assert response.status_code == 403
    assert not state["jobs"]


def test_historical_analysis_uses_legacy_index_and_mandatory_sources(semantic_api):
    from app.api.contracts import AnalysisResult
    from app.detection.fusion import RiskSource, fuse_risk
    from app.detection.policy_engine import evaluate_policies
    from app.explanation.local import explain_finding

    client, app, result, state, configured = semantic_api
    store = app.state.analysis_service.store
    original = store.get_analysis(result["analysis_id"])
    snapshot = store.get_configuration(original.configuration_id)
    findings = evaluate_policies(
        snapshot.canonical, device_id=original.device_id, catalog_version="policy-rules-0.6.0"
    )
    historical = AnalysisResult.model_validate(
        original.model_dump()
        | {
            "analysis_id": uuid4(),
            "policy_catalog_version": "policy-rules-0.6.0",
            "findings": tuple(findings),
            "explanations": tuple(explain_finding(item, snapshot.canonical) for item in findings),
            "risk": (
                None
                if original.risk is None
                else fuse_risk(
                    findings, device_id=original.device_id, completed_detectors=(RiskSource.POLICY,)
                )
            ),
        }
    )
    store.add_analysis(historical)
    response = explain(client, historical.model_dump(mode="json"))
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["knowledge_version"] == "project-knowledge-0.1.0"
    assert body["semantic_retrieval"]["index_sha256"] == configured.legacy_index_sha256
    assert state["jobs"][0]["knowledge_version"] == "project-knowledge-0.1.0"
    assert body["explanation"] == historical.model_dump(mode="json")["explanations"][0]


@pytest.mark.parametrize(
    "damage",
    [
        "index_sha256",
        "knowledge_sha256",
        "query_sha256",
        "version",
        "encoder",
        "duplicate",
        "content",
        "nan",
        "exit",
        "huge",
        "json",
        "timeout",
    ],
)
def test_worker_failure_or_forged_binding_fails_closed_and_never_changes_analysis(
    semantic_api, damage
):
    client, _app, result, state, _ = semantic_api
    state["damage"] = damage
    response = explain(client, result)
    assert response.status_code == 503, response.text
    assert response.json() == {"detail": "Document retrieval is unavailable."}
    if damage == "timeout":
        assert state["processes"][0].killed
    assert client.get(f"/api/v1/analyses/{result['analysis_id']}", headers=HEADERS).json() == result
    assert explain(client, result, retrieval="explicit_reference").status_code == 200


def test_busy_worker_is_bounded_and_disabled_mode_does_not_fall_back(semantic_api):
    client, app, result, state, _ = semantic_api
    runtime = app.state.document_retrieval
    runtime._lock.acquire()
    try:
        assert explain(client, result).status_code == 429
        with pytest.raises(RetrievalBusy):
            runtime.search(load_knowledge_catalog(), "public query")
    finally:
        runtime._lock.release()
    assert not state["jobs"]
    app.state.document_retrieval = None
    assert explain(client, result).status_code == 503
    assert explain(client, result, retrieval="explicit_reference").status_code == 200


def test_authorization_and_body_binding_happen_before_any_worker(semantic_api):
    client, _, result, state, _ = semantic_api
    assert explain(client, result, headers={}).status_code == 401
    assert explain(client, result, finding_sha256="0" * 64).status_code == 409
    assert explain(client, result, analysis_id=str(uuid4())).status_code == 404
    for update in ({"retrieval": "external"}, {"model_root": "private"}, {"query": PRIVATE}):
        assert explain(client, result, **update).status_code == 400
    assert not state["jobs"]


@pytest.mark.parametrize("case", ["version", "mode", "missing_required", "duplicate", "hash"])
def test_response_contract_rejects_misleading_semantic_metadata(semantic_api, case):
    client, _, result, _, _ = semantic_api
    body = explain(client, result).json()
    if case == "version":
        body["version"] = "finding-context-0.1.0"
    elif case == "mode":
        body["retrieval"] = "explicit_reference"
    elif case == "missing_required":
        body["semantic_retrieval"]["required_citations"] = [body["documents"][1]["citation"]]
    elif case == "duplicate":
        body["semantic_retrieval"]["matches"][0]["citation"] = body["documents"][0]["citation"]
    else:
        body["semantic_retrieval"]["matches"][0]["content_sha256"] = "0" * 64
    with pytest.raises(ValidationError):
        ExplanationBundle.model_validate(body)


def test_operator_pin_rejects_changed_index_before_worker(semantic_api):
    client, _, result, state, configured = semantic_api
    path = configured.index_root / "project-knowledge-0.2.0" / "index.json"
    path.write_bytes(b"private corrupt artifact")
    assert explain(client, result).status_code == 503
    assert not state["jobs"]


@pytest.mark.parametrize(
    "case", ["relative_model", "relative_index", "bad_hash", "timeout", "boolean"]
)
def test_operator_settings_reject_invalid_paths_pins_and_budgets(tmp_path, case):
    values = [tmp_path / "model", tmp_path / "index", "a" * 64, "b" * 64, 20]
    if case == "relative_model":
        values[0] = Path("relative")
    elif case == "relative_index":
        values[1] = Path("relative")
    elif case == "bad_hash":
        values[2] = "private"
    else:
        values[4] = True if case == "boolean" else 61
    with pytest.raises(ValueError):
        DocumentRetrievalSettings(*values)


def test_environment_requires_complete_config_and_unconfigured_api_cannot_accept_it(
    tmp_path, monkeypatch
):
    names = (
        "NETCONFIG_DOCUMENT_MODEL_ROOT",
        "NETCONFIG_DOCUMENT_INDEX_ROOT",
        "NETCONFIG_DOCUMENT_INDEX_SHA256_0_1",
        "NETCONFIG_DOCUMENT_INDEX_SHA256_0_2",
        "NETCONFIG_DOCUMENT_INDEX_SHA256_0_3",
    )
    for name in names:
        monkeypatch.delenv(name, raising=False)
    assert DocumentRetrievalSettings.from_environment() is None
    monkeypatch.setenv(names[0], str(tmp_path / "model"))
    with pytest.raises(ValueError):
        DocumentRetrievalSettings.from_environment()
    for name, value in zip(
        names[:4],
        (str(tmp_path / "model"), str(tmp_path / "index"), "a" * 64, "b" * 64),
        strict=True,
    ):
        monkeypatch.setenv(name, value)
    configured = DocumentRetrievalSettings.from_environment()
    assert configured is not None
    assert configured.expanded_index_sha256 is None
    monkeypatch.setenv(names[4], "c" * 64)
    assert DocumentRetrievalSettings.from_environment().expanded_index_sha256 == "c" * 64
    monkeypatch.setenv(names[4], "private invalid pin")
    with pytest.raises(ValueError):
        DocumentRetrievalSettings.from_environment()
    with pytest.raises(ValueError):
        create_app(document_retrieval=configured)


def test_runtime_releases_lock_after_unavailable_index(tmp_path):
    runtime = DocumentRetrievalRuntime(
        DocumentRetrievalSettings(tmp_path / "model", tmp_path / "absent", "a" * 64, "b" * 64)
    )
    for _ in range(2):
        with pytest.raises(RetrievalUnavailable):
            runtime.search(load_knowledge_catalog(), "public query")


@pytest.mark.parametrize(
    "detector,version",
    [
        ("expected_configuration", "expected-config-0.1.0"),
        ("peer_baseline", "peer-baseline-0.1.0"),
        ("expected_configuration", "expected-config-0.2.0"),
        ("peer_baseline", "peer-baseline-0.2.0"),
        ("peer_baseline", "peer-baseline-0.3.0"),
        ("isolation_forest", "isolation-forest-0.1.0"),
    ],
)
def test_nonpolicy_query_uses_public_constant_not_customer_facts(semantic_api, detector, version):
    _, app, result, _, _ = semantic_api
    finding = app.state.analysis_service.store.get_analysis(result["analysis_id"]).findings[0]
    other = finding.model_copy(update={"detector": detector, "model_version": version})
    query = public_retrieval_query(other)
    assert PRIVATE not in query and not any(
        value in query for value in other.observed.values() if isinstance(value, str)
    )


@pytest.mark.parametrize("release", ["project-knowledge-0.3.0", "project-knowledge-0.4.0"])
def test_expanded_semantic_release_never_reuses_an_older_external_pin(
    tmp_path, monkeypatch, release
):
    runtime = DocumentRetrievalRuntime(
        DocumentRetrievalSettings(tmp_path / "model", tmp_path / "index", "a" * 64, "b" * 64)
    )

    def unexpected(*args, **kwargs):
        raise AssertionError(
            "unconfigured expanded release must not read an index or spawn a worker"
        )

    monkeypatch.setattr("app.explanation.retrieval_runtime.load_document_index", unexpected)
    with pytest.raises(RetrievalUnavailable):
        runtime.search(load_knowledge_catalog(release), "public query")


def test_unsupported_detector_version_or_policy_category_has_no_semantic_query(semantic_api):
    _, app, result, _, _ = semantic_api
    finding = app.state.analysis_service.store.get_analysis(result["analysis_id"]).findings[0]
    for updates in ({"model_version": "unknown"}, {"category": "private-unreviewed-category"}):
        with pytest.raises(RetrievalUnavailable):
            public_retrieval_query(finding.model_copy(update=updates))
