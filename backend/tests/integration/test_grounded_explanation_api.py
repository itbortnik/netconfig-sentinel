"""Synthetic loopback transport checks, not real-model semantic quality evidence."""

import json
from copy import deepcopy
from dataclasses import replace
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
from app.api.grounded_explanation_contracts import GroundedExplanationBundle
from app.audit.contracts import metadata_hash
from app.explanation.knowledge import text_sha256
from app.main import create_app
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import text
from test_local_model_api import HEADERS, MODEL_KEY, analyze
from test_local_model_api import model_api as model_api
from test_local_model_api import model_server as model_server

READER = "grounded-explanation-reader-private-token-001"


@pytest.fixture
def grounded_api(model_api, monkeypatch):
    _client, _service, server, settings, old_model = model_api
    model = replace(old_model, allow_grounded_explanation=True)
    settings = replace(settings, reader_token=READER)
    application = create_app(settings, local_model=model)
    original = server.response

    def response(request):
        context = json.loads(request["messages"][1]["content"])
        if context.get("version") != "grounded-explanation-context-0.1.0":
            return original(request)
        answer = {
            "version": "grounded-explanation-answer-0.1.0",
            "facts_binding_sha256": context["facts_binding_sha256"],
            "fact_refs": context["available_fact_refs"],
            "recommendation_code": context["recommendation_code"],
            "missing_information_codes": [],
            "citations": context["required_citations"],
            "patch_draft": None,
            "requires_human_review": True,
        }
        if server.damage == "prose":
            answer["summary"] = "private-injected-approval"
        elif server.damage == "fact":
            answer["fact_refs"] = ["selected_reference"]
        elif server.damage == "citation":
            answer["citations"] = ["unknown#section"]
        elif server.damage == "binding":
            answer["facts_binding_sha256"] = "0" * 64
        elif server.damage == "review":
            answer["requires_human_review"] = 1
        elif server.damage == "patch":
            answer["patch_draft"] = "private-injected-command"
        answer_text = json.dumps(answer)
        if server.damage == "null":
            answer_text = "null"
        elif server.damage == "duplicate":
            answer_text = answer_text.replace('"patch_draft":', '"patch_draft":null,"patch_draft":')
        return json.dumps(
            {
                "choices": [
                    {
                        "message": {"role": "assistant", "content": answer_text},
                        "finish_reason": "stop",
                    }
                ]
            }
        ).encode()

    monkeypatch.setattr(server, "response", response)
    with TestClient(application) as selected:
        yield selected, application.state.analysis_service, server, settings, model


def explain(client, result, finding=None, **updates):
    finding = finding or result["findings"][0]
    saved = next(
        item for item in result["explanations"] if item["finding_id"] == finding["finding_id"]
    )
    return client.post(
        f"/api/v2/findings/{finding['finding_id']}/explain",
        headers=HEADERS,
        json={
            "analysis_id": result["analysis_id"],
            "finding_sha256": saved["finding_sha256"],
            "provider": "llm",
            "allow_local_model_context": True,
        }
        | updates,
    )


@pytest.mark.parametrize("vendor", ["cisco", "juniper"])
@pytest.mark.parametrize("partial", [False, True])
def test_closed_explanation_wire_and_saved_analysis_are_distinct(grounded_api, vendor, partial):
    client, service, server, settings, model = grounded_api
    result = analyze(client, vendor, partial)
    caps = client.get("/api/v2/explanation-capabilities", headers=HEADERS)
    assert caps.status_code == 200 and caps.json()["grounded_explanation"] == "configured"
    assert caps.json()["model_health_checked"] is False and not server.requests
    response = explain(client, result)
    assert response.status_code == 200, response.text
    data = response.json()
    bundle = GroundedExplanationBundle.model_validate(data)
    assert "source_facts" not in data and "presentation" not in data and "answer" not in data
    assert bundle.presentation.presentation_kind == "server_derived"
    assert bundle.source_facts.analysis_facts.analysis_status == result["status"]
    assert bundle.source_facts.invocation_facts.model_answer_storage == "not_stored_in_analysis"
    assert bundle.explanation.model_dump(mode="json") == result["explanations"][0]
    assert "formal verification" in bundle.presentation.technical_explanation
    assert len(bundle.presentation.missing_information) >= 5
    request, headers = server.requests[0]
    sent = json.dumps(request)
    assert "private-hostname" not in sent and "private-input.cfg" not in sent
    assert "private-secret" not in sent and result["analysis_id"] not in sent
    assert result["device_id"] not in sent and MODEL_KEY not in sent
    assert headers["Authorization"] == "Bearer " + MODEL_KEY
    context = json.loads(request["messages"][1]["content"])
    assert context["source_facts"] == json.loads(data["source_facts_json"])
    assert context["source_facts"]["parser"]["unparsed_count"] == int(partial)
    operation = client.app.state.operation_journal.get(UUID(response.headers["X-Operation-Id"]))
    assert operation.receipt.operation == "explain_finding"
    audit = operation.completion.result
    assert audit.context_sha256 == bundle.context_sha256
    assert audit.model_alias_sha256 == metadata_hash(model.model)
    assert bundle.renderer_version in audit.versions
    serialized = operation.model_dump_json()
    assert "source_facts_json" not in serialized and "fact_refs" not in serialized
    assert bundle.projection_json not in serialized and MODEL_KEY not in serialized
    assert {row.permission for row in operation.completion.permissions} == {
        "read",
        "model_explanation",
    }
    with TestClient(create_app(settings)) as restarted:
        assert (
            restarted.get(f"/api/v1/analyses/{result['analysis_id']}", headers=HEADERS).json()
            == result
        )
        assert explain(restarted, result).status_code == 503
    assert len(server.requests) == 1
    with service.store.engine.connect() as connection:
        assert connection.execute(text("SELECT count(*) FROM analyses")).scalar_one() == 1
        assert (
            connection.execute(text("SELECT count(*) FROM model_patch_intents")).scalar_one() == 0
        )


@pytest.mark.parametrize(
    "damage", ["prose", "fact", "citation", "binding", "review", "patch", "null", "duplicate"]
)
def test_rejected_choices_never_fall_back_or_mutate_scores(grounded_api, damage):
    client, _, server, _, _ = grounded_api
    result = analyze(client)
    server.damage = damage
    response = explain(client, result)
    assert response.status_code == 503, response.text
    assert "private-injected" not in response.text
    assert len(server.requests) == 1
    assert client.get(f"/api/v1/analyses/{result['analysis_id']}", headers=HEADERS).json() == result


@pytest.mark.parametrize(
    "updates,expected",
    [
        ({"allow_local_model_context": False}, 403),
        ({"allow_local_model_context": 1}, 400),
        ({"allow_local_model_context": "true"}, 400),
        ({"provider": "local", "allow_local_model_context": False}, 400),
        ({"finding_sha256": "a" * 64}, 409),
        ({"analysis_id": str(uuid4())}, 404),
        ({"endpoint": "http://outside.invalid"}, 400),
    ],
)
def test_invalid_or_unconsented_request_does_not_call_model(grounded_api, updates, expected):
    client, _, server, _, _ = grounded_api
    result = analyze(client)
    assert explain(client, result, **updates).status_code == expected
    assert not server.requests


def test_role_before_body_and_shared_slot_are_enforced(grounded_api):
    client, _, server, _, _ = grounded_api
    result = analyze(client)
    path = f"/api/v2/findings/{result['findings'][0]['finding_id']}/explain"
    denied = client.post(path, headers={"Authorization": f"Bearer {READER}"}, content=b"invalid")
    assert denied.status_code == 403
    assert client.post(path, content=b"invalid").status_code == 401
    runtime = client.app.state.local_model
    with runtime.grounded_explanation_provider():
        assert explain(client, result).status_code == 429
    assert not server.requests
    runtime.settings = replace(runtime.settings, allow_grounded_explanation=False)
    assert explain(client, result).status_code == 503 and not server.requests
    assert (
        client.get("/api/v2/explanation-capabilities", headers=HEADERS).json()[
            "grounded_explanation"
        ]
        == "disabled"
    )


@pytest.mark.parametrize(
    "field",
    [
        "source_facts_json",
        "projection_json",
        "facts_binding_sha256",
        "projection_sha256",
        "context_sha256",
        "instructions_sha256",
        "answer_schema_sha256",
        "renderer_policy_sha256",
        "model_answer_sha256",
    ],
)
def test_envelope_rechecks_exact_strings_and_protocol_bindings(grounded_api, field):
    client, _, _, _, _ = grounded_api
    data = explain(client, analyze(client)).json()
    changed = deepcopy(data)
    changed[field] = changed[field] + " " if field.endswith("_json") else "0" * 64
    with pytest.raises(ValidationError):
        GroundedExplanationBundle.model_validate(changed)


@pytest.mark.parametrize("vendor", ["cisco", "juniper"])
@pytest.mark.parametrize("version", ["0.1.0", "0.2.0", "0.3.0"])
@pytest.mark.parametrize("partial", [False, True])
def test_saved_peer_versions_keep_proxy_and_measured_semantics(
    grounded_api, vendor, version, partial
):
    client, _, server, _, _ = grounded_api

    def upload(host, target=False):
        content = (
            f"hostname {host}\nip ssh version 2\nntp server 192.0.2.{99 if target else 10}\n"
            if vendor == "cisco"
            else (
                f"set system host-name {host}\nset system services ssh\n"
                f"set system ntp server 192.0.2.{99 if target else 10}\n"
            )
        ) + ("unsupported private-secret\n" if partial and target else "")
        response = client.post(
            "/api/v1/configurations",
            headers=HEADERS,
            json={
                "device_id": str(uuid4()),
                "filename": "private-input.cfg",
                "content": content,
                "inventory": {
                    "device_role": "edge",
                    "site_class": "branch",
                    "service_profile": "private-profile",
                },
            },
        )
        assert response.status_code == 201, response.text
        return response.json()

    peers = [upload(f"private-peer-{number}") for number in range(3)]
    target = upload("private-target", True)
    response = client.post(
        f"/api/v1/configurations/{target['configuration_id']}/analyze",
        headers=HEADERS,
        json={
            "comparison_version": version,
            "peer_configuration_ids": [row["configuration_id"] for row in peers],
        },
    )
    assert response.status_code == 201, response.text
    result = response.json()
    findings = [item for item in result["findings"] if item["detector"] == "peer_baseline"]
    # Legacy0.1 does not compare NTP, but a sufficiently partial parser yields its proxy finding.
    if not findings:
        assert version == "0.1.0" and not partial
        policy = next(item for item in result["findings"] if item["detector"] == "policy_engine")
        findings = [policy]
    for finding in findings:
        response = explain(client, result, finding)
        assert response.status_code == 200, response.text
        facts = json.loads(response.json()["source_facts_json"])
        if finding["detector"] != "peer_baseline":
            assert facts["selection_facts"]["peer"] is None
            assert facts["analysis_facts"]["peer_report"] is None
            continue
        assert facts["selection_facts"]["peer"]["baseline_version"] == "peer-baseline-" + version
        assert facts["selection_facts"]["peer"]["selected_peer_count"] == 3
        assert (facts["analysis_facts"]["peer_report"] is None) == (version == "0.1.0")
        if partial:
            assert facts["peer"]["method"] == (
                "measured_source_fraction" if version == "0.3.0" else "confidence_deficit_proxy"
            )
            assert (facts["peer"]["command_units"] is not None) == (version == "0.3.0")
    assert all("private-profile" not in json.dumps(request) for request, _ in server.requests)


def upload_owned(client, content, *, device=None):
    response = client.post(
        "/api/v1/configurations",
        headers=HEADERS,
        json={
            "device_id": device or str(uuid4()),
            "filename": "private-source.cfg",
            "content": content,
            "inventory": {
                "device_role": "edge",
                "site_class": "branch",
                "service_profile": "control",
            },
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


@pytest.mark.parametrize("vendor", ["cisco", "juniper"])
@pytest.mark.parametrize("version", ["0.1.0", "0.2.0"])
def test_selected_reference_is_not_approval_or_current_anchor(grounded_api, vendor, version):
    client, _, server, _, _ = grounded_api
    if vendor == "cisco":
        before = "hostname private-reference\nip ssh version 2\n"
        after = "hostname private-reference\nip ssh version 1\n"
    else:
        before = (
            "set system host-name private-reference\nset system services ssh protocol-version v2\n"
        )
        after = (
            "set system host-name private-reference\nset system services ssh protocol-version v1\n"
        )
    if vendor == "cisco":
        before += "interface GigabitEthernet0/1\n ip address 192.0.2.1 255.255.255.0\n!\n"
        after += "interface GigabitEthernet0/1\n ip address 192.0.2.2 255.255.255.0\n!\n"
    else:
        before += "set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24\n"
        after += "set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.2/24\n"
    reference = upload_owned(client, before)
    target = upload_owned(client, after, device=reference["device_id"])
    analyzed = client.post(
        f"/api/v1/configurations/{target['configuration_id']}/analyze",
        headers=HEADERS,
        json={
            "reference_configuration_id": reference["configuration_id"],
            "comparison_version": version,
        },
    )
    assert analyzed.status_code == 201, analyzed.text
    result = analyzed.json()
    findings = [row for row in result["findings"] if row["detector"] == "expected_configuration"]
    assert findings
    for finding in findings:
        response = explain(client, result, finding)
        assert response.status_code == 200, response.text
        bundle = GroundedExplanationBundle.model_validate(response.json())
        facts = bundle.source_facts
        assert facts.reference.source_sha256 == reference["canonical"]["source"]["sha256"]
        assert facts.reference.approval == "not_proven"
        assert all(row.source_sha256 == result["source_sha256"] for row in facts.anchors)
        assert facts.selection_facts.peer is None and facts.analysis_facts.peer_report is None
    assert all("private-reference" not in json.dumps(request) for request, _ in server.requests)


@pytest.mark.parametrize("vendor", ["cisco", "juniper"])
def test_forest_explanation_uses_recorded_scores_without_refit(grounded_api, vendor, monkeypatch):
    client, _, server, _, _ = grounded_api

    def upload(index, count):
        content = (
            f"hostname private-forest-{index}\naaa new-model\nip ssh version 2\n"
            if vendor == "cisco"
            else f"set system host-name private-forest-{index}\nset system services ssh\n"
        )
        for vlan in range(count):
            content += (
                f"vlan {10 + vlan}\n name V{vlan}\n!\n"
                if vendor == "cisco"
                else f"set vlans V{vlan} vlan-id {10 + vlan}\n"
            )
        return upload_owned(client, content)

    training = [upload(index, index % 7 + 1) for index in range(16)]
    trained = client.post(
        "/api/v1/models/isolation-forest",
        headers=HEADERS,
        json={
            "configuration_ids": [row["configuration_id"] for row in training],
        },
    )
    assert trained.status_code == 201, trained.text
    target = upload(999, 40)
    analyzed = client.post(
        f"/api/v1/configurations/{target['configuration_id']}/analyze",
        headers=HEADERS,
        json={"statistical_model_id": trained.json()["model_id"]},
    )
    assert analyzed.status_code == 201, analyzed.text
    result = analyzed.json()
    finding = next(row for row in result["findings"] if row["detector"] == "isolation_forest")
    monkeypatch.setattr("sklearn.ensemble.IsolationForest.fit", lambda *args: pytest.fail("refit"))
    monkeypatch.setattr(
        "sklearn.ensemble.IsolationForest.predict", lambda *args: pytest.fail("rerun")
    )
    response = explain(client, result, finding)
    assert response.status_code == 200, response.text
    bundle = GroundedExplanationBundle.model_validate(response.json())
    facts = bundle.source_facts
    assert facts.forest.raw_anomaly_score == -result["statistical"]["score_samples"]
    assert facts.forest.decision_function == result["statistical"]["decision_function"]
    assert facts.selection_facts.statistical.artifact_sha256 == trained.json()["artifact_sha256"]
    assert "вероятностью" in bundle.presentation.technical_explanation
    assert len(server.requests) == 1


def test_semantic_supplements_do_not_replace_required_sources(grounded_api):
    from test_semantic_explanation_api import ArtificialEncoder

    client, _, server, _, _ = grounded_api
    result = analyze(client)
    selections = []

    def search(catalog, query):
        required = {
            chunk.citation
            for chunk in catalog.retrieve(
                client.app.state.analysis_service.feedback_target(
                    UUID(result["analysis_id"]), UUID(result["findings"][0]["finding_id"])
                )[1]
            )
        }
        chunk = next(item for item in catalog.chunks if item.citation not in required)
        selections.append(query)
        return SimpleNamespace(
            index_sha256="a" * 64,
            encoder=ArtificialEncoder.identity,
            query_sha256=text_sha256(query),
            matches=(SimpleNamespace(document=chunk, cosine_similarity=0.5),),
        )

    client.app.state.document_retrieval = SimpleNamespace(search=search)
    response = explain(client, result, retrieval="semantic_supplement")
    assert response.status_code == 200, response.text
    bundle = GroundedExplanationBundle.model_validate(response.json())
    assert selections and len(server.requests) == 1
    assert bundle.model_answer.citations == list(bundle.semantic_retrieval.required_citations)
    assert bundle.source_facts.documents[-1].role == "supplement"
    assert bundle.documents[-1].citation not in bundle.model_answer.citations
    record = client.app.state.operation_journal.get(UUID(response.headers["X-Operation-Id"]))
    assert bundle.renderer_version in record.completion.result.versions
    assert ArtificialEncoder.identity.pipeline_version in record.completion.result.versions


def test_receipt_failure_prevents_provider_and_completion_failure_does_not_retry(
    grounded_api, monkeypatch
):
    from app.audit.journal import OperationJournal

    client, _, server, _, _ = grounded_api
    result = analyze(client)
    original = OperationJournal.start

    def fail(*args, **kwargs):
        raise RuntimeError("private-failure")

    monkeypatch.setattr(OperationJournal, "start", fail)
    denied = explain(client, result)
    assert denied.status_code == 503 and "private-failure" not in denied.text
    assert not server.requests
    monkeypatch.setattr(OperationJournal, "start", original)
    monkeypatch.setattr(OperationJournal, "complete", fail)
    unconfirmed = explain(client, result)
    assert unconfirmed.status_code == 503 and len(server.requests) == 1
    assert "private-failure" not in unconfirmed.text and "unconfirmed" in unconfirmed.text
