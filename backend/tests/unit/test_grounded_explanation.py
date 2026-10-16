"""Pure authored saved records: closed choices, privacy, exact bytes and no model calls."""

import json
from dataclasses import replace
from uuid import UUID

import pytest
from app.domain import Evidence, Finding, Severity, SourceLocation
from app.domain.fingerprints import finding_fingerprint
from app.explanation import grounded_explanation as grounded
from app.explanation.facts import (
    ExplanationAnalysisFacts,
    ExplanationInvocationFacts,
    PeerReportFacts,
)
from app.explanation.grounded_explanation import (
    GroundedExplanationAnswer,
    GroundedExplanationFacts,
    GroundedExplanationPresentation,
    GroundedSelectionFacts,
    PeerSelectionFacts,
    ReferenceSelectionFacts,
    StatisticalSelectionFacts,
    available_fact_refs,
    generate_grounded_explanation,
    grounded_prompt_for_facts,
    prepare_grounded_explanation,
    recheck_grounded_explanation,
    validate_grounded_explanation_answer,
)
from app.explanation.knowledge import (
    knowledge_version_for_finding,
    load_knowledge_catalog,
    text_sha256,
)
from app.explanation.local import EvidenceAnchor, FindingExplanation
from app.explanation.provider import SYSTEM_INSTRUCTIONS, DraftAnswer, InvalidProviderAnswer

SOURCE = "a" * 64
REFERENCE = "b" * 64
BASELINE = "c" * 64
STATEMENT = "d" * 64
ARTIFACT = "e" * 64
PRIVATE = "private-sentinel-never-export"
FAMILIES = (
    "policy",
    "reference1",
    "reference2",
    "forest",
    "peer1",
    "peer2",
    "peer3",
    "proxy1",
    "proxy2",
    "measured",
)


def inputs(family="policy", vendor="cisco", *, selected=True, anchors=True):
    detector = "policy_engine"
    version = "policy-rules-0.7.0"
    category = "management.telnet_enabled"
    observed = {"management.telnet_enabled": True}
    expected = {"management.telnet_enabled": False}
    report = None
    selection = GroundedSelectionFacts()
    status = "partial" if family in {"proxy1", "proxy2", "measured"} else "completed"
    if family.startswith("reference"):
        detector = "expected_configuration"
        version = "expected-config-0.1.0" if family == "reference1" else "expected-config-0.2.0"
        category = "baseline.expected.bgp.remote_as"
        observed = {
            "object_key": [PRIVATE],
            "present": True,
            "value": 65003,
            "source_sha256": SOURCE,
        }
        expected = {
            "object_key": [PRIVATE],
            "present": True,
            "value": None,
            "reference_id": PRIVATE,
            "source_sha256": REFERENCE,
            "reference_lines": [2, 3],
        }
        selection = GroundedSelectionFacts(
            reference=ReferenceSelectionFacts(source_sha256=REFERENCE)
        )
    elif family == "forest":
        detector, version, category = (
            "isolation_forest",
            "isolation-forest-0.1.0",
            "statistical.configuration_outlier",
        )
        observed = {
            "model_id": PRIVATE,
            "artifact_sha256": ARTIFACT,
            "raw_anomaly_score": 0.73,
            "decision_function": -0.07,
            "top_feature_deviations": [{"feature": PRIVATE, "observed": 9.0}],
        }
        expected = {
            "decision_function": ">= 0",
            "training_score_min": 0.4,
            "training_score_max": 0.8,
            "training_sample_count": 5,
        }
        selection = GroundedSelectionFacts(
            statistical=StatisticalSelectionFacts(
                training_sample_count=5,
                raw_anomaly_score=0.73,
                decision_function=-0.07,
                artifact_sha256=ARTIFACT,
            )
        )
    elif family.startswith(("peer", "proxy")) or family == "measured":
        detector = "peer_baseline"
        suffix = "3" if family == "measured" else family[-1]
        version = f"peer-baseline-0.{suffix}.0"
        category = "baseline.management.ssh_enabled_deviation"
        expected = {"peer_support_count": 3, "peer_sample_count": 3}
        if suffix == "1":
            observed = {"management.ssh_enabled": False}
            expected["management.ssh_enabled"] = True
        else:
            observed = {"value": False, "source_sha256": SOURCE}
            expected.update(value=True, feature="management.ssh_enabled", baseline_sha256=BASELINE)
            report = PeerReportFacts(
                version=f"peer-comparison-report-0.{suffix}.0",
                status=status,
                selected_peer_count=3,
                profile_feature_count=19,
                compared_feature_count=19 if status == "completed" else 0,
                skipped_feature_count=0 if status == "completed" else 19,
            )
        if family.startswith("proxy"):
            category = "baseline.parser.unsupported_ratio_high"
            observed = (
                {"unsupported_ratio": 0.25}
                if suffix == "1"
                else {
                    "value": 0.25,
                    "source_sha256": SOURCE,
                }
            )
            expected = {"maximum_unsupported_ratio": 0.1, "peer_median": 0.0}
            if suffix != "1":
                expected["baseline_sha256"] = BASELINE
        elif family == "measured":
            category = "baseline.parser.unparsed_fraction_high"
            observed = {
                "value": 0.25,
                "source_sha256": SOURCE,
                "coverage_report_sha256": "f" * 64,
                "unit": "adapter_source_lines",
                "adapter_version": (
                    "cisco-ios-source-lines-0.1.0"
                    if vendor == "cisco"
                    else "junos-source-lines-0.1.0"
                ),
                "unparsed_units": 1,
                "command_units": 4,
            }
            expected = {
                "baseline_sha256": BASELINE,
                "maximum_unparsed_fraction": 0.1,
                "peer_median": 0.0,
            }
        selection = GroundedSelectionFacts(
            peer=PeerSelectionFacts(
                baseline_version=version,
                selected_peer_count=3,
                profile_feature_count=14 if suffix == "1" else 19,
                baseline_sha256=None if suffix == "1" else BASELINE,
            )
        )
    finding = Finding(
        finding_id=UUID(int=1),
        device_id=UUID(int=2),
        detector=detector,
        category=category,
        title=PRIVATE,
        severity=Severity.MEDIUM,
        confidence=0.8,
        anomaly_score=0.7,
        affected_lines=[2] if anchors else [],
        evidence=[
            Evidence(
                kind=PRIVATE,
                message=PRIVATE,
                source_location=(
                    SourceLocation(
                        source_lines=[2],
                        raw_text_hash=STATEMENT,
                        parser_confidence=1.0,
                    )
                    if anchors
                    else None
                ),
            )
        ],
        observed=observed,
        expected=expected,
        remediation=PRIVATE,
        limitations=[PRIVATE],
        references=[PRIVATE],
        model_version=version,
    )
    catalog = load_knowledge_catalog(knowledge_version_for_finding(finding))
    chunks = catalog.retrieve(finding)
    explanation = FindingExplanation(
        finding_id=finding.finding_id,
        device_id=finding.device_id,
        finding_sha256=finding_fingerprint(finding),
        source_sha256=SOURCE,
        detector_version=version,
        severity=finding.severity,
        confidence=finding.confidence,
        anomaly_score=finding.anomaly_score,
        summary=PRIVATE,
        technical_explanation=PRIVATE,
        recommendation=PRIVATE,
        anchors=(
            (
                EvidenceAnchor(
                    source_sha256=SOURCE,
                    lines=(2,),
                    statement_sha256=STATEMENT,
                ),
            )
            if anchors
            else ()
        ),
        citations=tuple(chunk.citation for chunk in chunks),
        limitations=(PRIVATE,),
    )
    return dict(
        finding=finding,
        explanation=explanation,
        chunks=chunks,
        vendor=vendor,
        platform="ios" if vendor == "cisco" else "junos",
        parser_confidence=1.0,
        warning_count=0,
        unparsed_count=0,
        knowledge_version=catalog.version,
        knowledge_sha256=catalog.sha256,
        required_citations=tuple(c.citation for c in chunks),
        analysis_facts=ExplanationAnalysisFacts(analysis_status=status, peer_report=report),
        invocation_facts=ExplanationInvocationFacts(
            entrypoint="saved_analysis_http",
            analysis_storage="stored_analysis",
            model_answer_storage="not_stored_in_analysis",
            selected_finding_peer_profile_storage=(
                "stored_in_analysis" if detector == "peer_baseline" else "not_applicable"
            ),
        ),
        selection_facts=selection if selected else None,
    )


def changed_finding(data, **updates):
    finding = data["finding"].model_copy(update=updates)
    return data | {
        "finding": finding,
        "explanation": data["explanation"].model_copy(
            update={
                "finding_sha256": finding_fingerprint(finding),
            }
        ),
    }


def choices(prepared, **updates):
    context = json.loads(prepared.prompt.context_json)
    return {
        "version": "grounded-explanation-answer-0.1.0",
        "facts_binding_sha256": prepared.facts_binding_sha256,
        "fact_refs": list(available_fact_refs(prepared.source_facts)),
        "recommendation_code": context["recommendation_code"],
        "missing_information_codes": [],
        "citations": context["required_citations"],
        "patch_draft": None,
        "requires_human_review": True,
    } | updates


def generated(prepared, **updates):
    return validate_grounded_explanation_answer(
        json.dumps(choices(prepared, **updates)).encode(), prepared
    )


@pytest.mark.parametrize("family", FAMILIES)
@pytest.mark.parametrize("vendor", ["cisco", "juniper"])
def test_all_supported_saved_families_render_exact_bound_facts_without_model(family, vendor):
    data = inputs(family, vendor)
    original = data["finding"].model_dump_json()
    prepared = prepare_grounded_explanation(**data)
    result = generated(prepared)
    assert result.source_facts_json == prepared.source_facts_json
    assert text_sha256(result.source_facts_json) == result.facts_binding_sha256
    assert text_sha256(result.projection_json) == result.projection_sha256
    assert (
        GroundedExplanationFacts.model_validate_json(result.source_facts_json)
        == result.source_facts
    )
    assert (
        GroundedExplanationPresentation.model_validate_json(result.projection_json)
        == result.presentation
    )
    assert result.presentation.patch_draft is None
    assert result.presentation.requires_human_review is True
    assert result.presentation.assumptions == ()
    assert result.presentation.missing_information
    assert PRIVATE not in prepared.prompt.context_json
    assert PRIVATE not in result.source_facts_json
    assert PRIVATE not in result.projection_json
    assert "formal verification" in result.presentation.technical_explanation
    assert "gateway" in result.presentation.technical_explanation
    assert "подписью" in result.presentation.technical_explanation
    assert prepared.prompt.context_sha256 == text_sha256(prepared.prompt.context_json)
    assert prepared.instructions_sha256 == text_sha256(prepared.prompt.instructions)
    assert prepared.answer_schema_sha256 == text_sha256(prepared.prompt.answer_schema_json)
    assert data["finding"].model_dump_json() == original
    assert generated(prepared).projection_json == result.projection_json


def test_missing_historical_metadata_stays_missing_without_dropping_recorded_values():
    legacy = prepare_grounded_explanation(**inputs("peer1", selected=False))
    assert legacy.source_facts.analysis_facts.peer_report is None
    assert legacy.source_facts.selection_facts.peer is None
    assert legacy.source_facts.peer.sample_count == 3
    assert "peer_report" not in available_fact_refs(legacy.source_facts)
    assert "selected_peer_profile" not in available_fact_refs(legacy.source_facts)
    assert "не предоставлен" in generated(legacy).presentation.technical_explanation
    data = inputs("forest", selected=False)
    data = changed_finding(
        data,
        observed={
            key: value
            for key, value in data["finding"].observed.items()
            if key not in {"model_id", "artifact_sha256"}
        },
    )
    forest = prepare_grounded_explanation(**data)
    assert forest.source_facts.forest.training_sample_count == 5
    assert forest.source_facts.selection_facts.statistical is None


@pytest.mark.parametrize("family", FAMILIES)
def test_prompt_replays_from_public_ledger_without_native_finding(family):
    data = inputs(family)
    prepared = prepare_grounded_explanation(**data)
    ledger = GroundedExplanationFacts.model_validate_json(prepared.source_facts_json)
    assert grounded_prompt_for_facts(ledger, data["chunks"]) == prepared.prompt
    context = json.loads(prepared.prompt.context_json)
    assert context["fact_authorities"]["observed_values"] == "saved_finding"
    assert context["fact_authorities"]["invocation_scope"] == "current_invocation"


@pytest.mark.parametrize(
    "updates",
    [
        {"observed": {"native-private-key": True}},
        {"expected": {"field_0001": PRIVATE}},
        {"verification_scope": {"vendor_syntax": "passed"}},
        {"category": PRIVATE},
        {"interpretation": "statistical_control"},
    ],
)
def test_prompt_replay_rejects_private_values_or_contradictory_scope(updates):
    data = inputs()
    prepared = prepare_grounded_explanation(**data)
    with pytest.raises(ValueError):
        grounded_prompt_for_facts(prepared.source_facts.model_copy(update=updates), data["chunks"])


@pytest.mark.parametrize("present,value", [(True, None), (False, None), (True, False), (True, 0)])
def test_reference_presence_null_and_anchors_remain_distinct(present, value):
    data = inputs("reference1", anchors=False)
    data = changed_finding(
        data,
        observed={
            **data["finding"].observed,
            "present": present,
            "value": value,
        },
    )
    prepared = prepare_grounded_explanation(**data)
    assert prepared.source_facts.reference.observed_present is present
    assert prepared.source_facts.anchors == ()
    assert prepared.source_facts.reference.reference_lines == (2, 3)
    result = generated(prepared)
    assert "не придумана" in result.presentation.technical_explanation
    assert "reference approval=not_proven" in result.presentation.technical_explanation


def test_proxy_and_measured_same_fraction_cannot_exchange_interpretation_or_counts():
    proxy = prepare_grounded_explanation(**inputs("proxy2"))
    measured = prepare_grounded_explanation(**inputs("measured"))
    assert proxy.source_facts.peer.observed_fraction == measured.source_facts.peer.observed_fraction
    assert proxy.source_facts.peer.command_units is None
    assert measured.source_facts.peer.command_units == 4
    assert proxy.source_facts.interpretation == "peer_confidence_deficit_proxy"
    assert measured.source_facts.interpretation == "peer_measured_source_fraction"
    assert "не измеренная" in generated(proxy).presentation.technical_explanation
    assert "unparsed=1; command units=4" in generated(measured).presentation.technical_explanation
    assert "compared=0; skipped=19" in generated(measured).presentation.technical_explanation


@pytest.mark.parametrize("value", [1e-7, 0.00001, -0.0])
def test_normative_json_preserves_float_bytes_and_uses_own_presentation(value):
    data = inputs("forest")
    data = changed_finding(data, observed={**data["finding"].observed, "decision_function": value})
    data["selection_facts"] = GroundedSelectionFacts(
        statistical=StatisticalSelectionFacts(
            training_sample_count=5,
            raw_anomaly_score=0.73,
            decision_function=value,
            artifact_sha256=ARTIFACT,
        )
    )
    prepared = prepare_grounded_explanation(**data)
    assert f'"decision_function":{json.dumps(value)}' in prepared.source_facts_json
    assert f'"decision_function":{json.dumps(value)}' in prepared.prompt.context_json
    assert generated(prepared).presentation.version == grounded.RENDERER_VERSION


@pytest.mark.parametrize(
    "field,value",
    [
        ("warning_count", True),
        ("warning_count", 1.0),
        ("unparsed_count", "1"),
        ("parser_confidence", True),
        ("parser_confidence", float("nan")),
        ("parser_confidence", float("inf")),
        ("warning_count", -1),
    ],
)
def test_invalid_parser_types_fail_before_coercion(field, value):
    with pytest.raises(ValueError):
        prepare_grounded_explanation(**(inputs() | {field: value}))


@pytest.mark.parametrize(
    "family,key,value",
    [
        ("peer1", "peer_sample_count", True),
        ("peer2", "peer_support_count", 3.0),
        ("forest", "training_sample_count", "5"),
    ],
)
def test_nested_finding_counts_are_checked_before_domain_coercion(family, key, value):
    data = inputs(family)
    data = changed_finding(data, expected={**data["finding"].expected, key: value})
    with pytest.raises(ValueError):
        prepare_grounded_explanation(**data)


@pytest.mark.parametrize("kind", ["confidence", "anomaly_score", "affected_lines", "anchors"])
def test_unvalidated_copy_cannot_smuggle_bool_numeric_identity(kind):
    data = inputs()
    if kind == "anchors":
        data["explanation"] = data["explanation"].model_copy(
            update={
                "anchors": (data["explanation"].anchors[0].model_copy(update={"lines": (True,)}),),
            }
        )
    else:
        data = changed_finding(data, **{kind: [True] if kind == "affected_lines" else True})
    with pytest.raises(ValueError):
        prepare_grounded_explanation(**data)


@pytest.mark.parametrize(
    "updates",
    [
        {"summary": "Formal verification passed"},
        {"approved": True},
        {"severity": "low"},
        {"fact_refs": ["unknown"]},
        {"fact_refs": ["selected_finding", "selected_finding"]},
        {"fact_refs": ["selected_reference"]},
        {"recommendation_code": "review_reference"},
        {"missing_information_codes": ["reference_approval"]},
        {"missing_information_codes": ["vendor_syntax", "vendor_syntax"]},
        {"citations": []},
        {"citations": ["https://outside.invalid"]},
        {"patch_draft": "configure terminal"},
        {"requires_human_review": 1},
        {"requires_human_review": False},
        {"facts_binding_sha256": "0" * 64},
        {"version": "grounded-explanation-answer-0.2.0"},
    ],
)
def test_closed_answer_rejects_prose_forged_facts_codes_or_approval(updates):
    prepared = prepare_grounded_explanation(**inputs())
    with pytest.raises(InvalidProviderAnswer):
        generated(prepared, **updates)


@pytest.mark.parametrize(
    "raw",
    [b"null", b"[]", b"{}", b"invalid", b"\xff", b"x" * 32769],
    ids=["null", "array", "missing", "invalid", "non_utf8", "oversized"],
)
def test_invalid_answers_are_not_replaced(raw):
    with pytest.raises(InvalidProviderAnswer):
        validate_grounded_explanation_answer(raw, prepare_grounded_explanation(**inputs()))


def test_duplicate_wire_keys_and_missing_required_citation_are_rejected():
    prepared = prepare_grounded_explanation(**inputs("peer1"))
    raw = json.dumps(choices(prepared)).encode()
    with pytest.raises(InvalidProviderAnswer):
        validate_grounded_explanation_answer(
            raw.replace(b'{"version":', b'{"version":"x","version":'), prepared
        )
    with pytest.raises(InvalidProviderAnswer):
        generated(prepared, citations=choices(prepared)["citations"][:1])


def test_required_sealed_release_supplements_and_authority_are_checked():
    data = inputs()
    catalog = load_knowledge_catalog(data["knowledge_version"])
    extra = next(
        chunk for chunk in catalog.chunks if chunk.citation not in data["required_citations"]
    )
    prepared = prepare_grounded_explanation(**(data | {"chunks": (*data["chunks"], extra)}))
    assert prepared.source_facts.documents[-1].role == "supplement"
    with pytest.raises(InvalidProviderAnswer):
        generated(prepared, citations=[extra.citation])
    changed = data["chunks"][0].model_copy(
        update={
            "content": "Forged project source",
            "content_sha256": text_sha256("Forged project source"),
        }
    )
    for updates in (
        {"chunks": (changed,)},
        {"knowledge_sha256": "0" * 64},
        {"knowledge_version": "project-knowledge-0.1.0"},
        {"required_citations": (extra.citation,)},
        {"chunks": (extra, *data["chunks"])},
    ):
        with pytest.raises(ValueError):
            prepare_grounded_explanation(**(data | updates))


@pytest.mark.parametrize(
    "kind",
    [
        "facts_json",
        "facts_hash",
        "facts_copy",
        "context",
        "instructions",
        "schema",
        "context_hash",
        "renderer",
        "renderer_hash",
        "instructions_hash",
        "schema_hash",
        "input",
    ],
)
def test_prepared_tamper_is_rejected_before_any_provider_call(kind):
    prepared = prepare_grounded_explanation(**inputs())
    if kind == "facts_json":
        prepared = replace(prepared, source_facts_json=prepared.source_facts_json + " ")
    elif kind == "facts_hash":
        prepared = replace(prepared, facts_binding_sha256="0" * 64)
    elif kind == "facts_copy":
        changed = prepared.source_facts.model_copy(
            update={"parser": prepared.source_facts.parser.model_copy(update={"confidence": True})}
        )
        prepared = replace(prepared, source_facts=changed)
    elif kind in {"context", "instructions", "schema", "context_hash"}:
        key = {
            "context": "context_json",
            "instructions": "instructions",
            "schema": "answer_schema_json",
            "context_hash": "context_sha256",
        }[kind]
        prepared = replace(prepared, prompt=replace(prepared.prompt, **{key: "changed"}))
    elif kind == "input":
        prepared._inputs.finding.observed["injected"] = PRIVATE
    else:
        key = {
            "renderer": "renderer_version",
            "renderer_hash": "renderer_policy_sha256",
            "instructions_hash": "instructions_sha256",
            "schema_hash": "answer_schema_sha256",
        }[kind]
        prepared = replace(prepared, **{key: "changed"})

    class Provider:
        calls = 0

        def generate(self, prompt):
            self.calls += 1
            return b"null"

    provider = Provider()
    with pytest.raises(ValueError):
        generate_grounded_explanation(provider, prepared, allow_local_context=True)
    assert provider.calls == 0


def test_mutable_ledger_and_renderer_policy_cannot_bypass_recheck(monkeypatch):
    prepared = prepare_grounded_explanation(**inputs())
    prepared.source_facts.observed["changed"] = True
    with pytest.raises(ValueError):
        recheck_grounded_explanation(prepared)
    prepared = prepare_grounded_explanation(**inputs())
    monkeypatch.setitem(grounded._RENDER_POLICY, "scope", "Changed policy")
    with pytest.raises(ValueError):
        recheck_grounded_explanation(prepared)


def test_exact_consent_single_call_after_provider_recheck_and_sanitized_failure():
    prepared = prepare_grounded_explanation(**inputs())

    class Provider:
        calls = 0

        def generate(self, prompt):
            assert prompt == prepared.prompt
            self.calls += 1
            return json.dumps(choices(prepared)).encode()

    provider = Provider()
    for permission in (False, 1, "true", None):
        with pytest.raises(ValueError):
            generate_grounded_explanation(provider, prepared, allow_local_context=permission)
    assert provider.calls == 0
    assert generate_grounded_explanation(provider, prepared, allow_local_context=True).presentation
    assert provider.calls == 1

    class MutatingProvider:
        def generate(self, prompt):
            prepared.source_facts.observed["changed"] = True
            return json.dumps(choices(prepared)).encode()

    with pytest.raises(ValueError):
        generate_grounded_explanation(MutatingProvider(), prepared, allow_local_context=True)
    fresh = prepare_grounded_explanation(**inputs())

    class FailingProvider:
        def generate(self, prompt):
            raise RuntimeError(PRIVATE)

    with pytest.raises(InvalidProviderAnswer, match=r"^Grounded explanation provider failed\.$"):
        generate_grounded_explanation(FailingProvider(), fresh, allow_local_context=True)


def test_selection_binding_rejects_cross_finding_counts_hashes_and_branches():
    for family, selection in (
        (
            "policy",
            GroundedSelectionFacts(reference=ReferenceSelectionFacts(source_sha256=REFERENCE)),
        ),
        (
            "peer2",
            GroundedSelectionFacts(
                peer=PeerSelectionFacts(
                    baseline_version="peer-baseline-0.2.0",
                    selected_peer_count=4,
                    profile_feature_count=19,
                    baseline_sha256=BASELINE,
                )
            ),
        ),
        (
            "forest",
            GroundedSelectionFacts(
                statistical=StatisticalSelectionFacts(
                    training_sample_count=5,
                    raw_anomaly_score=0.73,
                    decision_function=-0.08,
                    artifact_sha256=ARTIFACT,
                )
            ),
        ),
    ):
        with pytest.raises(ValueError):
            prepare_grounded_explanation(**(inputs(family) | {"selection_facts": selection}))


@pytest.mark.parametrize(
    "key,value",
    [
        ("unparsed_units", True),
        ("command_units", 4.0),
        ("command_units", 0),
        ("value", float("nan")),
        ("value", float("inf")),
        ("value", True),
        ("unparsed_units", 2),
        ("adapter_version", "junos-source-lines-0.1.0"),
    ],
)
def test_measured_record_requires_exact_counts_fraction_and_platform(key, value):
    data = inputs("measured")
    data = changed_finding(data, observed={**data["finding"].observed, key: value})
    with pytest.raises(ValueError):
        prepare_grounded_explanation(**data)


@pytest.mark.parametrize("present,value", [(1, None), (False, 4)])
def test_reference_does_not_coerce_presence_or_attach_values_to_absence(present, value):
    data = inputs("reference1")
    data = changed_finding(
        data,
        observed={
            **data["finding"].observed,
            "present": present,
            "value": value,
        },
    )
    with pytest.raises(ValueError):
        prepare_grounded_explanation(**data)


def test_raw_copied_selection_count_and_mismatched_report_scope_are_rejected():
    data = inputs("peer2")
    data["selection_facts"] = data["selection_facts"].model_copy(
        update={
            "peer": data["selection_facts"].peer.model_copy(update={"selected_peer_count": True})
        }
    )
    with pytest.raises(ValueError):
        prepare_grounded_explanation(**data)
    data = inputs("peer2")
    data["analysis_facts"] = ExplanationAnalysisFacts(
        analysis_status="partial",
        peer_report=PeerReportFacts(
            version="peer-comparison-report-0.2.0",
            status="partial",
            selected_peer_count=3,
            profile_feature_count=19,
            compared_feature_count=0,
            skipped_feature_count=19,
        ),
    )
    with pytest.raises(ValueError):
        prepare_grounded_explanation(**data)


def test_unavailable_offline_context_is_not_promoted_to_saved_http():
    data = inputs("policy") | {"analysis_facts": None, "invocation_facts": None}
    prepared = prepare_grounded_explanation(**data)
    assert prepared.source_facts.analysis_facts.analysis_status == "not_supplied"
    assert prepared.source_facts.invocation_facts.entrypoint == "not_supplied"
    assert generated(prepared).presentation.summary.startswith("not_supplied:")


def test_report_and_current_anchor_source_cannot_be_swapped():
    data = inputs("peer2")
    data["analysis_facts"] = ExplanationAnalysisFacts(
        analysis_status="completed",
        peer_report=PeerReportFacts(
            version="peer-comparison-report-0.3.0",
            status="completed",
            selected_peer_count=3,
            profile_feature_count=19,
            compared_feature_count=19,
            skipped_feature_count=0,
        ),
    )
    with pytest.raises(ValueError):
        prepare_grounded_explanation(**data)
    data = inputs("reference1")
    data["explanation"] = data["explanation"].model_copy(
        update={
            "anchors": (
                data["explanation"].anchors[0].model_copy(update={"source_sha256": REFERENCE}),
            )
        }
    )
    with pytest.raises(ValueError):
        prepare_grounded_explanation(**data)


def test_minimal_model_choices_cannot_suppress_mandatory_facts_or_unknowns():
    prepared = prepare_grounded_explanation(**inputs("measured"))
    result = generated(prepared, fact_refs=["selected_finding"], missing_information_codes=[])
    text = result.presentation.technical_explanation
    assert "unparsed=1; command units=4" in text
    assert "compared=0; skipped=19" in text
    assert "selection bias" in text
    assert "management access" in text
    assert len(result.presentation.missing_information) >= 6
    assert result.presentation.assumptions == ()


def test_legacy_instructions_and_schemas_are_untouched_by_new_protocol():
    old_schema = json.dumps(DraftAnswer.model_json_schema(), sort_keys=True)
    old_instructions = SYSTEM_INSTRUCTIONS
    prepared = prepare_grounded_explanation(**inputs())
    assert generated(prepared).presentation.version != "local-explanation-0.1.0"
    assert prepared.prompt.instructions != old_instructions
    assert prepared.prompt.answer_schema_json == json.dumps(
        GroundedExplanationAnswer.model_json_schema(),
        sort_keys=True,
    )
    assert json.dumps(DraftAnswer.model_json_schema(), sort_keys=True) == old_schema
    assert SYSTEM_INSTRUCTIONS == old_instructions
