"""Authored ingress contract controls; no SDK, model fitting, or engine execution."""

from datetime import UTC, datetime
from hashlib import sha256
from uuid import uuid4

import pytest
from app.api.source_evidence_decision_scope_contracts import (
    ReviewSourceEvidenceReportV4,
    parse_source_evidence_decision_json,
    source_evidence_decision,
    source_evidence_decision_summary,
    validate_source_evidence_decision,
)
from app.api.source_evidence_scope_contracts import (
    CreateSourceEvidenceReportV4,
    SourceEvidenceReportV4,
    parse_source_evidence_report_json,
    parse_source_evidence_request,
    source_evidence_report,
    source_evidence_summary,
    validate_source_evidence_report,
)
from app.api.source_patch_contracts import source_review_fingerprint
from app.api.source_patch_scope_contracts import (
    SourcePatchIntentV4,
    SourcePatchOutcomeV4,
    SourcePatchVerificationV4,
    VerifySourcePatchV4,
    parse_source_patch_review,
    source_patch_summary,
)
from app.verification.batfish import BatfishResult
from app.verification.ingress_scope import (
    BatfishScopeExecution,
    IngressScopeObservation,
    empty_ingress_scope,
)
from app.verification.ingress_scope_worker import canonical_id, derived_fields, location_rendering
from test_source_priority import inputs, parent, reseal


def authored_scope(result, state="observed"):
    if state in {"unknown", "not_observed"}:
        return empty_ingress_scope(
            result.before_sha256,
            result.after_sha256,
            result.scope,
            result.network_name,
            state=state,
            reason="query_failed" if state == "unknown" else "not_run",
        )
    node = result.scope.start_node
    rows = []
    for interface, prefix in [("GigabitEthernet0/0", "192.0.2.1/24")]:
        text = "owned-opaque-source-ip-space"
        rows.append(
            dict(
                node=node,
                interface=interface,
                canonical_id_sha256=canonical_id(node, interface),
                location_rendering=location_rendering(node, interface),
                active=True,
                switchport=False,
                interface_type="PHYSICAL",
                concrete_ipv4_prefixes=[prefix],
                eligible=True,
                eligibility_reason="active_concrete_ipv4",
                source_ip_rendering=text,
                source_ip_sha256=sha256(text.encode()).hexdigest(),
            )
        )
    before, after = {"interfaces": rows}, {"interfaces": rows}
    if state == "eligibility_unknown":
        before["interfaces"] = [
            rows[0]
            | {
                "concrete_ipv4_prefixes": [],
                "eligible": None,
                "eligibility_reason": "no_concrete_ipv4",
            }
        ]
    return IngressScopeObservation.model_validate(
        dict(
            before_sha256=result.before_sha256,
            after_sha256=result.after_sha256,
            scope=result.scope.model_dump(mode="json"),
            network_name=result.network_name,
            acquisition_state="observed",
            reason="query_completed",
            before=before,
            after=after,
        )
        | derived_fields(before, after)
    )


def scoped_inputs(name="loss", state="observed"):
    value = inputs(name)
    network = value[-1]
    request = VerifySourcePatchV4.model_validate(
        network.intent.request.model_dump()
        | {
            "version": "source-patch-request-0.4.0",
        }
    )
    intent = SourcePatchIntentV4.model_validate(
        network.intent.model_dump()
        | {
            "version": "source-patch-intent-0.4.0",
            "request": request.model_dump(),
        }
    )
    result = BatfishResult.model_validate(
        network.outcome.network_result.model_dump()
        | {
            "network_name": "sentinel-" + "a" * 32,
        }
    )
    execution = network.outcome.network_execution
    scoped = BatfishScopeExecution(
        result=result,
        sdk_version=execution.sdk_version,
        sdk_observation=execution.sdk_observation,
        reachability_impact=execution.reachability_impact,
        ingress_scope=authored_scope(result, state),
    )
    outcome = SourcePatchOutcomeV4(
        verification_id=request.verification_id,
        intent_sha256=source_review_fingerprint(intent),
        completed_at=network.outcome.completed_at,
        network_execution=scoped,
    )
    value[-1] = SourcePatchVerificationV4.from_records(intent, outcome)
    return value


def scoped_parent(value):
    draft, _, deterministic, forest, neural, network = value
    request = CreateSourceEvidenceReportV4(
        report_id=uuid4(),
        draft_sha256=draft.draft_sha256,
        **{
            kind: {
                "record_id": child.verification_id if kind == "network" else child.recheck_id,
                "review_sha256": child.review_sha256,
            }
            if child
            else None
            for kind, child in [
                ("deterministic", deterministic),
                ("forest", forest),
                ("neural", neural),
                ("network", network),
            ]
        },
    )
    value[1] = source_evidence_report(
        draft,
        request,
        deterministic,
        forest=forest,
        neural=neural,
        network=network,
        created_at=datetime.now(UTC),
    )
    return value


def validate_parent(report, value):
    draft, _, deterministic, forest, neural, network = value
    validate_source_evidence_report(
        report,
        draft,
        deterministic,
        forest=forest,
        neural=neural,
        network=network,
    )


@pytest.mark.parametrize("state", ["observed", "unknown", "eligibility_unknown"])
def test_full_scope_survives_source_report_decision_and_summary(state):
    value = scoped_parent(scoped_inputs(state=state))
    report, network = value[1], value[-1]
    assert report.network.ingress_scope == network.outcome.network_execution.ingress_scope
    assert report.network.execution_version == "batfish-execution-0.4.0"
    assert parse_source_patch_review(network).model_dump_json() == network.model_dump_json()
    assert parse_source_evidence_report_json(report.model_dump_json()) == report
    validate_parent(report, value)
    decision = source_evidence_decision(
        report,
        ReviewSourceEvidenceReportV4(
            decision_id=uuid4(),
            report_sha256=report.review_sha256,
            verdict="needs_more_information",
            comment="Authored scope control.",
        ),
        service_role="engineer",
        created_at=datetime.now(UTC),
    )
    validate_source_evidence_decision(decision, report)
    assert parse_source_evidence_decision_json(decision.model_dump_json()) == decision
    assert source_patch_summary(network).version == "source-patch-verification-summary-0.4.0"
    assert source_evidence_summary(report).version == "source-evidence-summary-0.4.0"
    assert (
        source_evidence_decision_summary(decision).version
        == "source-evidence-decision-summary-0.4.0"
    )
    assert report.formal_qualification == "not_proven"
    assert report.approved is report.applied is report.quality_proven is False
    assert decision.approved is decision.applied is decision.individual_identity_verified is False


@pytest.mark.parametrize(
    "field", ["identity", "eligibility", "sets", "hash", "semantic", "coverage"]
)
def test_resealed_false_scope_is_refused(field):
    body = scoped_parent(scoped_inputs())[1].model_dump(mode="json")
    scope = body["network"]["ingress_scope"]
    if field == "identity":
        scope["after"]["interfaces"][0]["canonical_id_sha256"] = "0" * 64
    elif field == "eligibility":
        scope["after"]["interfaces"][0]["eligible"] = False
    elif field == "sets":
        scope["common_eligible"] = []
    elif field == "hash":
        scope["after"]["interfaces"][0]["source_ip_sha256"] = "0" * 64
    else:
        scope["semantic_ip_sets_verified" if field == "semantic" else "complete_flow_coverage"] = (
            True
        )
    with pytest.raises(ValueError):
        SourceEvidenceReportV4.model_validate(reseal(body))


def test_valid_resealed_different_ip_space_requires_exact_saved_child():
    value = scoped_parent(scoped_inputs())
    body = value[1].model_dump(mode="json")
    scope = body["network"]["ingress_scope"]
    row = scope["after"]["interfaces"][0]
    row["source_ip_rendering"] = "different-opaque-space"
    row["source_ip_sha256"] = sha256(row["source_ip_rendering"].encode()).hexdigest()
    scope.update(derived_fields(scope["before"], scope["after"]))
    forged = SourceEvidenceReportV4.model_validate(reseal(body))
    with pytest.raises(ValueError):
        validate_parent(forged, value)


@pytest.mark.parametrize("version", ["0.1.0", "0.2.0", "0.3.0"])
def test_old_reports_replay_without_rewriting_and_reject_new_child(version):
    historical = inputs()
    historical[-1] = None
    parent(historical, version)
    report = historical[1]
    assert (
        parse_source_evidence_report_json(report.model_dump_json()).model_dump_json()
        == report.model_dump_json()
    )
    value = scoped_parent(scoped_inputs())
    request = parse_source_evidence_request(
        value[1].request.model_dump()
        | {
            "version": "source-evidence-request-" + version,
        }
    )
    draft, _, deterministic, forest, neural, network = value
    with pytest.raises(ValueError):
        source_evidence_report(
            draft,
            request,
            deterministic,
            forest=forest,
            neural=neural,
            network=network,
            created_at=datetime.now(UTC),
        )


def test_new_audit_projection_contains_metadata_only():
    from app.audit.results import result_metadata
    from test_source_scope_priority import assessment

    value = scoped_parent(scoped_inputs())
    for record in (value[-1], value[1], assessment(value)):
        metadata = result_metadata(record)
        assert record.version in metadata.versions
        raw = metadata.model_dump_json()
        for excluded in ("ingress_scope", "opaque", "source_ip", "witnesses", "review_json"):
            assert excluded not in raw
