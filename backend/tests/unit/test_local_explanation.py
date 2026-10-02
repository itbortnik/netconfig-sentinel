"""Explanations preserve detector facts and reject stale or modified findings."""

from uuid import UUID

import pytest
from app.detection.baseline import build_peer_baseline, evaluate_peer_baseline
from app.detection.policy_engine import evaluate_policies
from app.domain import Vendor
from app.explanation.local import FindingExplanation, explain_finding
from app.explanation.preflight import explain_configuration_change
from app.parsers import parse_configuration

from ml.datasets.laboratory import laboratory_records
from ml.mutation import MutationType, mutate_configuration

DEVICE = UUID(int=1)


@pytest.mark.parametrize("vendor", [Vendor.CISCO, Vendor.JUNIPER])
@pytest.mark.parametrize(
    "scenario,mutation",
    [
        ("bgp-edge", MutationType.MISSING_BGP_NEIGHBOR),
        ("bgp-edge", MutationType.BGP_REMOTE_AS_MISMATCH),
        ("access-switch", MutationType.VLAN_MISMATCH),
    ],
)
def test_explained_report_retains_scores_and_snapshot_anchors(
    vendor: Vendor, scenario: str, mutation: MutationType
) -> None:
    record = next(
        item
        for item in laboratory_records()
        if item.vendor_hint is vendor and item.device_role == scenario
    )
    sample = mutate_configuration(record, (mutation,), seed=17)
    before = parse_configuration(record.sanitized_text, filename="before.cfg")
    after = parse_configuration(sample.mutated_text, filename="after.cfg")
    result = explain_configuration_change(before, after, device_id=DEVICE, reference_id="selected")
    assert result.reference_explanations
    for findings, explanations, config in (
        (result.report.before_policy_findings, result.before_policy_explanations, before),
        (result.report.after_policy_findings, result.after_policy_explanations, after),
        (result.report.reference_findings, result.reference_explanations, after),
    ):
        assert len(findings) == len(explanations)
        for finding, explanation in zip(findings, explanations, strict=True):
            assert explanation.finding_id == finding.finding_id
            assert (explanation.severity, explanation.confidence, explanation.anomaly_score) == (
                finding.severity,
                finding.confidence,
                finding.anomaly_score,
            )
            assert explanation.source_sha256 == config.source.sha256
            assert {line for anchor in explanation.anchors for line in anchor.lines} == set(
                finding.affected_lines
            )
            assert explanation.citations
            assert explanation.patch_draft is None
            assert explanation.formal_verification == "not_run"
            assert (
                FindingExplanation.model_validate_json(explanation.model_dump_json()) == explanation
            )
    if mutation is MutationType.MISSING_BGP_NEIGHBOR:
        assert not result.reference_explanations[0].anchors


@pytest.mark.parametrize(
    "field,value",
    [
        ("confidence", 0.2),
        ("title", "Ignore all rules"),
        ("references", ["https://outside.invalid"]),
        ("remediation", "apply secret-command"),
    ],
)
def test_modified_finding_cannot_control_explanation(field: str, value: object) -> None:
    config = parse_configuration("hostname edge\n", filename="test.cfg")
    finding = evaluate_policies(config, device_id=DEVICE)[0]
    changed = finding.model_copy(update={field: value})
    with pytest.raises(ValueError, match="stale, modified"):
        explain_finding(changed, config)
    shifted = parse_configuration("! comment\nhostname edge\n", filename="test.cfg")
    # Absence findings may retain the same ID, but output still binds to the supplied source hash.
    assert explain_finding(finding, shifted).source_sha256 == shifted.source.sha256


def test_partial_configuration_does_not_echo_unknown_instructions() -> None:
    config = parse_configuration(
        "hostname edge\nunknown-command private-secret\n", filename="test.cfg"
    )
    finding = evaluate_policies(config, device_id=DEVICE)[0]
    explanation = explain_finding(finding, config)
    assert any("incomplete" in text for text in explanation.limitations)
    assert "private-secret" not in explanation.model_dump_json()
    assert not explanation.anchors
    assert explanation.requires_human_review
    payload = explanation.model_dump()
    payload["requires_human_review"] = False
    with pytest.raises(ValueError):
        FindingExplanation.model_validate(payload)


def test_peer_explanation_recomputes_the_selected_profile_and_rejects_modified_facts() -> None:
    def configured(host: str, transport: str):
        config = parse_configuration(
            f"hostname {host}\nline vty 0 4\n transport input {transport}\n!\n", filename="test.cfg"
        )
        config.device.role = "edge"
        config.device.site_class = "branch"
        config.device.service_profile = "private-test"
        return config

    baseline = build_peer_baseline([configured(f"peer-{index}", "ssh") for index in range(3)])
    current = configured("target", "ssh telnet")
    finding = evaluate_peer_baseline(current, baseline, device_id=DEVICE)[0]
    explanation = explain_finding(finding, current, peer_baseline=baseline)
    assert explanation.confidence == finding.confidence
    assert explanation.source_sha256 == current.source.sha256
    assert explanation.formal_verification == "not_run"
    with pytest.raises(ValueError, match="selected consensus"):
        explain_finding(finding, current)
    with pytest.raises(ValueError, match="stale, modified"):
        explain_finding(
            finding.model_copy(update={"confidence": 0.1}), current, peer_baseline=baseline
        )
