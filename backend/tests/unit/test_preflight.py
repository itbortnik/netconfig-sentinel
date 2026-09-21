"""Before/after local review is never an approval or formal verification."""

from uuid import UUID

import pytest
from app.domain import CanonicalConfig, Vendor
from app.parsers import parse_configuration
from app.verification.preflight import PreflightReport, review_configuration_change

from ml.datasets.laboratory import laboratory_records
from ml.datasets.models import ImportedDatasetRecord
from ml.mutation import MutationType, mutate_configuration

DEVICE = UUID("7f64381c-fda8-48f9-8e8a-fb772b2f64dc")


def _parse(text: str) -> CanonicalConfig:
    return parse_configuration(text, filename="test.cfg")


@pytest.mark.parametrize("vendor", [Vendor.CISCO, Vendor.JUNIPER])
@pytest.mark.parametrize("mutation", [MutationType.AAA_DISABLED, MutationType.TELNET_ENABLED])
def test_preflight_introduces_and_resolves_policy_changes(
    vendor: Vendor, mutation: MutationType
) -> None:
    record = next(item for item in laboratory_records() if item.vendor_hint is vendor)
    sample = mutate_configuration(record, (mutation,), seed=17)
    before, after = _parse(record.sanitized_text), _parse(sample.mutated_text)
    report = review_configuration_change(before, after, device_id=DEVICE, reference_id="lab-v1")
    assert report.policy_changes is not None
    assert report.policy_changes.introduced
    assert any(
        set(item.affected_lines) & set(sample.affected_lines)
        for item in report.policy_changes.introduced
    )
    assert report.reference_status == "completed"
    assert report.current_policy_risk is not None
    assert report.formal_verification == "not_run"
    assert report.ml_status == "not_run"
    assert report.requires_human_review
    assert report.review_status == "needs_review"
    reverse = review_configuration_change(after, before, device_id=DEVICE, reference_id="lab-v1")
    assert reverse.policy_changes is not None
    assert reverse.policy_changes.resolved
    assert report.report_id != reverse.report_id
    assert PreflightReport.model_validate_json(report.model_dump_json()) == report


@pytest.mark.parametrize("vendor", [Vendor.CISCO, Vendor.JUNIPER])
def test_preflight_reference_and_policy_signals_remain_separate(vendor: Vendor) -> None:
    record = next(
        item
        for item in laboratory_records()
        if item.vendor_hint is vendor and item.device_role == "bgp-edge"
    )
    sample = mutate_configuration(record, (MutationType.BGP_REMOTE_AS_MISMATCH,), seed=17)
    report = review_configuration_change(
        _parse(record.sanitized_text),
        _parse(sample.mutated_text),
        device_id=DEVICE,
        reference_id="lab-v1",
    )
    assert report.reference_findings
    assert report.policy_changes is not None
    assert not report.policy_changes.introduced
    assert all(item.detector == "expected_configuration" for item in report.reference_findings)
    assert report.current_policy_risk is not None
    assert all(
        item.finding_id not in component.finding_ids
        for item in report.reference_findings
        for component in report.current_policy_risk.components
    )


@pytest.mark.parametrize("partial_side", ["before", "after"])
def test_partial_parse_retains_findings_but_never_claims_resolution(partial_side: str) -> None:
    text = "hostname edge\nline vty 0 4\n transport input telnet\n"
    complete, partial = _parse(text), _parse(text + "unsupported-command secret-value\n")
    before, after = (partial, complete) if partial_side == "before" else (complete, partial)
    report = review_configuration_change(before, after, device_id=DEVICE, reference_id="old")
    assert report.after_policy_findings
    assert report.policy_changes is None
    assert report.reference_status == "unavailable"
    assert not report.reference_findings
    assert (report.current_policy_risk is None) == (partial_side == "after")
    assert "secret-value" not in report.model_dump_json()
    assert report.review_status == "needs_review"


def test_identical_inputs_stable_report_and_explicit_identity_guards() -> None:
    text = "hostname edge\n"
    first = review_configuration_change(
        _parse(text), _parse(text), device_id=DEVICE, reference_id="v1"
    )
    second = review_configuration_change(
        _parse(text), _parse(text), device_id=DEVICE, reference_id="v1"
    )
    assert first == second
    assert first.policy_changes is not None
    assert not first.policy_changes.introduced and not first.policy_changes.resolved
    assert first.review_status == "needs_review"
    with pytest.raises(ValueError, match="identity"):
        review_configuration_change(
            _parse(text), _parse("hostname other\n"), device_id=DEVICE, reference_id="v1"
        )
    with pytest.raises(ValueError, match="reference ID"):
        review_configuration_change(_parse(text), _parse(text), device_id=DEVICE, reference_id=" ")
    invalid = first.model_dump()
    invalid["formal_verification"] = "passed"
    with pytest.raises(ValueError):
        PreflightReport.model_validate(invalid)


@pytest.mark.parametrize("record", laboratory_records(), ids=lambda item: item.record_id)
def test_all_laboratory_scenarios_unchanged(record: ImportedDatasetRecord) -> None:
    config = _parse(record.sanitized_text)
    report = review_configuration_change(config, config, device_id=DEVICE, reference_id="lab")
    assert report.before.complete and report.after.complete
    assert report.reference_status == "completed"
    assert not report.reference_findings
    assert report.policy_changes is not None
    assert not report.policy_changes.introduced
    assert not report.policy_changes.resolved
    assert len(report.policy_changes.persistent) == len(report.after_policy_findings)


@pytest.mark.parametrize("tamper", ["completeness", "partial", "device", "changes", "catalog"])
def test_report_rejects_inconsistent_serialized_checks(tamper: str) -> None:
    config = _parse("hostname edge\n")
    report = review_configuration_change(config, config, device_id=DEVICE, reference_id="old")
    data = report.model_dump(mode="json")
    if tamper == "completeness":
        data["after"]["unparsed_count"] = 1
    elif tamper == "partial":
        data["after"]["unparsed_count"] = 1
        data["after"]["complete"] = False
    elif tamper == "device":
        data["after_policy_findings"][0]["device_id"] = str(UUID(int=0))
    elif tamper == "changes":
        data["policy_changes"]["persistent"] = []
    else:
        data["policy_catalog_version"] = "different"
    with pytest.raises(ValueError):
        PreflightReport.model_validate(data)


def test_ambiguous_reference_facts_keep_policy_results() -> None:
    record = next(item for item in laboratory_records() if item.device_role == "ospf-core")
    config = _parse(record.sanitized_text)
    assert config.ospf[0].networks
    config.ospf[0].networks.append(config.ospf[0].networks[0].model_copy(deep=True))
    report = review_configuration_change(config, config, device_id=DEVICE, reference_id="old")
    assert report.reference_status == "unavailable"
    assert report.policy_changes is not None
    assert report.current_policy_risk is not None
