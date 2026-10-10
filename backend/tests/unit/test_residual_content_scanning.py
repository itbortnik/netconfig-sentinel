"""Per-occurrence redaction and immutable historical artifact boundaries."""

import hashlib
import json
import runpy
from pathlib import Path

import pytest
from pydantic import ValidationError

from ml.datasets import (
    DatasetQualityReport,
    DatasetUse,
    build_dataset_quality_report,
    deduplicate_dataset,
    load_dataset_artifact,
    scan_sanitized_content,
    split_deduplicated_dataset,
    write_dataset_artifact,
)


def _scan(text: str) -> tuple[tuple[str, str], ...]:
    return scan_sanitized_content(
        text,
        sanitized_sha256=hashlib.sha256(text.encode()).hexdigest(),
        sanitization_version="config-sanitizer-0.1.0",
    )


@pytest.mark.parametrize(
    "text,code",
    (
        (
            "encrypted-password <redacted-secret>; encrypted-password fixture-only-leak;",
            "secret_value",
        ),
        ("password fixture-only-leak; encrypted-password <redacted-secret>;", "secret_value"),
        ("password minimum-length 14; encrypted-password fixture-only-leak;", "secret_value"),
        ("secret fixture-only-leak; password policy <redacted-secret>;", "secret_value"),
        ("password <redacted-secret>fixture-only-leak;", "secret_value"),
        ("password 123 <redacted-secret>;", "secret_value"),
        ("password fixture-only-leak <redacted-secret>;", "secret_value"),
        ("password '<redacted-secret>fixture-only-leak';", "secret_value"),
        ("pre-shared-key ascii-text fixture-only-leak <redacted-secret>;", "secret_value"),
        ("pre-shared-key ascii-text 9 <redacted-secret>;", "secret_value"),
        (
            "snmp community <redacted-community>; snmp community fixture-only-leak;",
            "snmp_community",
        ),
        ("snmp community 123 <redacted-community>;", "snmp_community"),
        ("snmp community <redacted-community>fixture-only-leak;", "snmp_community"),
        ("host-name host-000000000001; host-name fixture-only-leak;", "hostname"),
        ("hostname host-000000000001; host-name fixture-only-leak;", "hostname"),
        ("username user-000000000001; username fixture-only-leak;", "username"),
        ("set system login user user-000000000001; user fixture-only-leak;", "username"),
        ("domain-name domain-000000000001.invalid; domain-name fixture-only-leak;", "domain"),
        ("ip domain name domain-000000000001.invalid; domain-name fixture-only-leak;", "domain"),
        ("contact <redacted-contact>; location fixture-only-leak;", "contact"),
        ("location fixture-only-leak; contact <redacted-contact>;", "contact"),
        ("contact <redacted-contact>fixture-only-leak;", "contact"),
        ("location 123 <redacted-contact>;", "contact"),
    ),
    ids=[f"mixed-or-malformed-{index}" for index in range(23)],
)
def test_a_placeholder_never_exempts_another_recognized_occurrence(text: str, code: str) -> None:
    issues = _scan(text)
    assert f"sanitization.{code}" in {code for code, _ in issues}
    assert all("fixture-only-leak" not in message for _, message in issues)


@pytest.mark.parametrize(
    "text",
    (
        "encrypted-password <redacted-secret>; password <redacted-secret>;",
        "encrypted-password '<redacted-secret>'; password \"<redacted-secret>\";",
        "username user-000000000001 secret 9 <redacted-secret>;",
        "enable password 7 '<redacted-secret>';",
        "password minimum-length 14; encrypted-password <redacted-secret>;",
        "authentication-password <redacted-secret>;",
        "pre-shared-key ascii-text <redacted-secret>;",
        "snmp community '<redacted-community>'; snmp community <redacted-community>;",
        "hostname host-000000000001; host-name host-000000000002;",
        "username user-000000000001; username user-000000000002;",
        "domain-name domain-000000000001.invalid; domain-name domain-000000000002.invalid;",
        "location <redacted-contact>; contact '<redacted-contact>';",
        "-----BEGIN PRIVATE KEY-----\n  <redacted-material>\n-----END PRIVATE KEY-----\n",
        "-----BEGIN CERTIFICATE-----\n<redacted-material>\n-----END CERTIFICATE-----\n",
    ),
    ids=[f"every-occurrence-redacted-{index}" for index in range(14)],
)
def test_each_recognized_occurrence_can_be_independently_sanitized(text: str) -> None:
    assert _scan(text) == ()


@pytest.mark.parametrize(
    "text",
    (
        "-----BEGIN PRIVATE KEY-----\n<redacted-material>\n-----END CERTIFICATE-----\n",
        "-----END PRIVATE KEY-----\n",
        "-----BEGIN PRIVATE KEY-----\n-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----\n",
        "-----BEGIN CERTIFICATE-----\n<redacted-material> fixture-only-leak\n"
        "-----END CERTIFICATE-----\n",
        "-----BEGIN CERTIFICATE-----\nfixture-only-leak <redacted-material>\n"
        "-----END CERTIFICATE-----\n",
    ),
    ids=[f"unsafe-pem-{index}" for index in range(5)],
)
def test_pem_material_and_boundaries_are_checked_exactly(text: str) -> None:
    assert {code for code, _ in _scan(text)} & {
        "sanitization.certificate_material",
        "sanitization.incomplete_certificate_block",
    }


def test_repeated_markers_do_not_create_a_quadratic_exemption_search() -> None:
    text = " ".join(["password <redacted-secret>;"] * 4000)
    assert _scan(text) == ()
    assert {code for code, _ in _scan(text + " password fixture-only-leak;")} == {
        "sanitization.secret_value"
    }
    identities = " ".join(["host-name host-000000000001;"] * 4000)
    assert _scan(identities) == ()
    assert {code for code, _ in _scan(identities + " host-name fixture-only-leak;")} == {
        "sanitization.hostname"
    }


def _legacy_helpers():
    return runpy.run_path(str(Path(__file__).with_name("test_dataset_quality_artifacts.py")))


def _report(records, source):
    dedup = deduplicate_dataset(records)
    split = split_deduplicated_dataset(records, dedup)
    report = build_dataset_quality_report(
        records,
        dedup,
        split,
        sources=[source],
        intended_use=DatasetUse.TRAINING,
        synthetic_anomaly_count=0,
        confirmed_anomaly_count=0,
    )
    return dedup, split, report


def test_new_reports_are_versioned_and_historical_payloads_remain_readable(tmp_path: Path) -> None:
    helpers = _legacy_helpers()
    records = [helpers["_record"](index) for index in range(1, 7)]
    dedup, split, new = _report(records, helpers["_source"]())
    assert new.report_version == "dataset-quality-0.3.0"
    old_payload = new.model_dump(mode="json") | {"report_version": "dataset-quality-0.2.0"}
    old_json = json.dumps(old_payload, sort_keys=True, separators=(",", ":"))
    historical = DatasetQualityReport.model_validate_json(old_json)
    assert historical.model_dump(mode="json") == old_payload
    with pytest.raises(ValidationError):
        DatasetQualityReport.model_validate(
            old_payload | {"report_version": "dataset-quality-0.4.0"}
        )
    result = write_dataset_artifact(
        records,
        dedup,
        split,
        historical,
        output_root=tmp_path,
        artifact_name="old-review-clean-input",
    )
    manifest_before = (result.path / "manifest.json").read_bytes()
    report_before = (result.path / "quality-report.json").read_bytes()
    assert (
        load_dataset_artifact(result.path).pipeline_versions["quality_report"]
        == "dataset-quality-0.2.0"
    )
    assert (result.path / "manifest.json").read_bytes() == manifest_before
    assert (result.path / "quality-report.json").read_bytes() == report_before


def test_a_bound_legacy_report_cannot_bypass_current_checks_when_writing(tmp_path: Path) -> None:
    helpers = _legacy_helpers()
    records = [helpers["_record"](index) for index in range(1, 7)]
    records[0] = helpers["_record"](
        1,
        text=records[0].sanitized_text
        + "encrypted-password <redacted-secret>; encrypted-password fixture-only-leak;\n",
    )
    dedup, split, report = _report(records, helpers["_source"]())
    assert not report.technically_valid
    # Simulate a structurally valid earlier report which did not flag this line.
    payload = report.model_dump(mode="json") | {
        "report_version": "dataset-quality-0.2.0",
        "issues": [],
        "blocking_issue_count": 0,
        "warning_count": 0,
        "technically_valid": True,
    }
    legacy = DatasetQualityReport.model_validate(payload)
    with pytest.raises(ValueError, match="current residual-content checks") as error:
        write_dataset_artifact(
            records, dedup, split, legacy, output_root=tmp_path, artifact_name="must-not-be-created"
        )
    assert "fixture-only-leak" not in str(error.value)
    assert not (tmp_path / "must-not-be-created").exists()
