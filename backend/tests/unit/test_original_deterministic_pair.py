"""Authored original profiles and saved JSON replay; no ML, HTTP or approval claim."""

from datetime import timedelta
from uuid import uuid4

import pytest
from app.api.contracts import AnalysisOptions, AnalysisResult, InventoryLabels, UploadConfiguration
from app.api.service import AnalysisService
from app.core.settings import ApiSettings
from app.db.migrate import upgrade_database
from app.db.store import Store
from app.detection.baseline.pair import (
    prepare_original_reference,
    recheck_original_deterministic,
    require_original_deterministic_context,
)
from app.detection.fusion import RiskSource, fuse_risk
from app.detection.policy_engine import evaluate_policies
from app.explanation.local import explain_finding
from cryptography.fernet import Fernet


def text(vendor, hostname, address=None, telnet=False):
    if vendor == "cisco":
        return (
            f"hostname {hostname}\nip ssh version 2\nline vty 0 4\n transport input "
            + ("telnet ssh" if telnet else "ssh")
            + "\n!\n"
            + (
                f"interface GigabitEthernet0/1\n ip address 192.0.2.{address} 255.255.255.0\n!\n"
                if address
                else ""
            )
        )
    return (
        f"set system host-name {hostname}\nset system services ssh\n"
        + ("set system services telnet\n" if telnet else "")
        + (
            f"set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.{address}/24\n"
            if address
            else ""
        )
    )


@pytest.fixture
def prepared(tmp_path):
    store = Store(
        ApiSettings(
            f"sqlite:///{tmp_path / 'deterministic.sqlite3'}",
            "owned-original-deterministic-unit-token-00001",
            Fernet.generate_key().decode(),
        )
    )
    upgrade_database(store.engine)
    service = AnalysisService(store)

    def prepare(vendor="cisco", version="0.3.0", cohort="combined"):
        def upload(hostname, address=None, telnet=False, device=None):
            return service.upload(
                UploadConfiguration(
                    device_id=device or uuid4(),
                    filename="owned.cfg",
                    content=text(vendor, hostname, address, telnet),
                    inventory=InventoryLabels(
                        device_role="edge", site_class="branch", service_profile="authored-control"
                    ),
                )
            )

        peers = [upload(f"peer-{index}") for index in range(3)]
        reference = upload("target", 10)
        before = upload("target", 12, True, reference.device_id)
        after = upload("target", 13, False, reference.device_id)
        analysis = service.analyze(
            before.configuration_id,
            AnalysisOptions(
                reference_configuration_id=(
                    reference.configuration_id if cohort in {"reference_only", "combined"} else None
                ),
                peer_configuration_ids=(
                    tuple(peer.configuration_id for peer in peers)
                    if cohort in {"peers_only", "combined"}
                    else ()
                ),
                comparison_version=version,
            ),
        )
        assert analysis is not None
        # Saved untyped observation arrays must compare by exact normative JSON.
        saved = store.get_analysis(analysis.analysis_id)
        assert saved is not None
        return before, after, saved, reference if cohort in {"reference_only", "combined"} else None

    try:
        yield prepare
    finally:
        store.close()


@pytest.mark.parametrize("vendor", ["cisco", "juniper"])
@pytest.mark.parametrize("version", ["0.1.0", "0.2.0", "0.3.0"])
@pytest.mark.parametrize("cohort", ["reference_only", "peers_only", "combined"])
def test_original_saved_reference_and_profile_are_reused(prepared, vendor, version, cohort):
    before, after, analysis, reference = prepared(vendor, version, cohort)
    result = recheck_original_deterministic(before, after, analysis, reference)
    assert (result.before.reference_findings is not None) == (reference is not None)
    assert (result.after.peer_findings is not None) == (cohort != "reference_only")
    if reference is not None:
        assert result.reference.source_sha256 == reference.canonical.source.sha256
        assert result.reference.source_sha256 != before.canonical.source.sha256
        assert result.after.reference_findings
        assert any("192.0.2.10" in str(item.expected) for item in result.after.reference_findings)
        assert any("192.0.2.13" in str(item.observed) for item in result.after.reference_findings)
    assert any(
        item.category == "management.telnet_enabled" for item in result.policy_changes.resolved
    )


def test_policy_only_preserves_not_selected(prepared):
    before, after, analysis, reference = prepared(cohort="policy_only")
    result = recheck_original_deterministic(before, after, analysis, reference)
    assert result.before.reference_findings is result.after.reference_findings is None
    assert result.before.peer_findings is result.after.peer_findings is None
    assert result.before.peer_evaluation is result.after.peer_evaluation is None


@pytest.mark.parametrize(
    "case",
    [
        "wrong_source",
        "wrong_device",
        "same_snapshot",
        "missing_ref",
        "wrong_group",
        "partial",
        "reverse_time",
    ],
)
def test_binding_mismatch_refuses_before_comparison(prepared, case):
    before, after, analysis, reference = prepared()
    if case == "wrong_source":
        analysis = analysis.model_copy(update={"source_sha256": "a" * 64})
    elif case == "wrong_device":
        after = after.model_copy(update={"device_id": uuid4()})
    elif case == "same_snapshot":
        after = before
    elif case == "wrong_group":
        after = after.model_copy(
            update={
                "canonical": after.canonical.model_copy(
                    update={"device": after.canonical.device.model_copy(update={"role": "core"})}
                )
            }
        )
    elif case == "partial":
        after = after.model_copy(
            update={"canonical": after.canonical.model_copy(update={"parser_confidence": 0.5})}
        )
    elif case == "reverse_time":
        after = after.model_copy(update={"created_at": before.created_at - timedelta(seconds=1)})
    else:
        reference = None
    with pytest.raises(ValueError):
        recheck_original_deterministic(before, after, analysis, reference)


def test_changed_original_observation_refuses_before_after_output(prepared):
    before, after, analysis, reference = prepared()
    first, *others = analysis.findings
    first = first.model_copy(update={"observed": {"changed": "authored"}})
    analysis = analysis.model_copy(update={"findings": (first, *others)})
    with pytest.raises(ValueError):
        recheck_original_deterministic(before, after, analysis, reference)


def test_unselected_reference_is_not_silently_accepted(prepared):
    before, after, analysis, _reference = prepared(cohort="policy_only")
    with pytest.raises(ValueError):
        recheck_original_deterministic(before, after, analysis, before)


def test_new_execution_rejects_unknown_catalog_before_any_evaluation(prepared, monkeypatch):
    _before, _after, analysis, _reference = prepared(cohort="policy_only")
    changed = analysis.model_copy(update={"policy_catalog_version": "unavailable-catalog"})
    monkeypatch.setattr(
        "app.detection.baseline.pair.evaluate_policies", lambda *a, **k: pytest.fail("evaluation")
    )
    with pytest.raises(ValueError, match="catalog is unavailable"):
        require_original_deterministic_context(changed)


def test_new_execution_rejects_unknown_legacy_profile_version(prepared):
    _before, _after, analysis, _reference = prepared(version="0.1.0", cohort="peers_only")
    profile = analysis.comparison.peer_baseline.model_copy(
        update={"model_version": "unavailable-peer-algorithm"}
    )
    changed = analysis.model_copy(
        update={"comparison": analysis.comparison.model_copy(update={"peer_baseline": profile})}
    )
    with pytest.raises(ValueError, match="profile version is unavailable"):
        require_original_deterministic_context(changed)


def test_freezing_original_reference_does_not_evaluate_target(prepared, monkeypatch):
    before, _after, analysis, reference = prepared()
    for name in (
        "evaluate_policies",
        "compare_expanded_reference",
        "evaluate_measured_peer_baseline",
    ):
        monkeypatch.setattr(
            f"app.detection.baseline.pair.{name}", lambda *a, **k: pytest.fail("evaluation")
        )
    projection = prepare_original_reference(before, analysis, reference)
    assert projection.source_sha256 == reference.canonical.source.sha256


@pytest.mark.parametrize("vendor", ["cisco", "juniper"])
def test_actual_historical_policy_catalog_is_replayed(prepared, vendor):
    before, after, analysis, _reference = prepared(vendor, cohort="policy_only")
    catalog = "policy-rules-0.6.0"
    findings = tuple(
        evaluate_policies(before.canonical, device_id=before.device_id, catalog_version=catalog)
    )
    # Authored library history from real old rules; no claim of an earlier HTTP run.
    old = analysis.model_copy(
        update={
            "policy_catalog_version": catalog,
            "findings": findings,
            "explanations": tuple(explain_finding(item, before.canonical) for item in findings),
            "risk": fuse_risk(
                findings, device_id=before.device_id, completed_detectors=[RiskSource.POLICY]
            ),
        }
    )
    old = AnalysisResult.model_validate_json(old.model_dump_json())
    result = recheck_original_deterministic(before, after, old)
    assert result.before.policy_findings
    assert all(
        item.model_version == catalog
        for item in result.before.policy_findings + result.after.policy_findings
    )
