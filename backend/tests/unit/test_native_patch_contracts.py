"""Native public proof/private retention contracts on actual owned library drafts."""

import json
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from uuid import UUID

import pytest
from app.api.contracts import AnalysisResult, ConfigurationSnapshot
from app.api.model_patch_contracts import fingerprint
from app.api.native_patch_contracts import (
    NATIVE_PATCH_BLOCKERS,
    GenerateNativePatch,
    NativePatchBudgetError,
    NativePatchCandidate,
    NativePatchPrivate,
    NativePatchSelection,
    NativePatchSummary,
    native_patch_candidate,
    native_patch_fingerprint,
    native_patch_selection,
    native_patch_summary,
    validate_native_patch_parent,
)
from app.detection.fusion import RiskSource, fuse_risk
from app.detection.policy_engine import evaluate_policies
from app.domain import Finding
from app.explanation.local import explain_finding
from app.parsers import parse_configuration
from app.patching.vendor_drafts import create_vendor_draft
from app.verification.policy_changes import compare_policy_findings
from pydantic import ValidationError

DEVICE = UUID("dd465488-0abe-4374-9e5f-44c269a83ee2")
CONFIGURATION = UUID("3c99ee1e-c1d1-4c79-9534-00f7414e549c")
ANALYSIS = UUID("b1890810-ae49-42ed-bfd4-49b0fbb8f27c")
CANDIDATE = UUID("fc314104-a596-4c73-bbcf-44fd0ea4d9ad")
CREATED = datetime(2026, 10, 26, tzinfo=UTC)
CISCO = (
    "hostname owned\r\naaa new-model\r\nip ssh version 2\r\n"
    "username owned secret 0 private-password\r\nline vty 0 4\r\n"
    "\ttransport  input   telnet ssh \t\r\n!\r\n"
)
JUNOS = "set system host-name owned\nset system services ssh\nset system services telnet\n"


def make_case(source=CISCO):
    canonical = parse_configuration(source, filename="before.cfg", collected_at=CREATED)
    snapshot = ConfigurationSnapshot(
        configuration_id=CONFIGURATION,
        device_id=DEVICE,
        created_at=CREATED,
        canonical=canonical,
    )
    findings = tuple(evaluate_policies(canonical, device_id=DEVICE))
    analysis = AnalysisResult(
        analysis_id=ANALYSIS,
        configuration_id=CONFIGURATION,
        device_id=DEVICE,
        source_sha256=canonical.source.sha256,
        created_at=CREATED + timedelta(seconds=1),
        status="completed",
        policy_catalog_version="policy-rules-0.7.0",
        findings=findings,
        explanations=tuple(explain_finding(row, canonical) for row in findings),
        risk=fuse_risk(findings, device_id=DEVICE, completed_detectors=[RiskSource.POLICY]),
        limitations=("Owned unit input; not independent quality evidence.",),
    )
    selection = native_patch_selection(snapshot, analysis)
    pin = selection.finding_pins[0]
    request = GenerateNativePatch(
        version="native-patch-request-0.1.0",
        candidate_id=CANDIDATE,
        analysis_id=analysis.analysis_id,
        finding_id=pin.finding_id,
        analysis_sha256=selection.analysis_sha256,
        finding_sha256=pin.finding_sha256,
        source_sha256=canonical.source.sha256,
        canonical_sha256=selection.canonical_sha256,
        policy_catalog_version="policy-rules-0.7.0",
        allow_local_native_generation=True,
        allow_private_candidate_retention=True,
    )
    finding = next(row for row in findings if row.finding_id == request.finding_id)
    generated = create_vendor_draft(
        source,
        finding=finding,
        source_sha256=request.source_sha256,
        reference_id=str(CONFIGURATION),
    )
    public = native_patch_candidate(
        CONFIGURATION,
        request,
        snapshot,
        analysis,
        generated.metadata,
        created_at=CREATED + timedelta(seconds=2),
        service_role="engineer",
    )
    private = NativePatchPrivate(
        public=public,
        generated_metadata=generated.metadata,
        before_text=source,
        candidate_text=generated.candidate_text,
    )
    return snapshot, analysis, generated, request, public, private


def rehash(payload):
    payload = dict(payload)
    payload.pop("review_json", None)
    payload.pop("review_sha256", None)
    proof = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return {**payload, "review_json": proof, "review_sha256": sha256(proof.encode()).hexdigest()}


@pytest.fixture(scope="module")
def case():
    return make_case()


@pytest.mark.parametrize("source", [CISCO, JUNOS])
def test_actual_draft_public_proof_private_text_and_summary_round_trip(source):
    snapshot, analysis, generated, request, public, private = make_case(source)
    assert NativePatchCandidate.model_validate_json(public.model_dump_json()) == public
    assert NativePatchPrivate.model_validate_json(private.model_dump_json()) == private
    assert public.metadata == generated.metadata
    assert public.native_commands == generated.metadata.native_commands
    assert public.validation_blockers == NATIVE_PATCH_BLOCKERS
    assert public.metadata.review.validation_blockers != public.validation_blockers
    assert public.request == request
    assert json.loads(public.review_json) == public.model_dump(
        mode="json", exclude={"review_json", "review_sha256"}
    )
    assert sha256(public.review_json.encode()).hexdigest() == public.review_sha256
    assert "private-password" not in public.model_dump_json()
    assert source == private.before_text
    if source == CISCO:
        assert "private-password" in private.candidate_text
        assert "private-password" not in repr(private)
    validate_native_patch_parent(public, snapshot, analysis)
    summary = native_patch_summary(public)
    assert NativePatchSummary.model_validate_json(summary.model_dump_json()) == summary
    assert summary.analysis_id == analysis.analysis_id
    assert summary.finding_id == request.finding_id
    assert summary.review_sha256 == public.review_sha256
    assert summary.status == "needs_review"
    assert not summary.individual_identity_verified and not summary.approved and not summary.applied


def test_selection_is_server_derived_and_uses_historical_fingerprint_convention(case):
    snapshot, analysis, _, request, _, _ = case
    selection = native_patch_selection(snapshot, analysis)
    assert NativePatchSelection.model_validate_json(selection.model_dump_json()) == selection
    assert selection.analysis_sha256 == fingerprint(analysis) == native_patch_fingerprint(analysis)
    assert selection.finding_pins[0].finding_id == request.finding_id
    assert selection.finding_pins[0].finding_sha256 == request.finding_sha256
    assert selection.canonical_sha256 == request.canonical_sha256
    assert not hasattr(selection.source, "canonical_sha256")
    assert "private-password" not in selection.model_dump_json()


@pytest.mark.parametrize(
    "field",
    [
        "version",
        "allow_local_native_generation",
        "allow_private_candidate_retention",
    ],
)
def test_explicit_request_version_and_both_consents_are_required(case, field):
    payload = case[3].model_dump(mode="json")
    payload.pop(field)
    with pytest.raises(ValidationError):
        GenerateNativePatch.model_validate(payload)


@pytest.mark.parametrize(
    "field",
    [
        "allow_local_native_generation",
        "allow_private_candidate_retention",
    ],
)
@pytest.mark.parametrize("value", [False, 0, 1, "true", "false", None])
def test_consent_never_coerces_numbers_strings_or_false(case, field, value):
    with pytest.raises(ValidationError):
        GenerateNativePatch.model_validate({**case[3].model_dump(), field: value})


@pytest.mark.parametrize("field", ["content", "candidate_text", "baseline", "model", "edit"])
def test_client_cannot_supply_content_or_unversioned_extra_fields(case, field):
    with pytest.raises(ValidationError):
        GenerateNativePatch.model_validate({**case[3].model_dump(), field: "unexpected"})


@pytest.mark.parametrize(
    "field",
    [
        "calibrated",
        "quality_proven",
        "individual_identity_verified",
        "approved",
        "applied",
    ],
)
@pytest.mark.parametrize("value", [0, 1, True, "false"])
def test_public_assurances_require_exact_false_even_on_forged_typed_copy(case, field, value):
    public = case[4]
    for damaged in (
        public.model_copy(update={field: value}),
        rehash({**public.model_dump(mode="json"), field: value}),
    ):
        with pytest.raises(ValidationError):
            NativePatchCandidate.model_validate(damaged)
        if isinstance(damaged, NativePatchCandidate):
            with pytest.raises(ValidationError):
                native_patch_summary(damaged)


@pytest.mark.parametrize(
    "field",
    [
        "application_supported",
        "device_syntax_verified",
        "management_access_verified",
    ],
)
def test_legacy_metadata_flags_are_strict_at_new_serialized_and_typed_boundary(case, field):
    public, private = case[4:]
    bad_metadata = public.metadata.model_copy(update={field: 0})
    bad_public = public.model_copy(update={"metadata": bad_metadata})
    with pytest.raises(ValidationError, match="assurance"):
        NativePatchCandidate.model_validate(bad_public)
    with pytest.raises(ValidationError, match="assurance"):
        NativePatchPrivate.model_validate(
            private.model_copy(update={"generated_metadata": bad_metadata})
        )
    payload = public.model_dump(mode="json")
    payload["metadata"][field] = 0
    with pytest.raises(ValidationError, match="assurance"):
        NativePatchCandidate.model_validate(rehash(payload))


@pytest.mark.parametrize(
    "path,value",
    [
        (("requires_human_review",), 1),
        (("before", "complete"), 1),
        (("after", "complete"), "true"),
    ],
)
def test_nested_legacy_assurance_flags_are_not_silently_coerced(case, path, value):
    payload = case[4].model_dump(mode="json")
    report = payload["metadata"]["review"]["preflight"]
    target = report
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    with pytest.raises(ValidationError):
        NativePatchCandidate.model_validate(rehash(payload))


@pytest.mark.parametrize(
    "field,value",
    [
        ("candidate_id", str(UUID(int=99))),
        ("configuration_id", str(UUID(int=99))),
        ("native_commands", ["reload"]),
        ("validation_blockers", []),
        ("service_role", "reader"),
        ("generator_version", "future-generator"),
        ("status", "approved"),
        ("formal_qualification", "proven"),
    ],
)
def test_rehashing_does_not_erase_public_binding_or_status_failures(case, field, value):
    with pytest.raises(ValidationError):
        NativePatchCandidate.model_validate(
            rehash({**case[4].model_dump(mode="json"), field: value})
        )


def test_proof_covers_nested_payload_and_exact_canonical_json(case):
    payload = case[4].model_dump(mode="json")
    payload["selected_finding"]["remediation"] = "Changed saved finding."
    with pytest.raises(ValidationError):
        NativePatchCandidate.model_validate(payload)
    for updates in ({"review_json": "{}"}, {"review_sha256": "f" * 64}):
        with pytest.raises(ValidationError, match="proof"):
            NativePatchCandidate.model_validate({**case[4].model_dump(), **updates})


@pytest.mark.parametrize("field", ["analysis_created_at", "created_at"])
def test_public_times_require_timezone_and_chronological_binding(case, field):
    payload = case[4].model_dump(mode="json")
    for value in ("2026-10-26T00:00:00", "2026-10-25T00:00:00Z"):
        with pytest.raises(ValidationError):
            NativePatchCandidate.model_validate(rehash({**payload, field: value}))


def test_nested_snapshot_time_cannot_become_naive(case):
    payload = case[4].model_dump(mode="json")
    payload["source"]["created_at"] = "2026-10-26T00:00:00"
    with pytest.raises(ValidationError):
        NativePatchCandidate.model_validate(rehash(payload))


def test_parent_checks_are_saved_data_only_even_when_runtime_helpers_are_forbidden(
    case, monkeypatch
):
    def forbidden(*args, **kwargs):
        pytest.fail("historical proof attempted fresh execution")

    for name in (
        "app.parsers.parse_configuration",
        "app.detection.policy_engine.evaluate_policies",
        "app.patching.vendor_drafts.create_vendor_draft",
        "app.patching.vendor_drafts.check_vendor_draft",
        "app.patching.vendor_drafts._cisco_telnet",
        "app.patching.vendor_drafts._simple_edits",
        "app.patching.vendor_drafts.parse_configuration",
        "app.patching.vendor_drafts.evaluate_policies",
    ):
        monkeypatch.setattr(name, forbidden)
    snapshot, analysis, _, _, public, private = case
    validate_native_patch_parent(public, snapshot, analysis)
    assert NativePatchPrivate.model_validate_json(private.model_dump_json()) == private
    assert native_patch_summary(public).candidate_id == public.candidate_id
    assert native_patch_selection(snapshot, analysis).analysis_id == analysis.analysis_id


@pytest.mark.parametrize("change", ["snapshot_id", "device", "canonical", "partial", "time"])
def test_parent_rejects_changed_snapshot_or_incomplete_history(case, change):
    snapshot, analysis, _, _, public, _ = case
    if change == "snapshot_id":
        snapshot = snapshot.model_copy(update={"configuration_id": UUID(int=99)})
    elif change == "device":
        snapshot = snapshot.model_copy(update={"device_id": UUID(int=99)})
    elif change == "canonical":
        canonical = snapshot.canonical.model_copy(
            update={
                "device": snapshot.canonical.device.model_copy(update={"site_class": "changed"})
            }
        )
        snapshot = snapshot.model_copy(update={"canonical": canonical})
    elif change == "partial":
        canonical = snapshot.canonical.model_copy(update={"parser_confidence": 0.9})
        snapshot = snapshot.model_copy(update={"canonical": canonical})
    else:
        snapshot = snapshot.model_copy(update={"created_at": CREATED.replace(tzinfo=None)})
    with pytest.raises(ValueError):
        validate_native_patch_parent(public, snapshot, analysis)


@pytest.mark.parametrize(
    "field,value",
    [
        ("analysis_id", UUID(int=99)),
        ("created_at", CREATED + timedelta(seconds=3)),
        ("configuration_id", UUID(int=99)),
        ("source_sha256", "f" * 64),
        ("policy_catalog_version", "policy-rules-0.6.0"),
    ],
)
def test_parent_rejects_changed_analysis_bindings(case, field, value):
    snapshot, analysis, _, _, public, _ = case
    with pytest.raises(ValueError):
        validate_native_patch_parent(public, snapshot, analysis.model_copy(update={field: value}))


def test_private_rejects_metadata_divergence_and_unrelated_retained_edits(case):
    private = case[5]
    for update in (
        {"before_text": private.before_text + "!"},
        {
            "candidate_text": private.candidate_text.replace(
                "private-password", "different-password"
            )
        },
        {"candidate_text": private.candidate_text + "ntp server 192.0.2.1\n"},
    ):
        with pytest.raises(ValidationError):
            NativePatchPrivate.model_validate(private.model_copy(update=update))


def test_private_checks_the_separate_saved_metadata_even_when_it_is_internally_valid(case):
    private = case[5]
    payload = private.generated_metadata.model_dump()
    payload["review"]["preflight"]["limitations"] += ("Changed saved limitation.",)
    metadata = type(private.generated_metadata).model_validate(payload)
    with pytest.raises(ValidationError, match="private metadata differs"):
        NativePatchPrivate.model_validate(
            private.model_copy(update={"generated_metadata": metadata})
        )


def test_parent_matches_entire_saved_policy_map_not_just_the_selected_finding(case):
    snapshot, analysis, _, _, public, _ = case
    payload = public.model_dump(mode="json")
    report = payload["metadata"]["review"]["preflight"]
    other = next(
        row
        for row in report["before_policy_findings"]
        if row["category"] != "management.telnet_enabled"
    )
    other["remediation"] = "Changed nonselected saved policy finding."
    report["policy_changes"] = compare_policy_findings(
        tuple(Finding.model_validate(row) for row in report["before_policy_findings"]),
        tuple(Finding.model_validate(row) for row in report["after_policy_findings"]),
        device_id=DEVICE,
    ).model_dump(mode="json")
    damaged = NativePatchCandidate.model_validate(rehash(payload))
    with pytest.raises(ValueError, match="saved parents"):
        validate_native_patch_parent(damaged, snapshot, analysis)


@pytest.mark.parametrize(
    "field,value",
    [
        ("analysis_id", UUID(int=99)),
        ("analysis_sha256", "f" * 64),
        ("finding_id", UUID(int=99)),
        ("finding_sha256", "f" * 64),
        ("source_sha256", "f" * 64),
        ("canonical_sha256", "f" * 64),
    ],
)
def test_builder_rejects_every_stale_request_pin(case, field, value):
    snapshot, analysis, generated, request, _, _ = case
    with pytest.raises(ValueError):
        native_patch_candidate(
            CONFIGURATION,
            request.model_copy(update={field: value}),
            snapshot,
            analysis,
            generated.metadata,
            created_at=CREATED + timedelta(seconds=2),
            service_role="admin",
        )


def test_summary_requires_version_and_revalidates_typed_nested_request(case):
    summary = native_patch_summary(case[4]).model_dump(mode="json")
    summary.pop("version")
    with pytest.raises(ValidationError):
        NativePatchSummary.model_validate(summary)
    request = case[3].model_copy(update={"allow_local_native_generation": 1})
    with pytest.raises(ValidationError, match="exact true consent"):
        native_patch_summary(case[4].model_copy(update={"request": request}))


def test_byte_and_full_payload_budgets_are_enforced_with_generic_errors(case, monkeypatch):
    import app.api.native_patch_contracts as contracts

    with pytest.raises(ValidationError, match="budget") as caught:
        NativePatchPrivate.model_validate(
            case[5].model_copy(update={"before_text": "я" * 1_048_577})
        )
    assert any(
        isinstance(error.get("ctx", {}).get("error"), NativePatchBudgetError)
        for error in caught.value.errors()
    )
    monkeypatch.setattr(contracts, "MAX_NATIVE_PATCH_REVIEW_BYTES", 1)
    with pytest.raises(ValidationError, match="proof exceeds budget"):
        NativePatchCandidate.model_validate(case[4])


@pytest.mark.parametrize(
    "name", ["MAX_NATIVE_PATCH_PUBLIC_BYTES", "MAX_NATIVE_PATCH_PRIVATE_BYTES"]
)
def test_serialized_dto_budgets_are_separate(case, monkeypatch, name):
    import app.api.native_patch_contracts as contracts

    monkeypatch.setattr(contracts, name, 1)
    with pytest.raises(ValidationError, match="exceeds budget"):
        NativePatchPrivate.model_validate(case[5])
