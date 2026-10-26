"""Immutable, source-bound ordinary native candidates; no execution or approval."""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import datetime
from hashlib import sha256
from typing import Annotated, Any, Final, Literal, Self
from uuid import UUID

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from app.api.contracts import AnalysisResult, ConfigurationSnapshot, SnapshotBinding
from app.domain import Finding
from app.domain.fingerprints import finding_fingerprint
from app.ingestion.source_retention import canonical_fingerprint
from app.patching.vendor_drafts import VendorDraft

Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
MAX_NATIVE_PATCH_REVIEW_BYTES = 512 * 1024
MAX_NATIVE_PATCH_PUBLIC_BYTES = 2 * 1024 * 1024
MAX_NATIVE_PATCH_PRIVATE_BYTES = 8 * 1024 * 1024
MAX_NATIVE_PATCH_CIPHERTEXT_BYTES = 12 * 1024 * 1024
MAX_NATIVE_PATCH_TEXT_BYTES = 2 * 1024 * 1024
NATIVE_PATCH_BLOCKERS = (
    "formal_verification_not_run",
    "device_syntax_not_verified",
    "management_access_not_verified",
    "rollback_not_verified",
    "baseline_approval_not_proven",
    "independent_quality_not_proven",
    "individual_engineer_review_required",
)
CATALOG_VERSION = "policy-rules-0.7.0"
GENERATOR_VERSION: Final = "native-telnet-generator-0.1.0"


class NativePatchBudgetError(ValueError):
    """A native artifact exceeds a versioned byte/line budget."""


def _plain(value: Any) -> Any:
    """Discard trusted typed-instance shortcuts, including nested model_copy data."""
    if isinstance(value, BaseModel):
        return _plain(value.model_dump(mode="python"))
    if isinstance(value, Mapping):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_plain(item) for item in value]
    return value


def _metadata_flags(value: Any) -> None:
    """Legacy DTOs coerce some bools; require exact booleans at the new boundary."""
    if not isinstance(value, Mapping):
        return
    for key in ("application_supported", "device_syntax_verified", "management_access_verified"):
        if key in value and value[key] is not False:
            raise ValueError("native metadata assurance flags must be exact false")
    review = value.get("review", {})
    if not isinstance(review, Mapping):
        return
    report = review.get("preflight", {})
    if not isinstance(report, Mapping):
        return
    if "requires_human_review" in report and report["requires_human_review"] is not True:
        raise ValueError("native metadata requires exact human review")
    for name in ("before", "after"):
        summary = report.get(name, {})
        if (
            isinstance(summary, Mapping)
            and "complete" in summary
            and (type(summary["complete"]) is not bool)
        ):
            raise ValueError("native metadata parse flags require exact booleans")


def _json(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False
    )


def native_patch_fingerprint(value: BaseModel) -> str:
    """Use the established analysis/finding fingerprint convention unchanged."""
    return sha256(
        json.dumps(value.model_dump(mode="json"), sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    ).hexdigest()


class _FrozenNative(BaseModel):
    model_config = ConfigDict(
        extra="forbid", frozen=True, allow_inf_nan=False, revalidate_instances="always"
    )

    @model_validator(mode="before")
    @classmethod
    def serialized_inputs(cls, value: Any) -> Any:
        value = _plain(value)
        if isinstance(value, Mapping):
            for name in ("metadata", "generated_metadata"):
                _metadata_flags(value.get(name))
        return value


class GenerateNativePatch(_FrozenNative):
    version: Literal["native-patch-request-0.1.0"]
    candidate_id: UUID
    analysis_id: UUID
    finding_id: UUID
    analysis_sha256: Digest
    finding_sha256: Digest
    source_sha256: Digest
    canonical_sha256: Digest
    policy_catalog_version: Literal["policy-rules-0.7.0"]
    allow_local_native_generation: Literal[True]
    allow_private_candidate_retention: Literal[True]

    @field_validator(
        "allow_local_native_generation", "allow_private_candidate_retention", mode="before"
    )
    @classmethod
    def explicit_consent(cls, value: Any) -> Any:
        if value is not True:
            raise ValueError("native generation and private retention require exact true consent")
        return value


class NativeFindingPin(_FrozenNative):
    finding_id: UUID
    finding_sha256: Digest


class NativePatchSelection(_FrozenNative):
    version: Literal["native-patch-selection-0.1.0"] = "native-patch-selection-0.1.0"
    configuration_id: UUID
    source: SnapshotBinding
    canonical_sha256: Digest
    analysis_id: UUID
    analysis_sha256: Digest
    analysis_created_at: AwareDatetime
    policy_catalog_version: Literal["policy-rules-0.7.0"]
    finding_pins: tuple[NativeFindingPin, ...] = Field(max_length=128)

    @model_validator(mode="after")
    def bound_selection(self) -> Self:
        if self.configuration_id != self.source.configuration_id or (
            len({pin.finding_id for pin in self.finding_pins}) != len(self.finding_pins)
            or self.analysis_created_at < self.source.created_at
        ):
            raise ValueError("native selection bindings differ")
        return self


class NativePatchCandidate(_FrozenNative):
    version: Literal["native-patch-candidate-0.1.0"] = "native-patch-candidate-0.1.0"
    candidate_id: UUID
    configuration_id: UUID
    request: GenerateNativePatch
    source: SnapshotBinding
    analysis_created_at: AwareDatetime
    selected_finding: Finding
    created_at: AwareDatetime
    service_role: Literal["engineer", "admin"]
    generator_kind: Literal["deterministic_vendor"] = "deterministic_vendor"
    generator_version: Literal["native-telnet-generator-0.1.0"] = GENERATOR_VERSION
    metadata: VendorDraft
    native_commands: tuple[str, ...]
    local_reference: Literal["selected_original_not_approved_baseline"] = (
        "selected_original_not_approved_baseline"
    )
    status: Literal["needs_review"] = "needs_review"
    formal_qualification: Literal["not_proven"] = "not_proven"
    calibrated: Literal[False] = False
    quality_proven: Literal[False] = False
    individual_identity_verified: Literal[False] = False
    approved: Literal[False] = False
    applied: Literal[False] = False
    validation_blockers: tuple[str, ...] = NATIVE_PATCH_BLOCKERS
    review_json: str = Field(repr=False)
    review_sha256: Digest

    @field_validator(
        "calibrated",
        "quality_proven",
        "individual_identity_verified",
        "approved",
        "applied",
        mode="before",
    )
    @classmethod
    def exact_false(cls, value: Any) -> Any:
        if value is not False:
            raise ValueError("native assurance flags must be exact false")
        return value

    @model_validator(mode="after")
    def bound_candidate(self) -> Self:
        request, selected = self.request, self.selected_finding
        review, proposal = self.metadata.review, self.metadata.review.proposal
        report = review.preflight
        if (
            self.candidate_id != request.candidate_id
            or self.configuration_id != self.source.configuration_id
            or self.source.source_sha256 != request.source_sha256
            or self.source.created_at > self.created_at
            or self.analysis_created_at > self.created_at
            or self.analysis_created_at < self.source.created_at
            or selected.finding_id != request.finding_id
            or finding_fingerprint(selected) != request.finding_sha256
            or selected.device_id != self.source.device_id
            or selected.detector != "policy_engine"
            or selected.category != "management.telnet_enabled"
            or selected.model_version != request.policy_catalog_version
            or self.metadata.category != "management.telnet_enabled"
            or self.metadata.selected_finding_sha256 != request.finding_sha256
            or self.metadata.policy_catalog_version != request.policy_catalog_version
            or proposal.reference_id != str(self.configuration_id)
            or proposal.device_id != self.source.device_id
            or proposal.before_sha256 != self.source.source_sha256
            or selected not in report.before_policy_findings
            or self.native_commands != self.metadata.native_commands
            or self.validation_blockers != NATIVE_PATCH_BLOCKERS
            or not report.before.complete
            or not report.after.complete
            or review.status != "needs_review"
            or report.review_status != "needs_review"
            or report.formal_verification != "not_run"
            or report.ml_status != "not_run"
            or any(
                edit.kind not in {"cisco_vty_ssh_only", "junos_remove_telnet"}
                for edit in self.metadata.edits
            )
        ):
            raise ValueError("native candidate bindings differ")
        _policy_map(report.before_policy_findings)
        _policy_map(report.after_policy_findings)
        body = self.model_dump(mode="json", exclude={"review_json", "review_sha256"})
        encoded = _json(body)
        if len(encoded.encode("utf-8")) > MAX_NATIVE_PATCH_REVIEW_BYTES:
            raise NativePatchBudgetError("native public proof exceeds budget")
        if (
            self.review_json != encoded
            or self.review_sha256 != sha256(encoded.encode("utf-8")).hexdigest()
        ):
            raise ValueError("native public proof differs from its validated body")
        if len(self.model_dump_json().encode("utf-8")) > MAX_NATIVE_PATCH_PUBLIC_BYTES:
            raise NativePatchBudgetError("native public candidate exceeds budget")
        return self


class NativePatchSummary(_FrozenNative):
    version: Literal["native-patch-summary-0.1.0"]
    candidate_id: UUID
    configuration_id: UUID
    analysis_id: UUID
    finding_id: UUID
    created_at: AwareDatetime
    service_role: Literal["engineer", "admin"]
    generator_version: Literal["native-telnet-generator-0.1.0"] = GENERATOR_VERSION
    review_sha256: Digest
    status: Literal["needs_review"] = "needs_review"
    formal_qualification: Literal["not_proven"] = "not_proven"
    individual_identity_verified: Literal[False] = False
    approved: Literal[False] = False
    applied: Literal[False] = False

    @field_validator("individual_identity_verified", "approved", "applied", mode="before")
    @classmethod
    def exact_false(cls, value: Any) -> Any:
        if value is not False:
            raise ValueError("native summary assurance flags must be exact false")
        return value


class NativePatchPrivate(_FrozenNative):
    version: Literal["native-patch-private-0.1.0"] = "native-patch-private-0.1.0"
    public: NativePatchCandidate
    generated_metadata: VendorDraft
    before_text: str = Field(strict=True, repr=False)
    candidate_text: str = Field(strict=True, repr=False)

    @field_validator("before_text", "candidate_text")
    @classmethod
    def bounded_text(cls, value: str) -> str:
        try:
            size = len(value.encode("utf-8"))
        except UnicodeError as exc:
            raise ValueError("native private text requires valid UTF-8") from exc
        if size > MAX_NATIVE_PATCH_TEXT_BYTES or len(value.splitlines()) > 10_000:
            raise NativePatchBudgetError("native private text exceeds budget")
        if not value.strip() or any(ord(char) < 32 and char not in "\r\n\t" for char in value):
            raise ValueError("native private text is invalid")
        return value

    @model_validator(mode="after")
    def exact_private(self) -> Self:
        from app.patching.native_patch_validation import validate_native_patch_texts

        if self.generated_metadata != self.public.metadata or (
            sha256(self.before_text.encode("utf-8")).hexdigest() != self.public.source.source_sha256
        ):
            raise ValueError("native private metadata differs from its public candidate")
        validate_native_patch_texts(self.generated_metadata, self.before_text, self.candidate_text)
        if len(self.model_dump_json().encode("utf-8")) > MAX_NATIVE_PATCH_PRIVATE_BYTES:
            raise NativePatchBudgetError("native private payload exceeds budget")
        return self


def _policy_map(findings: tuple[Finding, ...]) -> dict[UUID, Finding]:
    result = {finding.finding_id: finding for finding in findings}
    if len(result) != len(findings):
        raise ValueError("native policy finding identities must be unique")
    return result


def _parents(
    snapshot: ConfigurationSnapshot, analysis: AnalysisResult, *, complete: bool
) -> tuple[ConfigurationSnapshot, AnalysisResult]:
    snapshot = ConfigurationSnapshot.model_validate_json(snapshot.model_dump_json())
    analysis = AnalysisResult.model_validate_json(analysis.model_dump_json())
    if (
        snapshot.created_at.utcoffset() is None
        or analysis.created_at.utcoffset() is None
        or analysis.configuration_id != snapshot.configuration_id
        or analysis.device_id != snapshot.device_id
        or analysis.source_sha256 != snapshot.canonical.source.sha256
        or analysis.created_at < snapshot.created_at
        or analysis.policy_catalog_version != CATALOG_VERSION
    ):
        raise ValueError("native saved parent bindings differ")
    if complete and (
        analysis.status != "completed"
        or snapshot.canonical.parser_confidence != 1
        or snapshot.canonical.parse_warnings
        or snapshot.canonical.unparsed_fragments
    ):
        raise ValueError("native candidate requires a complete saved parent")
    return snapshot, analysis


def native_patch_selection(
    snapshot: ConfigurationSnapshot, analysis: AnalysisResult
) -> NativePatchSelection:
    snapshot, analysis = _parents(snapshot, analysis, complete=False)
    return NativePatchSelection(
        configuration_id=snapshot.configuration_id,
        source=SnapshotBinding.from_snapshot(snapshot),
        canonical_sha256=canonical_fingerprint(snapshot),
        analysis_id=analysis.analysis_id,
        analysis_sha256=native_patch_fingerprint(analysis),
        analysis_created_at=analysis.created_at,
        policy_catalog_version=CATALOG_VERSION,
        finding_pins=tuple(
            NativeFindingPin(
                finding_id=finding.finding_id, finding_sha256=finding_fingerprint(finding)
            )
            for finding in analysis.findings
            if finding.detector == "policy_engine"
            and finding.category == "management.telnet_enabled"
        ),
    )


def validate_native_patch_parent(
    public: NativePatchCandidate, snapshot: ConfigurationSnapshot, analysis: AnalysisResult
) -> None:
    """Read-time proof/dependency check using saved typed data; no policy execution."""
    public = NativePatchCandidate.model_validate(public)
    snapshot, analysis = _parents(snapshot, analysis, complete=True)
    request = public.request
    selected = next(
        (row for row in analysis.findings if row.finding_id == request.finding_id), None
    )
    saved_policy = tuple(row for row in analysis.findings if row.detector == "policy_engine")
    if (
        public.source != SnapshotBinding.from_snapshot(snapshot)
        or public.configuration_id != snapshot.configuration_id
        or public.metadata.review.proposal.vendor != snapshot.canonical.device.vendor
        or public.metadata.review.proposal.platform != snapshot.canonical.device.platform
        or request.analysis_id != analysis.analysis_id
        or request.analysis_sha256 != native_patch_fingerprint(analysis)
        or request.canonical_sha256 != canonical_fingerprint(snapshot)
        or public.analysis_created_at != analysis.created_at
        or selected != public.selected_finding
        or _policy_map(saved_policy)
        != _policy_map(public.metadata.review.preflight.before_policy_findings)
    ):
        raise ValueError("native candidate differs from its saved parents")


def native_patch_candidate(
    configuration_id: UUID,
    request: GenerateNativePatch,
    snapshot: ConfigurationSnapshot,
    analysis: AnalysisResult,
    metadata: VendorDraft,
    *,
    created_at: datetime,
    service_role: Literal["engineer", "admin"],
) -> NativePatchCandidate:
    request = GenerateNativePatch.model_validate(request)
    snapshot, analysis = _parents(snapshot, analysis, complete=True)
    metadata_input = _plain(metadata)
    _metadata_flags(metadata_input)
    metadata = VendorDraft.model_validate(metadata_input)
    selected = next(
        (row for row in analysis.findings if row.finding_id == request.finding_id), None
    )
    if selected is None:
        raise ValueError("native selected finding is unavailable")
    # Build the complete public body; final schema validation binds its exact JSON.
    body: dict[str, Any] = {
        "version": "native-patch-candidate-0.1.0",
        "candidate_id": request.candidate_id,
        "configuration_id": configuration_id,
        "request": request,
        "source": SnapshotBinding.from_snapshot(snapshot),
        "analysis_created_at": analysis.created_at,
        "selected_finding": selected,
        "created_at": created_at,
        "service_role": service_role,
        "generator_kind": "deterministic_vendor",
        "generator_version": GENERATOR_VERSION,
        "metadata": metadata,
        "native_commands": metadata.native_commands,
        "local_reference": "selected_original_not_approved_baseline",
        "status": "needs_review",
        "formal_qualification": "not_proven",
        "calibrated": False,
        "quality_proven": False,
        "individual_identity_verified": False,
        "approved": False,
        "applied": False,
        "validation_blockers": NATIVE_PATCH_BLOCKERS,
    }
    # model_construct is only an intermediate encoder. Full validation follows;
    # no constructed model escapes this function or participates in parent checks.
    encoded = _json(NativePatchCandidate.model_construct(**body).model_dump(mode="json"))
    if len(encoded.encode("utf-8")) > MAX_NATIVE_PATCH_REVIEW_BYTES:
        raise NativePatchBudgetError("native public proof exceeds budget")
    public = NativePatchCandidate.model_validate(
        {
            **body,
            "review_json": encoded,
            "review_sha256": sha256(encoded.encode("utf-8")).hexdigest(),
        }
    )
    validate_native_patch_parent(public, snapshot, analysis)
    return public


def native_patch_summary(public: NativePatchCandidate) -> NativePatchSummary:
    public = NativePatchCandidate.model_validate(public)
    return NativePatchSummary(
        version="native-patch-summary-0.1.0",
        candidate_id=public.candidate_id,
        configuration_id=public.configuration_id,
        analysis_id=public.request.analysis_id,
        finding_id=public.request.finding_id,
        created_at=public.created_at,
        service_role=public.service_role,
        generator_version=public.generator_version,
        review_sha256=public.review_sha256,
    )
