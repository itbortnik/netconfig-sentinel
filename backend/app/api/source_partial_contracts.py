"""Explicit partial policy diagnostics, kept separate from complete deterministic evidence."""

from __future__ import annotations

from datetime import datetime
from hashlib import sha256
from typing import TYPE_CHECKING, Annotated, Literal, Self
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    TypeAdapter,
    field_validator,
    model_validator,
)

from app.api.source_deterministic_contracts import (
    MAX_SOURCE_DETERMINISTIC_BYTES,
    RunSourceDeterministicRecheck,
    SourceDeterministicIntent,
    SourceDeterministicMember,
    SourceDeterministicOutcome,
    SourceDeterministicRecheck,
    SourceDeterministicSelection,
    SourceDeterministicSummary,
    _findings_json,
    deterministic_blockers,
)
from app.api.source_ml_contracts import ml_json, source_ml_fingerprint
from app.domain import CanonicalConfig, Finding, SourceLocation
from app.verification.preflight import ParseSummary, _summary
from ml.evaluation.contracts import Digest, Frozen

if TYPE_CHECKING:
    from app.detection.policy_diagnostic import PartialPolicyPair

type PartialMode = Literal["policy_only_partial_diagnostic"]
MAX_UNKNOWN_LOCATIONS = 256


def _plain_diagnostic_value(value: object) -> object:
    """Normalize legacy model instances before any new protocol field is validated."""
    if isinstance(value, BaseModel):
        return value.model_dump(warnings=False)
    if isinstance(value, dict):
        return {key: _plain_diagnostic_value(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return tuple(_plain_diagnostic_value(item) for item in value)
    if isinstance(value, list):
        return [_plain_diagnostic_value(item) for item in value]
    return value


class _DiagnosticFrozen(Frozen):
    # New typed copies must be revalidated without changing historical classes.
    model_config = ConfigDict(
        extra="forbid", frozen=True, allow_inf_nan=False, revalidate_instances="always"
    )

    @model_validator(mode="before")
    @classmethod
    def validate_plain_nested_fields(cls, value: object) -> object:
        return _plain_diagnostic_value(value)

    @field_validator(
        "risk_fused",
        "calibrated",
        "quality_proven",
        "approved",
        "applied",
        mode="before",
        check_fields=False,
    )
    @classmethod
    def exact_false(cls, value: object) -> bool:
        if value is not False:
            raise ValueError("diagnostic evidence cannot promote safety, quality or approval")
        return value


class RunSourcePartialDiagnostic(_DiagnosticFrozen):
    version: Literal["source-deterministic-request-0.2.0"] = "source-deterministic-request-0.2.0"
    mode: PartialMode
    recheck_id: UUID
    draft_sha256: Digest
    before_analysis_id: UUID
    before_analysis_sha256: Digest
    reference_canonical_sha256: None
    allow_local_analysis_context: StrictBool = False


class PolicyDiagnosticParse(_DiagnosticFrozen):
    summary: ParseSummary
    unknown_locations: tuple[SourceLocation, ...] = Field(max_length=MAX_UNKNOWN_LOCATIONS)
    locations_truncated: StrictBool

    @model_validator(mode="after")
    def bounds(self) -> Self:
        summary = ParseSummary.model_validate(self.summary.model_dump(warnings=False))
        for location in self.unknown_locations:
            SourceLocation.model_validate(location.model_dump(warnings=False))
        if len(self.unknown_locations) != min(
            summary.unparsed_count, MAX_UNKNOWN_LOCATIONS
        ) or self.locations_truncated != (summary.unparsed_count > MAX_UNKNOWN_LOCATIONS):
            raise ValueError("partial parser location inventory differs")
        return self

    @classmethod
    def from_config(cls, config: CanonicalConfig) -> Self:
        config = CanonicalConfig.model_validate(config.model_dump(warnings=False))
        return cls.model_validate(
            {
                "summary": _summary(config).model_dump(),
                "unknown_locations": [
                    row.location.model_dump()
                    for row in config.unparsed_fragments[:MAX_UNKNOWN_LOCATIONS]
                ],
                "locations_truncated": len(config.unparsed_fragments) > MAX_UNKNOWN_LOCATIONS,
            }
        )


class SourcePartialIntent(_DiagnosticFrozen):
    version: Literal["source-deterministic-intent-0.2.0"] = "source-deterministic-intent-0.2.0"
    patch_id: UUID
    request: RunSourcePartialDiagnostic
    before: SourceDeterministicMember
    after: SourceDeterministicMember
    selection: SourceDeterministicSelection
    before_analysis_status: Literal["completed", "partial"]
    before_parse: PolicyDiagnosticParse
    after_parse: PolicyDiagnosticParse
    reference_projection: None
    created_at: datetime

    @model_validator(mode="after")
    def bindings(self) -> Self:
        request = RunSourcePartialDiagnostic.model_validate(self.request.model_dump(warnings=False))
        selected = SourceDeterministicSelection.model_validate(
            self.selection.model_dump(warnings=False)
        )
        old = SourceDeterministicMember.model_validate(self.before.model_dump(warnings=False))
        new = SourceDeterministicMember.model_validate(self.after.model_dump(warnings=False))
        previous = PolicyDiagnosticParse.model_validate(
            self.before_parse.model_dump(warnings=False)
        )
        current = PolicyDiagnosticParse.model_validate(self.after_parse.model_dump(warnings=False))
        if (
            self.created_at.utcoffset() is None
            or not old.created_at <= new.created_at <= self.created_at
            or self.created_at < selected.before_analysis_created_at
            or old.device_id != new.device_id
            or old.configuration_id == new.configuration_id
            or old.source_sha256 == new.source_sha256
            or request.allow_local_analysis_context is not True
            or self.patch_id != selected.patch_id
            or request.draft_sha256 != selected.draft_sha256
            or request.before_analysis_id != selected.before_analysis_id
            or request.before_analysis_sha256 != selected.before_analysis_sha256
            or old.model_dump(exclude={"canonical_sha256"}) != selected.before.model_dump()
            or selected.original.comparison is not None
            or selected.original.statistical_present
            or selected.reference is not None
            or previous.summary.source_sha256 != old.source_sha256
            or current.summary.source_sha256 != new.source_sha256
            or (previous.summary.complete and current.summary.complete)
            or self.before_analysis_status
            != ("completed" if previous.summary.complete else "partial")
        ):
            raise ValueError("partial diagnostic intent differs from its explicit original scope")
        return self


class SourcePartialSide(_DiagnosticFrozen):
    configuration_id: UUID
    source_sha256: Digest
    parse: PolicyDiagnosticParse
    policy_findings: tuple[Finding, ...] = Field(max_length=10000)

    @model_validator(mode="after")
    def policy_scope(self) -> Self:
        parsed = PolicyDiagnosticParse.model_validate(self.parse.model_dump(warnings=False))
        rows = tuple(
            Finding.model_validate(row.model_dump(warnings=False)) for row in self.policy_findings
        )
        if (
            parsed.summary.source_sha256 != self.source_sha256
            or len({row.finding_id for row in rows}) != len(rows)
            or any(row.detector != "policy_engine" for row in rows)
        ):
            raise ValueError("partial policy side source or finding scope differs")
        return self


class SourcePartialReport(_DiagnosticFrozen):
    version: Literal["source-deterministic-report-0.2.0"] = "source-deterministic-report-0.2.0"
    mode: PartialMode = "policy_only_partial_diagnostic"
    coverage: Literal["partial"] = "partial"
    policy_catalog_version: str = Field(min_length=1, max_length=128)
    comparison_version: Literal["not_selected"] = "not_selected"
    before: SourcePartialSide
    after: SourcePartialSide
    policy_changes: None
    policy_changes_reason: Literal["partial_parsing"] = "partial_parsing"
    reference_projection: None
    peer_profile_sha256: None

    @model_validator(mode="after")
    def partial_policy_scope(self) -> Self:
        old = SourcePartialSide.model_validate(self.before.model_dump(warnings=False))
        new = SourcePartialSide.model_validate(self.after.model_dump(warnings=False))
        rows = old.policy_findings + new.policy_findings
        if (
            old.configuration_id == new.configuration_id
            or old.source_sha256 == new.source_sha256
            or (old.parse.summary.complete and new.parse.summary.complete)
            or any(row.model_version != self.policy_catalog_version for row in rows)
            or len({row.device_id for row in rows}) > 1
        ):
            raise ValueError("partial policy report requires the original catalog and partial pair")
        return self

    @classmethod
    def from_pair(cls, intent: SourcePartialIntent, pair: PartialPolicyPair) -> Self:
        from app.detection.policy_diagnostic import PartialPolicyPair

        intent = SourcePartialIntent.model_validate(intent.model_dump(warnings=False))
        if not isinstance(pair, PartialPolicyPair) or (
            pair.before.canonical_sha256 != intent.before.canonical_sha256
            or pair.after.canonical_sha256 != intent.after.canonical_sha256
        ):
            raise ValueError("partial diagnostic requires the exact typed library pair")
        result = cls(
            policy_catalog_version=pair.policy_catalog_version,
            before=SourcePartialSide(
                configuration_id=intent.before.configuration_id,
                source_sha256=intent.before.source_sha256,
                parse=pair.before.parse,
                policy_findings=pair.before.policy_findings,
            ),
            after=SourcePartialSide(
                configuration_id=intent.after.configuration_id,
                source_sha256=intent.after.source_sha256,
                parse=pair.after.parse,
                policy_findings=pair.after.policy_findings,
            ),
            policy_changes=None,
            reference_projection=None,
            peer_profile_sha256=None,
        )
        result.validate_intent(intent)
        return result

    def validate_intent(self, intent: SourcePartialIntent) -> None:
        intent = SourcePartialIntent.model_validate(intent.model_dump(warnings=False))
        report = type(self).model_validate(self.model_dump(warnings=False))
        if report.policy_catalog_version != intent.selection.original.policy_catalog_version:
            raise ValueError("partial diagnostic catalog differs from the original")
        for side, member, parsed in (
            (report.before, intent.before, intent.before_parse),
            (report.after, intent.after, intent.after_parse),
        ):
            if (
                (side.configuration_id, side.source_sha256)
                != (member.configuration_id, member.source_sha256)
                or side.parse != parsed
                or any(row.device_id != member.device_id for row in side.policy_findings)
            ):
                raise ValueError("partial diagnostic member or saved parser diagnostics differ")
        if _findings_json(report.before.policy_findings) != _findings_json(
            intent.selection.original.findings
        ):
            raise ValueError("partial diagnostic differs from every original before finding field")


class SourcePartialOutcome(_DiagnosticFrozen):
    version: Literal["source-deterministic-outcome-0.2.0"] = "source-deterministic-outcome-0.2.0"
    recheck_id: UUID
    intent_sha256: Digest
    completed_at: datetime
    execution_status: Literal["completed", "failed"]
    report: SourcePartialReport | None = None
    failure_reason: Literal["original_context_or_deterministic_result_unavailable"] | None = None

    @model_validator(mode="after")
    def state(self) -> Self:
        if self.report is not None:
            SourcePartialReport.model_validate(self.report.model_dump(warnings=False))
        if (
            self.completed_at.utcoffset() is None
            or (self.execution_status == "completed") != (self.report is not None)
            or (self.execution_status == "failed") != (self.failure_reason is not None)
        ):
            raise ValueError("partial diagnostic outcome state differs")
        return self


def partial_blockers(
    intent: SourcePartialIntent, outcome: SourcePartialOutcome | None
) -> tuple[str, ...]:
    # Reuse established qualification wording with the actual recorded original scope.
    result = deterministic_blockers(intent.selection.original, None)[:-1]
    result += ("partial_parsing", "partial_comparison_unavailable")
    if outcome is None:
        return (*result, "deterministic_execution_unknown")
    if outcome.execution_status == "failed":
        return (*result, "original_deterministic_unavailable")
    return result


class SourcePartialDiagnostic(_DiagnosticFrozen):
    version: Literal["source-deterministic-recheck-0.2.0"] = "source-deterministic-recheck-0.2.0"
    mode: PartialMode = "policy_only_partial_diagnostic"
    coverage: Literal["partial"] = "partial"
    recheck_id: UUID
    patch_id: UUID
    draft_sha256: Digest
    before_analysis_id: UUID
    before_analysis_sha256: Digest
    reference_canonical_sha256: None
    intent: SourcePartialIntent
    outcome: SourcePartialOutcome | None
    execution_status: Literal["pending_unknown", "completed", "failed"]
    validation_blockers: tuple[str, ...]
    review_json: str = Field(min_length=1, max_length=MAX_SOURCE_DETERMINISTIC_BYTES, repr=False)
    review_sha256: Digest
    status: Literal["needs_review"] = "needs_review"
    formal_verification: Literal["not_run"] = "not_run"
    risk_fused: Literal[False] = False
    calibrated: Literal[False] = False
    quality_proven: Literal[False] = False
    approved: Literal[False] = False
    applied: Literal[False] = False

    @model_validator(mode="after")
    def bindings(self) -> Self:
        intent = SourcePartialIntent.model_validate(self.intent.model_dump(warnings=False))
        outcome = (
            SourcePartialOutcome.model_validate(self.outcome.model_dump(warnings=False))
            if self.outcome is not None
            else None
        )
        request = intent.request
        if (
            (
                self.recheck_id,
                self.patch_id,
                self.draft_sha256,
                self.before_analysis_id,
                self.before_analysis_sha256,
            )
            != (
                request.recheck_id,
                intent.patch_id,
                request.draft_sha256,
                request.before_analysis_id,
                request.before_analysis_sha256,
            )
            or self.execution_status != (outcome.execution_status if outcome else "pending_unknown")
            or self.validation_blockers != partial_blockers(intent, outcome)
        ):
            raise ValueError("partial diagnostic outer identity or qualification differs")
        if outcome is not None:
            if (
                outcome.recheck_id != self.recheck_id
                or outcome.intent_sha256 != source_ml_fingerprint(intent)
                or outcome.completed_at < intent.created_at
            ):
                raise ValueError("partial diagnostic outcome belongs to another intent")
            if outcome.report is not None:
                outcome.report.validate_intent(intent)
        expected = ml_json(self.model_dump(mode="json", exclude={"review_json", "review_sha256"}))
        if (
            self.review_json != expected
            or len(expected.encode()) > MAX_SOURCE_DETERMINISTIC_BYTES
            or self.review_sha256 != sha256(expected.encode()).hexdigest()
        ):
            raise ValueError("partial diagnostic proof differs")
        return self

    @classmethod
    def from_records(
        cls, intent: SourcePartialIntent, outcome: SourcePartialOutcome | None
    ) -> Self:
        intent = SourcePartialIntent.model_validate(intent.model_dump(warnings=False))
        outcome = (
            SourcePartialOutcome.model_validate(outcome.model_dump(warnings=False))
            if outcome
            else None
        )
        request = intent.request
        fields = dict(
            version="source-deterministic-recheck-0.2.0",
            mode="policy_only_partial_diagnostic",
            coverage="partial",
            recheck_id=str(request.recheck_id),
            patch_id=str(intent.patch_id),
            draft_sha256=request.draft_sha256,
            before_analysis_id=str(request.before_analysis_id),
            before_analysis_sha256=request.before_analysis_sha256,
            reference_canonical_sha256=None,
            intent=intent.model_dump(mode="json"),
            outcome=outcome.model_dump(mode="json") if outcome else None,
            execution_status=outcome.execution_status if outcome else "pending_unknown",
            validation_blockers=partial_blockers(intent, outcome),
            status="needs_review",
            formal_verification="not_run",
            risk_fused=False,
            calibrated=False,
            quality_proven=False,
            approved=False,
            applied=False,
        )
        proof = ml_json(fields)
        return cls.model_validate(
            fields | {"review_json": proof, "review_sha256": sha256(proof.encode()).hexdigest()}
        )


class SourcePartialSummary(_DiagnosticFrozen):
    version: Literal["source-deterministic-summary-0.2.0"] = "source-deterministic-summary-0.2.0"
    mode: PartialMode = "policy_only_partial_diagnostic"
    coverage: Literal["partial"] = "partial"
    recheck_id: UUID
    patch_id: UUID
    draft_sha256: Digest
    before_analysis_id: UUID
    review_sha256: Digest
    created_at: datetime
    completed_at: datetime | None
    execution_status: Literal["pending_unknown", "completed", "failed"]
    status: Literal["needs_review"] = "needs_review"

    @model_validator(mode="after")
    def chronology(self) -> Self:
        if (
            self.created_at.utcoffset() is None
            or (self.completed_at is None) != (self.execution_status == "pending_unknown")
            or (
                self.completed_at is not None
                and (self.completed_at.utcoffset() is None or self.completed_at < self.created_at)
            )
        ):
            raise ValueError("partial diagnostic summary chronology differs")
        return self

    @classmethod
    def from_recheck(cls, value: SourcePartialDiagnostic) -> Self:
        value = SourcePartialDiagnostic.model_validate(value.model_dump(warnings=False))
        return cls(
            recheck_id=value.recheck_id,
            patch_id=value.patch_id,
            draft_sha256=value.draft_sha256,
            before_analysis_id=value.before_analysis_id,
            review_sha256=value.review_sha256,
            created_at=value.intent.created_at,
            completed_at=value.outcome.completed_at if value.outcome else None,
            execution_status=value.execution_status,
        )


type SourceDeterministicRequest = RunSourceDeterministicRecheck | RunSourcePartialDiagnostic
type SourceDeterministicIntentRecord = SourceDeterministicIntent | SourcePartialIntent
type SourceDeterministicOutcomeRecord = SourceDeterministicOutcome | SourcePartialOutcome
type SourceDeterministicRecord = SourceDeterministicRecheck | SourcePartialDiagnostic
type SourceDeterministicSummaryRecord = SourceDeterministicSummary | SourcePartialSummary
_Request = Annotated[SourceDeterministicRequest, Field(discriminator="version")]
_Intent = Annotated[SourceDeterministicIntentRecord, Field(discriminator="version")]
_Outcome = Annotated[SourceDeterministicOutcomeRecord, Field(discriminator="version")]
_Record = Annotated[SourceDeterministicRecord, Field(discriminator="version")]
_Summary = Annotated[SourceDeterministicSummaryRecord, Field(discriminator="version")]
_REQUEST: TypeAdapter[SourceDeterministicRequest] = TypeAdapter(_Request)
_INTENT: TypeAdapter[SourceDeterministicIntentRecord] = TypeAdapter(_Intent)
_OUTCOME: TypeAdapter[SourceDeterministicOutcomeRecord] = TypeAdapter(_Outcome)
_RECORD: TypeAdapter[SourceDeterministicRecord] = TypeAdapter(_Record)
_SUMMARY: TypeAdapter[SourceDeterministicSummaryRecord] = TypeAdapter(_Summary)


def parse_source_deterministic_request(value: object) -> SourceDeterministicRequest:
    if isinstance(value, BaseModel):
        value = value.model_dump(warnings=False)
    if isinstance(value, dict) and "version" not in value:
        value = value | {"version": "source-deterministic-request-0.1.0"}
    return _REQUEST.validate_python(value)


def parse_source_deterministic_intent_json(value: str) -> SourceDeterministicIntentRecord:
    return _INTENT.validate_json(value)


def parse_source_deterministic_outcome_json(value: str) -> SourceDeterministicOutcomeRecord:
    return _OUTCOME.validate_json(value)


def parse_source_deterministic_record_json(value: str) -> SourceDeterministicRecord:
    return _RECORD.validate_json(value)


def parse_source_deterministic_summary_json(value: str) -> SourceDeterministicSummaryRecord:
    return _SUMMARY.validate_json(value)


def source_deterministic_view(
    intent: SourceDeterministicIntentRecord, outcome: SourceDeterministicOutcomeRecord | None
) -> SourceDeterministicRecord:
    if isinstance(intent, SourcePartialIntent):
        if outcome is not None and not isinstance(outcome, SourcePartialOutcome):
            raise ValueError("partial diagnostic intent/outcome protocols differ")
        return SourcePartialDiagnostic.from_records(intent, outcome)
    if isinstance(outcome, SourcePartialOutcome):
        raise ValueError("complete deterministic intent/outcome protocols differ")
    return SourceDeterministicRecheck.from_records(intent, outcome)


def source_deterministic_summary(
    value: SourceDeterministicRecord,
) -> SourceDeterministicSummaryRecord:
    if isinstance(value, SourcePartialDiagnostic):
        return SourcePartialSummary.from_recheck(value)
    return SourceDeterministicSummary.from_recheck(value)
