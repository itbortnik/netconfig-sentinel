"""Immutable request receipts and independently recorded response completions."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, model_validator

from app.core.permissions import PERMISSIONS, Permission, Role

type Operation = Literal[
    "upload_configuration",
    "list_configurations",
    "get_configuration",
    "analyze_configuration",
    "list_analyses",
    "get_analysis",
    "get_findings",
    "train_model",
    "list_models",
    "get_model",
    "submit_feedback",
    "list_feedback",
    "create_patch",
    "list_patches",
    "get_patch",
    "verify_patch",
    "list_verifications",
    "get_verification",
    "snapshot_diff",
    "explain_finding",
    "explanation_capabilities",
    "session_access",
    "list_operation_audit",
    "get_operation_audit",
    "unmatched_api",
]
type Method = Literal["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "OTHER"]
type Authorization = Literal["allowed", "denied", "not_authenticated", "not_checked"]
type Digest = str


def metadata_hash(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    ).hexdigest()


class Receipt(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["operation-receipt-0.1.0"] = "operation-receipt-0.1.0"
    operation_id: UUID
    started_at: datetime
    operation: Operation
    method: Method
    service_role: Role | None
    individual_identity_verified: Literal[False] = False

    @model_validator(mode="after")
    def aware_time(self) -> Receipt:
        if self.started_at.utcoffset() is None:
            raise ValueError("operation receipt requires an aware timestamp")
        return self

    @property
    def sha256(self) -> str:
        return metadata_hash(self.model_dump(mode="json"))


class PermissionDecision(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    permission: Permission
    granted: StrictBool


class ResultMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    # Fingerprint of all selected metadata, not a transcript or a response-content signature.
    metadata_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    result_count: StrictInt = Field(ge=0, le=100_000)
    resource_ids: tuple[UUID, ...] = Field(default=(), max_length=16)
    source_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    finding_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    versions: tuple[str, ...] = Field(default=(), max_length=128)
    knowledge_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    document_index_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    document_encoder_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    context_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    model_alias_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    retrieval: Literal["explicit_reference", "semantic_supplement"] | None = None

    @model_validator(mode="after")
    def unique_metadata(self) -> ResultMetadata:
        if len(set(self.resource_ids)) != len(self.resource_ids) or self.versions != tuple(
            sorted(set(self.versions))
        ):
            raise ValueError("duplicate or unordered result metadata")
        if any(
            not value
            or len(value) > 100
            or not value.isascii()
            or any(not (char.isalnum() or char in "._-") for char in value)
            for value in self.versions
        ):
            raise ValueError("unsupported result version")
        if self.retrieval == "semantic_supplement" and (
            self.document_index_sha256 is None or self.document_encoder_sha256 is None
        ):
            raise ValueError("semantic result requires model and index metadata")
        return self


class Completion(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["operation-completion-0.1.0"] = "operation-completion-0.1.0"
    operation_id: UUID
    receipt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    completed_at: datetime
    status_code: StrictInt = Field(ge=200, le=599)
    duration_ms: StrictInt = Field(ge=0)
    permissions: tuple[PermissionDecision, ...] = Field(default=(), max_length=16)
    result: ResultMetadata | None = None

    @model_validator(mode="after")
    def consistent_completion(self) -> Completion:
        if self.completed_at.utcoffset() is None or len(
            {item.permission for item in self.permissions}
        ) != len(self.permissions):
            raise ValueError("unsupported completion timestamp or permission decisions")
        if self.status_code >= 400 and self.result is not None:
            raise ValueError("failed responses do not claim successful result metadata")
        return self


class OperationRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["operation-record-0.1.0"] = "operation-record-0.1.0"
    receipt: Receipt
    completion: Completion | None = None
    outcome: Literal["pending", "successful_response", "rejected_response", "failed_response"]
    authorization: Authorization

    @model_validator(mode="after")
    def bound_completion(self) -> OperationRecord:
        completion, receipt = self.completion, self.receipt
        if completion is None:
            if self.outcome != "pending" or self.authorization != "not_checked":
                raise ValueError("missing completion must remain unconfirmed")
            return self
        if (
            completion.operation_id != receipt.operation_id
            or completion.receipt_sha256 != receipt.sha256
            or completion.completed_at < receipt.started_at
        ):
            raise ValueError("completion does not bind its original receipt")
        for decision in completion.permissions:
            expected = receipt.service_role is not None and (
                decision.permission in PERMISSIONS[receipt.service_role]
            )
            if decision.granted != expected:
                raise ValueError("permission decision conflicts with service role")
        authorization: Authorization = (
            "not_authenticated"
            if receipt.service_role is None
            else "denied"
            if any(not item.granted for item in completion.permissions)
            else "allowed"
            if completion.permissions
            else "not_checked"
        )
        outcome = (
            "successful_response"
            if completion.status_code < 400
            else "rejected_response"
            if completion.status_code < 500
            else "failed_response"
        )
        if self.authorization != authorization or self.outcome != outcome:
            raise ValueError("response outcome or authorization is inconsistent")
        return self

    @classmethod
    def combine(cls, receipt: Receipt, completion: Completion | None) -> OperationRecord:
        if completion is None:
            return cls(receipt=receipt, outcome="pending", authorization="not_checked")
        return cls(
            receipt=receipt,
            completion=completion,
            outcome=(
                "successful_response"
                if completion.status_code < 400
                else "rejected_response"
                if completion.status_code < 500
                else "failed_response"
            ),
            authorization=(
                "not_authenticated"
                if receipt.service_role is None
                else "denied"
                if any(not item.granted for item in completion.permissions)
                else "allowed"
                if completion.permissions
                else "not_checked"
            ),
        )


class OperationPage(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["operation-page-0.1.0"] = "operation-page-0.1.0"
    records: tuple[OperationRecord, ...] = Field(max_length=100)
    next_before: UUID | None = None

    @model_validator(mode="after")
    def ordered_page(self) -> OperationPage:
        keys = [(item.receipt.started_at, str(item.receipt.operation_id)) for item in self.records]
        if keys != sorted(set(keys), reverse=True) or (
            self.next_before is not None
            and (not self.records or self.next_before != self.records[-1].receipt.operation_id)
        ):
            raise ValueError("unordered operation page or incompatible cursor")
        return self
