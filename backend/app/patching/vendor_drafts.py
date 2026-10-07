"""Exact supported source edits and inspectable native commands; no device connector."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from hashlib import sha256
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, StrictInt, model_validator

from app.detection.policy_engine import evaluate_policies
from app.domain import CanonicalConfig, Finding, Vendor
from app.domain.fingerprints import finding_fingerprint
from app.ingestion.local import validate_configuration_text
from app.parsers import parse_configuration
from app.patching.proposal import create_patch_proposal
from app.patching.review import PatchReview, review_patch_proposal
from app.policies import POLICY_CATALOG_VERSION

Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
type Category = Literal["management.telnet_enabled", "management.ssh_version_1"]
type EditKind = Literal["cisco_vty_ssh_only", "cisco_ssh_v2", "junos_remove_telnet", "junos_ssh_v2"]


def _digest(text: str) -> str:
    return sha256(text.encode("utf-8")).hexdigest()


class VtyRange(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    first: StrictInt = Field(ge=0, le=9999)
    last: StrictInt = Field(ge=0, le=9999)

    @model_validator(mode="after")
    def ordered(self) -> Self:
        if self.first > self.last:
            raise ValueError("reversed VTY range")
        return self


class VendorEdit(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    kind: EditKind
    source_line: StrictInt = Field(ge=1, le=10000)
    before_line_sha256: Digest
    after_line_sha256: Digest | None
    vty: VtyRange | None = None

    @model_validator(mode="after")
    def typed_context(self) -> Self:
        if (self.kind == "cisco_vty_ssh_only") != (self.vty is not None):
            raise ValueError("VTY context differs from edit kind")
        if (self.kind == "junos_remove_telnet") != (self.after_line_sha256 is None):
            raise ValueError("deleted-line hash differs from edit kind")
        return self


class VendorDraft(BaseModel):
    """Metadata only: candidate source is a separate confidential file/string."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["vendor-patch-draft-0.1.0"] = "vendor-patch-draft-0.1.0"
    category: Category
    selected_finding_sha256: Digest
    policy_catalog_version: Literal["policy-rules-0.7.0"] = "policy-rules-0.7.0"
    edits: tuple[VendorEdit, ...] = Field(min_length=1, max_length=128)
    review: PatchReview
    application_supported: Literal[False] = False
    device_syntax_verified: Literal[False] = False
    management_access_verified: Literal[False] = False
    rollback_plan: Literal["retain_and_review_exact_before_snapshot"] = (
        "retain_and_review_exact_before_snapshot"
    )

    @model_validator(mode="after")
    def bound_draft(self) -> Self:
        lines = tuple(edit.source_line for edit in self.edits)
        if lines != tuple(sorted(set(lines))):
            raise ValueError("draft edit anchors must be sorted and unique")
        report = self.review.preflight
        selected = next(
            (
                finding
                for finding in report.before_policy_findings
                if finding.category == self.category
            ),
            None,
        )
        allowed = {
            (Vendor.CISCO, "management.telnet_enabled"): "cisco_vty_ssh_only",
            (Vendor.CISCO, "management.ssh_version_1"): "cisco_ssh_v2",
            (Vendor.JUNIPER, "management.telnet_enabled"): "junos_remove_telnet",
            (Vendor.JUNIPER, "management.ssh_version_1"): "junos_ssh_v2",
        }
        if (
            selected is None
            or finding_fingerprint(selected) != self.selected_finding_sha256
            or report.policy_catalog_version != self.policy_catalog_version
            or self.review.proposal.platform
            != ("ios" if self.review.proposal.vendor is Vendor.CISCO else "junos")
            or not report.before.complete
            or not report.after.complete
            or any(finding.category == self.category for finding in report.after_policy_findings)
            or tuple(selected.affected_lines) != lines
            or any(
                edit.kind != allowed[(self.review.proposal.vendor, self.category)]
                for edit in self.edits
            )
            or (report.policy_changes is not None and report.policy_changes.introduced)
        ):
            raise ValueError("vendor draft does not match its source-bound local review")
        return self

    @property
    def native_commands(self) -> tuple[str, ...]:
        """Inspection text in the vendor's configuration context; never executed here."""
        commands: list[str] = []
        for edit in self.edits:
            if edit.kind == "cisco_vty_ssh_only":
                if edit.vty is None:
                    raise ValueError("missing VTY context")
                commands.extend(
                    (f"line vty {edit.vty.first} {edit.vty.last}", "transport input ssh", "exit")
                )
            elif edit.kind == "cisco_ssh_v2":
                commands.append("ip ssh version 2")
            elif edit.kind == "junos_remove_telnet":
                commands.append("delete system services telnet")
            else:
                commands.append("set system services ssh protocol-version v2")
        return tuple(commands)


@dataclass(frozen=True)
class GeneratedVendorDraft:
    metadata: VendorDraft
    candidate_text: str = field(repr=False)


def _complete(config: CanonicalConfig) -> bool:
    return (
        config.parser_confidence == 1
        and not config.parse_warnings
        and not config.unparsed_fragments
    )


def _replace_line(raw: str, command: str) -> str:
    content = raw.rstrip("\r\n")
    leading = content[: len(content) - len(content.lstrip(" \t"))]
    trailing = content[len(content.rstrip(" \t")) :]
    return leading + command + trailing + raw[len(content) :]


def _cisco_telnet(lines: list[str]) -> tuple[dict[int, str], tuple[VendorEdit, ...]]:
    ranges: list[VtyRange] = []
    changes, edits = {}, []
    current: VtyRange | None = None
    transport_seen = False
    for index, raw in enumerate(lines):
        command = raw.strip()
        if not command:
            continue
        if command.startswith("!") or command.lower() in {"exit", "end", "configure terminal"}:
            current = None
            continue
        if command.lower().startswith("line vty"):
            match = re.fullmatch(r"line vty ([0-9]{1,4})(?: ([0-9]{1,4}))?", command, re.I)
            if match is None or raw[0].isspace():
                raise ValueError("unsupported VTY selector")
            current = VtyRange(first=int(match[1]), last=int(match[2] or match[1]))
            if any(
                current.first <= previous.last and previous.first <= current.last
                for previous in ranges
            ):
                raise ValueError("overlapping VTY selectors")
            ranges.append(current)
            if len(ranges) > 128:
                raise ValueError("VTY selector budget exceeded")
            transport_seen = False
            continue
        if not raw[0].isspace():
            current = None
        if command.lower().split()[:2] == ["transport", "input"]:
            if current is None or transport_seen:
                raise ValueError("ambiguous transport context")
            transport_seen = True
            tokens = command.lower().split()
            if tokens in (["transport", "input", "ssh"], ["transport", "input", "none"]):
                continue
            if tokens[:2] != ["transport", "input"] or (
                len(tokens) != 4 or set(tokens[2:]) != {"ssh", "telnet"}
            ):
                raise ValueError("Telnet removal requires explicit SSH-only alternative")
            changed = _replace_line(raw, "transport input ssh")
            changes[index] = changed
            edits.append(
                VendorEdit(
                    kind="cisco_vty_ssh_only",
                    source_line=index + 1,
                    before_line_sha256=_digest(raw),
                    after_line_sha256=_digest(changed),
                    vty=current,
                )
            )
    return changes, tuple(edits)


def _simple_edits(
    lines: list[str], vendor: Vendor, category: Category
) -> tuple[dict[int, str], tuple[VendorEdit, ...]]:
    changes, edits = {}, []
    if vendor is Vendor.JUNIPER:
        # Hierarchical/quoted/service suboptions are not rewritten into guessed set syntax.
        if any(raw.strip() and not raw.strip().startswith(("set ", "#")) for raw in lines):
            raise ValueError("only flat JunOS set input is supported")
    if vendor is Vendor.JUNIPER and category == "management.telnet_enabled":
        if not any(
            raw.strip().removesuffix(";")
            in {"set system services ssh", "set system services ssh protocol-version v2"}
            for raw in lines
        ):
            raise ValueError("explicit supported SSH service is required")
        expected, replacement, kind = "set system services telnet", "", "junos_remove_telnet"
    elif vendor is Vendor.JUNIPER:
        expected = "set system services ssh protocol-version"
        replacement, kind = "set system services ssh protocol-version v2", "junos_ssh_v2"
    else:
        expected, replacement, kind = "ip ssh version", "ip ssh version 2", "cisco_ssh_v2"
    matched = 0
    for index, raw in enumerate(lines):
        command = raw.strip().removesuffix(";") if vendor is Vendor.JUNIPER else raw.strip()
        if not command.lower().startswith(expected):
            continue
        matched += 1
        if category == "management.telnet_enabled":
            supported = command == expected
        else:
            supported = command in {expected + " 1", expected + " v1"}
            if vendor is Vendor.CISCO:
                supported = command.lower() == expected + " 1" and not raw[0].isspace()
        if not supported:
            raise ValueError("ambiguous management command")
        # Exact JunOS service statement deletion; otherwise retain whitespace/line endings.
        changed = (
            ""
            if not replacement
            else _replace_line(
                raw, replacement + (";" if raw.rstrip("\r\n \t").endswith(";") else "")
            )
        )
        changes[index] = changed
        edits.append(
            VendorEdit(
                kind=kind,
                source_line=index + 1,
                before_line_sha256=_digest(raw),
                after_line_sha256=_digest(changed) if changed else None,
            )
        )
    if matched != 1:
        raise ValueError("simple management changes require one unambiguous explicit statement")
    return changes, tuple(edits)


def _semantic(config: CanonicalConfig) -> dict[str, object]:
    def strip(value: object) -> object:
        if isinstance(value, dict):
            return {key: strip(item) for key, item in value.items() if key != "provenance"}
        if isinstance(value, list):
            return [strip(item) for item in value]
        return value

    payload = config.model_dump(mode="json", exclude={"source"})
    return {key: strip(value) for key, value in payload.items()}


def create_vendor_draft(
    before: str,
    *,
    finding: Finding,
    source_sha256: str,
    reference_id: str,
) -> GeneratedVendorDraft:
    """Deterministic two-policy draft, only on a current exact fully parsed source."""
    validate_configuration_text(before)
    finding = Finding.model_validate(finding.model_dump())
    parsed = parse_configuration(before, filename="before.cfg")
    if (
        _digest(before) != source_sha256
        or not _complete(parsed)
        or finding.detector != "policy_engine"
        or finding.model_version != POLICY_CATALOG_VERSION
        or finding.category not in {"management.telnet_enabled", "management.ssh_version_1"}
        or finding not in evaluate_policies(parsed, device_id=finding.device_id)
    ):
        raise ValueError("selected source/finding is stale, unsupported or incomplete")
    category: Category = (
        "management.telnet_enabled"
        if finding.category == "management.telnet_enabled"
        else "management.ssh_version_1"
    )
    lines = before.splitlines(keepends=True)
    changes, edits = (
        _cisco_telnet(lines)
        if parsed.device.vendor is Vendor.CISCO and category == "management.telnet_enabled"
        else _simple_edits(lines, parsed.device.vendor, category)
    )
    if (
        not changes
        or len(changes) > 128
        or tuple(edit.source_line for edit in edits) != tuple(finding.affected_lines)
    ):
        raise ValueError("supported edits do not exactly cover selected finding anchors")
    after = "".join(changes.get(index, raw) for index, raw in enumerate(lines))
    validate_configuration_text(after)
    candidate = parse_configuration(after, filename="after.cfg")
    expected = _semantic(parsed)
    management = expected["management"]
    if not isinstance(management, dict):
        raise ValueError("unsupported normalized management")
    management["telnet_enabled" if category == "management.telnet_enabled" else "ssh_version"] = (
        False if category == "management.telnet_enabled" else "2"
    )
    if not _complete(candidate) or _semantic(candidate) != expected:
        raise ValueError("candidate changed unrelated semantics or is incompletely parsed")
    proposal = create_patch_proposal(
        before, after, device_id=finding.device_id, reference_id=reference_id
    )
    review = review_patch_proposal(proposal, before, after, device_id=finding.device_id)
    return GeneratedVendorDraft(
        VendorDraft(
            category=category,
            selected_finding_sha256=finding_fingerprint(finding),
            edits=edits,
            review=review,
        ),
        after,
    )


def check_vendor_draft(metadata: VendorDraft, before: str, after: str) -> GeneratedVendorDraft:
    """Rebuild the allowed edit from original source, not a stored checksum alone."""
    metadata = VendorDraft.model_validate(metadata.model_dump())
    selected = next(
        row
        for row in metadata.review.preflight.before_policy_findings
        if row.category == metadata.category
    )
    fresh = create_vendor_draft(
        before,
        finding=selected,
        source_sha256=metadata.review.proposal.before_sha256,
        reference_id=metadata.review.proposal.reference_id,
    )
    if metadata != fresh.metadata or after != fresh.candidate_text:
        raise ValueError("saved vendor draft is stale or changed; recreate it")
    return fresh
