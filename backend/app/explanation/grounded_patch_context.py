"""Closed minimized patch context checks, without authenticating the original source.

Only the source-bound builder and its replay establish the source/finding binding.
This module checks the component's types, closed vocabulary and internal coherence;
it neither runs a parser/verifier/model nor establishes real-device facts.
"""

from __future__ import annotations

import json
import re
from typing import Annotated, Any, Literal, cast

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt

from app.explanation.knowledge import (
    DocumentChunk,
    KnowledgeUnavailable,
    load_knowledge_catalog,
)
from app.explanation.provider import MAX_PROMPT_BYTES
from app.policies import POLICY_CATALOG_VERSION, POLICY_CATALOGS

type _Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
type _Line = Annotated[StrictInt, Field(ge=1, le=10_000)]
type _Version = Literal["1", "2"] | None

_LIMITATIONS = (
    "Only two explicit management policies are eligible; all other source is omitted.",
    "Local parse completeness is not vendor syntax or reachability verification.",
    "Baseline approval, management access, rollback, ML and formal checks are not proven.",
    "Hashes, numeric anchors and management facts can still be confidential.",
)
_JUNOS_COMMANDS = frozenset(
    {
        "set system services ssh",
        "set system services ssh protocol-version v1",
        "set system services ssh protocol-version v2",
        "set system services telnet",
    }
)
# The edit builder also accepts numeric SSHv1 at an affected source anchor.
# Its supporting/baseline minimizer deliberately emits only the v1/v2 spellings.
_JUNOS_AFFECTED_COMMANDS = _JUNOS_COMMANDS | {"set system services ssh protocol-version 1"}
_CISCO_SSH_COMMANDS = frozenset({"ip ssh version 1", "ip ssh version 2"})
_CISCO_TRANSPORT_COMMANDS = frozenset(
    {"transport input ssh", "transport input ssh telnet", "transport input telnet ssh"}
)


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class _Management(_Strict):
    telnet_enabled: StrictBool | None
    ssh_enabled: StrictBool | None
    ssh_version: _Version


class _Command(_Strict):
    source_line: _Line
    command: str = Field(min_length=1, max_length=256)
    configuration_context: str = Field(min_length=1, max_length=32)


class _AffectedCommand(_Command):
    source_line_sha256: _Digest


class _Finding(_Strict):
    sha256: _Digest
    detector: Literal["policy_engine"]
    detector_version: Literal["policy-rules-0.7.0"]
    category: Literal["management.telnet_enabled", "management.ssh_version_1"]
    affected_lines: list[_Line] = Field(min_length=1, max_length=128)
    observed: _Management


class _AbsentBaseline(_Strict):
    status: Literal["not_supplied"]


class _AvailableBaseline(_Strict):
    status: Literal["available"]
    source_sha256: _Digest
    management: _Management
    approval: Literal["not_proven"]
    supported_management_commands: list[_Command] = Field(max_length=256)


class _TelnetChange(_Strict):
    property: Literal["telnet_enabled"]
    baseline: StrictBool | None
    observed: StrictBool | None


class _SshChange(_Strict):
    property: Literal["ssh_version"]
    baseline: _Version
    observed: _Version


class _AbsentDiff(_Strict):
    status: Literal["not_available"]
    scope: Literal["management_telnet_and_ssh_version_only"]


class _AvailableDiff(_Strict):
    status: Literal["available"]
    scope: Literal["management_telnet_and_ssh_version_only"]
    changes: list[Annotated[_TelnetChange | _SshChange, Field(discriminator="property")]] = Field(
        max_length=2
    )


class _Formal(_Strict):
    status: Literal["not_run"]
    reason: Literal["candidate_not_generated"]


class _Parser(_Strict):
    complete: StrictBool
    warning_count: StrictInt = Field(ge=0, le=0)
    unparsed_count: StrictInt = Field(ge=0, le=0)


class _Document(DocumentChunk):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    # The component carries explicit fields; validation must never fill this default.
    authority: Literal["internal_project_document"]


class _Component(_Strict):
    version: Literal["source-bound-model-patch-0.2.0"]
    source_sha256: _Digest
    reference_sha256: _Digest
    vendor: Literal["cisco", "juniper"]
    platform: Literal["ios", "junos"]
    finding: _Finding
    affected_block: list[_AffectedCommand] = Field(min_length=1, max_length=128)
    supporting_block: list[_Command] = Field(max_length=256)
    baseline: Annotated[_AbsentBaseline | _AvailableBaseline, Field(discriminator="status")]
    safe_diff: Annotated[_AbsentDiff | _AvailableDiff, Field(discriminator="status")]
    formal_verification: _Formal
    parser: _Parser
    limitations: list[str] = Field(min_length=4, max_length=4)
    knowledge_version: Literal["project-knowledge-0.2.0"]
    knowledge_sha256: _Digest
    documents: list[_Document] = Field(min_length=1, max_length=4)


def _ordered(lines: list[int]) -> None:
    if lines != sorted(set(lines)):
        raise ValueError("unordered or duplicate component anchors")


def _command_scope(item: _Command, vendor: str, *, affected: bool = False) -> None:
    command = item.command
    if not command.isascii() or any(not char.isprintable() for char in command):
        raise ValueError("unsupported component command")
    if vendor == "juniper":
        allowed = _JUNOS_AFFECTED_COMMANDS if affected else _JUNOS_COMMANDS
        if command not in allowed or item.configuration_context != "root":
            raise ValueError("unsupported component command scope")
        return
    # Cisco affected commands retain source case; supporting commands are emitted
    # by the builder's exact lowercase public-syntax allowlist.
    normalized = command.lower() if affected else command
    if normalized in _CISCO_SSH_COMMANDS and item.configuration_context == "root":
        return
    context = re.fullmatch(
        r"line vty (0|[1-9][0-9]{0,3}) (0|[1-9][0-9]{0,3})", item.configuration_context
    )
    if (
        normalized not in _CISCO_TRANSPORT_COMMANDS
        or context is None
        or int(context[1]) > int(context[2])
    ):
        raise ValueError("unsupported component command scope")


def _check_source_scope(data: _Component) -> None:
    if (data.vendor, data.platform) not in {("cisco", "ios"), ("juniper", "junos")}:
        raise ValueError("component platform differs")
    lines = [item.source_line for item in data.affected_block]
    _ordered(lines)
    _ordered(data.finding.affected_lines)
    supporting = [item.source_line for item in data.supporting_block]
    _ordered(supporting)
    if (
        lines != data.finding.affected_lines
        or set(lines).intersection(supporting)
        or len(lines) + len(supporting) > 256
    ):
        raise ValueError("component finding anchors differ")
    for item in data.affected_block:
        _command_scope(item, data.vendor, affected=True)
    for support in data.supporting_block:
        _command_scope(support, data.vendor)
    expected = {
        ("cisco", "management.telnet_enabled"): {
            "transport input ssh telnet",
            "transport input telnet ssh",
        },
        ("cisco", "management.ssh_version_1"): {"ip ssh version 1"},
        ("juniper", "management.telnet_enabled"): {"set system services telnet"},
        ("juniper", "management.ssh_version_1"): {
            "set system services ssh protocol-version 1",
            "set system services ssh protocol-version v1",
        },
    }[(data.vendor, data.finding.category)]
    if (
        any(item.command.lower() not in expected for item in data.affected_block)
        or any(item.command.lower() in expected for item in data.supporting_block)
        or (
            (data.vendor, data.finding.category) != ("cisco", "management.telnet_enabled")
            and len(data.affected_block) != 1
        )
    ):
        raise ValueError("component commands differ from selected policy")
    observed = data.finding.observed
    if (
        observed.ssh_enabled is not True
        or (
            data.finding.category == "management.telnet_enabled"
            and observed.telnet_enabled is not True
        )
        or (data.finding.category == "management.ssh_version_1" and observed.ssh_version != "1")
    ):
        raise ValueError("component observation differs from selected policy")


def _check_baseline(data: _Component) -> None:
    if isinstance(data.baseline, _AbsentBaseline):
        if not isinstance(data.safe_diff, _AbsentDiff):
            raise ValueError("component baseline and diff availability differ")
        return
    if not isinstance(data.safe_diff, _AvailableDiff):
        raise ValueError("component baseline and diff availability differ")
    commands = data.baseline.supported_management_commands
    _ordered([item.source_line for item in commands])
    for item in commands:
        _command_scope(item, data.vendor)
    previous = data.baseline.management.model_dump()
    observed = data.finding.observed.model_dump()
    expected = [
        {"property": key, "baseline": previous[key], "observed": observed[key]}
        for key in ("telnet_enabled", "ssh_version")
        if previous[key] != observed[key]
    ]
    if [item.model_dump() for item in data.safe_diff.changes] != expected:
        raise ValueError("component safe diff differs from supplied observations")


def _check_documents(data: _Component) -> None:
    if data.finding.detector_version != POLICY_CATALOG_VERSION:
        raise ValueError("component policy version differs")
    catalog = load_knowledge_catalog(data.knowledge_version)
    if data.knowledge_sha256 != catalog.sha256:
        raise ValueError("component knowledge binding differs")
    sealed = {item.citation: item.model_dump(mode="json") for item in catalog.chunks}
    citations = [item.citation for item in data.documents]
    if len(set(citations)) != len(citations) or any(
        item.model_dump(mode="json") != sealed.get(item.citation) for item in data.documents
    ):
        raise ValueError("component documents differ from sealed release")
    rule = next(
        item
        for item in POLICY_CATALOGS[data.finding.detector_version]
        if item.rule_id == data.finding.category
    )
    if not set(rule.references) <= set(citations):
        raise ValueError("component policy references are missing")


def check_grounded_patch_component(value: object) -> dict[str, Any]:
    """Validate and return the exact supplied mapping, without defaults or new facts.

    This is a structural/coherence guard, not source authentication, parser replay,
    vendor syntax validation, baseline approval or any formal-verification result.
    Rejected private values and Pydantic error details never leave this boundary.
    """
    try:
        if type(value) is not dict:
            raise ValueError("component must be an object")
        data = _Component.model_validate(value, strict=True)
        if data.parser.complete is not True or tuple(data.limitations) != _LIMITATIONS:
            raise ValueError("component fixed limitations differ")
        _check_source_scope(data)
        _check_baseline(data)
        _check_documents(data)
        serialized = json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
        )
        if len(serialized.encode("utf-8")) > MAX_PROMPT_BYTES:
            raise ValueError("component exceeds budget")
        return cast(dict[str, Any], value)
    except (ValueError, TypeError, RecursionError, KnowledgeUnavailable):
        raise ValueError("Grounded patch component was rejected.") from None
