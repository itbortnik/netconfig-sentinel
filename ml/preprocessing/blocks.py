"""Lossless structural segmentation with source-line provenance."""

from __future__ import annotations

import hashlib
import re
from enum import StrEnum

from app.domain import Vendor
from app.parsers import detect_vendor
from pydantic import BaseModel, ConfigDict, Field, model_validator

from ml.datasets.models import ImportedDatasetRecord
from ml.preprocessing.sanitization import SANITIZATION_VERSION

SEGMENTATION_VERSION = "config-blocks-0.1.0"


class BlockCategory(StrEnum):
    MANAGEMENT = "management"
    INTERFACES = "interfaces"
    LAYER2 = "layer2"
    ACCESS_CONTROL = "access_control"
    BGP = "bgp"
    OSPF = "ospf"
    STATIC_ROUTES = "static_routes"
    UNKNOWN = "unknown"
    MIXED = "mixed"


class ConfigurationBlock(BaseModel):
    """Exact contiguous source slice; unknown syntax is retained."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    segmentation_version: str = Field(
        default=SEGMENTATION_VERSION, pattern=r"^config-blocks-0\.1\.0$"
    )
    source_id: str
    record_id: str
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    block_id: str = Field(pattern=r"^block-[0-9a-f]{24}$")
    category: BlockCategory
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    text: str = Field(min_length=1)
    text_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_slice(self) -> ConfigurationBlock:
        if self.end_line - self.start_line + 1 != len(self.text.splitlines()):
            raise ValueError("block line range does not match text")
        if digest(self.text) != self.text_sha256:
            raise ValueError("block text hash does not match")
        if self.block_id != _block_id(
            self.source_id,
            self.record_id,
            self.source_sha256,
            self.start_line,
            self.end_line,
            self.category,
        ):
            raise ValueError("block identity does not match provenance")
        return self


def digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _block_id(
    source: str,
    record: str,
    source_hash: str,
    start: int,
    end: int,
    category: BlockCategory,
) -> str:
    return (
        "block-"
        + digest(
            f"{SEGMENTATION_VERSION}\0{source}\0{record}\0{source_hash}\0{start}\0{end}\0{category}"
        )[:24]
    )


def segment_configuration(record: ImportedDatasetRecord) -> tuple[ConfigurationBlock, ...]:
    """Partition every source line exactly once, including comments and unknowns."""
    text = record.sanitized_text
    if not text.strip() or len(text.encode("utf-8")) > 1024 * 1024:
        raise ValueError("segmentation requires nonempty text up to 1 MiB")
    if record.sanitization_version != SANITIZATION_VERSION:
        raise ValueError("unsupported sanitization version")
    if digest(text) != record.sanitized_sha256:
        raise ValueError("sanitized input hash mismatch")
    vendor = detect_vendor(text).parser_key
    expected = Vendor.CISCO if vendor == "cisco_ios" else Vendor.JUNIPER
    if record.vendor_hint is not None and record.vendor_hint != expected:
        raise ValueError("vendor hint disagrees with content")
    lines = text.splitlines(keepends=True)
    tags = _cisco_tags(lines) if expected == Vendor.CISCO else _junos_tags(lines)
    blocks: list[ConfigurationBlock] = []
    start = 0
    for end in range(1, len(lines) + 1):
        if end < len(lines) and tags[end] == tags[start]:
            continue
        body = "".join(lines[start:end])
        category = tags[start][0]
        blocks.append(
            ConfigurationBlock(
                source_id=record.source_id,
                record_id=record.record_id,
                source_sha256=record.sanitized_sha256,
                block_id=_block_id(
                    record.source_id,
                    record.record_id,
                    record.sanitized_sha256,
                    start + 1,
                    end,
                    category,
                ),
                category=category,
                start_line=start + 1,
                end_line=end,
                text=body,
                text_sha256=digest(body),
            )
        )
        start = end
    return tuple(blocks)


type _Tag = tuple[BlockCategory, str]


def _cisco_tags(lines: list[str]) -> list[_Tag]:
    tags: list[_Tag] = []
    active: _Tag = (BlockCategory.UNKNOWN, "")
    for line in lines:
        command = line.strip().casefold()
        if not command or command.startswith("!"):
            tags.append(active)
            active = (BlockCategory.UNKNOWN, "")
            continue
        if not line[0].isspace():
            words = command.split()
            if command.startswith("interface "):
                active = (BlockCategory.INTERFACES, command)
            elif command.startswith("vlan "):
                active = (BlockCategory.LAYER2, command)
            elif command.startswith(("ip access-list ", "ipv6 access-list ", "route-map ")):
                active = (BlockCategory.ACCESS_CONTROL, command)
            elif command.startswith(("ip prefix-list ", "ipv6 prefix-list ", "access-list ")):
                active = (BlockCategory.ACCESS_CONTROL, " ".join(words[:3]))
            elif command.startswith("router bgp "):
                active = (BlockCategory.BGP, command)
            elif command.startswith("router ospf "):
                active = (BlockCategory.OSPF, command)
            elif command.startswith(("ip route ", "ipv6 route ")):
                active = (BlockCategory.STATIC_ROUTES, "routes")
            elif words[0] in {
                "hostname",
                "version",
                "aaa",
                "username",
                "enable",
                "snmp-server",
                "ntp",
                "logging",
                "line",
                "radius-server",
                "tacacs-server",
            } or command.startswith(("ip ssh ", "no aaa ", "ip domain")):
                active = (BlockCategory.MANAGEMENT, "management")
            else:
                active = (BlockCategory.UNKNOWN, command)
        tags.append(active)
    return tags


_JUNOS_LEXER = re.compile(
    r'/\*.*?\*/|\#[^\r\n]*|"(?:\\.|[^"\\])*"|[{};]|[^\s{};"#]+',
    re.DOTALL,
)


def _junos_category(path: list[str]) -> _Tag:
    words = [word.casefold() for word in path]
    if not words:
        return BlockCategory.UNKNOWN, ""
    first = words[0]
    if first in {"system", "snmp"}:
        return BlockCategory.MANAGEMENT, first
    if first == "interfaces":
        return BlockCategory.INTERFACES, " ".join(words[:2])
    if first == "vlans":
        return BlockCategory.LAYER2, " ".join(words[:2])
    if first in {"firewall", "policy-options"}:
        return BlockCategory.ACCESS_CONTROL, " ".join(words[:2])
    if words[:2] == ["protocols", "bgp"]:
        return BlockCategory.BGP, "bgp"
    if words[:2] == ["protocols", "ospf"]:
        return BlockCategory.OSPF, "ospf"
    if words[:2] == ["routing-options", "static"]:
        return BlockCategory.STATIC_ROUTES, "routes"
    if first == "routing-options" and len(words) > 1:
        if words[1] in {"autonomous-system", "router-id"}:
            return BlockCategory.BGP, "routing-options"
    return BlockCategory.UNKNOWN, " ".join(words[:2])


def _junos_tags(lines: list[str]) -> list[_Tag]:
    meaningful = [
        line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#")
    ]
    if meaningful and all(line.startswith("set ") for line in meaningful):
        return [
            _junos_category(line.strip().split()[1:])
            if line.strip().startswith("set ")
            else (BlockCategory.UNKNOWN, "")
            for line in lines
        ]
    text = "".join(lines)
    # A lexical brace stack handles quoted braces and multiline comments.
    stack: list[list[str]] = []
    pending: list[str] = []
    tags_by_line: list[list[_Tag]] = [[] for _ in lines]
    line_index = 0
    cursor = 0
    for match in _JUNOS_LEXER.finditer(text):
        gap = text[cursor : match.start()]
        if gap.strip():
            raise ValueError("malformed JunOS quoted string or comment")
        line_index += gap.count("\n")
        token = match.group()
        path = [word for frame in stack for word in frame]
        if token.startswith(("#", "/*")):
            tag = _junos_category(path)
        elif token == "}":
            if not stack or pending:
                raise ValueError("unbalanced JunOS structure")
            tag = _junos_category(path)
            stack.pop()
        elif token == "{":
            if not pending:
                raise ValueError("JunOS block is missing a header")
            tag = _junos_category(path + pending)
            stack.append(pending)
            pending = []
        elif token == ";":
            tag = _junos_category(path + pending)
            pending = []
        else:
            pending.append(token)
            tag = _junos_category(path + pending)
        for index in range(line_index, min(len(lines), line_index + token.count("\n") + 1)):
            tags_by_line[index].append(tag)
        line_index += token.count("\n")
        cursor = match.end()
    if stack or pending or text[cursor:].strip():
        raise ValueError("unfinished JunOS structure")
    result: list[_Tag] = []
    for candidates in tags_by_line:
        known = [tag for tag in candidates if tag[0] is not BlockCategory.UNKNOWN]
        categories = {tag[0] for tag in known}
        if len(categories) > 1:
            result.append((BlockCategory.MIXED, "inline"))
        elif known:
            result.append(known[-1])
        else:
            result.append(candidates[-1] if candidates else (BlockCategory.UNKNOWN, ""))
    return result
