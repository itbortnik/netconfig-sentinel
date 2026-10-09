"""Versioned census of current adapter input lines, separate from the canonical IR.

Acceptance is the adapter's observed disposition, not semantic completeness or a
vendor syntax verdict. Headers and repeated statements are individual input units;
comments and exact structural delimiters do not enter the unknown fraction.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.domain import CanonicalConfig, Vendor
from app.ingestion.local import MAX_INPUT_LINES, validate_configuration_text
from app.parsers.base import text_sha256
from app.parsers.juniper_junos.parser import _strip_comment
from app.parsers.registry import parse_configuration

Disposition = Literal["accepted", "unparsed", "structural", "ignored"]
AdapterVersion = Literal["cisco-ios-source-lines-0.1.0", "junos-source-lines-0.1.0"]


class ParserSourceUnit(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    source_line: int = Field(strict=True, ge=1, le=MAX_INPUT_LINES)
    raw_text_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    disposition: Disposition


class ParserCoverage(BaseModel):
    """Hash-bound line accounting; never infer this from parser confidence."""

    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)
    version: Literal["parser-coverage-0.1.0"] = "parser-coverage-0.1.0"
    unit: Literal["adapter_source_lines"] = "adapter_source_lines"
    adapter_version: AdapterVersion
    vendor: Vendor
    platform: Literal["ios", "junos"]
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_line_count: int = Field(strict=True, ge=1, le=MAX_INPUT_LINES)
    accepted_units: int = Field(strict=True, ge=0, le=MAX_INPUT_LINES)
    unparsed_units: int = Field(strict=True, ge=0, le=MAX_INPUT_LINES)
    structural_units: int = Field(strict=True, ge=0, le=MAX_INPUT_LINES)
    ignored_lines: int = Field(strict=True, ge=0, le=MAX_INPUT_LINES)
    command_units: int = Field(strict=True, ge=0, le=MAX_INPUT_LINES)
    unparsed_fraction: float | None = Field(strict=True, ge=0, le=1)
    proves_vendor_syntax: Literal[False] = False
    units: tuple[ParserSourceUnit, ...] = Field(min_length=1, max_length=MAX_INPUT_LINES)

    @field_validator("proves_vendor_syntax", mode="before")
    @classmethod
    def no_syntax_verdict(cls, value: object) -> object:
        if value is not False:
            raise ValueError("coverage is not a vendor syntax verdict")
        return value

    @model_validator(mode="after")
    def exact_accounting(self) -> ParserCoverage:
        expected_adapter = {
            (Vendor.CISCO, "ios"): "cisco-ios-source-lines-0.1.0",
            (Vendor.JUNIPER, "junos"): "junos-source-lines-0.1.0",
        }.get((self.vendor, self.platform))
        if expected_adapter != self.adapter_version:
            raise ValueError("coverage adapter does not match the platform")
        if len(self.units) != self.source_line_count or any(
            item.source_line != number for number, item in enumerate(self.units, 1)
        ):
            raise ValueError("coverage requires every source line exactly once in order")
        counts = Counter(item.disposition for item in self.units)
        if (
            self.accepted_units != counts["accepted"]
            or self.unparsed_units != counts["unparsed"]
            or self.structural_units != counts["structural"]
            or self.ignored_lines != counts["ignored"]
            or self.command_units != self.accepted_units + self.unparsed_units
        ):
            raise ValueError("coverage counts differ from source units")
        expected = self.unparsed_units / self.command_units if self.command_units else None
        if self.unparsed_fraction != expected:
            raise ValueError("coverage fraction differs from observed counts")
        return self

    def validate_binding(self, canonical: CanonicalConfig) -> None:
        """Check available source/fragment anchors, not the truth of accepted semantics."""
        if (
            self.source_sha256 != canonical.source.sha256
            or self.vendor != canonical.device.vendor
            or self.platform != canonical.device.platform
        ):
            raise ValueError("coverage belongs to a different configuration")
        unparsed_lines = {
            number
            for fragment in canonical.unparsed_fragments
            for number in fragment.location.source_lines
        }
        if unparsed_lines != {
            item.source_line for item in self.units if item.disposition == "unparsed"
        }:
            raise ValueError("coverage differs from unparsed source anchors")
        for fragment in canonical.unparsed_fragments:
            lines = fragment.raw_text.split("\n")
            if (
                text_sha256(fragment.raw_text) != fragment.location.raw_text_hash
                or len(lines) != len(fragment.location.source_lines)
                or any(
                    self.units[number - 1].raw_text_sha256 != text_sha256(raw_line)
                    for number, raw_line in zip(fragment.location.source_lines, lines, strict=True)
                )
            ):
                raise ValueError("coverage differs from unparsed text hashes")


@dataclass(frozen=True)
class ParsedConfiguration:
    canonical: CanonicalConfig
    coverage: ParserCoverage


def _disposition(raw_line: str, vendor: Vendor) -> Disposition:
    if vendor == Vendor.CISCO:
        command = raw_line.strip()
        if not command or command.startswith("!"):
            return "ignored"
        if command.lower() in {"end", "exit", "configure terminal", "exit-address-family"}:
            return "structural"
    else:
        # Deliberately follow the current adapter, including its comment limitations.
        command = _strip_comment(raw_line).strip()
        if not command or command.startswith("##"):
            return "ignored"
        if command in {"}", "};"}:
            return "structural"
    return "accepted"


def parse_configuration_with_coverage(
    text: str, *, filename: str, collected_at: datetime | None = None
) -> ParsedConfiguration:
    """Bound input, parse once, and count final unsupported anchors, including late ones."""
    validate_configuration_text(text)
    canonical = parse_configuration(text, filename=filename, collected_at=collected_at)
    unsupported = {
        number
        for fragment in canonical.unparsed_fragments
        for number in fragment.location.source_lines
    }
    units = tuple(
        ParserSourceUnit(
            source_line=number,
            raw_text_sha256=text_sha256(raw_line),
            disposition=(
                "unparsed"
                if number in unsupported
                else _disposition(raw_line, canonical.device.vendor)
            ),
        )
        for number, raw_line in enumerate(text.splitlines(), 1)
    )
    counts = Counter(item.disposition for item in units)
    command_units = counts["accepted"] + counts["unparsed"]
    adapter: AdapterVersion = (
        "cisco-ios-source-lines-0.1.0"
        if canonical.device.vendor == Vendor.CISCO
        else "junos-source-lines-0.1.0"
    )
    platform: Literal["ios", "junos"] = (
        "ios" if canonical.device.vendor == Vendor.CISCO else "junos"
    )
    report = ParserCoverage(
        adapter_version=adapter,
        vendor=canonical.device.vendor,
        platform=platform,
        source_sha256=canonical.source.sha256,
        source_line_count=len(units),
        accepted_units=counts["accepted"],
        unparsed_units=counts["unparsed"],
        structural_units=counts["structural"],
        ignored_lines=counts["ignored"],
        command_units=command_units,
        unparsed_fraction=counts["unparsed"] / command_units if command_units else None,
        units=units,
    )
    report.validate_binding(canonical)
    return ParsedConfiguration(canonical, report)
