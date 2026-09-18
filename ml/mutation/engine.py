"""Deterministic, reversible mutation engine for sanitized configurations."""

from __future__ import annotations

import hashlib
import re
from collections import Counter
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from difflib import SequenceMatcher

from app.domain import CanonicalConfig, Vendor
from app.parsers import parse_configuration

from ml.datasets.deduplication import DatasetRecordReference
from ml.datasets.models import ImportedDatasetRecord
from ml.mutation.models import (
    MUTATION_ENGINE_VERSION,
    MutationFormalValidation,
    MutationOperation,
    MutationSyntaxValidation,
    MutationType,
    MutationValidationStatus,
    SyntheticAnomalyLabel,
    SyntheticMutationSample,
)
from ml.preprocessing import SANITIZATION_VERSION


class MutationNotApplicableError(ValueError):
    """Raised when a source does not satisfy a mutation precondition."""


class MutationValidationError(ValueError):
    """Raised when a generated mutation fails a required validation."""


@dataclass(frozen=True, slots=True)
class _TextLayout:
    lines: list[str]
    newline: str
    trailing_newline: bool

    def render(self, lines: Sequence[str]) -> str:
        text = self.newline.join(lines)
        return text + self.newline if self.trailing_newline else text


@dataclass(frozen=True, slots=True)
class _MutationSpec:
    precondition: str
    description: str
    expected_effect: str
    category: str


type _MutationHandler = Callable[
    [list[str], Vendor, int, str, MutationType, _MutationSpec],
    tuple[list[str], MutationOperation],
]


_SPECS: dict[MutationType, _MutationSpec] = {
    MutationType.AAA_DISABLED: _MutationSpec(
        "External AAA is enabled.",
        "Disable the configured external AAA path.",
        "Canonical management AAA becomes disabled.",
        "management.aaa.disabled",
    ),
    MutationType.TELNET_ENABLED: _MutationSpec(
        "Remote management allows SSH but not Telnet.",
        "Enable Telnet using the source configuration style.",
        "Canonical management reports Telnet as enabled.",
        "management.telnet.enabled",
    ),
    MutationType.SNMP_DOWNGRADE: _MutationSpec(
        "SNMPv3 is present without a legacy SNMP community.",
        "Introduce a sanitized legacy SNMP community.",
        "Canonical SNMP versions include v1 or v2c.",
        "management.snmp.downgrade",
    ),
    MutationType.PERMISSIVE_ACL: _MutationSpec(
        "A parsed ACL contains a deny rule.",
        "Change one deny rule into a permit rule.",
        "The number of parsed permit-any rules increases.",
        "access_control.acl.permissive",
    ),
    MutationType.MISSING_ACL_ENTRY: _MutationSpec(
        "A parsed ACL contains at least one permit entry.",
        "Remove one complete permit entry or term.",
        "The parsed ACL rule count decreases.",
        "access_control.acl.missing_entry",
    ),
    MutationType.VLAN_MISMATCH: _MutationSpec(
        "An access interface has an explicit VLAN membership.",
        "Change the access VLAN while retaining the surrounding syntax.",
        "At least one parsed access VLAN changes.",
        "layer2.vlan.mismatch",
    ),
    MutationType.INCORRECT_ACCESS_TRUNK_MODE: _MutationSpec(
        "An interface has an explicit access or trunk mode.",
        "Switch one interface between access and trunk mode.",
        "At least one parsed switchport mode changes.",
        "layer2.switchport.incorrect_mode",
    ),
    MutationType.BGP_REMOTE_AS_MISMATCH: _MutationSpec(
        "A BGP neighbor has a parsed remote AS.",
        "Change one peer or neighbor remote AS to another valid value.",
        "The parsed remote-AS sequence changes without removing the neighbor.",
        "routing.bgp.remote_as_mismatch",
    ),
    MutationType.MISSING_BGP_NEIGHBOR: _MutationSpec(
        "At least one BGP neighbor is parsed.",
        "Remove every source line that defines one selected neighbor.",
        "The selected neighbor is absent from the parsed result.",
        "routing.bgp.missing_neighbor",
    ),
    MutationType.OSPF_AREA_MISMATCH: _MutationSpec(
        "At least one OSPF network or interface has an area assignment.",
        "Change one area to another valid area identifier.",
        "The parsed OSPF area sequence changes.",
        "routing.ospf.area_mismatch",
    ),
    MutationType.REMOVED_STATIC_ROUTE: _MutationSpec(
        "At least one static route is parsed.",
        "Remove every source line for one selected static route.",
        "The parsed static-route count decreases.",
        "routing.static_route.removed",
    ),
    MutationType.MANAGEMENT_EXPOSURE: _MutationSpec(
        "A management ACL permit rule restricts its source network.",
        "Broaden one restricted permit source to any IPv4 address.",
        "The number of parsed permit rules with an any source increases.",
        "management.access.exposed",
    ),
    MutationType.MISSING_NTP_SYSLOG: _MutationSpec(
        "At least one NTP or Syslog destination is parsed.",
        "Remove all configured NTP and Syslog destination lines.",
        "The parsed NTP and Syslog destination count decreases.",
        "observability.destinations.missing",
    ),
    MutationType.ROUTE_MAP_ORDER_CHANGE: _MutationSpec(
        "A Cisco route-map has at least two sequence entries.",
        "Exchange two route-map sequence numbers without moving their bodies.",
        "The route-map evaluation order changes while its neighboring text remains.",
        "routing.route_map.order_change",
    ),
    MutationType.CONFLICTING_IP_ADDRESS: _MutationSpec(
        "Two parsed interfaces have distinct addresses in the same family.",
        "Replace one interface address with the address of another interface.",
        "The parsed configuration contains a duplicate interface address.",
        "interfaces.ip.conflict",
    ),
}


def mutate_configuration(
    record: ImportedDatasetRecord,
    mutation_types: Sequence[MutationType],
    *,
    seed: int = 0,
) -> SyntheticMutationSample:
    """Apply one to five unique mutations and validate the resulting syntax."""

    requested = tuple(MutationType(item) for item in mutation_types)
    if not requested:
        raise ValueError("at least one mutation type is required")
    if len(requested) > 5:
        raise ValueError("at most five linked mutation types are allowed")
    if len(requested) != len(set(requested)):
        raise ValueError("mutation types must be unique within one sample")
    if seed < 0 or seed > 2**63 - 1:
        raise ValueError("seed must fit the supported non-negative range")
    actual_hash = _sha256(record.sanitized_text)
    if actual_hash != record.sanitized_sha256:
        raise ValueError("record sanitized text does not match its SHA-256")
    if record.sanitization_version != SANITIZATION_VERSION:
        raise ValueError("record uses an unsupported sanitization version")
    if record.vendor_hint is None:
        raise MutationNotApplicableError("mutation requires an explicit vendor hint")

    layout = _text_layout(record.sanitized_text)
    original_config = _parse(record, record.sanitized_text)
    if original_config.device.vendor is not record.vendor_hint:
        raise MutationValidationError("vendor hint does not match parser detection")
    _require_supported_style(layout.lines, record.vendor_hint)

    lines = list(layout.lines)
    operations: list[MutationOperation] = []
    for mutation_type in requested:
        handler = _HANDLERS[mutation_type]
        lines, operation = handler(
            lines,
            record.vendor_hint,
            seed,
            record.sanitized_sha256,
            mutation_type,
            _SPECS[mutation_type],
        )
        operations.append(operation)

    mutated_text = layout.render(lines)
    mutated_config = _parse(record, mutated_text)
    if mutated_config.device.vendor is not record.vendor_hint:
        raise MutationValidationError("mutation changed vendor detection")
    route_map_partial = MutationType.ROUTE_MAP_ORDER_CHANGE in requested
    introduced_warnings = sum(
        (
            Counter(mutated_config.parse_warnings)
            - Counter(original_config.parse_warnings)
        ).values()
    )
    introduced_unparsed = (
        0
        if route_map_partial
        else sum(
            (
                Counter(item.raw_text for item in mutated_config.unparsed_fragments)
                - Counter(item.raw_text for item in original_config.unparsed_fragments)
            ).values()
        )
    )
    if introduced_warnings or introduced_unparsed:
        raise MutationValidationError(
            "mutation introduced parser warnings or unsupported fragments"
        )
    for mutation_type in requested:
        if not _effect_observed(
            mutation_type,
            original_config,
            mutated_config,
            record.sanitized_text,
            mutated_text,
        ):
            raise MutationValidationError(
                f"expected mutation effect was not observed: {mutation_type.value}"
            )

    mutated_hash = _sha256(mutated_text)
    mutation_id = _mutation_id(
        record,
        requested,
        seed,
        mutated_hash,
    )
    affected_lines = _changed_line_numbers(layout.lines, lines)
    return SyntheticMutationSample(
        mutation_id=mutation_id,
        source_record=DatasetRecordReference(
            source_id=record.source_id,
            record_id=record.record_id,
        ),
        vendor=record.vendor_hint,
        seed=seed,
        original_sha256=record.sanitized_sha256,
        mutated_sha256=mutated_hash,
        mutated_text=mutated_text,
        operations=tuple(operations),
        labels=tuple(
            SyntheticAnomalyLabel(
                mutation_type=mutation_type,
                category=_SPECS[mutation_type].category,
            )
            for mutation_type in requested
        ),
        affected_lines=affected_lines,
        syntax_validation=MutationSyntaxValidation(
            status=(
                MutationValidationStatus.PARTIAL
                if route_map_partial
                else MutationValidationStatus.PASSED
            ),
            parser=(
                "cisco_ios" if record.vendor_hint is Vendor.CISCO else "juniper_junos"
            ),
            parser_confidence=mutated_config.parser_confidence,
            warning_count=len(mutated_config.parse_warnings),
            unparsed_fragment_count=len(mutated_config.unparsed_fragments),
            introduced_warning_count=introduced_warnings,
            introduced_unparsed_fragment_count=introduced_unparsed,
            limitations=(
                (
                    "Route-map syntax is not semantically covered by the current parser; "
                    "only the surrounding configuration was parser-checked."
                ),
            )
            if route_map_partial
            else (),
        ),
        formal_validation=MutationFormalValidation(
            status=MutationValidationStatus.NOT_RUN,
            validator="network_behavior",
            reason="No external network-behavior validator is configured in this stage.",
        ),
        limitations=(
            "Canonical parsing is a bounded syntax check, not a device acceptance test.",
            "The synthetic label is not a confirmed real-world anomaly.",
        ),
    )


def list_applicable_mutations(
    record: ImportedDatasetRecord,
    *,
    seed: int = 0,
) -> tuple[MutationType, ...]:
    """Return mutations that independently produce a validated sample."""

    applicable: list[MutationType] = []
    for mutation_type in MutationType:
        try:
            mutate_configuration(record, (mutation_type,), seed=seed)
        except (MutationNotApplicableError, MutationValidationError):
            continue
        applicable.append(mutation_type)
    return tuple(applicable)


def count_synthetic_anomaly_labels(
    samples: Sequence[SyntheticMutationSample],
) -> int:
    """Count labels once per unique generated sample for quality reporting."""

    mutation_ids = [sample.mutation_id for sample in samples]
    if len(mutation_ids) != len(set(mutation_ids)):
        raise ValueError("synthetic mutation samples must have unique IDs")
    return sum(len(sample.labels) for sample in samples)


def reverse_mutation(sample: SyntheticMutationSample, mutated_text: str) -> str:
    """Apply recorded inverse edits and verify the restored original hash."""

    if _sha256(mutated_text) != sample.mutated_sha256:
        raise MutationValidationError("mutated text does not match the sample hash")
    layout = _text_layout(mutated_text)
    lines = list(layout.lines)
    for operation in reversed(sample.operations):
        start = operation.mutated_start_line - 1
        end = start + len(operation.mutated_lines)
        if tuple(lines[start:end]) != operation.mutated_lines:
            raise MutationValidationError("mutation reverse context does not match")
        lines[start:end] = operation.original_lines
    restored = layout.render(lines)
    if _sha256(restored) != sample.original_sha256:
        raise MutationValidationError("reverse operations did not restore the original")
    return restored


def _parse(record: ImportedDatasetRecord, text: str) -> CanonicalConfig:
    extension = "cfg" if record.vendor_hint is Vendor.CISCO else "conf"
    try:
        return parse_configuration(
            text,
            filename=f"mutation-input.{extension}",
            collected_at=record.captured_at,
        )
    except (ValueError, IndexError) as error:
        raise MutationValidationError("configuration parsing failed") from error


def _text_layout(text: str) -> _TextLayout:
    newline = "\r\n" if "\r\n" in text else "\n"
    trailing = text.endswith(("\n", "\r"))
    lines = text.splitlines()
    layout = _TextLayout(lines=lines, newline=newline, trailing_newline=trailing)
    if layout.render(lines) != text:
        raise MutationNotApplicableError("mixed or unsupported newline encoding")
    return layout


def _require_supported_style(lines: Sequence[str], vendor: Vendor) -> None:
    if vendor is not Vendor.JUNIPER:
        return
    meaningful = [
        line.strip()
        for line in lines
        if line.strip() and not line.lstrip().startswith(("#", "/*", "*"))
    ]
    if any(not line.casefold().startswith("set ") for line in meaningful):
        raise MutationNotApplicableError(
            "mutation engine version 0.1.0 supports JunOS set syntax only"
        )


def _operation(
    mutation_type: MutationType,
    spec: _MutationSpec,
    original_lines: Sequence[str],
    mutated_lines: Sequence[str],
    *,
    start_index: int,
    affected_lines: Sequence[int] | None = None,
) -> MutationOperation:
    changed_lines = tuple(
        affected_lines
        or range(start_index + 1, start_index + max(1, len(mutated_lines)) + 1)
    )
    return MutationOperation(
        mutation_type=mutation_type,
        precondition=spec.precondition,
        description=spec.description,
        expected_effect=spec.expected_effect,
        original_start_line=start_index + 1,
        original_lines=tuple(original_lines),
        mutated_start_line=start_index + 1,
        mutated_lines=tuple(mutated_lines),
        affected_lines=tuple(sorted(set(changed_lines))),
    )


def _replace_span(
    lines: list[str],
    start: int,
    end: int,
    replacement: Sequence[str],
    mutation_type: MutationType,
    spec: _MutationSpec,
    *,
    affected_lines: Sequence[int] | None = None,
) -> tuple[list[str], MutationOperation]:
    updated = list(lines)
    original = tuple(lines[start:end])
    updated[start:end] = replacement
    return updated, _operation(
        mutation_type,
        spec,
        original,
        replacement,
        start_index=start,
        affected_lines=affected_lines,
    )


def _candidate(
    candidates: Sequence[int],
    *,
    seed: int,
    fingerprint: str,
    mutation_type: MutationType,
    salt: str = "candidate",
) -> int:
    if not candidates:
        raise MutationNotApplicableError(
            f"precondition is not satisfied: {mutation_type.value}"
        )
    digest = hashlib.sha256(
        f"{MUTATION_ENGINE_VERSION}\0{fingerprint}\0{seed}\0"
        f"{mutation_type.value}\0{salt}".encode()
    ).digest()
    return candidates[int.from_bytes(digest[:8], "big") % len(candidates)]


def _variant(
    values: Sequence[str],
    *,
    seed: int,
    fingerprint: str,
    mutation_type: MutationType,
) -> str:
    index = _candidate(
        list(range(len(values))),
        seed=seed,
        fingerprint=fingerprint,
        mutation_type=mutation_type,
        salt="variant",
    )
    return values[index]


def _simple_replace(
    lines: list[str],
    vendor: Vendor,
    seed: int,
    fingerprint: str,
    mutation_type: MutationType,
    spec: _MutationSpec,
    patterns: dict[Vendor, re.Pattern[str]],
    replacement: Callable[[re.Match[str]], str],
) -> tuple[list[str], MutationOperation]:
    pattern = patterns[vendor]
    matches = [(index, pattern.match(line)) for index, line in enumerate(lines)]
    candidates = [index for index, match in matches if match is not None]
    index = _candidate(
        candidates,
        seed=seed,
        fingerprint=fingerprint,
        mutation_type=mutation_type,
    )
    match = pattern.match(lines[index])
    assert match is not None
    return _replace_span(
        lines,
        index,
        index + 1,
        (replacement(match),),
        mutation_type,
        spec,
    )


def _aaa_disabled(
    lines: list[str],
    vendor: Vendor,
    seed: int,
    fingerprint: str,
    mutation_type: MutationType,
    spec: _MutationSpec,
) -> tuple[list[str], MutationOperation]:
    patterns = {
        Vendor.CISCO: re.compile(r"^(?P<indent>\s*)aaa\s+new-model\s*$", re.I),
        Vendor.JUNIPER: re.compile(
            r"^(?P<indent>\s*)set\s+system\s+authentication-order\b.*$", re.I
        ),
    }
    return _simple_replace(
        lines,
        vendor,
        seed,
        fingerprint,
        mutation_type,
        spec,
        patterns,
        lambda match: (
            f"{match.group('indent')}no aaa new-model"
            if vendor is Vendor.CISCO
            else f"{match.group('indent')}set system authentication-order password"
        ),
    )


def _telnet_enabled(
    lines: list[str],
    vendor: Vendor,
    seed: int,
    fingerprint: str,
    mutation_type: MutationType,
    spec: _MutationSpec,
) -> tuple[list[str], MutationOperation]:
    if vendor is Vendor.CISCO:
        pattern = re.compile(
            r"^(?P<indent>\s*)transport\s+input\s+(?P<protocols>.+?)\s*$", re.I
        )
        candidates = []
        for index, line in enumerate(lines):
            match = pattern.match(line)
            if match is None:
                continue
            protocols = match.group("protocols").casefold().split()
            if "ssh" in protocols and "telnet" not in protocols and "all" not in protocols:
                candidates.append(index)
        index = _candidate(
            candidates,
            seed=seed,
            fingerprint=fingerprint,
            mutation_type=mutation_type,
        )
        match = pattern.match(lines[index])
        assert match is not None
        order = _variant(
            ("ssh telnet", "telnet ssh", "all"),
            seed=seed,
            fingerprint=fingerprint,
            mutation_type=mutation_type,
        )
        replacement = f"{match.group('indent')}transport input {order}"
        return _replace_span(
            lines, index, index + 1, (replacement,), mutation_type, spec
        )
    ssh = re.compile(r"^(?P<indent>\s*)set\s+system\s+services\s+ssh\b.*$", re.I)
    candidates = [index for index, line in enumerate(lines) if ssh.match(line)]
    index = _candidate(
        candidates,
        seed=seed,
        fingerprint=fingerprint,
        mutation_type=mutation_type,
    )
    indent = ssh.match(lines[index]).group("indent")  # type: ignore[union-attr]
    junos_replacement = (lines[index], f"{indent}set system services telnet")
    return _replace_span(
        lines,
        index,
        index + 1,
        junos_replacement,
        mutation_type,
        spec,
        affected_lines=(index + 2,),
    )


def _snmp_downgrade(
    lines: list[str],
    vendor: Vendor,
    seed: int,
    fingerprint: str,
    mutation_type: MutationType,
    spec: _MutationSpec,
) -> tuple[list[str], MutationOperation]:
    if vendor is Vendor.CISCO:
        pattern = re.compile(r"^(?P<indent>\s*)snmp-server\s+group\b.*\bv3\b.*$", re.I)
        return _simple_replace(
            lines,
            vendor,
            seed,
            fingerprint,
            mutation_type,
            spec,
            {Vendor.CISCO: pattern, Vendor.JUNIPER: pattern},
            lambda match: (
                f"{match.group('indent')}snmp-server community <redacted-community> RO"
            ),
        )
    pattern = re.compile(r"^(?P<indent>\s*)set\s+snmp\s+v3\b.*$", re.I)
    candidates = [index for index, line in enumerate(lines) if pattern.match(line)]
    index = _candidate(
        candidates,
        seed=seed,
        fingerprint=fingerprint,
        mutation_type=mutation_type,
    )
    indent = pattern.match(lines[index]).group("indent")  # type: ignore[union-attr]
    replacement = (
        lines[index],
        f"{indent}set snmp community <redacted-community> authorization read-only",
    )
    return _replace_span(
        lines, index, index + 1, replacement, mutation_type, spec, affected_lines=(index + 2,)
    )


def _permissive_acl(
    lines: list[str],
    vendor: Vendor,
    seed: int,
    fingerprint: str,
    mutation_type: MutationType,
    spec: _MutationSpec,
) -> tuple[list[str], MutationOperation]:
    patterns = {
        Vendor.CISCO: re.compile(
            r"^(?P<prefix>\s*(?:\d+\s+)?)deny(?P<suffix>\s+.+)$", re.I
        ),
        Vendor.JUNIPER: re.compile(
            r"^(?P<prefix>\s*set\s+firewall\b.*\sthen\s+)"
            r"(?:discard|reject)(?P<suffix>\s*)$",
            re.I,
        ),
    }
    return _simple_replace(
        lines,
        vendor,
        seed,
        fingerprint,
        mutation_type,
        spec,
        patterns,
        lambda match: (
            f"{match.group('prefix')}"
            f"{'permit' if vendor is Vendor.CISCO else 'accept'}"
            f"{match.group('suffix')}"
        ),
    )


def _missing_acl_entry(
    lines: list[str],
    vendor: Vendor,
    seed: int,
    fingerprint: str,
    mutation_type: MutationType,
    spec: _MutationSpec,
) -> tuple[list[str], MutationOperation]:
    if vendor is Vendor.CISCO:
        pattern = re.compile(r"^\s*(?:\d+\s+)?permit\s+.+$", re.I)
        candidates = [index for index, line in enumerate(lines) if pattern.match(line)]
        index = _candidate(
            candidates,
            seed=seed,
            fingerprint=fingerprint,
            mutation_type=mutation_type,
        )
        return _replace_span(
            lines,
            index,
            index + 1,
            (),
            mutation_type,
            spec,
            affected_lines=(index + 1,),
        )
    pattern = re.compile(
        r"^\s*set\s+firewall\s+family\s+\S+\s+filter\s+\S+\s+term\s+(?P<term>\S+)\b",
        re.I,
    )
    accepting_terms: list[str] = []
    for line in lines:
        match = pattern.match(line)
        if match is not None and re.search(r"\sthen\s+accept\s*$", line, re.I):
            accepting_terms.append(match.group("term"))
    selected_index = _candidate(
        list(range(len(accepting_terms))),
        seed=seed,
        fingerprint=fingerprint,
        mutation_type=mutation_type,
    )
    term = accepting_terms[selected_index]
    term_indices = [
        index
        for index, line in enumerate(lines)
        if (match := pattern.match(line)) is not None and match.group("term") == term
    ]
    return _remove_indices(lines, term_indices, mutation_type, spec)


def _vlan_mismatch(
    lines: list[str],
    vendor: Vendor,
    seed: int,
    fingerprint: str,
    mutation_type: MutationType,
    spec: _MutationSpec,
) -> tuple[list[str], MutationOperation]:
    patterns = {
        Vendor.CISCO: re.compile(
            r"^(?P<prefix>\s*switchport\s+access\s+vlan\s+)(?P<vlan>\d+)(?P<suffix>\s*)$",
            re.I,
        ),
        Vendor.JUNIPER: re.compile(
            r"^(?P<prefix>\s*set\s+interfaces\s+\S+(?:\s+unit\s+\S+)?\s+family\s+ethernet-switching\s+vlan\s+members\s+)"
            r"(?P<vlan>\S+)(?P<suffix>\s*)$",
            re.I,
        ),
    }
    pattern = patterns[vendor]
    matches = [(index, pattern.match(line)) for index, line in enumerate(lines)]
    candidates = [index for index, match in matches if match is not None]
    index = _candidate(
        candidates,
        seed=seed,
        fingerprint=fingerprint,
        mutation_type=mutation_type,
    )
    match = pattern.match(lines[index])
    assert match is not None
    current = match.group("vlan")
    if current.isdigit():
        value = str(1 if int(current) >= 4094 else int(current) + 1)
    else:
        value = f"{current}-MISMATCH"
    replacement = f"{match.group('prefix')}{value}{match.group('suffix')}"
    return _replace_span(lines, index, index + 1, (replacement,), mutation_type, spec)


def _incorrect_mode(
    lines: list[str],
    vendor: Vendor,
    seed: int,
    fingerprint: str,
    mutation_type: MutationType,
    spec: _MutationSpec,
) -> tuple[list[str], MutationOperation]:
    patterns = {
        Vendor.CISCO: re.compile(
            r"^(?P<prefix>\s*switchport\s+mode\s+)(?P<mode>access|trunk)(?P<suffix>\s*)$",
            re.I,
        ),
        Vendor.JUNIPER: re.compile(
            r"^(?P<prefix>\s*set\s+interfaces\s+\S+(?:\s+unit\s+\S+)?\s+family\s+ethernet-switching\s+interface-mode\s+)"
            r"(?P<mode>access|trunk)(?P<suffix>\s*)$",
            re.I,
        ),
    }
    return _simple_replace(
        lines,
        vendor,
        seed,
        fingerprint,
        mutation_type,
        spec,
        patterns,
        lambda match: (
            f"{match.group('prefix')}"
            f"{'trunk' if match.group('mode').casefold() == 'access' else 'access'}"
            f"{match.group('suffix')}"
        ),
    )


def _bgp_remote_as(
    lines: list[str],
    vendor: Vendor,
    seed: int,
    fingerprint: str,
    mutation_type: MutationType,
    spec: _MutationSpec,
) -> tuple[list[str], MutationOperation]:
    patterns = {
        Vendor.CISCO: re.compile(
            r"^(?P<prefix>\s*neighbor\s+\S+\s+remote-as\s+)(?P<asn>\d+)(?P<suffix>\s*)$",
            re.I,
        ),
        Vendor.JUNIPER: re.compile(
            r"^(?P<prefix>\s*set\s+protocols\s+bgp\b.*\speer-as\s+)"
            r"(?P<asn>\d+)(?P<suffix>\s*)$",
            re.I,
        ),
    }
    return _simple_replace(
        lines,
        vendor,
        seed,
        fingerprint,
        mutation_type,
        spec,
        patterns,
        lambda match: (
            f"{match.group('prefix')}{_different_asn(int(match.group('asn')))}"
            f"{match.group('suffix')}"
        ),
    )


def _missing_bgp_neighbor(
    lines: list[str],
    vendor: Vendor,
    seed: int,
    fingerprint: str,
    mutation_type: MutationType,
    spec: _MutationSpec,
) -> tuple[list[str], MutationOperation]:
    patterns = {
        Vendor.CISCO: re.compile(r"^\s*neighbor\s+(?P<neighbor>\S+)\b", re.I),
        Vendor.JUNIPER: re.compile(
            r"^\s*set\s+protocols\s+bgp\b.*\sneighbor\s+(?P<neighbor>\S+)\b",
            re.I,
        ),
    }
    pattern = patterns[vendor]
    neighbors = sorted(
        {
            match.group("neighbor")
            for line in lines
            if (match := pattern.match(line)) is not None
        }
    )
    selected = _candidate(
        list(range(len(neighbors))),
        seed=seed,
        fingerprint=fingerprint,
        mutation_type=mutation_type,
    )
    neighbor = neighbors[selected]
    indices = [
        index
        for index, line in enumerate(lines)
        if (match := pattern.match(line)) is not None
        and match.group("neighbor") == neighbor
    ]
    return _remove_indices(lines, indices, mutation_type, spec)


def _ospf_area(
    lines: list[str],
    vendor: Vendor,
    seed: int,
    fingerprint: str,
    mutation_type: MutationType,
    spec: _MutationSpec,
) -> tuple[list[str], MutationOperation]:
    patterns = {
        Vendor.CISCO: re.compile(
            r"^(?P<prefix>\s*network\s+\S+\s+\S+\s+area\s+)"
            r"(?P<area>\S+)(?P<suffix>\s*)$",
            re.I,
        ),
        Vendor.JUNIPER: re.compile(
            r"^(?P<prefix>\s*set\s+protocols\s+ospf\s+area\s+)"
            r"(?P<area>\S+)(?P<suffix>\s+interface\s+.*)$",
            re.I,
        ),
    }
    return _simple_replace(
        lines,
        vendor,
        seed,
        fingerprint,
        mutation_type,
        spec,
        patterns,
        lambda match: (
            f"{match.group('prefix')}{_different_area(match.group('area'))}"
            f"{match.group('suffix')}"
        ),
    )


def _removed_static_route(
    lines: list[str],
    vendor: Vendor,
    seed: int,
    fingerprint: str,
    mutation_type: MutationType,
    spec: _MutationSpec,
) -> tuple[list[str], MutationOperation]:
    patterns = {
        Vendor.CISCO: re.compile(
            r"^\s*(?:ip|ipv6)\s+route\s+(?P<destination>\S+)(?:\s+\S+)?\b", re.I
        ),
        Vendor.JUNIPER: re.compile(
            r"^\s*set\s+routing-options\s+static\s+route\s+(?P<destination>\S+)\b",
            re.I,
        ),
    }
    pattern = patterns[vendor]
    destinations = sorted(
        {
            match.group("destination")
            for line in lines
            if (match := pattern.match(line)) is not None
        }
    )
    selected = _candidate(
        list(range(len(destinations))),
        seed=seed,
        fingerprint=fingerprint,
        mutation_type=mutation_type,
    )
    destination = destinations[selected]
    indices = [
        index
        for index, line in enumerate(lines)
        if (match := pattern.match(line)) is not None
        and match.group("destination") == destination
    ]
    return _remove_indices(lines, indices, mutation_type, spec)


def _management_exposure(
    lines: list[str],
    vendor: Vendor,
    seed: int,
    fingerprint: str,
    mutation_type: MutationType,
    spec: _MutationSpec,
) -> tuple[list[str], MutationOperation]:
    if vendor is Vendor.CISCO:
        pattern = re.compile(
            r"^(?P<prefix>\s*(?:\d+\s+)?permit\s+(?:tcp|udp|ip)\s+)"
            r"(?P<source>host\s+\S+|"
            r"(?:\d{1,3}\.){3}\d{1,3}\s+(?:\d{1,3}\.){3}\d{1,3})"
            r"(?P<suffix>\s+.+)$",
            re.I,
        )
        return _simple_replace(
            lines,
            vendor,
            seed,
            fingerprint,
            mutation_type,
            spec,
            {Vendor.CISCO: pattern, Vendor.JUNIPER: pattern},
            lambda match: f"{match.group('prefix')}any{match.group('suffix')}",
        )
    pattern = re.compile(
        r"^(?P<prefix>\s*set\s+firewall\b.*\sfrom\s+source-address\s+)"
        r"(?P<source>(?!0\.0\.0\.0/0)\S+)(?P<suffix>\s*)$",
        re.I,
    )
    return _simple_replace(
        lines,
        vendor,
        seed,
        fingerprint,
        mutation_type,
        spec,
        {Vendor.CISCO: pattern, Vendor.JUNIPER: pattern},
        lambda match: f"{match.group('prefix')}0.0.0.0/0{match.group('suffix')}",
    )


def _missing_ntp_syslog(
    lines: list[str],
    vendor: Vendor,
    seed: int,
    fingerprint: str,
    mutation_type: MutationType,
    spec: _MutationSpec,
) -> tuple[list[str], MutationOperation]:
    del seed, fingerprint
    if vendor is Vendor.CISCO:
        pattern = re.compile(r"^\s*(?:ntp\s+server|logging\s+host)\b", re.I)
    else:
        pattern = re.compile(
            r"^\s*set\s+system\s+(?:ntp\s+server|syslog\s+host)\b", re.I
        )
    indices = [index for index, line in enumerate(lines) if pattern.match(line)]
    if not indices:
        raise MutationNotApplicableError(
            f"precondition is not satisfied: {mutation_type.value}"
        )
    return _remove_indices(lines, indices, mutation_type, spec)


def _route_map_order(
    lines: list[str],
    vendor: Vendor,
    seed: int,
    fingerprint: str,
    mutation_type: MutationType,
    spec: _MutationSpec,
) -> tuple[list[str], MutationOperation]:
    if vendor is not Vendor.CISCO:
        raise MutationNotApplicableError("route-map order mutation is Cisco-only")
    pattern = re.compile(
        r"^(?P<prefix>\s*route-map\s+(?P<name>\S+)\s+(?:permit|deny)\s+)"
        r"(?P<sequence>\d+)(?P<suffix>\s*)$",
        re.I,
    )
    by_name: dict[str, list[int]] = {}
    for index, line in enumerate(lines):
        if (match := pattern.match(line)) is not None:
            by_name.setdefault(match.group("name"), []).append(index)
    pairs: list[tuple[int, int]] = []
    for indices in by_name.values():
        for left in range(len(indices)):
            for right in range(left + 1, len(indices)):
                left_match = pattern.match(lines[indices[left]])
                right_match = pattern.match(lines[indices[right]])
                assert left_match is not None and right_match is not None
                if left_match.group("sequence") != right_match.group("sequence"):
                    pairs.append((indices[left], indices[right]))
    selected = _candidate(
        list(range(len(pairs))),
        seed=seed,
        fingerprint=fingerprint,
        mutation_type=mutation_type,
    )
    first, second = pairs[selected]
    first_match = pattern.match(lines[first])
    second_match = pattern.match(lines[second])
    assert first_match is not None and second_match is not None
    replacement = list(lines[first : second + 1])
    replacement[0] = (
        f"{first_match.group('prefix')}{second_match.group('sequence')}"
        f"{first_match.group('suffix')}"
    )
    replacement[-1] = (
        f"{second_match.group('prefix')}{first_match.group('sequence')}"
        f"{second_match.group('suffix')}"
    )
    return _replace_span(
        lines,
        first,
        second + 1,
        replacement,
        mutation_type,
        spec,
        affected_lines=(first + 1, second + 1),
    )


def _conflicting_ip(
    lines: list[str],
    vendor: Vendor,
    seed: int,
    fingerprint: str,
    mutation_type: MutationType,
    spec: _MutationSpec,
) -> tuple[list[str], MutationOperation]:
    patterns = {
        Vendor.CISCO: re.compile(
            r"^(?P<prefix>\s*ip\s+address\s+)(?P<address>\S+)\s+"
            r"(?P<mask>\S+)(?P<suffix>\s*)$",
            re.I,
        ),
        Vendor.JUNIPER: re.compile(
            r"^(?P<prefix>\s*set\s+interfaces\s+(?P<interface>\S+)"
            r"(?:\s+unit\s+\S+)?\s+family\s+inet\s+address\s+)"
            r"(?P<address>\S+)(?P<suffix>\s*)$",
            re.I,
        ),
    }
    pattern = patterns[vendor]
    matches: list[tuple[int, re.Match[str], str]] = []
    current_interface: str | None = None
    interface_header = re.compile(r"^interface\s+(?P<interface>\S+)\s*$", re.I)
    for index, line in enumerate(lines):
        if vendor is Vendor.CISCO:
            if (header_match := interface_header.match(line)) is not None:
                current_interface = header_match.group("interface")
            elif line and not line[0].isspace() and not line.lstrip().startswith("!"):
                current_interface = None
        match = pattern.match(line)
        if match is None:
            continue
        interface = (
            current_interface
            if vendor is Vendor.CISCO
            else match.group("interface")
        )
        if interface is not None:
            matches.append((index, match, interface))
    pairs = [
        (left, right)
        for left in range(len(matches))
        for right in range(len(matches))
        if left != right
        and matches[left][1].group("address") != matches[right][1].group("address")
        and matches[left][2] != matches[right][2]
    ]
    selected = _candidate(
        list(range(len(pairs))),
        seed=seed,
        fingerprint=fingerprint,
        mutation_type=mutation_type,
    )
    source_position, target_position = pairs[selected]
    _, source, _ = matches[source_position]
    target_index, target, _ = matches[target_position]
    if vendor is Vendor.CISCO:
        replacement = (
            f"{target.group('prefix')}{source.group('address')} "
            f"{source.group('mask')}{target.group('suffix')}"
        )
    else:
        replacement = (
            f"{target.group('prefix')}{source.group('address')}{target.group('suffix')}"
        )
    return _replace_span(
        lines,
        target_index,
        target_index + 1,
        (replacement,),
        mutation_type,
        spec,
    )


def _remove_indices(
    lines: list[str],
    indices: Sequence[int],
    mutation_type: MutationType,
    spec: _MutationSpec,
) -> tuple[list[str], MutationOperation]:
    if not indices:
        raise MutationNotApplicableError(
            f"precondition is not satisfied: {mutation_type.value}"
        )
    start = min(indices)
    end = max(indices) + 1
    removed = set(indices)
    replacement = [
        line
        for index, line in enumerate(lines[start:end], start)
        if index not in removed
    ]
    return _replace_span(
        lines,
        start,
        end,
        replacement,
        mutation_type,
        spec,
        affected_lines=tuple(index + 1 for index in indices),
    )


def _effect_observed(
    mutation_type: MutationType,
    before: CanonicalConfig,
    after: CanonicalConfig,
    before_text: str,
    after_text: str,
) -> bool:
    if mutation_type is MutationType.AAA_DISABLED:
        return before.management.aaa_enabled and not after.management.aaa_enabled
    if mutation_type is MutationType.TELNET_ENABLED:
        return not before.management.telnet_enabled and after.management.telnet_enabled
    if mutation_type is MutationType.SNMP_DOWNGRADE:
        return (
            "v3" in before.management.snmp_versions
            and not ({"v1", "v2c"} & set(before.management.snmp_versions))
            and bool({"v1", "v2c"} & set(after.management.snmp_versions))
        )
    if mutation_type is MutationType.PERMISSIVE_ACL:
        return _permit_any_count(after) > _permit_any_count(before)
    if mutation_type is MutationType.MISSING_ACL_ENTRY:
        return _acl_rule_count(after) < _acl_rule_count(before)
    if mutation_type is MutationType.VLAN_MISMATCH:
        return _access_vlans(after) != _access_vlans(before)
    if mutation_type is MutationType.INCORRECT_ACCESS_TRUNK_MODE:
        return _switchport_modes(after) != _switchport_modes(before)
    if mutation_type is MutationType.BGP_REMOTE_AS_MISMATCH:
        return (
            len(_remote_as_values(after)) == len(_remote_as_values(before))
            and _remote_as_values(after) != _remote_as_values(before)
        )
    if mutation_type is MutationType.MISSING_BGP_NEIGHBOR:
        return len(_remote_as_values(after)) < len(_remote_as_values(before))
    if mutation_type is MutationType.OSPF_AREA_MISMATCH:
        return _ospf_areas(after) != _ospf_areas(before)
    if mutation_type is MutationType.REMOVED_STATIC_ROUTE:
        return len(after.static_routes) < len(before.static_routes)
    if mutation_type is MutationType.MANAGEMENT_EXPOSURE:
        return _permit_any_source_count(after) > _permit_any_source_count(before)
    if mutation_type is MutationType.MISSING_NTP_SYSLOG:
        before_count = len(before.management.ntp_servers) + len(
            before.management.syslog_servers
        )
        after_count = len(after.management.ntp_servers) + len(
            after.management.syslog_servers
        )
        return after_count < before_count
    if mutation_type is MutationType.ROUTE_MAP_ORDER_CHANGE:
        return _route_map_sequences(after_text) != _route_map_sequences(before_text)
    if mutation_type is MutationType.CONFLICTING_IP_ADDRESS:
        return _duplicate_interface_address_count(after) > _duplicate_interface_address_count(
            before
        )
    return False


def _acl_rule_count(config: CanonicalConfig) -> int:
    return sum(len(acl.rules) for acl in config.acls)


def _permit_any_count(config: CanonicalConfig) -> int:
    return sum(
        rule.action == "permit"
        and (not rule.source_addresses or "any" in rule.source_addresses)
        and (not rule.destination_addresses or "any" in rule.destination_addresses)
        for acl in config.acls
        for rule in acl.rules
    )


def _permit_any_source_count(config: CanonicalConfig) -> int:
    return sum(
        rule.action == "permit"
        and bool({"any", "0.0.0.0/0", "::/0"} & set(rule.source_addresses))
        for acl in config.acls
        for rule in acl.rules
    )


def _access_vlans(config: CanonicalConfig) -> tuple[tuple[str, int | None, str | None], ...]:
    return tuple(
        (interface.name, interface.access_vlan.vlan_id, interface.access_vlan.name)
        for interface in config.interfaces
        if interface.access_vlan is not None
    )


def _switchport_modes(config: CanonicalConfig) -> tuple[tuple[str, str | None], ...]:
    return tuple(
        (interface.name, interface.switchport_mode) for interface in config.interfaces
    )


def _remote_as_values(config: CanonicalConfig) -> tuple[tuple[str, int], ...]:
    if config.bgp is None:
        return ()
    return tuple((neighbor.address, neighbor.remote_as) for neighbor in config.bgp.neighbors)


def _ospf_areas(config: CanonicalConfig) -> tuple[str, ...]:
    return tuple(
        [network.area_id for process in config.ospf for network in process.networks]
        + [
            interface.area_id
            for process in config.ospf
            for interface in process.interfaces
            if interface.area_id is not None
        ]
    )


def _route_map_sequences(text: str) -> tuple[tuple[str, int], ...]:
    pattern = re.compile(
        r"^\s*route-map\s+(?P<name>\S+)\s+(?:permit|deny)\s+(?P<sequence>\d+)\s*$",
        re.I,
    )
    return tuple(
        (match.group("name"), int(match.group("sequence")))
        for line in text.splitlines()
        if (match := pattern.match(line)) is not None
    )


def _duplicate_interface_address_count(config: CanonicalConfig) -> int:
    addresses = [
        address.address
        for interface in config.interfaces
        for address in interface.addresses
    ]
    return len(addresses) - len(set(addresses))


def _different_asn(value: int) -> int:
    return value - 1 if value == 4_294_967_295 else value + 1


def _different_area(value: str) -> str:
    if value in {"0", "0.0.0.0"}:
        return "0.0.0.1"
    return "0.0.0.0"


def _mutation_id(
    record: ImportedDatasetRecord,
    mutation_types: tuple[MutationType, ...],
    seed: int,
    mutated_hash: str,
) -> str:
    payload = "\0".join(
        (
            MUTATION_ENGINE_VERSION,
            record.source_id,
            record.record_id,
            record.sanitized_sha256,
            str(seed),
            *(item.value for item in mutation_types),
            mutated_hash,
        )
    )
    return f"mutation-{_sha256(payload)[:24]}"


def _changed_line_numbers(
    original_lines: Sequence[str], mutated_lines: Sequence[str]
) -> tuple[int, ...]:
    changed: set[int] = set()
    matcher = SequenceMatcher(a=original_lines, b=mutated_lines, autojunk=False)
    for tag, _left_start, _left_end, right_start, right_end in matcher.get_opcodes():
        if tag == "equal":
            continue
        if right_start < right_end:
            changed.update(range(right_start + 1, right_end + 1))
        else:
            changed.add(min(max(1, right_start + 1), max(1, len(mutated_lines))))
    return tuple(sorted(changed))


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


_HANDLERS: dict[MutationType, _MutationHandler] = {
    MutationType.AAA_DISABLED: _aaa_disabled,
    MutationType.TELNET_ENABLED: _telnet_enabled,
    MutationType.SNMP_DOWNGRADE: _snmp_downgrade,
    MutationType.PERMISSIVE_ACL: _permissive_acl,
    MutationType.MISSING_ACL_ENTRY: _missing_acl_entry,
    MutationType.VLAN_MISMATCH: _vlan_mismatch,
    MutationType.INCORRECT_ACCESS_TRUNK_MODE: _incorrect_mode,
    MutationType.BGP_REMOTE_AS_MISMATCH: _bgp_remote_as,
    MutationType.MISSING_BGP_NEIGHBOR: _missing_bgp_neighbor,
    MutationType.OSPF_AREA_MISMATCH: _ospf_area,
    MutationType.REMOVED_STATIC_ROUTE: _removed_static_route,
    MutationType.MANAGEMENT_EXPOSURE: _management_exposure,
    MutationType.MISSING_NTP_SYSLOG: _missing_ntp_syslog,
    MutationType.ROUTE_MAP_ORDER_CHANGE: _route_map_order,
    MutationType.CONFLICTING_IP_ADDRESS: _conflicting_ip,
}
