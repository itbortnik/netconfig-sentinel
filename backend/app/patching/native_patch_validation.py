"""Frozen v1 text operations for private native history, without renewed execution."""

from __future__ import annotations

import re
from difflib import SequenceMatcher
from hashlib import sha256
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from app.patching.vendor_drafts import VendorDraft

NATIVE_PATCH_TEXT_VALIDATION_VERSION = "native-telnet-text-validation-0.1.0"
MAX_NATIVE_TEXT_BYTES = 2 * 1024 * 1024
MAX_NATIVE_TEXT_LINES = 10_000


def _digest(text: str) -> str:
    return sha256(text.encode("utf-8")).hexdigest()


def _text_lines(text: str) -> list[str]:
    if type(text) is not str:
        raise ValueError("native history requires exact text")
    try:
        size = len(text.encode("utf-8"))
    except UnicodeError as exc:
        raise ValueError("native history requires valid UTF-8") from exc
    if size > MAX_NATIVE_TEXT_BYTES:
        raise ValueError("native history text exceeds byte budget")
    if not text.strip() or any(ord(char) < 32 and char not in "\r\n\t" for char in text):
        raise ValueError("native history contains invalid text")
    lines = text.splitlines(keepends=True)
    if len(lines) > MAX_NATIVE_TEXT_LINES:
        raise ValueError("native history text exceeds line budget")
    return lines


def _cisco_v1(lines: list[str]) -> tuple[dict[int, str], list[dict[str, Any]]]:
    """Preserve the released generator's v1 line/context and ASCII whitespace rules."""
    ranges: list[tuple[int, int]] = []
    current: tuple[int, int] | None = None
    transport_seen = False
    replacements: dict[int, str] = {}
    edits: list[dict[str, Any]] = []
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
                raise ValueError("native history has an unsupported VTY selector")
            first, last = int(match[1]), int(match[2] or match[1])
            if first > last or any(
                first <= old_last and old_first <= last for old_first, old_last in ranges
            ):
                raise ValueError("native history has ambiguous VTY ranges")
            current = (first, last)
            ranges.append(current)
            if len(ranges) > 128:
                raise ValueError("native history exceeds the VTY context budget")
            transport_seen = False
            continue
        if not raw[0].isspace():
            current = None
        tokens = command.lower().split()
        if tokens[:2] != ["transport", "input"]:
            continue
        if current is None or transport_seen:
            raise ValueError("native history has ambiguous transport context")
        transport_seen = True
        if tokens in (["transport", "input", "ssh"], ["transport", "input", "none"]):
            continue
        if len(tokens) != 4 or set(tokens[2:]) != {"ssh", "telnet"}:
            raise ValueError("native history requires an explicit SSH alternative")
        content = raw.rstrip("\r\n")
        leading = content[: len(content) - len(content.lstrip(" \t"))]
        trailing = content[len(content.rstrip(" \t")) :]
        changed = leading + "transport input ssh" + trailing + raw[len(content) :]
        replacements[index] = changed
        edits.append(
            {
                "kind": "cisco_vty_ssh_only",
                "source_line": index + 1,
                "before_line_sha256": _digest(raw),
                "after_line_sha256": _digest(changed),
                "vty": {"first": current[0], "last": current[1]},
            }
        )
    return replacements, edits


def _junos_v1(lines: list[str]) -> tuple[dict[int, str], list[dict[str, Any]]]:
    if any(raw.strip() and not raw.strip().startswith(("set ", "#")) for raw in lines):
        raise ValueError("native history requires flat JunOS set text")
    if not any(
        raw.strip().removesuffix(";")
        in {"set system services ssh", "set system services ssh protocol-version v2"}
        for raw in lines
    ):
        raise ValueError("native history requires explicit supported SSH")
    replacements: dict[int, str] = {}
    edits: list[dict[str, Any]] = []
    for index, raw in enumerate(lines):
        command = raw.strip().removesuffix(";")
        if not command.lower().startswith("set system services telnet"):
            continue
        if command != "set system services telnet":
            raise ValueError("native history has an ambiguous Telnet statement")
        replacements[index] = ""
        edits.append(
            {
                "kind": "junos_remove_telnet",
                "source_line": index + 1,
                "before_line_sha256": _digest(raw),
                "after_line_sha256": None,
                "vty": None,
            }
        )
    if len(edits) != 1:
        raise ValueError("native history requires one exact Telnet statement")
    return replacements, edits


def validate_native_patch_texts(
    metadata: VendorDraft, before_text: str, candidate_text: str
) -> None:
    """Validate retained bytes/edits/spans using frozen v1 rules, never fresh policy.

    The metadata class's serialized validation checks saved typed references and
    policy-change arithmetic. It does not run a parser, generator or policy engine.
    No helpers from the current generator participate in historical text checking.
    """
    saved = metadata.model_dump(mode="python")
    if any(
        saved[name] is not False
        for name in (
            "application_supported",
            "device_syntax_verified",
            "management_access_verified",
        )
    ):
        raise ValueError("native history assurance flags must be exact false")
    report = saved["review"]["preflight"]
    if report["requires_human_review"] is not True or any(
        report[name]["complete"] is not True for name in ("before", "after")
    ):
        raise ValueError("native history requires exact complete local review flags")
    metadata = type(metadata).model_validate_json(metadata.model_dump_json())
    if metadata.version != "vendor-patch-draft-0.1.0" or (
        metadata.category != "management.telnet_enabled"
    ):
        raise ValueError("unsupported native history operation")
    before, after = _text_lines(before_text), _text_lines(candidate_text)
    proposal = metadata.review.proposal
    if (
        proposal.before_sha256 != _digest(before_text)
        or proposal.after_sha256 != _digest(candidate_text)
        or proposal.before_line_count != len(before)
        or proposal.after_line_count != len(after)
    ):
        raise ValueError("native history text bindings differ")
    if proposal.vendor.value == "cisco" and proposal.platform == "ios":
        replacements, edits = _cisco_v1(before)
    elif proposal.vendor.value == "juniper" and proposal.platform == "junos":
        replacements, edits = _junos_v1(before)
    else:
        raise ValueError("unsupported native history platform")
    if not 1 <= len(edits) <= 128 or (
        edits != [edit.model_dump(mode="json") for edit in metadata.edits]
        or "".join(replacements.get(index, raw) for index, raw in enumerate(before))
        != candidate_text
    ):
        raise ValueError("native history differs from its exact allowed edits")
    spans = [
        {
            "operation": tag,
            "before_start": old_start,
            "before_end": old_end,
            "after_start": new_start,
            "after_end": new_end,
        }
        for tag, old_start, old_end, new_start, new_end in SequenceMatcher(
            a=before, b=after, autojunk=True
        ).get_opcodes()
        if tag != "equal"
    ]
    if [span.model_dump(mode="json") for span in proposal.changes] != spans:
        raise ValueError("native history change spans differ from the retained texts")
