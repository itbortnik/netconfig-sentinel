"""Deterministic topology-scoped sanitization for configuration text."""

from __future__ import annotations

import hashlib
import hmac
import re
from ipaddress import IPv4Address, IPv6Address, ip_address

from pydantic import BaseModel, ConfigDict, Field

SANITIZATION_VERSION = "config-sanitizer-0.1.0"

_CISCO_HOSTNAME = re.compile(r"^(?P<prefix>\s*hostname\s+)(?P<value>\S+)", re.I)
_JUNOS_HOSTNAME = re.compile(r"(?P<prefix>\bhost-name\s+)(?P<value>\S+)", re.I)
_CISCO_USERNAME = re.compile(r"^(?P<prefix>\s*username\s+)(?P<value>\S+)", re.I)
_CISCO_SNMP_USERNAME = re.compile(
    r"^(?P<prefix>\s*snmp-server\s+user\s+)(?P<value>\S+)", re.I
)
_JUNOS_SET_USERNAME = re.compile(
    r"(?P<prefix>\bsystem\s+login\s+user\s+)(?P<value>\S+)", re.I
)
_JUNOS_SNMP_USERNAME = re.compile(
    r"(?P<prefix>\bsnmp\s+v3\s+usm\s+\S+\s+user\s+)(?P<value>\S+)", re.I
)
_JUNOS_BLOCK_USERNAME = re.compile(
    r"^(?P<prefix>\s*user\s+)(?P<value>\S+)(?=\s*\{)", re.I
)
_DOMAIN = re.compile(
    r"(?P<prefix>\b(?:ip\s+domain(?:-name|\s+name)|domain-name)\s+)"
    r"(?P<value>\S+)",
    re.I,
)
_CISCO_COMMUNITY = re.compile(
    r"^(?P<prefix>\s*snmp-server\s+community\s+)(?P<value>\S+)", re.I
)
_JUNOS_SET_COMMUNITY = re.compile(
    r"(?P<prefix>\bsnmp\s+community\s+)(?P<value>\S+)", re.I
)
_JUNOS_BLOCK_COMMUNITY = re.compile(
    r"^(?P<prefix>\s*community\s+)(?P<value>\S+)(?=\s*\{)", re.I
)
_SECRET = re.compile(
    r"(?P<prefix>\b(?:"
    r"enable\s+(?:secret|password)|"
    r"password|secret|encrypted-password|key-string|shared-secret|"
    r"authentication-key|tacacs-server\s+key|radius-server\s+key|"
    r"pre-shared-key(?:\s+ascii-text)?|ssh-(?:rsa|dss|ed25519)"
    r")\s+(?:\d+\s+)?)"
    r"(?P<value>\"[^\"]*\"|'[^']*'|\S+)",
    re.I,
)
_SNMP_AUTH_SECRET = re.compile(
    r"(?P<prefix>\bauth\s+(?:md5|sha(?:-?\d+)?)\s+)(?P<value>\S+)", re.I
)
_SNMP_PRIV_SECRET = re.compile(
    r"(?P<prefix>\bpriv\s+(?:des|3des|aes(?:\s+\d+)?|aes-?\d+)\s+)"
    r"(?P<value>\S+)",
    re.I,
)
_STANDALONE_KEY = re.compile(
    r"^(?P<prefix>\s*key\s+(?:[067]\s+)?)(?P<value>\S+)", re.I
)
_CONTACT = re.compile(
    r"^(?P<prefix>\s*(?:set\s+(?:system\s+contact|"
    r"snmp\s+(?:contact|location))|snmp-server\s+(?:contact|location)|"
    r"contact|location)\s+)"
    r"(?P<value>.*?)(?P<suffix>;?\s*)$",
    re.I,
)
_IPV4 = re.compile(
    r"(?<![A-Za-z0-9_.])(?P<value>(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?)"
    r"(?![A-Za-z0-9_.])"
)
_IPV6 = re.compile(
    r"(?<![0-9A-Fa-f:])(?P<value>[0-9A-Fa-f]*:[0-9A-Fa-f:]+(?:/\d{1,3})?)"
    r"(?![0-9A-Fa-f:])"
)
_PEM_BEGIN = re.compile(r"-----BEGIN (?:[A-Z0-9 ]*PRIVATE KEY|CERTIFICATE)-----")
_PEM_END = re.compile(r"-----END (?:[A-Z0-9 ]*PRIVATE KEY|CERTIFICATE)-----")
_CISCO_PKI_CHAIN = re.compile(
    r"^(?P<prefix>\s*crypto\s+pki\s+certificate\s+chain\s+)"
    r"(?P<value>\S+)",
    re.I,
)
_CISCO_CERTIFICATE_BEGIN = re.compile(
    r"^(?P<prefix>\s*certificate\s+(?:ca|self-signed)\s+)"
    r"(?P<value>\S+)",
    re.I,
)


class SanitizationPolicy(BaseModel):
    """Explicit choices which may vary by reviewed dataset source."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    pseudonymize_ip_addresses: bool = True


class SanitizationResult(BaseModel):
    """Sanitized text and non-sensitive replacement counters."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    text: str
    replacements: dict[str, int] = Field(default_factory=dict)
    version: str = SANITIZATION_VERSION


def sanitize_configuration(
    text: str,
    *,
    topology_id: str,
    pseudonymization_key: bytes,
    policy: SanitizationPolicy | None = None,
) -> SanitizationResult:
    """Remove secrets and topology-scope identifiers without returning a mapping."""

    if not topology_id.strip():
        raise ValueError("topology_id must not be empty")
    if len(pseudonymization_key) < 16:
        raise ValueError("pseudonymization_key must contain at least 16 bytes")

    effective_policy = policy or SanitizationPolicy()
    topology_key = hmac.new(
        pseudonymization_key,
        b"topology\0" + topology_id.encode("utf-8"),
        hashlib.sha256,
    ).digest()
    counts: dict[str, int] = {}
    output: list[str] = []
    in_pem_block = False
    in_cisco_certificate = False

    for raw_line in text.splitlines(keepends=True):
        if _PEM_BEGIN.search(raw_line):
            in_pem_block = True
            _increment(counts, "key_or_certificate")
            output.append(raw_line)
            continue
        if in_pem_block:
            if _PEM_END.search(raw_line):
                in_pem_block = False
                output.append(raw_line)
            else:
                output.append(_redacted_material_line(raw_line))
            continue
        if in_cisco_certificate:
            if raw_line.strip().lower() == "quit":
                in_cisco_certificate = False
                output.append(raw_line)
            else:
                output.append(_redacted_material_line(raw_line))
            continue
        if _CISCO_CERTIFICATE_BEGIN.search(raw_line):
            in_cisco_certificate = True
            _increment(counts, "key_or_certificate")
            output.append(
                _replace_fixed(
                    raw_line,
                    _CISCO_CERTIFICATE_BEGIN,
                    "certificate_identity",
                    "<redacted-certificate-id>",
                    counts,
                )
            )
            continue

        line = raw_line
        line = _replace_alias(
            line, _CISCO_HOSTNAME, "hostname", "host", topology_key, counts
        )
        line = _replace_alias(
            line, _JUNOS_HOSTNAME, "hostname", "host", topology_key, counts
        )
        line = _replace_alias(
            line, _CISCO_USERNAME, "username", "user", topology_key, counts
        )
        line = _replace_alias(
            line, _CISCO_SNMP_USERNAME, "username", "user", topology_key, counts
        )
        line = _replace_alias(
            line, _JUNOS_SET_USERNAME, "username", "user", topology_key, counts
        )
        line = _replace_alias(
            line, _JUNOS_SNMP_USERNAME, "username", "user", topology_key, counts
        )
        line = _replace_alias(
            line, _JUNOS_BLOCK_USERNAME, "username", "user", topology_key, counts
        )
        line = _replace_alias(
            line, _DOMAIN, "domain", "domain", topology_key, counts, suffix=".invalid"
        )
        line = _replace_fixed(
            line, _CISCO_COMMUNITY, "snmp_community", "<redacted-community>", counts
        )
        line = _replace_fixed(
            line,
            _JUNOS_SET_COMMUNITY,
            "snmp_community",
            "<redacted-community>",
            counts,
        )
        line = _replace_fixed(
            line,
            _JUNOS_BLOCK_COMMUNITY,
            "snmp_community",
            "<redacted-community>",
            counts,
        )
        line = _replace_fixed(line, _SECRET, "secret", "<redacted-secret>", counts)
        line = _replace_fixed(
            line, _SNMP_AUTH_SECRET, "secret", "<redacted-secret>", counts
        )
        line = _replace_fixed(
            line, _SNMP_PRIV_SECRET, "secret", "<redacted-secret>", counts
        )
        line = _replace_fixed(
            line, _STANDALONE_KEY, "secret", "<redacted-secret>", counts
        )
        line = _replace_alias(
            line,
            _CISCO_PKI_CHAIN,
            "certificate_identity",
            "certificate",
            topology_key,
            counts,
        )
        line = _replace_contact(line, counts)
        if effective_policy.pseudonymize_ip_addresses:
            line = _replace_ip_addresses(line, topology_key, counts)
        output.append(line)

    return SanitizationResult(text="".join(output), replacements=counts)


def pseudonymize_identifier(
    value: str,
    *,
    kind: str,
    scope_id: str,
    pseudonymization_key: bytes,
) -> str:
    """Return a stable alias without exposing the reversible value mapping."""

    if not value or not kind or not scope_id:
        raise ValueError("value, kind, and scope_id must not be empty")
    if len(pseudonymization_key) < 16:
        raise ValueError("pseudonymization_key must contain at least 16 bytes")
    scope_key = hmac.new(
        pseudonymization_key,
        b"scope\0" + scope_id.encode("utf-8"),
        hashlib.sha256,
    ).digest()
    return f"{kind}-{_token_digest(kind, value, scope_key)}"


def _replace_alias(
    line: str,
    pattern: re.Pattern[str],
    category: str,
    alias_kind: str,
    key: bytes,
    counts: dict[str, int],
    *,
    suffix: str = "",
) -> str:
    def replacement(match: re.Match[str]) -> str:
        _increment(counts, category)
        raw_value = match.group("value")
        plain_value = _plain_token(raw_value)
        alias = f"{alias_kind}-{_token_digest(alias_kind, plain_value, key)}{suffix}"
        return match.group("prefix") + _render_token(raw_value, alias)

    return pattern.sub(replacement, line)


def _replace_fixed(
    line: str,
    pattern: re.Pattern[str],
    category: str,
    replacement_value: str,
    counts: dict[str, int],
) -> str:
    def replacement(match: re.Match[str]) -> str:
        _increment(counts, category)
        return match.group("prefix") + _render_token(
            match.group("value"), replacement_value
        )

    return pattern.sub(replacement, line)


def _replace_contact(line: str, counts: dict[str, int]) -> str:
    def replacement(match: re.Match[str]) -> str:
        _increment(counts, "contact")
        return match.group("prefix") + "<redacted-contact>" + match.group("suffix")

    return _CONTACT.sub(replacement, line)


def _replace_ip_addresses(
    line: str, key: bytes, counts: dict[str, int]
) -> str:
    def replacement(match: re.Match[str]) -> str:
        raw_value = match.group("value")
        address_text, separator, prefix = raw_value.partition("/")
        try:
            address = ip_address(address_text)
        except ValueError:
            return raw_value
        if _preserve_address(address) or (
            isinstance(address, IPv4Address) and _looks_like_ipv4_mask(address)
        ):
            return raw_value
        _increment(counts, "ip_address")
        anonymized = _prefix_preserving_address(address, key)
        return f"{anonymized}{separator}{prefix}" if separator else str(anonymized)

    return _IPV6.sub(replacement, _IPV4.sub(replacement, line))


def _prefix_preserving_address(
    address: IPv4Address | IPv6Address, key: bytes
) -> IPv4Address | IPv6Address:
    width = address.max_prefixlen
    original = int(address)
    anonymized = 0
    family = b"4" if isinstance(address, IPv4Address) else b"6"
    for index in range(width):
        prefix_value = original >> (width - index) if index else 0
        prefix_bytes = prefix_value.to_bytes((index + 7) // 8, "big")
        digest = hmac.new(
            key,
            family + index.to_bytes(2, "big") + prefix_bytes,
            hashlib.sha256,
        ).digest()
        original_bit = (original >> (width - index - 1)) & 1
        anonymized = (anonymized << 1) | (original_bit ^ (digest[0] & 1))
    return IPv4Address(anonymized) if width == 32 else IPv6Address(anonymized)


def _preserve_address(address: IPv4Address | IPv6Address) -> bool:
    return (
        address.is_unspecified
        or address.is_loopback
        or address.is_multicast
        or address.is_link_local
        or (isinstance(address, IPv4Address) and int(address) == 0xFFFFFFFF)
    )


def _looks_like_ipv4_mask(address: IPv4Address) -> bool:
    value = int(address)
    inverted = value ^ 0xFFFFFFFF
    return _contiguous_low_bits(inverted) or _contiguous_low_bits(value)


def _contiguous_low_bits(value: int) -> bool:
    return value == 0 or (value & (value + 1)) == 0


def _plain_token(value: str) -> str:
    suffixless = value[:-1] if value.endswith(";") else value
    if len(suffixless) >= 2 and suffixless[0] == suffixless[-1] and suffixless[0] in {'"', "'"}:
        return suffixless[1:-1]
    return suffixless


def _render_token(original: str, replacement: str) -> str:
    semicolon = ";" if original.endswith(";") else ""
    value = original[:-1] if semicolon else original
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return f"{value[0]}{replacement}{value[0]}{semicolon}"
    return replacement + semicolon


def _token_digest(kind: str, value: str, key: bytes) -> str:
    return hmac.new(
        key,
        kind.encode("utf-8") + b"\0" + value.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()[:12]


def _redacted_material_line(line: str) -> str:
    newline = "\r\n" if line.endswith("\r\n") else "\n" if line.endswith("\n") else ""
    content = line[: -len(newline)] if newline else line
    indent = content[: len(content) - len(content.lstrip())]
    return indent + "<redacted-material>" + newline


def _increment(counts: dict[str, int], category: str) -> None:
    counts[category] = counts.get(category, 0) + 1
