"""Common parser interface and provenance helpers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence
from datetime import UTC, datetime
from hashlib import sha256

from app.domain import CanonicalConfig, ConfigSource, SourceLocation, Vendor


def text_sha256(text: str) -> str:
    """Return the lowercase SHA-256 digest used in public contracts."""

    return sha256(text.encode("utf-8")).hexdigest()


def source_location(
    source_lines: Sequence[tuple[int, str]], parser_confidence: float = 1.0
) -> SourceLocation:
    """Build provenance from ordered one-based source lines."""

    ordered = sorted(source_lines, key=lambda item: item[0])
    raw_text = "\n".join(text for _, text in ordered)
    return SourceLocation(
        source_lines=[number for number, _ in ordered],
        raw_text_hash=text_sha256(raw_text),
        parser_confidence=parser_confidence,
    )


def config_source(
    text: str, filename: str, collected_at: datetime | None = None
) -> ConfigSource:
    """Create immutable source metadata while keeping parsing deterministic in tests."""

    timestamp = collected_at or datetime.now(UTC)
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=UTC)
    return ConfigSource(
        filename=filename,
        sha256=text_sha256(text),
        collected_at=timestamp,
    )


class VendorParser(ABC):
    """Contract implemented by each independent vendor adapter."""

    vendor: Vendor
    platform: str

    @abstractmethod
    def parse(
        self,
        text: str,
        *,
        filename: str,
        collected_at: datetime | None = None,
    ) -> CanonicalConfig:
        """Parse text without discarding unsupported non-empty commands."""
