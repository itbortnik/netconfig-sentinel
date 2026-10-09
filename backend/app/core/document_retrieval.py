"""Explicit operator paths and external index pins; disabled unless configured together."""

import os
import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class DocumentRetrievalSettings:
    model_root: Path = field(repr=False)
    index_root: Path = field(repr=False)
    legacy_index_sha256: str
    current_index_sha256: str
    timeout_seconds: int = 20
    expanded_index_sha256: str | None = None
    measured_index_sha256: str | None = None

    def __post_init__(self) -> None:
        if (
            any(
                not isinstance(path, Path)
                or not path.is_absolute()
                or len(str(path)) > 2048
                or not str(path).isprintable()
                for path in (self.model_root, self.index_root)
            )
            or any(
                not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value)
                for value in (self.legacy_index_sha256, self.current_index_sha256)
            )
            or type(self.timeout_seconds) is not int
            or not 1 <= self.timeout_seconds <= 60
            or (
                any(
                    pin is not None
                    and (not isinstance(pin, str) or not re.fullmatch(r"[0-9a-f]{64}", pin))
                    for pin in (self.expanded_index_sha256, self.measured_index_sha256)
                )
            )
        ):
            raise ValueError("invalid local document retrieval configuration")

    @classmethod
    def from_environment(cls) -> "DocumentRetrievalSettings | None":
        values = [
            os.environ.get(name, "")
            for name in (
                "NETCONFIG_DOCUMENT_MODEL_ROOT",
                "NETCONFIG_DOCUMENT_INDEX_ROOT",
                "NETCONFIG_DOCUMENT_INDEX_SHA256_0_1",
                "NETCONFIG_DOCUMENT_INDEX_SHA256_0_2",
            )
        ]
        expanded = os.environ.get("NETCONFIG_DOCUMENT_INDEX_SHA256_0_3", "")
        measured = os.environ.get("NETCONFIG_DOCUMENT_INDEX_SHA256_0_4", "")
        if not any(values) and not expanded and not measured:
            return None
        if not all(values):
            raise ValueError("local document paths and both release index pins are required")
        return cls(
            Path(values[0]),
            Path(values[1]),
            values[2],
            values[3],
            expanded_index_sha256=expanded or None,
            measured_index_sha256=measured or None,
        )
