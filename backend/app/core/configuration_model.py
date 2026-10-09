"""Fixed operator selection for optional saved-analysis model diagnostics."""

import os
import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class ConfigurationModelSettings:
    registry_root: Path | None = field(default=None, repr=False)
    model_sha256: str | None = None
    foundation_source: Path | None = field(default=None, repr=False)
    timeout_seconds: int = 60

    def __post_init__(self) -> None:
        if type(self.timeout_seconds) is not int or not 1 <= self.timeout_seconds <= 300:
            raise ValueError("invalid configuration inference deadline")
        if (self.registry_root is None) != (self.model_sha256 is None) or (
            self.foundation_source is not None and self.registry_root is None
        ):
            raise ValueError("model registry and independent pin are required together")
        for path in (self.registry_root, self.foundation_source):
            if path is not None and (
                not isinstance(path, Path)
                or not path.is_absolute()
                or len(str(path)) > 2048
                or not str(path).isprintable()
            ):
                raise ValueError("invalid operator-selected model path")
        if self.model_sha256 is not None and (
            type(self.model_sha256) is not str
            or re.fullmatch(r"[0-9a-f]{64}", self.model_sha256) is None
        ):
            raise ValueError("invalid operator-selected model pin")

    @classmethod
    def from_environment(cls) -> "ConfigurationModelSettings | None":
        root = os.environ.get("NETCONFIG_CONFIG_MODEL_REGISTRY", "")
        pin = os.environ.get("NETCONFIG_CONFIG_MODEL_SHA256", "")
        source = os.environ.get("NETCONFIG_CONFIG_MODEL_FOUNDATION_SOURCE", "")
        if not any((root, pin, source)):
            return None
        return cls(
            registry_root=Path(root) if root else None,
            model_sha256=pin or None,
            foundation_source=Path(source) if source else None,
        )
