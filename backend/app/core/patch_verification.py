"""Operator-selected local verification; HTTP inputs cannot choose code or model paths."""

import os
import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class PatchVerificationSettings:
    allow_engine_upload: bool = False
    engine_timeout_seconds: int = 60
    registry_root: Path | None = field(default=None, repr=False)
    transformer_sha256: str | None = None
    foundation_source: Path | None = field(default=None, repr=False)
    ml_timeout_seconds: int = 60

    def __post_init__(self) -> None:
        if type(self.allow_engine_upload) is not bool or any(
            type(value) is not int or not 1 <= value <= 300
            for value in (self.engine_timeout_seconds, self.ml_timeout_seconds)
        ):
            raise ValueError("invalid local patch verification settings")
        if (self.registry_root is None) != (self.transformer_sha256 is None) or (
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
        if self.transformer_sha256 is not None and (
            type(self.transformer_sha256) is not str
            or re.fullmatch(r"[0-9a-f]{64}", self.transformer_sha256) is None
        ):
            raise ValueError("invalid operator-selected model pin")

    @classmethod
    def from_environment(cls) -> "PatchVerificationSettings | None":
        engine = os.environ.get("NETCONFIG_PATCH_ALLOW_ENGINE_UPLOAD", "")
        root = os.environ.get("NETCONFIG_PATCH_MODEL_REGISTRY", "")
        pin = os.environ.get("NETCONFIG_PATCH_MODEL_SHA256", "")
        foundation = os.environ.get("NETCONFIG_PATCH_FOUNDATION_SOURCE", "")
        if engine not in {"", "0", "1"}:
            raise ValueError("engine upload flag must be blank, 0 or 1")
        if not any((engine == "1", root, pin, foundation)):
            return None
        return cls(
            allow_engine_upload=engine == "1",
            registry_root=Path(root) if root else None,
            transformer_sha256=pin or None,
            foundation_source=Path(foundation) if foundation else None,
        )
