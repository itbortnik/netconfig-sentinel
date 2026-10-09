"""Opt-in literal loopback only; no DNS, arbitrary paths or runtime endpoint selection."""

import os
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit


@dataclass(frozen=True)
class LocalModelSettings:
    endpoint: str = field(repr=False)
    model: str
    allow_local_context: bool = False
    api_key: str = field(default="", repr=False)
    timeout_seconds: int = 10
    allow_patch_draft: bool = False

    def __post_init__(self) -> None:
        try:
            url = urlsplit(self.endpoint)
            if (
                url.scheme != "http"
                or url.hostname != "127.0.0.1"
                or url.port is None
                or not 1024 <= url.port <= 65535
                or url.netloc != f"127.0.0.1:{url.port}"
                or url.path != "/v1/chat/completions"
                or url.query
                or url.fragment
                or self.endpoint != f"http://127.0.0.1:{url.port}/v1/chat/completions"
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", self.model)
                or self.allow_local_context is not True
                or type(self.allow_patch_draft) is not bool
                or type(self.timeout_seconds) is not int
                or not 1 <= self.timeout_seconds <= 20
                or (
                    self.api_key
                    and (
                        len(self.api_key) > 512
                        or any(not 33 <= ord(char) <= 126 for char in self.api_key)
                    )
                )
            ):
                raise ValueError("invalid model settings")
        except (ValueError, TypeError):
            raise ValueError(
                "invalid local model configuration or missing context permission"
            ) from None

    @classmethod
    def from_environment(cls) -> "LocalModelSettings | None":
        endpoint, model, permission, key = (
            os.environ.get(name, "")
            for name in (
                "NETCONFIG_LLM_ENDPOINT",
                "NETCONFIG_LLM_MODEL",
                "NETCONFIG_LLM_ALLOW_LOCAL_CONTEXT",
                "NETCONFIG_LLM_API_KEY",
            )
        )
        patch_permission = os.environ.get("NETCONFIG_LLM_ALLOW_PATCH_DRAFT", "")
        if not any((endpoint, model, permission, key, patch_permission)):
            return None
        if not endpoint or not model or permission != "1" or patch_permission not in {"", "0", "1"}:
            raise ValueError(
                "local model endpoint, alias and explicit context permission are required"
            )
        return cls(
            endpoint,
            model,
            allow_local_context=True,
            api_key=key,
            allow_patch_draft=patch_permission == "1",
        )
