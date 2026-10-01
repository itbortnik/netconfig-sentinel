"""Explicit storage and authentication configuration for persistent API operations."""

import os
from dataclasses import dataclass, field

from cryptography.fernet import Fernet
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError


@dataclass(frozen=True)
class ApiSettings:
    database_url: str = field(repr=False)
    api_token: str = field(repr=False)
    encryption_key: str = field(repr=False)

    def __post_init__(self) -> None:
        try:
            url = make_url(self.database_url)
            if url.drivername not in {"sqlite", "postgresql+psycopg"}:
                raise ValueError("unsupported database")
            if url.drivername == "sqlite" and (not url.database or url.database == ":memory:"):
                raise ValueError("API requires a persistent database")
            if len(self.api_token) < 32 or any(
                not 33 <= ord(char) <= 126 for char in self.api_token
            ):
                raise ValueError("API token must be at least 32 non-whitespace ASCII characters")
            Fernet(self.encryption_key.encode("ascii"))
        except (ArgumentError, ValueError, UnicodeError):
            raise ValueError("invalid API storage, token or encryption configuration") from None

    @classmethod
    def from_environment(cls) -> "ApiSettings | None":
        values = [
            os.environ.get(name, "")
            for name in (
                "NETCONFIG_DATABASE_URL",
                "NETCONFIG_API_TOKEN",
                "NETCONFIG_ENCRYPTION_KEY",
            )
        ]
        if not any(values):
            return None
        if not all(values):
            raise ValueError(
                "database URL, API token and encryption key must be configured together"
            )
        return cls(*values)
