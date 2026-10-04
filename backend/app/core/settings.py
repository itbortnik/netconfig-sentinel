"""Explicit storage and authentication configuration for persistent API operations."""

import os
import secrets
from dataclasses import dataclass, field

from cryptography.fernet import Fernet
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError

from app.core.permissions import Role


@dataclass(frozen=True)
class ApiSettings:
    database_url: str = field(repr=False)
    api_token: str = field(repr=False)
    encryption_key: str = field(repr=False)
    reader_token: str = field(default="", repr=False)
    analyst_token: str = field(default="", repr=False)
    engineer_token: str = field(default="", repr=False)

    def __post_init__(self) -> None:
        try:
            url = make_url(self.database_url)
            if url.drivername not in {"sqlite", "postgresql+psycopg"}:
                raise ValueError("unsupported database")
            if url.drivername == "sqlite" and (not url.database or url.database == ":memory:"):
                raise ValueError("API requires a persistent database")
            tokens = [self.api_token, self.reader_token, self.analyst_token, self.engineer_token]
            if any(not isinstance(token, str) for token in tokens):
                raise ValueError("invalid token type")
            if (
                not self.api_token
                or any(
                    token
                    and (not 32 <= len(token) <= 512 or any(not 33 <= ord(c) <= 126 for c in token))
                    for token in tokens
                )
                or len({token for token in tokens if token})
                != len([token for token in tokens if token])
            ):
                raise ValueError("API tokens must be distinct bounded non-whitespace ASCII strings")
            Fernet(self.encryption_key.encode("ascii"))
        except (ArgumentError, ValueError, UnicodeError):
            raise ValueError("invalid API storage, token or encryption configuration") from None

    def role_for_token(self, token: str) -> Role | None:
        """Compare every configured role key without retaining credentials in request state."""
        selected: Role | None = None
        offered = token.encode("utf-8")
        candidates: tuple[tuple[Role, str], ...] = (
            ("admin", self.api_token),
            ("reader", self.reader_token),
            ("analyst", self.analyst_token),
            ("engineer", self.engineer_token),
        )
        for role, configured in candidates:
            match = secrets.compare_digest(offered, configured.encode("ascii"))
            if configured and match:
                selected = role
        return selected

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
        role_values = {
            name: os.environ.get(environment, "")
            for name, environment in (
                ("reader_token", "NETCONFIG_READER_TOKEN"),
                ("analyst_token", "NETCONFIG_ANALYST_TOKEN"),
                ("engineer_token", "NETCONFIG_ENGINEER_TOKEN"),
            )
        }
        if not any(values) and not any(role_values.values()):
            return None
        if not all(values):
            raise ValueError(
                "database URL, API token and encryption key must be configured together"
            )
        return cls(*values, **role_values)
