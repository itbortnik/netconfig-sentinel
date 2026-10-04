"""Atomic, deliberately narrow device-account grammar with credential-free facts."""

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Literal

from app.domain import LocalAuthentication, LocalUserConfig
from app.parsers.base import source_location

_NAME = re.compile(r"^[A-Za-z0-9_.@+-]{1,64}$")


def valid_account_name(value: str) -> bool:
    return _NAME.fullmatch(value) is not None


@dataclass
class LocalUserBuilder:
    name: str
    privilege: int | None = None
    login_class: str | None = None
    uid: int | None = None
    authentication: dict[str, LocalAuthentication] = field(default_factory=dict)
    facts: dict[str, list[tuple[int, str]]] = field(default_factory=lambda: defaultdict(list))

    def remember(self, field_name: str, number: int, raw_line: str) -> None:
        self.facts[field_name] = [(number, raw_line)]

    def build(self) -> LocalUserConfig:
        return LocalUserConfig(
            name=self.name,
            privilege=self.privilege,
            login_class=self.login_class,
            uid=self.uid,
            authentication=list(self.authentication.values()),
            provenance={key: source_location(value) for key, value in self.facts.items()},
        )


def ensure_user(
    users: dict[str, LocalUserBuilder], name: str, number: int, raw_line: str
) -> LocalUserBuilder:
    if name not in users:
        users[name] = LocalUserBuilder(name)
    user = users[name]
    user.facts["name"].append((number, raw_line))
    return user


def consume_cisco_user(
    users: dict[str, LocalUserBuilder], command: str, number: int, raw_line: str
) -> bool:
    tokens = command.split()
    if len(tokens) == 3 and [token.lower() for token in tokens[:2]] == ["no", "username"]:
        if not valid_account_name(tokens[2]):
            return False
        users.pop(tokens[2], None)
        return True
    if len(tokens) < 3 or tokens[0].lower() != "username" or not valid_account_name(tokens[1]):
        return False
    name = tokens[1]
    options = tokens[2:]
    privilege = None
    if options[0].lower() == "privilege":
        if len(options) < 2 or not options[1].isascii() or not options[1].isdigit():
            return False
        privilege = int(options[1])
        if not 0 <= privilege <= 15:
            return False
        options = options[2:]
    authentication = None
    if options:
        keyword = options[0].lower()
        if keyword == "nopassword" and len(options) == 1:
            authentication = LocalAuthentication(
                kind="none", provenance=source_location([(number, raw_line)])
            )
        elif keyword in {"password", "secret"}:
            encoding: Literal["unspecified", "0", "4", "5", "7", "8", "9"]
            allowed = {"0", "7"} if keyword == "password" else {"0", "4", "5", "8", "9"}
            if len(options) == 2:
                if options[1] in {"0", "4", "5", "7", "8", "9"}:
                    return False
                encoding = "unspecified"
                credential = options[1]
            elif len(options) == 3 and options[1] in allowed:
                encoding = options[1]  # type: ignore[assignment]
                credential = options[2]
            else:
                return False
            if not credential or not credential.isprintable():
                return False
            authentication = LocalAuthentication(
                kind="password" if keyword == "password" else "secret",
                encoding=encoding,
                provenance=source_location([(number, raw_line)]),
            )
        else:
            return False
    if privilege is None and authentication is None:
        return False
    user = ensure_user(users, name, number, raw_line)
    if privilege is not None:
        user.privilege = privilege
        user.remember("privilege", number, raw_line)
    if authentication is not None:
        if authentication.kind == "none":
            user.authentication.clear()
        else:
            user.authentication.pop("none", None)
        user.authentication[authentication.kind] = authentication
    return True


def consume_junos_user(
    users: dict[str, LocalUserBuilder], name: str, options: list[str], number: int, raw_line: str
) -> bool:
    if not valid_account_name(name) or not options:
        return False
    lowered = [token.lower() for token in options]
    privilege_class = None
    uid = None
    authentication = None
    auth_key = ""
    if len(options) == 2 and lowered[0] == "class" and valid_account_name(options[1]):
        privilege_class = options[1]
    elif len(options) == 2 and lowered[0] == "uid":
        if not options[1].isascii() or not options[1].isdigit():
            return False
        uid = int(options[1])
        if not 100 <= uid <= 64000:
            return False
    elif len(options) == 3 and lowered[0] == "authentication":
        credential = options[2]
        if not credential.strip() or not credential.isprintable():
            return False
        if lowered[1] == "encrypted-password":
            authentication = LocalAuthentication(
                kind="secret",
                encoding="encrypted",
                provenance=source_location([(number, raw_line)]),
            )
            auth_key = "secret"
        elif lowered[1] in {"ssh-rsa", "ssh-ecdsa", "ssh-ed25519"}:
            authentication = LocalAuthentication(
                kind="ssh_public_key",
                encoding=lowered[1],
                provenance=source_location([(number, raw_line)]),
            )
            auth_key = lowered[1]
        else:
            return False
    else:
        return False
    user = ensure_user(users, name, number, raw_line)
    if privilege_class is not None:
        user.login_class = privilege_class
        user.remember("login_class", number, raw_line)
    if uid is not None:
        user.uid = uid
        user.remember("uid", number, raw_line)
    if authentication is not None:
        user.authentication[auth_key] = authentication
    return True
