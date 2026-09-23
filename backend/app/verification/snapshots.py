"""Bounded multi-device inputs with generated filenames and no implicit discovery."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path
from uuid import UUID

from app.ingestion.local import validate_configuration_text
from app.parsers import parse_configuration


@dataclass(frozen=True)
class SnapshotConfig:
    device_id: UUID
    hostname: str
    platform: str
    text: str = field(repr=False)

    @property
    def filename(self) -> str:
        return f"{self.device_id}.cfg"

    @property
    def digest(self) -> str:
        return sha256(self.text.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class NetworkSnapshot:
    configs: tuple[SnapshotConfig, ...]

    @property
    def digest(self) -> str:
        payload = [
            (str(item.device_id), item.hostname, item.platform, item.digest)
            for item in self.configs
        ]
        return sha256(json.dumps(payload, separators=(",", ":")).encode("utf-8")).hexdigest()


def prepare_snapshot(configurations: Mapping[UUID, str]) -> NetworkSnapshot:
    if not 1 <= len(configurations) <= 32:
        raise ValueError("snapshot requires 1 to 32 devices")
    if sum(len(text.encode("utf-8")) for text in configurations.values()) > 8 * 1024 * 1024:
        raise ValueError("snapshot byte budget exceeded")
    configs = []
    hosts = set()
    for device_id, text in sorted(configurations.items(), key=lambda item: str(item[0])):
        if not isinstance(device_id, UUID):
            raise ValueError("snapshot device keys must be UUIDs")
        validate_configuration_text(text)
        config = parse_configuration(text, filename=f"{device_id}.cfg")
        hostname = config.device.hostname
        if hostname is None or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", hostname) is None:
            raise ValueError("snapshot requires explicit simple hostnames")
        if hostname.casefold() in hosts:
            raise ValueError("snapshot hostnames must be unique")
        if config.parse_warnings or config.unparsed_fragments or config.parser_confidence != 1:
            raise ValueError("snapshot requires complete local parsing")
        hosts.add(hostname.casefold())
        configs.append(SnapshotConfig(device_id, hostname, config.device.platform, text))
    return NetworkSnapshot(tuple(configs))


def validate_snapshot_pair(before: NetworkSnapshot, after: NetworkSnapshot) -> None:
    for snapshot in (before, after):
        rebuilt = prepare_snapshot({item.device_id: item.text for item in snapshot.configs})
        if rebuilt != snapshot:
            raise ValueError("snapshot metadata does not match configuration text")
    old = [(item.device_id, item.hostname, item.platform) for item in before.configs]
    new = [(item.device_id, item.hostname, item.platform) for item in after.configs]
    if old != new:
        raise ValueError("snapshot membership or device identity changed")


def write_snapshot(snapshot: NetworkSnapshot, destination: Path) -> None:
    """Create one new private snapshot directory; never merge into an existing one."""
    validate_snapshot_pair(snapshot, snapshot)
    destination.mkdir()
    configs = destination / "configs"
    configs.mkdir()
    for config in snapshot.configs:
        with (configs / config.filename).open("xb") as stream:
            stream.write(config.text.encode("utf-8"))
