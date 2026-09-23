"""Check an explicitly listed local network pair; uploads are disabled by default."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.ingestion.local import read_local_configuration
from app.verification.batfish import ReachabilityScope, check_with_batfish
from app.verification.snapshots import prepare_snapshot


class DeviceFiles(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    device_id: UUID
    before: str = Field(min_length=1, max_length=512)
    after: str = Field(min_length=1, max_length=512)


class NetworkCheckManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["network-check-0.1.0"]
    devices: tuple[DeviceFiles, ...] = Field(min_length=1, max_length=32)
    scope: ReachabilityScope

    @model_validator(mode="after")
    def unique_devices(self) -> NetworkCheckManifest:
        ids = [device.device_id for device in self.devices]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate device IDs")
        return self


def _input_path(root: Path, relative: str) -> Path:
    path = Path(relative)
    if path.is_absolute() or path.drive or ".." in path.parts:
        raise ValueError("manifest inputs must be relative child paths")
    resolved = (root / path).resolve()
    if not resolved.is_relative_to(root):
        raise ValueError("manifest input escapes its directory")
    return resolved


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--allow-local-upload", action="store_true")
    parser.add_argument("--timeout", type=int, default=60)
    args = parser.parse_args(argv)
    try:
        with args.manifest.open("rb") as stream:
            data = stream.read(65_537)
        if len(data) > 65_536:
            raise ValueError("manifest too large")
        manifest = NetworkCheckManifest.model_validate_json(data)
        root = args.manifest.resolve().parent
        before = prepare_snapshot(
            {
                item.device_id: read_local_configuration(_input_path(root, item.before))
                for item in manifest.devices
            }
        )
        after = prepare_snapshot(
            {
                item.device_id: read_local_configuration(_input_path(root, item.after))
                for item in manifest.devices
            }
        )
        result = check_with_batfish(
            before,
            after,
            manifest.scope,
            allow_local_upload=args.allow_local_upload,
            timeout_seconds=args.timeout,
        )
    except (OSError, ValueError):
        print(
            "Network check refused: invalid manifest, bounded inputs or snapshot identity.",
            file=sys.stderr,
        )
        return 2
    print(result.model_dump_json(indent=2))
    return {"no_differences_in_scope": 0, "differences_found": 1, "error": 2}.get(result.status, 3)


if __name__ == "__main__":
    raise SystemExit(main())
