"""Reviewed Qwen publisher files; pinned local integrity, not training-data provenance."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import MappingProxyType
from typing import Literal

from ml.inference.change_artifacts import safe_path

MODEL_ID: Literal["Qwen/Qwen3-4B-Instruct-2507"] = "Qwen/Qwen3-4B-Instruct-2507"
REVISION: Literal["cdbee75f17c01a7cc42f958dc650907174af0554"] = (
    "cdbee75f17c01a7cc42f958dc650907174af0554"
)
FILES = MappingProxyType(
    {
        "LICENSE": (11343, "832dd9e00a68dd83b3c3fb9f5588dad7dcf337a0db50f7d9483f310cd292e92e"),
        "README.md": (8168, "8e3dd0c3b5b11897cc71092ccfe517bb7a9783479baa3665aad73c8d1a2041cd"),
        "config.json": (727, "5beea1a4a34c62782bfb2f911c606741a3bab8f92d80a118fa053c28af12e8ba"),
        "generation_config.json": (
            238,
            "835fffe355c9438e7a25be099b3fccaa98350b83451f9fd2d99512e74f1ade48",
        ),
        "merges.txt": (1671839, "599bab54075088774b1733fde865d5bd747cbcc7a547c5bc12610e874e26f5e3"),
        "model-00001-of-00003.safetensors": (
            3957900840,
            "75311d91bb08cf0b882913da464a1e722a31fb44db35208663487efb7a3d8ed6",
        ),
        "model-00002-of-00003.safetensors": (
            3987450520,
            "0b48adbb1f60e901153d91907ba11ce63bd4b8b584482e730f48808d055dfba1",
        ),
        "model-00003-of-00003.safetensors": (
            99630640,
            "7dd39ccca5e4de123c74c14af44c9bf2eb75df33b4614382af0134528e060d5d",
        ),
        "model.safetensors.index.json": (
            32819,
            "d6c42883a895dfef5b0080ed2116a1bcd764f558406b98923d675978a1abf29c",
        ),
        "tokenizer.json": (
            11422654,
            "aeb13307a71acd8fe81861d94ad54ab689df773318809eed3cbe794b4492dae4",
        ),
        "tokenizer_config.json": (
            9377,
            "a62ff0a2472a0fa1b8eaabcb57c59b58afa42a22831dc141400b6e0cf2b65ce3",
        ),
        "vocab.json": (2776833, "ca10d7e9fb3ed18575dd1e277a2579c16d108e32f27439684afa0e10b1440910"),
    }
)


def inventory_sha256() -> str:
    return hashlib.sha256(
        json.dumps(dict(FILES), sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()


def verify_model_files(root: Path, *, expected_inventory_sha256: str) -> str:
    """Stream all 8 GB before allocation. No download, custom code or serialized objects."""
    try:
        if expected_inventory_sha256 != inventory_sha256():
            raise ValueError("independent source pin differs")
        safe_path(root)
        if not root.is_dir():
            raise ValueError("missing source")
        names: set[str] = set()
        for item in root.iterdir():
            if len(names) >= len(FILES) or item.name not in FILES:
                raise ValueError("unsupported source inventory")
            names.add(item.name)
        if names != FILES.keys():
            raise ValueError("incomplete source inventory")
        for name, (size, pin) in FILES.items():
            path = root / name
            safe_path(path)
            if not path.is_file() or path.stat().st_size != size:
                raise ValueError("unsupported source file")
            with path.open("rb") as stream:
                if hashlib.file_digest(stream, "sha256").hexdigest() != pin:
                    raise ValueError("source checksum differs")
        return expected_inventory_sha256
    except (OSError, ValueError):
        raise ValueError("Local instruct source is unavailable.") from None
