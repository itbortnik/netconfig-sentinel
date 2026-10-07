"""New private native-draft directories and source-rebuilding rechecks, never approval."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, model_validator

from app.ingestion.local import (
    MAX_INPUT_BYTES,
    read_local_configuration,
    validate_configuration_text,
)
from app.patching.artifacts import (
    MAX_ARTIFACT_BYTES,
    _unique_keys,
    load_patch_review,
    save_patch_review,
)
from app.patching.vendor_drafts import (
    Digest,
    GeneratedVendorDraft,
    VendorDraft,
    _digest,
    check_vendor_draft,
)

_FILES = {"candidate.cfg", "metadata.json", "native-commands.txt", "local-review.json"}


def _checksum(metadata: VendorDraft) -> str:
    return _digest(
        json.dumps(metadata.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    )


class _Envelope(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["vendor-draft-artifact-0.1.0"] = "vendor-draft-artifact-0.1.0"
    payload: VendorDraft
    sha256: Digest

    @model_validator(mode="after")
    def bound_payload(self) -> Self:
        if self.sha256 != _checksum(self.payload):
            raise ValueError("vendor draft artifact checksum differs")
        return self


def _safe_path(path: Path) -> None:
    path = path.absolute()
    if any(item.is_symlink() or item.is_junction() for item in (path, *path.parents)):
        raise ValueError("linked vendor draft path is not supported")


def _commands(metadata: VendorDraft) -> str:
    context = (
        "Cisco global configuration mode (VTY selectors included where needed)"
        if metadata.review.proposal.platform == "ios"
        else "JunOS root [edit] configuration context"
    )
    return (
        "INSPECTION-ONLY DRAFT: not validated, approved, applied or device-qualified.\n"
        "Do not execute without formal checks, verified access/rollback and engineer approval.\n"
        f"Context: {context}\n\n" + "\n".join(metadata.native_commands) + "\n"
    )


def save_vendor_draft(generated: GeneratedVendorDraft, path: Path, *, before: str) -> None:
    """Rebuild first, then create one unused private directory; never overwrite."""
    fresh = check_vendor_draft(generated.metadata, before, generated.candidate_text)
    envelope = _Envelope(payload=fresh.metadata, sha256=_checksum(fresh.metadata))
    payload = (envelope.model_dump_json(indent=2) + "\n").encode("utf-8")
    if len(payload) > MAX_ARTIFACT_BYTES:
        raise ValueError("vendor draft metadata exceeds budget")
    _safe_path(path)
    path.mkdir(exist_ok=False)
    marker = path / ".incomplete"
    with marker.open("xb") as target:
        target.write(b"vendor draft writing\n")
    for name, contents in (
        ("candidate.cfg", fresh.candidate_text.encode("utf-8")),
        ("metadata.json", payload),
        ("native-commands.txt", _commands(fresh.metadata).encode("utf-8")),
    ):
        with (path / name).open("xb") as target:
            target.write(contents)
    save_patch_review(fresh.metadata.review, path / "local-review.json")
    marker.unlink()


def _read(path: Path, budget: int) -> bytes:
    _safe_path(path)
    if not path.is_file() or path.stat().st_size > budget:
        raise ValueError("vendor draft file is missing or oversized")
    with path.open("rb") as stream:
        contents = stream.read(budget + 1)
    if len(contents) > budget:
        raise ValueError("vendor draft file grew past its budget")
    return contents


def load_vendor_draft(path: Path) -> GeneratedVendorDraft:
    """Checks content/inventory, not authorization or trustworthy publisher/ground truth."""
    _safe_path(path)
    if not path.is_dir() or {item.name for item in path.iterdir()} != _FILES:
        raise ValueError("vendor draft directory is missing or incomplete")
    try:
        parsed = json.loads(
            _read(path / "metadata.json", MAX_ARTIFACT_BYTES).decode("utf-8"),
            object_pairs_hook=_unique_keys,
        )
    except RecursionError:
        raise ValueError("vendor draft JSON exceeds nesting budget") from None
    metadata = _Envelope.model_validate(parsed).payload
    candidate = _read(path / "candidate.cfg", MAX_INPUT_BYTES).decode("utf-8")
    validate_configuration_text(candidate)
    if _digest(candidate) != metadata.review.proposal.after_sha256:
        raise ValueError("vendor candidate no longer matches reviewed hash")
    if _read(path / "native-commands.txt", 64 * 1024).decode("utf-8") != _commands(metadata):
        raise ValueError("native inspection commands differ from typed draft")
    _read(path / "local-review.json", MAX_ARTIFACT_BYTES)
    if load_patch_review(path / "local-review.json") != metadata.review:
        raise ValueError("network-check export differs from vendor local review")
    return GeneratedVendorDraft(metadata, candidate)


def recheck_vendor_draft(path: Path, before_path: Path) -> GeneratedVendorDraft:
    """Recreate exact allowed edits and current preflight from the original snapshot."""
    saved = load_vendor_draft(path)
    before = read_local_configuration(before_path)
    return check_vendor_draft(saved.metadata, before, saved.candidate_text)
