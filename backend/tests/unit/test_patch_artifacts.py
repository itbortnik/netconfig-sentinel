"""Local review artifacts are bounded, tamper-evident and never overwritten."""

import json
from pathlib import Path
from uuid import UUID

import pytest
from app.patching.artifacts import load_patch_review, recheck_patch_review, save_patch_review
from app.patching.proposal import create_patch_proposal
from app.patching.review import review_patch_proposal

DEVICE = UUID("7f64381c-fda8-48f9-8e8a-fb772b2f64dc")
BEFORE, AFTER = "hostname edge\naaa new-model\n", "hostname edge\nno aaa new-model\n"


def test_artifact_roundtrip_and_recheck(tmp_path: Path) -> None:
    draft = create_patch_proposal(BEFORE, AFTER, device_id=DEVICE, reference_id="v1")
    review = review_patch_proposal(draft, BEFORE, AFTER, device_id=DEVICE)
    path = tmp_path / "review.json"
    save_patch_review(review, path)
    saved = path.read_bytes()
    assert load_patch_review(path) == review
    assert recheck_patch_review(path, BEFORE, AFTER, device_id=DEVICE) == review
    with pytest.raises(FileExistsError):
        save_patch_review(review, path)
    assert path.read_bytes() == saved
    with pytest.raises(ValueError):
        recheck_patch_review(path, BEFORE, AFTER + "! changed\n", device_id=DEVICE)
    assert path.read_bytes() == saved


def test_artifact_corruption_rejected(tmp_path: Path) -> None:
    draft = create_patch_proposal(BEFORE, AFTER, device_id=DEVICE, reference_id="v1")
    path = tmp_path / "review.json"
    save_patch_review(review_patch_proposal(draft, BEFORE, AFTER, device_id=DEVICE), path)
    envelope = json.loads(path.read_text(encoding="utf-8"))
    envelope["payload"]["preflight"]["report_id"] = str(UUID(int=0))
    path.write_text(json.dumps(envelope), encoding="utf-8")
    with pytest.raises(ValueError, match="checksum"):
        load_patch_review(path)


@pytest.mark.parametrize("data", [b"\xff", b"[]", b"{}", b'{"version":1,"version":2}'])
def test_bad_artifact_rejected(tmp_path: Path, data: bytes) -> None:
    path = tmp_path / "bad.json"
    path.write_bytes(data)
    with pytest.raises(ValueError):
        load_patch_review(path)


def test_rechecks_do_not_trust_rehashed_old_evidence(tmp_path: Path) -> None:
    from hashlib import sha256

    draft = create_patch_proposal(BEFORE, AFTER, device_id=DEVICE, reference_id="v1")
    path = tmp_path / "review.json"
    save_patch_review(review_patch_proposal(draft, BEFORE, AFTER, device_id=DEVICE), path)
    envelope = json.loads(path.read_text(encoding="utf-8"))
    envelope["payload"]["preflight"]["report_id"] = str(UUID(int=0))
    canonical = json.dumps(envelope["payload"], sort_keys=True, separators=(",", ":"))
    envelope["sha256"] = sha256(canonical.encode("utf-8")).hexdigest()
    path.write_text(json.dumps(envelope), encoding="utf-8")
    # A checksum is not a signature; only recomputation checks the selected inputs.
    load_patch_review(path)
    with pytest.raises(ValueError, match="stale"):
        recheck_patch_review(path, BEFORE, AFTER, device_id=DEVICE)


def test_artifact_size_budgets(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from app.patching import artifacts

    draft = create_patch_proposal(BEFORE, AFTER, device_id=DEVICE, reference_id="v1")
    review = review_patch_proposal(draft, BEFORE, AFTER, device_id=DEVICE)
    path = tmp_path / "review.json"
    monkeypatch.setattr(artifacts, "MAX_ARTIFACT_BYTES", 10)
    with pytest.raises(ValueError, match="size"):
        save_patch_review(review, path)
    assert not path.exists()
    path.write_bytes(b" " * 11)
    with pytest.raises(ValueError, match="size"):
        load_patch_review(path)
