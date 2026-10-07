"""Acquisition tests substitute small public-artifact fixtures, never contact a network."""

import hashlib
from io import BytesIO

import pytest
from app.explanation.vector_index import RetrievalUnavailable

from ml.retrieval import acquire


class Response(BytesIO):
    def geturl(self):
        return "https://public-artifact-fixture.invalid/only"


@pytest.fixture
def acquisition(monkeypatch):
    raw = b"public-model-fixture"
    digest = hashlib.sha256(raw).hexdigest()
    monkeypatch.setattr(acquire, "FILES", {"model.safetensors": (len(raw), digest)})
    verified = []
    urls = []

    def get(url, timeout):
        assert timeout == 30
        urls.append(url)
        return Response(raw)

    monkeypatch.setattr(acquire, "urlopen", get)
    monkeypatch.setattr(acquire, "verify_model_files", lambda root: verified.append(root))
    return raw, urls, verified


def test_acquisition_uses_fixed_public_revision_and_preserves_existing_outputs(
    acquisition, tmp_path
):
    raw, urls, verified = acquisition
    root = tmp_path / "model"
    acquire.acquire_model(root)
    assert (root / "model.safetensors").read_bytes() == raw
    assert urls == [
        f"https://huggingface.co/{acquire.MODEL_ID}/resolve/{acquire.REVISION}/model.safetensors"
    ]
    assert verified == [root]
    with pytest.raises(FileExistsError):
        acquire.acquire_model(root)
    assert (root / "model.safetensors").read_bytes() == raw
    assert len(urls) == 1


@pytest.mark.parametrize("case", ["oversize", "truncated", "changed", "deadline", "insecure"])
def test_partial_or_insecure_download_never_becomes_a_verified_artifact(
    acquisition, tmp_path, monkeypatch, case
):
    raw, _, verified = acquisition

    class InvalidResponse(Response):
        def geturl(self):
            return "http://invalid.invalid/only" if case == "insecure" else super().geturl()

    response_raw = {
        "oversize": raw + b"extra",
        "truncated": raw[:-1],
        "changed": b"x" * len(raw),
    }.get(case, raw)
    monkeypatch.setattr(acquire, "urlopen", lambda *args, **kwargs: InvalidResponse(response_raw))
    if case == "deadline":
        times = iter([0, 601])
        monkeypatch.setattr(acquire, "monotonic", lambda: next(times))
    with pytest.raises(ValueError):
        acquire.acquire_model(tmp_path / "model")
    assert not verified


def test_post_download_verification_errors_are_not_success(acquisition, tmp_path, monkeypatch):
    def reject(root):
        raise RetrievalUnavailable("Document encoder is unavailable.")

    monkeypatch.setattr(acquire, "verify_model_files", reject)
    with pytest.raises(RetrievalUnavailable):
        acquire.acquire_model(tmp_path / "model")
