"""Small artificial tensors exercise encoder mechanics; published diagnostics use real weights."""

import hashlib
from pathlib import Path
from types import SimpleNamespace

import numpy as np
import pytest
import torch
from app.explanation.vector_index import RetrievalUnavailable
from tokenizers import Tokenizer
from tokenizers.models import WordLevel
from tokenizers.pre_tokenizers import WhitespaceSplit

from ml.retrieval import minilm


@pytest.fixture
def tokenizer():
    native = Tokenizer(
        WordLevel(
            {"<s>": 0, "<pad>": 1, "</s>": 2, "<unk>": 3, "head": 4, "tail": 5}, unk_token="<unk>"
        )
    )
    native.pre_tokenizer = WhitespaceSplit()
    return native


def test_windowing_keeps_every_content_token_and_tail_with_original_owner(tokenizer):
    windows, owners = minilm._windows(tokenizer, ("head " * 252 + "tail", "tail"))
    assert owners == [0, 0, 0, 1]
    assert [len(row) for row in windows] == [128, 128, 3, 3]
    assert [
        item for row, owner in zip(windows, owners, strict=True) if owner == 0 for item in row[1:-1]
    ] == [4] * 252 + [5]
    assert all(row[0] == 0 and row[-1] == 2 for row in windows)


@pytest.mark.parametrize("texts", [(), ("",), ("\x00",), ("x" * 16385,), ("head",) * 257])
def test_windowing_rejects_unsupported_inputs(tokenizer, texts):
    with pytest.raises(RetrievalUnavailable):
        minilm._windows(tokenizer, texts)


def test_window_budget_refuses_whole_batch_instead_of_truncating(tokenizer, monkeypatch):
    monkeypatch.setattr(minilm, "MAX_WINDOWS", 1)
    with pytest.raises(RetrievalUnavailable):
        minilm._windows(tokenizer, ("head " * 127,))


class ArtificialModel:
    def __call__(self, ids, attention_mask):
        assert torch.is_inference_mode_enabled()
        assert ids.device.type == "cpu"
        output = torch.zeros(*ids.shape, 384)
        output[..., 0] = (ids == 4).float()
        output[..., 1] = (ids == 5).float()
        output[..., 2] = ((ids == 0) | (ids == 2)).float()
        # If padding accidentally contributes, its enormous value corrupts direction.
        output[..., 3] = (ids == 1).float() * 100000
        return SimpleNamespace(last_hidden_state=output)


def encoder_fixture(tokenizer, model=None):
    encoder = minilm.LocalDocumentEncoder.__new__(minilm.LocalDocumentEncoder)
    encoder._model = model or ArtificialModel()
    encoder._tokenizer = tokenizer
    return encoder


def test_real_pooling_code_masks_padding_and_covers_all_windows(tokenizer, monkeypatch):
    encoder = encoder_fixture(tokenizer)
    before_rng = torch.random.get_rng_state().clone()
    before_threads = torch.get_num_threads()
    result = encoder.encode(("head " * 252 + "tail", "tail"))
    expected = np.zeros((2, 384), dtype=np.float32)
    expected[0, :3] = [252, 1, 6]
    expected[1, :3] = [0, 1, 2]
    expected /= np.linalg.norm(expected, axis=1, keepdims=True)
    np.testing.assert_allclose(result, expected, rtol=1e-6, atol=1e-7)
    monkeypatch.setattr(minilm, "BATCH_SIZE", 1)
    np.testing.assert_allclose(encoder.encode(("head " * 252 + "tail", "tail")), result)
    assert torch.equal(torch.random.get_rng_state(), before_rng)
    assert torch.get_num_threads() == before_threads


@pytest.mark.parametrize("case", ["nan", "zero", "shape", "runtime"])
def test_invalid_hidden_states_and_failure_are_sanitized(tokenizer, case):
    class BrokenModel:
        def __call__(self, ids, attention_mask):
            if case == "runtime":
                raise RuntimeError("private source marker")
            output = torch.zeros(*ids.shape, 384 if case != "shape" else 383)
            if case == "nan":
                output[:] = float("nan")
            return SimpleNamespace(last_hidden_state=output)

    with pytest.raises(RetrievalUnavailable, match=r"^Document encoder is unavailable\.$"):
        encoder_fixture(tokenizer, BrokenModel()).encode(("head",))


@pytest.fixture
def small_model_files(tmp_path, monkeypatch):
    root = tmp_path / "model"
    (root / "1_Pooling").mkdir(parents=True)
    files = {
        "config.json": b"{}",
        "1_Pooling/config.json": b"{}",
        "model.safetensors": b"fixture-only",
    }
    for name, raw in files.items():
        (root / name).write_bytes(raw)
    monkeypatch.setattr(
        minilm,
        "FILES",
        {name: (len(raw), hashlib.sha256(raw).hexdigest()) for name, raw in files.items()},
    )
    return root


def test_fixed_inventory_and_hashes_before_model_allocation(small_model_files):
    minilm.verify_model_files(small_model_files)


@pytest.mark.parametrize("case", ["extra", "changed", "missing", "extra_pooling", "size"])
def test_model_file_tampering_is_rejected(small_model_files, case):
    root = small_model_files
    if case == "extra":
        (root / "model.bin").write_bytes(b"never load pickle")
    elif case == "extra_pooling":
        (root / "1_Pooling" / "custom.py").write_text("never execute", encoding="utf-8")
    elif case == "missing":
        (root / "config.json").unlink()
    elif case == "size":
        (root / "model.safetensors").write_bytes(b"bad")
    else:
        (root / "config.json").write_bytes(b"[]")
    with pytest.raises(RetrievalUnavailable):
        minilm.verify_model_files(root)


@pytest.mark.parametrize("kind", ["is_symlink", "is_junction"])
@pytest.mark.parametrize(
    "name", ["root", "parent", "1_Pooling", "config.json", "1_Pooling/config.json"]
)
def test_model_links_are_rejected(small_model_files, monkeypatch, kind, name):
    root = small_model_files
    target = root if name == "root" else root.parent if name == "parent" else root / name
    original = getattr(Path, kind)
    monkeypatch.setattr(Path, kind, lambda self: self == target or original(self))
    with pytest.raises(RetrievalUnavailable):
        minilm.verify_model_files(root)


@pytest.mark.parametrize(
    "case", ["buffer_value", "buffer_dtype", "missing_buffer", "nan", "missing_tensor"]
)
def test_known_buffer_compatibility_does_not_allow_loose_learned_tensor_loading(
    tmp_path, monkeypatch, case
):
    (tmp_path / "config.json").write_text("{}", encoding="utf-8")

    class TinyModel(torch.nn.Module):
        def __init__(self, _):
            super().__init__()
            self.weight = torch.nn.Parameter(torch.randn(1))

    monkeypatch.setattr(minilm, "BertModel", TinyModel)
    positions = torch.arange(512).unsqueeze(0)
    state = {"weight": torch.ones(1), "embeddings.position_ids": positions}
    if case == "buffer_value":
        state["embeddings.position_ids"] = positions + 1
    elif case == "buffer_dtype":
        state["embeddings.position_ids"] = positions.float()
    elif case == "missing_buffer":
        del state["embeddings.position_ids"]
    elif case == "nan":
        state["weight"][:] = float("nan")
    else:
        del state["weight"]
    monkeypatch.setattr(minilm, "load_file", lambda *args, **kwargs: state)
    rng = torch.random.get_rng_state().clone()
    with pytest.raises((RetrievalUnavailable, RuntimeError)):
        minilm._load_model(tmp_path)
    assert torch.equal(rng, torch.random.get_rng_state())
