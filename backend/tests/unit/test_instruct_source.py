"""Offline instruct source admission; real GPU generation is a separate diagnostic."""

import hashlib
from pathlib import Path

import pytest

from ml.instruct import source


@pytest.fixture
def small_source(tmp_path, monkeypatch):
    files = {"config.json": b"{}", "model.safetensors": b"tensor-only-fixture"}
    inventory = {name: (len(raw), hashlib.sha256(raw).hexdigest()) for name, raw in files.items()}
    monkeypatch.setattr(source, "FILES", inventory)
    for name, raw in files.items():
        (tmp_path / name).write_bytes(raw)
    return tmp_path, source.inventory_sha256()


def test_complete_source_requires_independent_inventory_pin(small_source):
    root, pin = small_source
    assert source.verify_model_files(root, expected_inventory_sha256=pin) == pin
    with pytest.raises(ValueError):
        source.verify_model_files(root, expected_inventory_sha256="0" * 64)


@pytest.mark.parametrize("change", ["missing", "extra", "size", "content", "directory"])
def test_changed_or_incomplete_source_is_refused(small_source, change):
    root, pin = small_source
    if change == "missing":
        (root / "config.json").unlink()
    elif change == "extra":
        (root / "unreviewed.py").write_text("raise Exception('not allowed')")
    elif change == "size":
        (root / "config.json").write_bytes(b"large")
    elif change == "content":
        (root / "config.json").write_bytes(b"[]")
    else:
        (root / "config.json").unlink()
        (root / "config.json").mkdir()
    with pytest.raises(ValueError):
        source.verify_model_files(root, expected_inventory_sha256=pin)


@pytest.mark.parametrize("target", ["root", "ancestor", "file"])
@pytest.mark.parametrize("method", ["is_symlink", "is_junction"])
def test_file_and_ancestor_link_metadata_is_refused(small_source, monkeypatch, target, method):
    root, pin = small_source
    selected = {"root": root, "ancestor": root.parent, "file": root / "config.json"}[target]
    original = getattr(Path, method)
    monkeypatch.setattr(Path, method, lambda path: path == selected or original(path))
    with pytest.raises(ValueError):
        source.verify_model_files(root, expected_inventory_sha256=pin)


def test_fixed_source_identity_has_only_reviewed_files():
    assert source.MODEL_ID == "Qwen/Qwen3-4B-Instruct-2507"
    assert source.REVISION == "cdbee75f17c01a7cc42f958dc650907174af0554"
    assert len(source.FILES) == 12
    assert sum(size for size, _ in source.FILES.values()) == 8060915998
    assert all(
        len(pin) == 64 and Path(name).name == name for name, (_, pin) in source.FILES.items()
    )
    assert len(source.inventory_sha256()) == 64
