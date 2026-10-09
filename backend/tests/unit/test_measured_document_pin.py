"""New source release has its own optional external pin; old pins are not aliases."""

from dataclasses import replace

import pytest
from app.core.document_retrieval import DocumentRetrievalSettings

NAMES = (
    "NETCONFIG_DOCUMENT_MODEL_ROOT",
    "NETCONFIG_DOCUMENT_INDEX_ROOT",
    "NETCONFIG_DOCUMENT_INDEX_SHA256_0_1",
    "NETCONFIG_DOCUMENT_INDEX_SHA256_0_2",
    "NETCONFIG_DOCUMENT_INDEX_SHA256_0_3",
    "NETCONFIG_DOCUMENT_INDEX_SHA256_0_4",
)


def test_measured_release_pin_requires_core_settings_and_is_not_an_older_pin(tmp_path, monkeypatch):
    for name in NAMES:
        monkeypatch.delenv(name, raising=False)
    assert DocumentRetrievalSettings.from_environment() is None
    monkeypatch.setenv(NAMES[-1], "d" * 64)
    with pytest.raises(ValueError):
        DocumentRetrievalSettings.from_environment()
    for name, value in zip(
        NAMES[:4],
        [str(tmp_path / "model"), str(tmp_path / "index"), "a" * 64, "b" * 64],
        strict=True,
    ):
        monkeypatch.setenv(name, value)
    measured = DocumentRetrievalSettings.from_environment()
    assert measured is not None and measured.measured_index_sha256 == "d" * 64
    assert measured.expanded_index_sha256 is None
    monkeypatch.setenv(NAMES[-2], "c" * 64)
    both = DocumentRetrievalSettings.from_environment()
    assert both is not None and both.expanded_index_sha256 == "c" * 64
    assert both.measured_index_sha256 == "d" * 64
    monkeypatch.delenv(NAMES[-1])
    legacy = DocumentRetrievalSettings.from_environment()
    assert legacy is not None and legacy.measured_index_sha256 is None
    assert legacy.expanded_index_sha256 == "c" * 64
    monkeypatch.setenv(NAMES[-1], "PRIVATE invalid pin")
    with pytest.raises(ValueError):
        DocumentRetrievalSettings.from_environment()


@pytest.mark.parametrize("pin", ["", "a" * 63, "A" * 64, "x" * 64, True, 10])
def test_invalid_measured_external_pin_fails_closed(tmp_path, pin):
    setting = DocumentRetrievalSettings(tmp_path / "model", tmp_path / "index", "a" * 64, "b" * 64)
    with pytest.raises(ValueError):
        replace(setting, measured_index_sha256=pin)
