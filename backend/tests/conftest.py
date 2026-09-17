"""Shared paths and deterministic timestamps for tests."""

from datetime import UTC, datetime
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SAMPLES_ROOT = REPOSITORY_ROOT / "samples"
GOLDEN_ROOT = Path(__file__).resolve().parent / "golden" / "expected"


@pytest.fixture
def collected_at() -> datetime:
    return datetime(2026, 1, 1, tzinfo=UTC)
