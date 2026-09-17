"""Full canonical JSON snapshots for the four supported fixture styles."""

import json
from datetime import datetime
from pathlib import Path

import pytest
from app.parsers import parse_configuration

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
SAMPLES_ROOT = REPOSITORY_ROOT / "samples"
GOLDEN_ROOT = Path(__file__).resolve().parent / "expected"

CASES = (
    Path("cisco_ios/edge-secure.cfg"),
    Path("cisco_ios/access-legacy.cfg"),
    Path("juniper_junos/edge-secure.conf"),
    Path("juniper_junos/access-set.conf"),
)


@pytest.mark.parametrize("relative_path", CASES, ids=lambda path: str(path))
def test_canonical_config_matches_golden(
    relative_path: Path, collected_at: datetime
) -> None:
    source_path = SAMPLES_ROOT / relative_path
    actual = parse_configuration(
        source_path.read_text(encoding="utf-8"),
        filename=source_path.name,
        collected_at=collected_at,
    ).model_dump(mode="json")
    golden_path = GOLDEN_ROOT / relative_path.with_suffix(relative_path.suffix + ".json")
    expected = json.loads(golden_path.read_text(encoding="utf-8"))

    assert actual == expected
