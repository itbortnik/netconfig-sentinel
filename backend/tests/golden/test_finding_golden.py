"""Full policy finding snapshots for the four supported fixture styles."""

import json
from datetime import datetime
from pathlib import Path
from uuid import UUID

import pytest
from app.detection import evaluate_policies
from app.parsers import parse_configuration

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
SAMPLES_ROOT = REPOSITORY_ROOT / "samples"
GOLDEN_ROOT = Path(__file__).resolve().parent / "expected_findings"
DEVICE_ID = UUID("619e8467-a870-464d-890e-4b5209058c8a")

CASES = (
    Path("cisco_ios/edge-secure.cfg"),
    Path("cisco_ios/access-legacy.cfg"),
    Path("juniper_junos/edge-secure.conf"),
    Path("juniper_junos/access-set.conf"),
)


@pytest.mark.parametrize("relative_path", CASES, ids=lambda path: str(path))
def test_policy_findings_match_golden(
    relative_path: Path, collected_at: datetime
) -> None:
    source_path = SAMPLES_ROOT / relative_path
    config = parse_configuration(
        source_path.read_text(encoding="utf-8"),
        filename=source_path.name,
        collected_at=collected_at,
    )
    actual = [
        finding.model_dump(mode="json")
        for finding in evaluate_policies(config, device_id=DEVICE_ID)
    ]
    golden_path = GOLDEN_ROOT / relative_path.with_suffix(relative_path.suffix + ".json")
    expected = json.loads(golden_path.read_text(encoding="utf-8"))

    assert actual == expected
