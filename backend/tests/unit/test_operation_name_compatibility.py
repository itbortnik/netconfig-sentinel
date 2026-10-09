"""The browser must read receipts for every API operation, including new histories."""

import re
from pathlib import Path
from typing import get_args

from app.audit.contracts import Operation


def test_browser_audit_operation_inventory_matches_backend():
    content = (Path(__file__).parents[3] / "frontend/src/audit.ts").read_text(encoding="utf-8")
    inventory = content.split("export const operationNames = [", 1)[1].split("] as const;", 1)[0]
    operations = re.findall(r'"([a-z_]+)"', inventory)
    assert len(operations) == len(set(operations))
    assert set(operations) == set(get_args(Operation.__value__))
