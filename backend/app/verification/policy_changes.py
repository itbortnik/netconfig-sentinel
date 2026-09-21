"""Multiset comparison of policy facts, independent of evidence line positions."""

from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Sequence
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from app.domain import Finding


class PersistentPolicyFinding(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    before: Finding
    after: Finding


class PolicyChanges(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    introduced: tuple[Finding, ...] = ()
    resolved: tuple[Finding, ...] = ()
    persistent: tuple[PersistentPolicyFinding, ...] = ()


def _semantic_key(finding: Finding) -> str:
    return json.dumps(
        [finding.category, finding.severity.value, finding.observed, finding.expected],
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def compare_policy_findings(
    before: Sequence[Finding], after: Sequence[Finding], *, device_id: UUID
) -> PolicyChanges:
    """Compare fully evaluated snapshots from one policy catalog and one device.

    Changed observations are a resolved/introduced pair, not proof of remediation.
    Equal occurrences are paired by evidence order; duplicate multiplicity is retained.
    """
    groups: list[dict[str, list[Finding]]] = []
    versions = set()
    for findings in (before, after):
        group: dict[str, list[Finding]] = defaultdict(list)
        for original in findings:
            finding = Finding.model_validate(original.model_dump())
            if finding.detector != "policy_engine" or finding.device_id != device_id:
                raise ValueError("policy comparison requires policy findings from one device")
            versions.add(finding.model_version)
            group[_semantic_key(finding)].append(finding)
        for items in group.values():
            items.sort(key=lambda item: (item.affected_lines, str(item.finding_id)))
        groups.append(group)
    if len(versions) > 1:
        raise ValueError("policy catalog versions differ")
    old, new = groups
    introduced: list[Finding] = []
    resolved: list[Finding] = []
    persistent: list[PersistentPolicyFinding] = []
    for key in sorted(old.keys() | new.keys()):
        old_items, new_items = old.get(key, []), new.get(key, [])
        common = min(len(old_items), len(new_items))
        persistent.extend(
            PersistentPolicyFinding(before=old_items[index], after=new_items[index])
            for index in range(common)
        )
        resolved.extend(old_items[common:])
        introduced.extend(new_items[common:])
    return PolicyChanges(
        introduced=tuple(introduced), resolved=tuple(resolved), persistent=tuple(persistent)
    )
