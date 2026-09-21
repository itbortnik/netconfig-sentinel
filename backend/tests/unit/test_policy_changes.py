"""Semantic policy changes retain multiplicity and separate snapshot evidence."""

from uuid import UUID

import pytest
from app.detection.policy_engine import evaluate_policies
from app.domain import Finding
from app.parsers import parse_configuration
from app.verification.policy_changes import compare_policy_findings

DEVICE = UUID("7f64381c-fda8-48f9-8e8a-fb772b2f64dc")


def _findings(text: str) -> list[Finding]:
    return evaluate_policies(parse_configuration(text, filename="test.cfg"), device_id=DEVICE)


def test_line_shifts_are_persistent_with_separate_evidence() -> None:
    text = "hostname edge\nline vty 0 4\n transport input telnet\n"
    before, after = _findings(text), _findings("! comment\n" + text)
    changes = compare_policy_findings(before, after, device_id=DEVICE)
    assert not changes.introduced and not changes.resolved
    assert len(changes.persistent) == len(before)
    telnet = next(item for item in changes.persistent if "telnet" in item.before.category)
    assert telnet.before.affected_lines == [3]
    assert telnet.after.affected_lines == [4]
    assert telnet.before.finding_id != telnet.after.finding_id
    assert compare_policy_findings(before[::-1], after[::-1], device_id=DEVICE) == changes


def test_duplicate_occurrences_and_changed_observations() -> None:
    finding = _findings("hostname edge\n")[0]
    changes = compare_policy_findings([finding, finding], [finding], device_id=DEVICE)
    assert len(changes.persistent) == 1
    assert len(changes.resolved) == 1
    changed = finding.model_copy(deep=True)
    changed.observed = {"different": True}
    changes = compare_policy_findings([finding], [changed], device_id=DEVICE)
    assert not changes.persistent
    assert changes.introduced == (changed,)
    assert changes.resolved == (finding,)
    changed.observed.clear()
    assert changes.introduced[0].observed == {"different": True}


@pytest.mark.parametrize("field", ["device_id", "detector", "model_version"])
def test_comparison_rejects_incompatible_findings(field: str) -> None:
    finding = _findings("hostname edge\n")[0]
    changed = finding.model_copy(update={field: UUID(int=0) if field == "device_id" else "other"})
    with pytest.raises(ValueError):
        compare_policy_findings([finding], [changed], device_id=DEVICE)


def test_empty_policy_comparison() -> None:
    result = compare_policy_findings([], [], device_id=DEVICE)
    assert not result.introduced and not result.resolved and not result.persistent
