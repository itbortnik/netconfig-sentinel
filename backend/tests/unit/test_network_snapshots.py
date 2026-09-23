"""Network snapshots have explicit bounded membership and generated file names."""

from pathlib import Path
from uuid import UUID

import pytest
from app.verification.snapshots import prepare_snapshot, validate_snapshot_pair, write_snapshot

DEVICE = UUID(int=1)


def test_snapshot_order_digest_and_private_export(tmp_path: Path) -> None:
    texts = {UUID(int=2): "hostname core\n", DEVICE: "hostname edge\n"}
    before = prepare_snapshot(texts)
    assert before == prepare_snapshot(dict(reversed(list(texts.items()))))
    assert "hostname edge" not in repr(before)
    changed = prepare_snapshot({**texts, DEVICE: "hostname edge\n! change\n"})
    validate_snapshot_pair(before, changed)
    assert before.digest != changed.digest
    output = tmp_path / "snapshot"
    write_snapshot(before, output)
    assert (output / "configs" / f"{DEVICE}.cfg").read_text() == texts[DEVICE]
    with pytest.raises(FileExistsError):
        write_snapshot(changed, output)


@pytest.mark.parametrize(
    "texts",
    [
        {},
        {DEVICE: "hostname edge\nunknown secret-value\n"},
        {DEVICE: "hostname edge\n", UUID(int=2): "hostname EDGE\n"},
        {DEVICE: "hostname bad.name\n"},
    ],
)
def test_snapshot_rejects_ambiguous_or_unsupported_inputs(texts: dict[UUID, str]) -> None:
    with pytest.raises(ValueError):
        prepare_snapshot(texts)


def test_snapshot_pair_rejects_identity_changes() -> None:
    before = prepare_snapshot({DEVICE: "hostname edge\n"})
    for after in ({UUID(int=2): "hostname edge\n"}, {DEVICE: "hostname changed\n"}):
        with pytest.raises(ValueError):
            validate_snapshot_pair(before, prepare_snapshot(after))
