"""Exact boundaries of the shared local input reader."""

from pathlib import Path

import pytest
from app.ingestion.local import read_local_configuration


def test_reader_accepts_exact_limits_and_crlf_bom(tmp_path: Path) -> None:
    source = tmp_path / "input.CFG"
    data = b"\xef\xbb\xbfhostname edge\r\n"
    source.write_bytes(data)
    assert read_local_configuration(source, max_bytes=len(data), max_lines=1) == "hostname edge\r\n"
    with pytest.raises(ValueError, match="large"):
        read_local_configuration(source, max_bytes=len(data) - 1)
    with pytest.raises(ValueError, match="positive"):
        read_local_configuration(source, max_lines=0)
    with pytest.raises(ValueError, match="unsupported"):
        read_local_configuration(tmp_path)
