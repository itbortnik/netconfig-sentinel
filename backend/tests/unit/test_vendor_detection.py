"""Content-based vendor detection tests."""

import pytest
from app.parsers.detection import UnsupportedVendorError, detect_vendor


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("hostname edge-01\nline vty 0 4\n transport input ssh\n", "cisco_ios"),
        ("system {\n host-name edge-01;\n}\n", "juniper_junos"),
        ("set system host-name edge-01\nset system services ssh\n", "juniper_junos"),
    ],
)
def test_detect_vendor(text: str, expected: str) -> None:
    detection = detect_vendor(text)

    assert detection.parser_key == expected
    assert 0.0 < detection.confidence <= 1.0
    assert detection.matched_markers


def test_rejects_unknown_vendor() -> None:
    with pytest.raises(UnsupportedVendorError, match="supported vendor markers"):
        detect_vendor("name: generic-router\nmanagement: enabled\n")


def test_rejects_ambiguous_vendor() -> None:
    text = "hostname edge-01\nsystem {\n}\n"

    with pytest.raises(UnsupportedVendorError, match="ambiguous"):
        detect_vendor(text)
