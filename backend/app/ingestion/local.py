"""Bounded local text input shared by offline configuration commands."""

from pathlib import Path

MAX_INPUT_BYTES = 2 * 1024 * 1024
MAX_INPUT_LINES = 10_000


def read_local_configuration(
    path: Path,
    *,
    max_bytes: int = MAX_INPUT_BYTES,
    max_lines: int = MAX_INPUT_LINES,
) -> str:
    """Read a caller-selected file without logging paths or configuration text."""
    if max_bytes < 1 or max_lines < 1:
        raise ValueError("input limits must be positive")
    if path.suffix.lower() not in {".cfg", ".conf", ".txt"} or not path.is_file():
        raise ValueError("unsupported input")
    with path.open("rb") as stream:
        data = stream.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError("input too large")
    text = data.decode("utf-8-sig")
    if not text.strip() or any(ord(char) < 32 and char not in "\r\n\t" for char in text):
        raise ValueError("invalid text")
    if len(text.splitlines()) > max_lines:
        raise ValueError("too many lines")
    return text
