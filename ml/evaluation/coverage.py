"""Command-line parser coverage, not confidence or full syntax validation."""

from app.domain import CanonicalConfig, Vendor
from app.parsers.base import text_sha256
from app.parsers.juniper_junos.parser import _strip_comment

from ml.evaluation.contracts import ParserCoverage


def parser_coverage(text: str, config: CanonicalConfig) -> ParserCoverage:
    config = CanonicalConfig.model_validate(config.model_dump())
    if len(text.encode("utf-8")) > 1024 * 1024 or text_sha256(text) != config.source.sha256:
        raise ValueError("coverage text must match the bounded parsed source")
    significant = set()
    for number, line in enumerate(text.splitlines(), 1):
        command = (
            line.strip() if config.device.vendor is Vendor.CISCO else _strip_comment(line).strip()
        )
        if command and not command.startswith(
            "!" if config.device.vendor is Vendor.CISCO else "##"
        ):
            significant.add(number)
    unknown = {
        line for fragment in config.unparsed_fragments for line in fragment.location.source_lines
    }
    if not unknown.issubset(significant):
        raise ValueError("unsupported line anchors do not match significant source lines")
    return ParserCoverage(
        significant_lines=len(significant), recognized_lines=len(significant - unknown)
    )
