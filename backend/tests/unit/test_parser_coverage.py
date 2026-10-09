"""Measured adapter source-line coverage is not a confidence deficit or syntax verdict."""

from copy import deepcopy
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path

import pytest
from app.parsers import parse_configuration
from app.parsers.coverage import ParserCoverage, parse_configuration_with_coverage

STAMP = datetime(2026, 10, 10, tzinfo=UTC)


@pytest.mark.parametrize(
    "source,accepted,unparsed,structural,ignored",
    [
        ("! comment\nhostname owned\nunknown PRIVATE_VALUE\nend\n\n", 1, 1, 1, 2),
        ("set system host-name owned\n# comment\nset unsupported PRIVATE_VALUE\n", 1, 1, 0, 1),
        ("system {\n host-name owned;\n unsupported PRIVATE_VALUE;\n}\n", 2, 1, 1, 0),
        ("hostname owned\ninterface Gi0/1\n description owned\n exit\nend\n", 3, 0, 2, 0),
        ("set system host-name owned\nset system host-name owned\n", 2, 0, 0, 0),
    ],
)
def test_census_counts_actual_source_units_without_changing_canonical(
    source, accepted, unparsed, structural, ignored
):
    result = parse_configuration_with_coverage(source, filename="owned.cfg", collected_at=STAMP)
    report = result.coverage
    assert result.canonical == parse_configuration(source, filename="owned.cfg", collected_at=STAMP)
    assert (
        report.accepted_units,
        report.unparsed_units,
        report.structural_units,
        report.ignored_lines,
    ) == (accepted, unparsed, structural, ignored)
    assert report.source_line_count == len(source.splitlines()) == len(report.units)
    assert report.command_units == accepted + unparsed
    assert report.unparsed_fraction == unparsed / (accepted + unparsed)
    assert report.source_sha256 == sha256(source.encode()).hexdigest()
    assert "PRIVATE_VALUE" not in report.model_dump_json()
    for number, unit in enumerate(report.units, 1):
        assert unit.source_line == number
        assert unit.raw_text_sha256 == sha256(source.splitlines()[number - 1].encode()).hexdigest()
    assert ParserCoverage.model_validate_json(report.model_dump_json()) == report


def test_new_entrypoint_parses_once_and_budgets_precede_that_call(monkeypatch):
    calls = []

    def observed(*args, **kwargs):
        calls.append(1)
        return parse_configuration(*args, **kwargs)

    monkeypatch.setattr("app.parsers.coverage.parse_configuration", observed)
    parse_configuration_with_coverage("hostname owned\n", filename="owned.cfg")
    assert calls == [1]
    with pytest.raises(ValueError):
        parse_configuration_with_coverage("hostname owned\n\x00", filename="owned.cfg")
    assert calls == [1]


@pytest.mark.parametrize(
    "source,expected",
    [
        ("hostname owned\nend something\n", (1, 1, 0, 0)),
        ("hostname owned\nexit-address-family\n", (1, 1, 0, 0)),
        ("hostname owned\nrouter bgp 65000\n exit-address-family\nend\n", (2, 0, 2, 0)),
        ("hostname owned\n! owned\n\nend\n", (1, 0, 1, 2)),
        ("set system host-name owned // comment\n // ignored\n# ignored\n", (1, 0, 0, 2)),
        ("system {\n host-name owned;\n}; // comment\n", (2, 0, 1, 0)),
        ("system {\n unsupported {\n  unknown OWNED;\n }\n}\n", (1, 2, 2, 0)),
        ("set system host-name owned\nset unknown OWNED\nset unknown OWNED\n", (1, 2, 0, 0)),
    ],
)
def test_comments_exact_delimiters_context_and_repeated_unknown_units(source, expected):
    report = parse_configuration_with_coverage(source, filename="owned.cfg").coverage
    assert (
        report.accepted_units,
        report.unparsed_units,
        report.structural_units,
        report.ignored_lines,
    ) == expected


@pytest.mark.parametrize("value", [0, 1, None, "false", True])
def test_syntax_verdict_requires_exact_false(value):
    report = parse_configuration_with_coverage(
        "hostname owned\n", filename="owned.cfg"
    ).coverage.model_dump()
    report["proves_vendor_syntax"] = value
    with pytest.raises(ValueError):
        ParserCoverage.model_validate(report)


def test_missing_identity_warning_is_not_counted_as_an_unknown_command():
    result = parse_configuration_with_coverage("ip ssh version 2\n", filename="owned.cfg")
    assert result.canonical.parse_warnings
    assert result.coverage.unparsed_fraction == 0
    assert result.coverage.accepted_units == 1
    assert result.coverage.proves_vendor_syntax is False


def test_no_command_units_is_missing_not_a_zero_unknown_fraction():
    result = parse_configuration_with_coverage("## Last commit: owned\n}\n", filename="owned.cfg")
    assert result.coverage.command_units == 0
    assert result.coverage.unparsed_fraction is None


def test_late_incomplete_bgp_lines_are_unparsed_once_even_if_facts_reference_them():
    result = parse_configuration_with_coverage(
        "hostname owned\nrouter bgp 65000\n neighbor 192.0.2.1 description OWNED\n!\n",
        filename="owned.cfg",
    )
    assert result.coverage.unparsed_units == 1
    assert result.coverage.units[2].disposition == "unparsed"
    assert result.canonical.bgp is not None and not result.canonical.bgp.neighbors


@pytest.mark.parametrize(
    "case",
    [
        "fraction",
        "counts",
        "source_lines",
        "order",
        "duplicates",
        "version",
        "boolean_count",
        "verdict",
        "adapter",
    ],
)
def test_census_contract_refuses_corrupt_or_invented_metadata(case):
    report = parse_configuration_with_coverage(
        "hostname owned\nunknown OWNED\n", filename="owned.cfg"
    ).coverage
    changed = deepcopy(report.model_dump(mode="json"))
    if case == "fraction":
        changed["unparsed_fraction"] = 0.1
    elif case == "counts":
        changed["accepted_units"] = 10
    elif case == "source_lines":
        changed["source_line_count"] = 100
    elif case == "order":
        changed["units"].reverse()
    elif case == "duplicates":
        changed["units"][1] = changed["units"][0]
    elif case == "version":
        changed["version"] = "parser-coverage-0.2.0"
    elif case == "boolean_count":
        changed["accepted_units"] = True
    elif case == "verdict":
        changed["proves_vendor_syntax"] = True
    else:
        changed["adapter_version"] = "unsupported"
    with pytest.raises(ValueError):
        ParserCoverage.model_validate(changed)


@pytest.mark.parametrize(
    "text",
    [
        "hostname owned\n" + "\n" * 10001,
        "hostname owned\n" + "!" * (2 * 1024 * 1024),
        "hostname owned\n\x00",
    ],
    ids=["too-many-lines", "too-many-bytes", "control-character"],
)
def test_input_budgets_precede_parser_work(text):
    with pytest.raises(ValueError):
        parse_configuration_with_coverage(text, filename="owned.cfg")


@pytest.mark.parametrize(
    "relative",
    [
        "cisco_ios/edge-secure.cfg",
        "cisco_ios/access-legacy.cfg",
        "juniper_junos/edge-secure.conf",
        "juniper_junos/access-set.conf",
    ],
)
def test_current_golden_sources_keep_exact_canonical_bytes(relative):
    path = Path(__file__).resolve().parents[3] / "samples" / relative
    source = path.read_text(encoding="utf-8")
    old = parse_configuration(source, filename=path.name, collected_at=STAMP)
    parsed = parse_configuration_with_coverage(source, filename=path.name, collected_at=STAMP)
    assert old.model_dump_json() == parsed.canonical.model_dump_json()
    assert parsed.coverage.unparsed_units == len(
        {number for fragment in old.unparsed_fragments for number in fragment.location.source_lines}
    )
