"""Actual raw-file v3 CLI paths; default v2 and its tolerance flag keep their meaning."""

import json
from pathlib import Path

import pytest
from app.detection.baseline import peer_compare_cli


def source(host, form="ios", address="192.0.2.10", unknown=False):
    if form == "ios":
        return (
            f"hostname {host}\nip ssh version 2\nntp server {address}\n"
            + ("unknown PRIVATE_VALUE\n" if unknown else "")
            + "end\n"
        )
    if form == "set":
        return (
            f"set system host-name {host}\nset system services ssh\n"
            f"set system ntp server {address}\n"
            + ("set unknown PRIVATE_VALUE\n" if unknown else "")
        )
    return (
        f"system {{\n host-name {host};\n services {{\n  ssh;\n }}\n"
        f" ntp {{\n  server {address};\n }}\n"
        + (" unknown PRIVATE_VALUE;\n" if unknown else "")
        + "}\n"
    )


def args(tmp_path, form="ios"):
    for number in range(3):
        (tmp_path / f"peer-{number}.cfg").write_text(
            source(f"peer-{number}", form), encoding="utf-8"
        )
    (tmp_path / "current.cfg").write_text(source("target", form), encoding="utf-8")
    return [
        "--current",
        str(tmp_path / "current.cfg"),
        "--device-id",
        "f6156954-3f3b-4aa2-b693-5a710fe35d44",
        "--device-role",
        "edge",
        "--site-class",
        "branch",
        "--service-profile",
        "owned",
        "--collected-at",
        "2026-10-10T00:00:00+00:00",
        *[
            value
            for number in range(3)
            for value in ("--peer", str(tmp_path / f"peer-{number}.cfg"))
        ],
    ]


@pytest.mark.parametrize("form", ["ios", "set", "blocks"])
@pytest.mark.parametrize("scenario,exit_code", [("normal", 0), ("property", 1), ("partial", 3)])
def test_explicit_measured_cli_uses_counts_and_preserves_selected_files(
    tmp_path: Path, capsys, form, scenario, exit_code
):
    selected = args(tmp_path, form)
    target = tmp_path / "current.cfg"
    target.write_text(
        source(
            "target",
            form,
            "192.0.2.99" if scenario == "property" else "192.0.2.10",
            scenario == "partial",
        ),
        encoding="utf-8",
    )
    before = {path.name: path.read_bytes() for path in tmp_path.iterdir()}
    assert peer_compare_cli.main([*selected, "--comparison-version", "0.3.0"]) == exit_code
    first = capsys.readouterr()
    wire = json.loads(first.out)
    assert not first.err and "PRIVATE_VALUE" not in first.out
    assert wire["version"] == "peer-comparison-cli-0.3.0"
    assert wire["baseline"]["model_version"] == "peer-baseline-0.3.0"
    report = wire["evaluation"]
    assert report["version"] == "peer-comparison-report-0.3.0"
    assert report["coverage"]["source_sha256"] == report["source_sha256"]
    assert wire["configuration_applied"] is wire["network_safety_verified"] is False
    if scenario == "partial":
        assert report["status"] == "partial" and report["compared_features"] == []
        assert (
            report["findings"][0]["observed"]["value"]
            == report["coverage"]["unparsed_units"] / report["coverage"]["command_units"]
        )
    assert peer_compare_cli.main([*selected, "--comparison-version", "0.3.0"]) == exit_code
    assert capsys.readouterr().out == first.out
    assert {path.name: path.read_bytes() for path in tmp_path.iterdir()} == before


def test_default_report_and_explicit_legacy_version_are_exactly_equal(tmp_path, capsys):
    selected = args(tmp_path)
    assert peer_compare_cli.main(selected) == 0
    legacy = capsys.readouterr().out
    assert peer_compare_cli.main([*selected, "--comparison-version", "0.2.0"]) == 0
    assert capsys.readouterr().out == legacy
    assert json.loads(legacy)["version"] == "peer-comparison-cli-0.2.0"


def test_measured_tolerance_can_trigger_a_finding_when_the_old_proxy_does_not(tmp_path, capsys):
    selected = args(tmp_path)
    (tmp_path / "current.cfg").write_text(source("target", unknown=True), encoding="utf-8")
    assert peer_compare_cli.main([*selected, "--unsupported-ratio-tolerance", "0.2"]) == 3
    old = json.loads(capsys.readouterr().out)["evaluation"]
    assert old["findings"] == [] and old["status"] == "partial"
    assert (
        peer_compare_cli.main(
            [*selected, "--comparison-version", "0.3.0", "--unparsed-fraction-tolerance", "0.2"]
        )
        == 3
    )
    measured = json.loads(capsys.readouterr().out)["evaluation"]
    assert measured["findings"][0]["category"] == "baseline.parser.unparsed_fraction_high"
    assert measured["findings"][0]["observed"]["value"] == 0.25


@pytest.mark.parametrize(
    "flags",
    [
        ["--unparsed-fraction-tolerance", "0.1"],
        ["--comparison-version", "0.3.0", "--unsupported-ratio-tolerance", "0.1"],
        ["--comparison-version", "0.3.0", "--unparsed-fraction-tolerance", "nan"],
        ["--comparison-version", "0.3.0", "--unparsed-fraction-tolerance", "inf"],
        ["--comparison-version", "0.3.0", "--unparsed-fraction-tolerance", "-0.1"],
        ["--comparison-version", "0.3.0", "--unparsed-fraction-tolerance", "1.1"],
    ],
)
def test_wrong_version_flags_and_nonfinite_limits_are_refused(tmp_path, capsys, flags):
    selected = args(tmp_path)
    assert peer_compare_cli.main([*selected, *flags]) == 2
    result = capsys.readouterr()
    assert not result.out and str(tmp_path) not in result.err


@pytest.mark.parametrize("case", ["missing", "partial-peer", "duplicate", "budget"])
def test_measured_input_refusals_do_not_disclose_text_or_private_paths(
    tmp_path, capsys, monkeypatch, case
):
    selected = args(tmp_path)
    if case == "missing":
        selected[-1] = str(tmp_path / "PRIVATE_VALUE.cfg")
    elif case == "partial-peer":
        (tmp_path / "peer-2.cfg").write_text(source("peer-2", unknown=True), encoding="utf-8")
    elif case == "duplicate":
        selected[-1] = selected[-3]
    else:
        monkeypatch.setattr(peer_compare_cli, "MAX_INPUT_BYTES", 1)
    assert peer_compare_cli.main([*selected, "--comparison-version", "0.3.0"]) == 2
    result = capsys.readouterr()
    assert not result.out and str(tmp_path) not in result.err and "PRIVATE_VALUE" not in result.err
