"""Owned, local-only peer comparison without implicit inventory or network calls."""

import json
from pathlib import Path

import pytest
from app.detection.baseline import peer_compare_cli
from app.domain import Vendor


def _text(hostname: str, vendor: Vendor, ntp: str = "192.0.2.10") -> str:
    if vendor is Vendor.CISCO:
        return f"hostname {hostname}\nip ssh version 2\nntp server {ntp}\n"
    return (
        f"set system host-name {hostname}\nset system services ssh\nset system ntp server {ntp}\n"
    )


def _args(tmp_path: Path, vendor: Vendor = Vendor.CISCO) -> list[str]:
    peers = [tmp_path / f"peer-{index}.cfg" for index in range(3)]
    for index, path in enumerate(peers):
        path.write_text(_text(f"peer-{index}", vendor), encoding="utf-8")
    target = tmp_path / "current.cfg"
    target.write_text(_text("target", vendor), encoding="utf-8")
    return [
        "--current",
        str(target),
        "--device-id",
        "f6156954-3f3b-4aa2-b693-5a710fe35d44",
        "--device-role",
        "edge",
        "--site-class",
        "lab",
        "--service-profile",
        "transit",
        "--collected-at",
        "2026-01-01T00:00:00+00:00",
        *[item for path in peers for item in ("--peer", str(path))],
    ]


@pytest.mark.parametrize("vendor", list(Vendor))
def test_local_peer_cli_compares_values_and_preserves_input_files(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    vendor: Vendor,
) -> None:
    args = _args(tmp_path, vendor)
    target = tmp_path / "current.cfg"
    before = {path.name: path.read_bytes() for path in tmp_path.iterdir()}
    assert peer_compare_cli.main(args) == 0
    first = json.loads(capsys.readouterr().out)
    assert first["evaluation"]["status"] == "completed"
    assert first["baseline"]["model_version"] == "peer-baseline-0.2.0"
    assert first["evaluation"]["findings"] == []
    target.write_text(_text("target", vendor, "192.0.2.99"), encoding="utf-8")
    assert peer_compare_cli.main(args) == 1
    output = capsys.readouterr()
    report = json.loads(output.out)
    assert not output.err
    findings = report["evaluation"]["findings"]
    assert (
        len(findings) == 1
        and findings[0]["category"] == "baseline.management.ntp_servers_deviation"
    )
    assert findings[0]["affected_lines"] == [3]
    assert report["evaluation"]["baseline_sha256"] == findings[0]["expected"]["baseline_sha256"]
    assert peer_compare_cli.main(args) == 1
    assert capsys.readouterr().out == output.out
    assert all(
        path.read_bytes() == before[path.name] for path in tmp_path.iterdir() if path != target
    )
    assert set(path.name for path in tmp_path.iterdir()) == set(before)


def test_partial_current_produces_explicit_partial_report_not_a_success_exit(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    args = _args(tmp_path)
    target = tmp_path / "current.cfg"
    target.write_text(
        _text("target", Vendor.CISCO) + "unsupported PRIVATE_VALUE\n", encoding="utf-8"
    )
    assert peer_compare_cli.main(args) == 3
    result = capsys.readouterr()
    report = json.loads(result.out)
    assert not result.err and "PRIVATE_VALUE" not in result.out
    evaluation = report["evaluation"]
    assert evaluation["status"] == "partial"
    assert evaluation["compared_features"] == [] and evaluation["skipped_features"]
    assert all(
        item["category"] == "baseline.parser.unsupported_ratio_high"
        for item in evaluation["findings"]
    )


@pytest.mark.parametrize(
    "case", ["partial_peer", "duplicate", "target", "missing", "vendor", "count"]
)
def test_peer_cli_failures_do_not_echo_private_values_or_paths(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    case: str,
) -> None:
    args = _args(tmp_path)
    peer = tmp_path / "peer-2.cfg"
    if case == "partial_peer":
        peer.write_text(
            _text("peer-2", Vendor.CISCO) + "unsupported PRIVATE_VALUE\n", encoding="utf-8"
        )
    elif case == "duplicate":
        args[-1] = args[-3]
    elif case == "target":
        peer.write_text(_text("target", Vendor.CISCO), encoding="utf-8")
    elif case == "missing":
        args[-1] = str(tmp_path / "PRIVATE_VALUE.cfg")
    elif case == "vendor":
        peer.write_text(_text("peer-2", Vendor.JUNIPER), encoding="utf-8")
    else:
        args = args[:-2]
    assert peer_compare_cli.main(args) == 2
    result = capsys.readouterr()
    assert not result.out and "PRIVATE_VALUE" not in result.err and str(tmp_path) not in result.err


def test_invalid_peer_threshold_is_refused_before_reading_files(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    args = _args(tmp_path)
    for value in ["nan", "inf", "0.5", "1.01"]:
        assert peer_compare_cli.main([*args, "--consensus-threshold", value]) == 2
        assert not capsys.readouterr().out


@pytest.mark.parametrize("date", ["invalid", "2026-01-01T00:00:00"])
def test_peer_cli_refuses_invalid_or_naive_declared_dates(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    date: str,
) -> None:
    args = _args(tmp_path)
    args[args.index("--collected-at") + 1] = date
    assert peer_compare_cli.main(args) == 2
    assert not capsys.readouterr().out


def test_peer_cli_cannot_use_unrelated_system_files_or_links(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    args = _args(tmp_path)
    monkeypatch.setattr(peer_compare_cli, "MAX_INPUT_BYTES", 1)
    assert peer_compare_cli.main(args) == 2
    assert not capsys.readouterr().out
    monkeypatch.setattr(peer_compare_cli, "MAX_INPUT_BYTES", 2 * 1024 * 1024)
    args[-1] = str(tmp_path / "input.exe")
    (tmp_path / "input.exe").write_text("hostname private\n", encoding="utf-8")
    assert peer_compare_cli.main(args) == 2
    assert not capsys.readouterr().out
