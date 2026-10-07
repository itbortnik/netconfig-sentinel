"""Private local lifecycle, no overwriting, silent source-rebuilding CLI refusal."""

import json
import os
import subprocess
import sys
from hashlib import sha256
from pathlib import Path
from uuid import UUID

import pytest
from app.detection.policy_engine import evaluate_policies
from app.parsers import parse_configuration
from app.patching.artifacts import load_patch_review
from app.patching.vendor_artifacts import load_vendor_draft, recheck_vendor_draft, save_vendor_draft
from app.patching.vendor_cli import main
from app.patching.vendor_drafts import create_vendor_draft

DEVICE = UUID("090e4d66-151d-4a57-97f0-56bf5f90a9a5")
BEFORE = "set system host-name PRIVATE-HOST\nset system services ssh\nset system services telnet\n"


def digest(text):
    return sha256(text.encode()).hexdigest()


@pytest.fixture
def draft():
    finding = next(
        row
        for row in evaluate_policies(
            parse_configuration(BEFORE, filename="before.cfg"), device_id=DEVICE
        )
        if row.category == "management.telnet_enabled"
    )
    return create_vendor_draft(
        BEFORE, finding=finding, source_sha256=digest(BEFORE), reference_id="owned-v1"
    )


def test_round_trip_and_fresh_check_do_not_modify_original_files(draft, tmp_path):
    before = tmp_path / "before.cfg"
    before.write_bytes(BEFORE.encode())
    artifact = tmp_path / "draft"
    save_vendor_draft(draft, artifact, before=BEFORE)
    assert load_vendor_draft(artifact) == draft
    assert recheck_vendor_draft(artifact, before) == draft
    assert before.read_bytes() == BEFORE.encode()
    assert {row.name for row in artifact.iterdir()} == {
        "candidate.cfg",
        "metadata.json",
        "native-commands.txt",
        "local-review.json",
    }
    commands = (artifact / "native-commands.txt").read_text()
    assert (
        commands.startswith("INSPECTION-ONLY DRAFT") and "delete system services telnet" in commands
    )
    assert "PRIVATE-HOST" not in commands and "commit" not in commands
    assert load_patch_review(artifact / "local-review.json") == draft.metadata.review
    original = (artifact / "candidate.cfg").read_bytes()
    with pytest.raises(FileExistsError):
        save_vendor_draft(draft, artifact, before=BEFORE)
    assert (artifact / "candidate.cfg").read_bytes() == original
    before.write_bytes(BEFORE.replace("PRIVATE-HOST", "CHANGED-HOST").encode())
    with pytest.raises(ValueError):
        recheck_vendor_draft(artifact, before)


@pytest.mark.parametrize(
    "damage",
    ["extra", "marker", "metadata", "candidate", "commands", "duplicate", "oversized", "export"],
)
def test_load_rejects_tampered_or_partial_artifact(draft, tmp_path, damage):
    artifact = tmp_path / "draft"
    save_vendor_draft(draft, artifact, before=BEFORE)
    if damage in ("extra", "marker"):
        (artifact / ("extra.txt" if damage == "extra" else ".incomplete")).touch()
    elif damage == "metadata":
        (artifact / "metadata.json").write_text("{}")
    elif damage == "candidate":
        (artifact / "candidate.cfg").write_text(BEFORE)
    elif damage == "commands":
        (artifact / "native-commands.txt").write_text("commit\n")
    elif damage == "export":
        (artifact / "local-review.json").write_text("{}")
    elif damage == "duplicate":
        text = (artifact / "metadata.json").read_text()
        (artifact / "metadata.json").write_text(
            text.replace('"sha256":', '"sha256":"' + "0" * 64 + '","sha256":', 1)
        )
    else:
        (artifact / "native-commands.txt").write_bytes(b"x" * (65536 + 1))
    with pytest.raises(ValueError):
        load_vendor_draft(artifact)


def test_recomputed_checksum_and_native_text_do_not_bypass_source_rebuilding(draft, tmp_path):
    artifact = tmp_path / "draft"
    save_vendor_draft(draft, artifact, before=BEFORE)
    # Structurally valid line hashes still must match fresh edits when source is supplied.
    metadata_path = artifact / "metadata.json"
    payload = json.loads(metadata_path.read_text())
    payload["payload"]["edits"][0]["before_line_sha256"] = "f" * 64
    payload["sha256"] = digest(
        json.dumps(payload["payload"], sort_keys=True, separators=(",", ":"))
    )
    metadata_path.write_text(json.dumps(payload))
    loaded = load_vendor_draft(artifact)
    assert loaded.metadata != draft.metadata
    before_path = tmp_path / "before.cfg"
    before_path.write_bytes(BEFORE.encode())
    with pytest.raises(ValueError, match="stale or changed"):
        recheck_vendor_draft(artifact, before_path)


def test_write_failure_leaves_explicit_incomplete_marker(draft, tmp_path, monkeypatch):
    artifact = tmp_path / "draft"
    original = Path.open

    def fail(path, *args, **kwargs):
        if path.name == "metadata.json":
            raise OSError("controlled write failure")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", fail)
    with pytest.raises(OSError):
        save_vendor_draft(draft, artifact, before=BEFORE)
    assert (artifact / ".incomplete").is_file()
    with pytest.raises(ValueError, match="incomplete"):
        load_vendor_draft(artifact)


def test_cli_reports_only_ids_hashes_and_unconfirmed_status(draft, tmp_path, capsys):
    before = tmp_path / "PRIVATE-FILENAME.cfg"
    before.write_bytes(BEFORE.encode())
    artifact = tmp_path / "draft"
    arguments = [
        "generate",
        "--before",
        str(before),
        "--device-id",
        str(DEVICE),
        "--reference-id",
        "owned-v1",
        "--source-sha256",
        digest(BEFORE),
        "--category",
        "management.telnet_enabled",
        "--output",
        str(artifact),
    ]
    assert main(arguments) == 0
    message = capsys.readouterr()
    assert "PRIVATE" not in message.out + message.err
    response = json.loads(message.out)
    assert response["status"] == "needs_review" and response["formal_verification"] == "not_run"
    assert not response["applied"] and not response["management_access_verified"]
    assert main(["check", "--before", str(before), "--artifact", str(artifact)]) == 0
    capsys.readouterr()
    assert main(arguments) == 2
    assert "PRIVATE" not in capsys.readouterr().err
    assert before.read_bytes() == BEFORE.encode()
    with pytest.raises(SystemExit):
        main(["apply", "--artifact", str(artifact)])


def test_separate_cli_process_reads_new_artifact_without_source_path_leak(tmp_path):
    before = tmp_path / "PRIVATE-FILENAME.cfg"
    before.write_bytes(BEFORE.encode())
    project_root = Path(__file__).resolve().parents[3]
    environment = {
        key: value
        for key, value in os.environ.items()
        if key.upper() in {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP"}
    }
    code = (
        "import sys; sys.path.insert(0,sys.argv.pop(1)); "
        "from app.patching.vendor_cli import main; raise SystemExit(main())"
    )
    artifact = tmp_path / "draft"
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            code,
            str(project_root / "backend"),
            "generate",
            "--before",
            str(before),
            "--device-id",
            str(DEVICE),
            "--reference-id",
            "owned-v1",
            "--source-sha256",
            digest(BEFORE),
            "--category",
            "management.telnet_enabled",
            "--output",
            str(artifact),
        ],
        env=environment,
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    assert "PRIVATE" not in result.stdout + result.stderr
    assert json.loads(result.stdout)["applied"] is False
    assert recheck_vendor_draft(artifact, before).candidate_text == BEFORE.replace(
        "set system services telnet\n", ""
    )


def test_symbolic_linked_files_and_parents_are_refused(draft, tmp_path):
    artifact = tmp_path / "draft"
    save_vendor_draft(draft, artifact, before=BEFORE)
    link = tmp_path / "linked"
    try:
        link.symlink_to(artifact, target_is_directory=True)
    except OSError:
        if os.name != "nt":
            pytest.skip("symbolic link creation is unavailable on this platform")
        # A junction in this owned test directory needs no elevated symlink privilege.
        subprocess.run(
            ["cmd.exe", "/d", "/c", "mklink", "/J", str(link), str(artifact)],
            cwd=tmp_path,
            capture_output=True,
            check=True,
            timeout=30,
        )
        assert link.is_junction()
    with pytest.raises(ValueError, match="linked"):
        load_vendor_draft(link)
    with pytest.raises(ValueError, match="linked"):
        save_vendor_draft(draft, link / "child", before=BEFORE)
