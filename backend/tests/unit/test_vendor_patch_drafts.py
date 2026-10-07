"""Conservative native drafts on owned inputs, never reachability or application proof."""

from hashlib import sha256
from uuid import UUID

import pytest
from app.detection.policy_engine import evaluate_policies
from app.parsers import parse_configuration
from app.patching.vendor_drafts import check_vendor_draft, create_vendor_draft

DEVICE = UUID("090e4d66-151d-4a57-97f0-56bf5f90a9a5")
TELNET = "management.telnet_enabled"
SSHV1 = "management.ssh_version_1"


def digest(text):
    return sha256(text.encode()).hexdigest()


def select(before, category):
    config = parse_configuration(before, filename="before.cfg")
    return next(
        row for row in evaluate_policies(config, device_id=DEVICE) if row.category == category
    )


def create(before, category=TELNET, **updates):
    arguments = {
        "finding": select(before, category),
        "source_sha256": digest(before),
        "reference_id": "owned-selected-v1",
    }
    arguments.update(updates)
    return create_vendor_draft(before, **arguments)


@pytest.mark.parametrize(
    "before,after,category,commands",
    [
        (
            "hostname owned\nip ssh version 2\nline vty 0 4\n transport input ssh telnet\n!\n",
            "hostname owned\nip ssh version 2\nline vty 0 4\n transport input ssh\n!\n",
            TELNET,
            ("line vty 0 4", "transport input ssh", "exit"),
        ),
        (
            "set system host-name owned\nset system services ssh\nset system services telnet\n",
            "set system host-name owned\nset system services ssh\n",
            TELNET,
            ("delete system services telnet",),
        ),
        (
            "hostname owned\nip ssh version 1\n",
            "hostname owned\nip ssh version 2\n",
            SSHV1,
            ("ip ssh version 2",),
        ),
        (
            "set system host-name owned\nset system services ssh protocol-version v1\n",
            "set system host-name owned\nset system services ssh protocol-version v2\n",
            SSHV1,
            ("set system services ssh protocol-version v2",),
        ),
    ],
)
def test_exact_native_candidate_is_bound_and_always_needs_review(before, after, category, commands):
    generated = create(before, category)
    assert generated.candidate_text == after
    assert generated.metadata.native_commands == commands
    assert generated.metadata.review.proposal.before_sha256 == digest(before)
    assert generated.metadata.review.proposal.after_sha256 == digest(after)
    assert generated.metadata.review.status == "needs_review"
    assert generated.metadata.review.preflight.formal_verification == "not_run"
    assert generated.metadata.review.proposal.status == "draft"
    assert generated.metadata.review.validation_blockers[:2] == (
        "formal_verification_not_run",
        "human_review_required",
    )
    assert generated.metadata.review.preflight.before.complete
    assert generated.metadata.review.preflight.after.complete
    assert not any(
        row.category == category
        for row in generated.metadata.review.preflight.after_policy_findings
    )
    assert check_vendor_draft(generated.metadata, before, after) == generated
    assert create(before, category) == generated


def test_multiple_disjoint_vty_ranges_preserve_every_unrelated_byte_and_line_ending():
    before = (
        "hostname owned\r\naaa new-model\r\nip ssh version 2\r\n"
        "line vty 0 4\r\n\ttransport  input   telnet ssh  \r\n!\r\n"
        "line vty 5 15\r\n transport input ssh telnet\r\n!\r\n"
        "ntp server 192.0.2.1\r\nlogging host 192.0.2.2"
    )
    generated = create(before)
    assert generated.candidate_text == before.replace(
        "\ttransport  input   telnet ssh  \r\n", "\ttransport input ssh  \r\n"
    ).replace(" transport input ssh telnet\r\n", " transport input ssh\r\n")
    assert tuple(edit.source_line for edit in generated.metadata.edits) == (5, 8)
    assert "ntp server 192.0.2.1\r\nlogging host 192.0.2.2" in generated.candidate_text


@pytest.mark.parametrize(
    "before",
    [
        "hostname owned\nline vty 0 4\n transport input telnet\n",
        "hostname owned\nline vty 0 4\n transport input all\n",
        "hostname owned\nline vty 0 4\n transport input ssh telnet rlogin\n",
        "hostname owned\ntransport input ssh telnet\n",
        "hostname owned\nline vty 4 0\n transport input ssh telnet\n",
        "hostname owned\nline vty 0 4 extra\n transport input ssh telnet\n",
        "hostname owned\nline vty 0 4\n transport input ssh telnet\n transport input ssh\n",
        "hostname owned\nline vty 0 4\n transport input ssh telnet\n!\n"
        "line vty 4 8\n transport input ssh telnet\n",
        "hostname owned\nip ssh version 2\nline vty 0 4\n"
        " transport input ssh telnet\n unsupported token\n",
        "set system host-name owned\nset system services telnet\n",
        "set system host-name owned\nset system services ssh unexpected-option\n"
        "set system services telnet\n",
        "set system host-name owned\nset system services ssh\n"
        "set system services telnet connection-limit 1\n",
        "set system host-name owned\nset system services ssh\n"
        "set system services telnet\nset system services telnet\n",
        "system {\n host-name owned;\n services {\n  ssh;\n  telnet;\n }\n}\n",
    ],
)
def test_ambiguous_or_unsupported_management_inputs_are_not_rewritten(before):
    with pytest.raises(ValueError):
        create(before)


def test_existing_source_and_current_exact_finding_are_required():
    before = "hostname owned\nip ssh version 2\nline vty 0 4\n transport input ssh telnet\n"
    selected = select(before, TELNET)
    for updates in (
        {"source_sha256": "f" * 64},
        {"finding": selected.model_copy(update={"device_id": UUID(int=1)})},
        {"finding": selected.model_copy(update={"model_version": "policy-rules-0.6.0"})},
        {"finding": selected.model_copy(update={"affected_lines": [1]})},
        {"finding": selected.model_copy(update={"remediation": "SECRET injection"})},
    ):
        with pytest.raises(ValueError):
            create(before, **updates)


def test_recheck_rejects_changed_candidate_even_when_source_identity_is_unchanged():
    before = "set system host-name owned\nset system services ssh\nset system services telnet\n"
    generated = create(before)
    for changed in (
        generated.candidate_text + "set system services telnet\n",
        generated.candidate_text.replace("owned", "foreign"),
        generated.candidate_text
        + "set routing-options static route 0.0.0.0/0 next-hop 192.0.2.1\n",
    ):
        with pytest.raises(ValueError):
            check_vendor_draft(generated.metadata, before, changed)


@pytest.mark.parametrize(
    "before",
    [
        "hostname owned\nip ssh version 2\nip ssh version 1\n",
        "hostname owned\n ip ssh version 1\n",
        "set system host-name owned\nset system services ssh protocol-version v2\n"
        "set system services ssh protocol-version v1\n",
    ],
)
def test_conflicting_or_non_root_ssh_versions_do_not_produce_a_draft(before):
    with pytest.raises(ValueError):
        create(before, SSHV1)


def test_a_disjoint_disabled_vty_range_is_left_intact():
    before = (
        "hostname owned\nline vty 0 4\n transport input ssh telnet\n!\n"
        "line vty 5 15\n transport input none\n!\n"
    )
    generated = create(before)
    assert generated.candidate_text == before.replace(
        "transport input ssh telnet", "transport input ssh"
    )
    assert len(generated.metadata.edits) == 1


def test_excessive_vty_contexts_fail_without_silently_dropping_any():
    before = "hostname owned\n" + "".join(
        f"line vty {number} {number}\n transport input ssh telnet\n!\n" for number in range(129)
    )
    with pytest.raises(ValueError, match="budget"):
        create(before)
