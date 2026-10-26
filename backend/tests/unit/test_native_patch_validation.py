"""Frozen text operation correspondence, independent of current parser/generator calls."""

import json
from hashlib import sha256
from uuid import UUID, uuid5

import pytest
from app.detection.policy_engine import evaluate_policies
from app.parsers import parse_configuration
from app.patching.native_patch_validation import validate_native_patch_texts
from app.patching.proposal import PROPOSAL_NAMESPACE
from app.patching.vendor_drafts import VendorDraft, create_vendor_draft

DEVICE = UUID("a41a1390-0e97-45a2-b2f3-7692ca6f31e8")
CISCO = "hostname owned\nip ssh version 2\nline vty 0 4\n transport input ssh telnet\n!\n"
JUNOS = "set system host-name owned\nset system services ssh\nset system services telnet\n"


def generate(source):
    config = parse_configuration(source, filename="before.cfg")
    selected = next(
        row
        for row in evaluate_policies(config, device_id=DEVICE)
        if row.category == "management.telnet_enabled"
    )
    return create_vendor_draft(
        source,
        finding=selected,
        source_sha256=sha256(source.encode()).hexdigest(),
        reference_id="owned-frozen-text-validator",
    )


def rebound_metadata(generated, *, before=None, after=None, edit_updates=None, spans=None):
    payload = generated.metadata.model_dump(mode="json")
    proposal = payload["review"]["proposal"]
    for name, text in (("before", before), ("after", after)):
        if text is not None:
            digest = sha256(text.encode()).hexdigest()
            proposal[name + "_sha256"] = digest
            proposal[name + "_line_count"] = len(text.splitlines())
            payload["review"]["preflight"][name]["source_sha256"] = digest
    if edit_updates:
        payload["edits"][0].update(edit_updates)
    if spans is not None:
        proposal["changes"] = spans
    proposal.pop("proposal_id")
    proposal["proposal_id"] = str(
        uuid5(PROPOSAL_NAMESPACE, json.dumps(proposal, sort_keys=True, separators=(",", ":")))
    )
    return VendorDraft.model_validate(payload)


@pytest.mark.parametrize(
    "source",
    [
        CISCO,
        JUNOS,
        CISCO.replace("\n", "\r\n").replace(
            " transport input ssh telnet", "\tTRANSPORT  INPUT telnet ssh \t"
        ),
        CISCO.rstrip("\n"),
        JUNOS.replace("set system services telnet\n", "  set system services telnet;\r\n"),
        CISCO + "line vty 5 15\n transport input none\n!\n",
        CISCO + "line vty 5 15\n transport input telnet ssh\n!\n",
    ],
)
def test_precise_released_text_semantics_are_preserved(source, monkeypatch):
    generated = generate(source)

    def forbidden(*args, **kwargs):
        pytest.fail("frozen history called runtime parser/policy/generator")

    for name in (
        "app.patching.vendor_drafts.create_vendor_draft",
        "app.patching.vendor_drafts.check_vendor_draft",
        "app.patching.vendor_drafts._cisco_telnet",
        "app.patching.vendor_drafts._simple_edits",
        "app.patching.vendor_drafts._replace_line",
        "app.patching.vendor_drafts._digest",
        "app.patching.vendor_drafts.parse_configuration",
        "app.patching.vendor_drafts.evaluate_policies",
        "app.parsers.parse_configuration",
        "app.detection.policy_engine.evaluate_policies",
    ):
        monkeypatch.setattr(name, forbidden)
    validate_native_patch_texts(generated.metadata, source, generated.candidate_text)


@pytest.mark.parametrize("source", [CISCO, JUNOS])
def test_rehashed_unrelated_text_edit_is_rejected(source):
    generated = generate(source)
    after = generated.candidate_text.replace("owned", "foreign")
    forged = rebound_metadata(generated, after=after)
    with pytest.raises(ValueError, match="exact allowed edits"):
        validate_native_patch_texts(forged, source, after)


@pytest.mark.parametrize("source", [CISCO, JUNOS])
def test_internally_valid_rehashed_change_spans_must_match_exact_retained_texts(source):
    generated = generate(source)
    span = generated.metadata.review.proposal.changes[0].model_dump(mode="json")
    # Equal total lengths and proposal UUID are insufficient: move the edit to host-name.
    if span["operation"] == "replace":
        span.update(before_start=0, before_end=1, after_start=0, after_end=1)
    else:
        span.update(before_start=0, before_end=1, after_start=0, after_end=0)
    forged = rebound_metadata(generated, spans=[span])
    with pytest.raises(ValueError, match="change spans"):
        validate_native_patch_texts(forged, source, generated.candidate_text)


@pytest.mark.parametrize(
    "update",
    [
        {"before_line_sha256": "a" * 64},
        {"after_line_sha256": "a" * 64},
        {"vty": {"first": 5, "last": 15}},
    ],
)
def test_line_hash_and_vty_context_are_verified_from_exact_original_text(update):
    generated = generate(CISCO)
    forged = rebound_metadata(generated, edit_updates=update)
    with pytest.raises(ValueError, match="exact allowed edits"):
        validate_native_patch_texts(forged, CISCO, generated.candidate_text)


@pytest.mark.parametrize(
    "source",
    [
        CISCO.replace("line vty 0 4", " line vty 0 4"),
        CISCO.replace("line vty 0 4", "line vty 4 0"),
        CISCO.replace("line vty 0 4", "line vty 0 4 extra"),
        CISCO.replace(" transport input ssh telnet", "transport input ssh telnet"),
        CISCO.replace(" transport input ssh telnet", " transport input all"),
        CISCO.replace(" transport input ssh telnet", " transport input telnet"),
        CISCO.replace(" transport input ssh telnet", " transport input ssh telnet rlogin"),
        CISCO + "line vty 4 8\n transport input none\n!\n",
        CISCO.replace("!\n", " transport input ssh\n!\n"),
        JUNOS.replace("set system services ssh\n", ""),
        JUNOS.replace(
            "set system services telnet", "set system services telnet connection-limit 1"
        ),
        JUNOS + "set system services telnet\n",
        JUNOS.replace("set system services telnet", 'set system services "telnet"'),
        JUNOS.replace("set system services telnet", "system { services { telnet; } }"),
    ],
)
def test_ambiguous_original_cannot_be_made_valid_by_rebinding_whole_text_hashes(source):
    generated = generate(CISCO if source.startswith("hostname") else JUNOS)
    # Keep before/after line deltas consistent, even for added/removed original lines.
    after = source.replace("transport input ssh telnet", "transport input ssh")
    if source.startswith("set "):
        after = "".join(
            line
            for line in source.splitlines(keepends=True)
            if line.strip() == "set system services ssh"
            or line.strip().startswith("set system host-name")
        )
    if source == after:
        after = source.replace("owned", "other")
    # For metadata revalidation, derive the internally consistent actual spans;
    # the frozen validator must still reject unsupported source/context operations.
    from difflib import SequenceMatcher

    spans = [
        {"operation": tag, "before_start": i, "before_end": j, "after_start": k, "after_end": end}
        for tag, i, j, k, end in SequenceMatcher(
            a=source.splitlines(keepends=True), b=after.splitlines(keepends=True)
        ).get_opcodes()
        if tag != "equal"
    ]
    forged = rebound_metadata(generated, before=source, after=after, spans=spans)
    with pytest.raises(ValueError):
        validate_native_patch_texts(forged, source, after)


def test_partial_representation_of_multiple_matching_vty_edits_is_rejected():
    source = CISCO + "line vty 5 15\n transport input ssh telnet\n!\n"
    generated = generate(source)
    # Syntactically typed copies do not establish complete edit coverage.
    metadata = generated.metadata.model_copy(update={"edits": generated.metadata.edits[:1]})
    with pytest.raises(ValueError):
        validate_native_patch_texts(metadata, source, generated.candidate_text)


@pytest.mark.parametrize(
    "flag",
    [
        "application_supported",
        "device_syntax_verified",
        "management_access_verified",
    ],
)
def test_standalone_frozen_validation_rejects_forged_typed_assurance_flags(flag):
    generated = generate(CISCO)
    metadata = generated.metadata.model_copy(update={flag: 0})
    with pytest.raises(ValueError, match="exact false"):
        validate_native_patch_texts(metadata, CISCO, generated.candidate_text)


def test_new_native_history_does_not_admit_the_existing_offline_ssh_v1_operation():
    source = "hostname owned\nip ssh version 1\n"
    config = parse_configuration(source, filename="before.cfg")
    finding = next(
        row
        for row in evaluate_policies(config, device_id=DEVICE)
        if row.category == "management.ssh_version_1"
    )
    generated = create_vendor_draft(
        source,
        finding=finding,
        source_sha256=sha256(source.encode()).hexdigest(),
        reference_id="owned-existing-offline-ssh-v1",
    )
    assert generated.candidate_text == "hostname owned\nip ssh version 2\n"
    with pytest.raises(ValueError, match="unsupported native history operation"):
        validate_native_patch_texts(generated.metadata, source, generated.candidate_text)


@pytest.mark.parametrize(
    "source",
    ["", "\n\t", "invalid\x00text", "я" * 1_048_577, "line\n" * 10_001, "\ud800"],
    ids=["empty", "whitespace", "control", "utf8-byte-budget", "line-budget", "surrogate"],
)
def test_history_text_is_nonempty_utf8_bounded_and_without_control_characters(source):
    generated = generate(CISCO)
    with pytest.raises(ValueError):
        validate_native_patch_texts(generated.metadata, source, generated.candidate_text)
