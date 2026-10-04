"""Device-account facts preserve anchors but never normalize credential material."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from app.api.contracts import ConfigurationSnapshot
from app.comparison.snapshots import compare_snapshots
from app.domain import CanonicalConfig, LocalAuthentication, LocalUserConfig, SourceLocation
from app.parsers import parse_configuration


def parse(text, filename="synthetic.cfg"):
    return parse_configuration(text, filename=filename)


def test_cisco_accounts_merge_explicit_facts_and_drop_credential_values():
    config = parse(
        "hostname edge\n"
        "username admin privilege 15 secret 9 PRIVATE-CISCO-HASH\n"
        "username observer privilege 1\n"
        "username observer password 7 PRIVATE-ENCODED-PASSWORD\n"
        "username emergency nopassword\n"
    )
    assert config.schema_version == "1.1" and config.parser_confidence == 1
    assert not config.unparsed_fragments
    admin, observer, emergency = config.local_users
    assert (admin.name, admin.privilege, admin.login_class, admin.uid) == ("admin", 15, None, None)
    assert admin.provenance["privilege"].source_lines == [2]
    assert admin.authentication[0].encoding == "9"
    assert admin.authentication[0].provenance.source_lines == [2]
    assert observer.provenance["name"].source_lines == [3, 4]
    assert observer.provenance["privilege"].source_lines == [3]
    assert observer.authentication[0].kind == "password"
    assert observer.authentication[0].encoding == "7"
    assert emergency.privilege is None and emergency.authentication[0].kind == "none"
    assert "PRIVATE" not in config.model_dump_json()


@pytest.mark.parametrize(
    "keyword,encoding",
    [
        ("secret", "0"),
        ("secret", "4"),
        ("secret", "5"),
        ("secret", "8"),
        ("secret", "9"),
        ("password", "0"),
        ("password", "7"),
        ("secret", "unspecified"),
        ("password", "unspecified"),
    ],
)
def test_cisco_credential_metadata_variants(keyword, encoding):
    value = "" if encoding == "unspecified" else encoding + " "
    config = parse(f"hostname edge\nusername test {keyword} {value}PRIVATE-VALUE\n")
    assert config.local_users[0].authentication[0].encoding == encoding
    assert not config.unparsed_fragments and "PRIVATE" not in config.model_dump_json()


def test_cisco_valid_replacements_and_removal_have_exact_current_anchors():
    config = parse(
        "hostname edge\nusername test privilege 1\nusername test privilege 15\n"
        "username test nopassword\nusername test secret 8 PRIVATE\n"
        "username gone secret 9 OTHER\nno username gone\n"
    )
    assert len(config.local_users) == 1
    user = config.local_users[0]
    assert user.privilege == 15 and user.provenance["privilege"].source_lines == [3]
    assert [(item.kind, item.encoding) for item in user.authentication] == [("secret", "8")]
    assert not config.unparsed_fragments


@pytest.mark.parametrize(
    "command",
    [
        "username admin privilege 16 secret 9 PRIVATE",
        "username admin privilege -1",
        "username admin privilege true",
        "username admin privilege 15 unknown PRIVATE",
        "username admin secret 9 PRIVATE trailing",
        "username admin secret 7 PRIVATE",
        "username admin password 9 PRIVATE",
        "username admin secret 5",
        "username admin password 7",
        "username admin secret",
        "username admin nopassword trailing",
        "username admin algorithm-type scrypt secret PRIVATE",
        "username admin autocommand PRIVATE",
        'username "admin" secret 9 PRIVATE',
        "username admin",
        "no username admin privilege 15",
        "username admin privilege 15 password",
    ],
)
def test_unknown_cisco_account_options_are_atomic_and_keep_original_line(command):
    config = parse("hostname edge\nusername admin privilege 1 secret 9 OLD\n" + command + "\n")
    assert config.local_users[0].privilege == 1
    assert config.local_users[0].authentication[0].provenance.source_lines == [2]
    assert len(config.unparsed_fragments) == 1
    assert config.unparsed_fragments[0].raw_text == command
    assert config.unparsed_fragments[0].location.source_lines == [3]
    assert config.parser_confidence < 1


def test_account_command_inside_interface_is_not_global():
    config = parse(
        "hostname edge\ninterface Gi0/1\n username admin privilege 15 secret 9 PRIVATE\n"
    )
    assert not config.local_users and len(config.unparsed_fragments) == 1


JUNOS_SET = (
    "set system host-name edge\n"
    "set system login user admin class super-user\n"
    "set system login user admin uid 1001\n"
    'set system login user admin authentication encrypted-password "PRIVATE-JUNOS-HASH"\n'
    'set system login user admin authentication ssh-ed25519 "ssh-ed25519 PRIVATE-KEY comment"\n'
    "set system login user remote class read-only\n"
)
JUNOS_HIERARCHICAL = (
    "system {\n    host-name edge;\n    login {\n        user admin {\n"
    "            class super-user;\n            uid 1001;\n            authentication {\n"
    '                encrypted-password "PRIVATE-JUNOS-HASH";\n'
    '                ssh-ed25519 "ssh-ed25519 PRIVATE-KEY comment";\n'
    "            }\n        }\n        user remote {\n            class read-only;\n"
    "        }\n    }\n}\n"
)


@pytest.mark.parametrize("text", [JUNOS_SET, JUNOS_HIERARCHICAL])
def test_junos_accounts_support_set_and_hierarchical_without_secret_material(text):
    config = parse(text, "synthetic.conf")
    assert not config.unparsed_fragments and config.parser_confidence == 1
    admin, remote = config.local_users
    assert (admin.name, admin.login_class, admin.uid, admin.privilege) == (
        "admin",
        "super-user",
        1001,
        None,
    )
    assert [(item.kind, item.encoding) for item in admin.authentication] == [
        ("secret", "encrypted"),
        ("ssh_public_key", "ssh-ed25519"),
    ]
    assert remote.authentication == []  # Absence does not prove passwordless access.
    assert remote.login_class == "read-only"
    assert "PRIVATE" not in config.model_dump_json()
    for user in config.local_users:
        assert user.provenance["name"].source_lines
        for method in user.authentication:
            assert method.provenance.source_lines


@pytest.mark.parametrize(
    "options",
    [
        "class super-user extra",
        "uid 99",
        "uid 64001",
        "uid 1.5",
        "uid true",
        "authentication encrypted-password",
        'authentication encrypted-password ""',
        'authentication encrypted-password " "',
        "authentication plain-text-password",
        'authentication ssh-rsa "KEY" from "192.0.2.1"',
        "authentication load-key-file PRIVATE",
        "full-name PRIVATE",
        "class",
        "authentication no-public-keys",
        "unknown PRIVATE",
    ],
)
def test_unsupported_junos_options_preserve_unknown_source_without_partial_side_effect(options):
    command = "set system login user admin " + options
    config = parse(
        "set system host-name edge\nset system login user admin class operator\n" + command + "\n"
    )
    assert len(config.local_users) == 1
    assert config.local_users[0].login_class == "operator"
    assert config.local_users[0].uid is None and not config.local_users[0].authentication
    assert [item.raw_text for item in config.unparsed_fragments] == [command]
    assert config.parser_confidence < 1


@pytest.mark.parametrize("method", ["ssh-rsa", "ssh-ecdsa", "ssh-ed25519"])
def test_junos_keys_are_only_declared_metadata_not_cryptographically_verified(method):
    config = parse(
        "set system host-name edge\n"
        f'set system login user test authentication {method} "PRIVATE";\n'
    )
    assert config.local_users[0].authentication[0].encoding == method
    assert "PRIVATE" not in config.model_dump_json() and not config.unparsed_fragments


def test_unknown_junos_nested_blocks_cannot_be_misinterpreted_as_account_options():
    config = parse(
        "system {\n host-name edge;\n login {\n  user admin {\n   class operator;\n"
        "   unknown {\n    class super-user;\n    uid 1001;\n   }\n  }\n }\n}\n",
        "synthetic.conf",
    )
    assert config.local_users[0].login_class == "operator"
    assert config.local_users[0].uid is None
    assert len(config.unparsed_fragments) == 3 and config.parser_confidence < 1


def test_legacy_canonical_json_keeps_its_serialized_shape_and_new_version_is_explicit():
    path = Path(__file__).resolve().parents[1] / "golden/expected/cisco_ios/edge-secure.cfg.json"
    legacy = json.loads(path.read_text(encoding="utf-8"))
    legacy["schema_version"] = "1.0"
    legacy.pop("local_users", None)
    restored = CanonicalConfig.model_validate(legacy)
    assert restored.local_users == [] and restored.model_dump(mode="json") == legacy
    new = parse("hostname edge\nusername test privilege 1\n")
    assert new.schema_version == "1.1"
    with pytest.raises(ValueError, match=r"schema 1\.1"):
        CanonicalConfig.model_validate(new.model_dump(mode="json") | {"schema_version": "1.0"})
    with pytest.raises(ValueError, match="unique"):
        CanonicalConfig.model_validate(
            new.model_dump(mode="json") | {"local_users": [new.local_users[0]] * 2}
        )


def test_normalized_account_diff_is_independent_of_credential_values_and_account_order():
    def snapshot(text, seconds):
        return ConfigurationSnapshot(
            configuration_id=uuid4(),
            device_id=UUID(int=1),
            created_at=datetime(2026, 10, 4, tzinfo=UTC) + timedelta(seconds=seconds),
            canonical=parse(text),
        )

    before = snapshot(
        "hostname edge\nusername admin privilege 1 secret 9 PRIVATE-OLD\n"
        "username reader privilege 1\n",
        0,
    )
    after = snapshot(
        "hostname edge\nusername reader privilege 1\n"
        "username admin privilege 1 secret 9 PRIVATE-NEW\n",
        1,
    )
    diff = compare_snapshots(before, after)
    assert diff.changes == () and diff.source_changed
    changed = snapshot("hostname edge\nusername admin privilege 15 secret 9 PRIVATE-NEW\n", 2)
    report = compare_snapshots(after, changed)
    assert {item.section for item in report.changes} == {"local_users"}
    assert {item.kind for item in report.changes} == {"removed", "modified"}
    assert "PRIVATE" not in report.model_dump_json()
    modified = next(item for item in report.changes if item.kind == "modified")
    assert modified.before_value["privilege"] == 1 and modified.after_value["privilege"] == 15
    assert modified.before_locations and modified.after_locations


def test_auth_contract_rejects_secret_fields_invalid_encoding_and_duplicate_methods():
    location = SourceLocation(source_lines=[1], raw_text_hash="a" * 64, parser_confidence=1)
    with pytest.raises(ValueError):
        LocalAuthentication.model_validate(
            {"kind": "secret", "encoding": "9", "value": "PRIVATE", "provenance": location}
        )
    with pytest.raises(ValueError):
        LocalAuthentication(kind="password", encoding="9", provenance=location)
    method = LocalAuthentication(kind="secret", encoding="9", provenance=location)
    with pytest.raises(ValueError):
        LocalUserConfig(name="test", authentication=[method, method])
    with pytest.raises(ValueError):
        LocalUserConfig(name="test", privilege=True)
