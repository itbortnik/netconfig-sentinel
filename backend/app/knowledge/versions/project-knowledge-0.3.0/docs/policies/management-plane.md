# Management-plane policy

These controls apply to Cisco IOS and Juniper JunOS configuration snapshots.
They are evaluated from normalized facts, while evidence points back to the
original configuration whenever the triggering statement is explicit.

## Hostname must be explicit

Policy ID: `management.hostname_missing`

Severity: medium

Every device must have an explicit unique hostname so findings, logs, and
inventory records can be correlated reliably. A missing supported hostname
statement is reported as an absence-based finding.

## Telnet must be disabled

Policy ID: `management.telnet_enabled`

Severity: high

Unencrypted Telnet access must not be enabled. Use SSH and restrict management
access to approved source networks.

## SSH must be enabled

Policy ID: `management.ssh_disabled`

Severity: high

SSH must be explicitly enabled for remote administration. A missing supported
enablement statement is reported as an absence-based finding with the parser's
overall confidence and an explicit limitation.

## SSH version 1 must be disabled

Policy ID: `management.ssh_version_1`

Severity: high

An explicitly configured SSH protocol version 1 is reported because it uses
obsolete cryptography and protocol design. The rule remains silent when the
version is not explicit; it does not infer a platform default.

## Centralized AAA must be enabled

Policy ID: `management.aaa_disabled`

Severity: high

Centralized authentication, authorization, and accounting must be enabled with
an explicitly tested local fallback. A missing supported enablement statement
is reported as an absence-based finding.

## Local accounts must not be passwordless

Policy ID: `account.passwordless`

Severity: critical. Platform: Cisco IOS/IOS-XE parser slice.

Report only explicitly parsed `nopassword`. Missing credential metadata is not
passwordless access: a JunOS remote-template account or unsupported authentication
must not be reclassified. Review intended fallback access before requiring an
approved credential. Actual login and effective authentication are not verified.

## Local credentials must not use type 0

Policy ID: `account.cleartext_credential`

Severity: high. Platform: Cisco IOS/IOS-XE parser slice.

Report explicit storage type 0 for either password or secret. The implicit
`unspecified` type is not guessed. Require an approved non-reversible format and
protect source files; the finding never includes credential values or claims to
validate them. This is distinct from reversible storage and legacy hash formats.

## Local passwords must not be reversible

Policy ID: `account.reversible_password`

Severity: high. Platform: Cisco IOS/IOS-XE parser slice.

Report explicitly declared password type 7. Migrate to an approved non-reversible
secret after testing fallback access. No decryption is attempted. Cisco describes
type 7 as weak reversible storage in its [secrets guidance](https://www.cisco.com/c/en/us/about/trust-center/resilient-infrastructure/protecting-secrets.html).

## Local secrets must not use legacy formats

Policy ID: `account.legacy_secret`

Severity: medium. Platform: Cisco IOS/IOS-XE parser slice.

The internal policy requires review/migration of explicitly declared secret types
4 and 5. One policy covers both legacy formats, not separate vendor or encoding
copies. Check target-release support before migration. Type 4 has a documented
[Cisco advisory](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130318-type4);
the parser neither validates hash bytes nor infers the strength of an unspecified
type or a JunOS `encrypted-password` value.

## Local account UIDs must be unique

Policy ID: `account.duplicate_uid`

Severity: high. Platform: JunOS parser slice.

Report each explicitly assigned UID shared by different parsed account names,
with both statements as evidence. Omitted/default UIDs are not invented. Review
identity mappings and use unique UIDs through the approved change process.
[Juniper's user reference](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/user-edit-system-login.html)
requires uniqueness on the device; this check covers only the supplied parsed
accounts, not actual login or runtime identity.
