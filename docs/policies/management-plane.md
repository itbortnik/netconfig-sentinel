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
