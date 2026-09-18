# Observability and audit policy

These controls apply to Cisco IOS and Juniper JunOS configuration snapshots.
Absence-based findings carry the parser's overall confidence and explicitly
state that only supported syntax was evaluated.

## Legacy SNMP must be disabled

Policy ID: `management.snmp_legacy_enabled`

Severity: high

SNMPv1 and SNMPv2c must not be used because community-based access does not
provide modern authentication and privacy. Use SNMPv3 or disable SNMP.

## Monitoring must be configured

Policy ID: `management.snmp_not_configured`

Severity: medium

Managed devices must expose approved monitoring, normally through SNMPv3. An
approved alternative must be documented when SNMP is intentionally disabled.

## Time synchronization is required

Policy ID: `management.ntp_not_configured`

Severity: medium

At least one approved NTP server must be configured so event timestamps and
protocol operations use a consistent time source. Redundant servers are
recommended but are not yet enforced by this rule.

## Remote audit logging is required

Policy ID: `management.syslog_not_configured`

Severity: high

Security and operational events must be sent to an approved remote Syslog
collector so evidence survives local device failure or tampering.
