# Supported features

## Cisco IOS / IOS-XE

Supported in the current parser slice:

- `hostname`;
- `version`;
- `aaa new-model` and `no aaa new-model`;
- `ip ssh ...`;
- `line vty` with `transport input ssh`, `telnet`, or `all`;
- `snmp-server group ... v3`;
- `snmp-server community ...` (reported conservatively as v1/v2c-capable);
- `ntp server`;
- `logging host`.

## Juniper JunOS

Both hierarchical and `set` syntax are supported for:

- `system host-name`;
- `system services ssh|telnet`;
- external AAA indicators in `authentication-order`, `radius-server`, and
  `tacplus-server`;
- SNMP v3 and community configuration;
- NTP servers;
- Syslog hosts.

## Current limitations

- interfaces, VLANs, ACLs, prefix lists, routing, and nested policy statements
  remain unparsed;
- IOS platform refinement (IOS versus IOS-XE) is not inferred yet;
- SNMP community syntax cannot prove whether v1, v2c, or both are reachable, so
  the canonical result reports both;
- JunOS groups, `apply-groups`, inactive statements, quoted multiline values,
  and bracket expansion are not interpreted;
- comments and formatting are not included in the unsupported-line ratio;
- vendor detection uses tested marker evidence, not file extensions.
