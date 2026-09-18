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
- interface blocks with `description`, `shutdown`/`no shutdown`, IPv4
  `ip address`, and CIDR-form IPv6 `ipv6 address`;
- single-ID `vlan` definitions with `name`;
- `switchport mode access|trunk`, `switchport access vlan`, trunk native VLAN,
  and explicit/all/none trunk allowed VLAN selections;
- numeric trunk ranges such as `10,20-30` are expanded into a sorted canonical
  VLAN set.
- named standard and extended IPv4 ACLs plus named IPv6 ACLs, including
  sequence, permit/deny, protocol, `any`, host, IPv4 wildcard/CIDR operands,
  common port operators, and trailing options;
- IPv4 and IPv6 prefix lists with optional sequence, `ge`, and `le` bounds.

## Juniper JunOS

Both hierarchical and `set` syntax are supported for:

- `system host-name`;
- `system services ssh|telnet`;
- external AAA indicators in `authentication-order`, `radius-server`, and
  `tacplus-server`;
- SNMP v3 and community configuration;
- NTP servers;
- Syslog hosts.
- physical interfaces and logical units with descriptions, `disable`, and
  `family inet|inet6 address` in hierarchical and `set` syntax.
- named `vlans` with `vlan-id` in hierarchical and `set` syntax;
- `family ethernet-switching` with access/trunk mode, native VLAN, and named or
  numeric VLAN members; known VLAN names are also resolved to numeric IDs.
- `firewall family inet|inet6 filter` terms in hierarchical and `set` syntax,
  including source/destination addresses and ports, protocol, selected match
  options, and accept/discard/reject actions;
- `policy-options prefix-list` membership in hierarchical and `set` syntax.

## Current limitations

- VRF/routing-instance assignment, aggregation, tunnel parameters, and
  operational state beyond the commands listed above remain unparsed;
- VTP, private VLANs, Q-in-Q, JunOS `vlan-id-list`, and incremental IOS trunk
  operations (`add`, `remove`, `except`) remain unsupported;
- numbered IOS ACLs, object/object-group operands, time ranges, dynamic ACLs,
  reflexive ACLs, and advanced protocol-specific ACL options remain unparsed;
- JunOS firewall actions and match conditions beyond the explicitly listed
  subset, prefix-list filters, route filters, routing, and nested policy
  statements remain unparsed;
- IOS platform refinement (IOS versus IOS-XE) is not inferred yet;
- SNMP community syntax cannot prove whether v1, v2c, or both are reachable, so
  the canonical result reports both;
- JunOS groups, `apply-groups`, inactive statements, quoted multiline values,
  and bracket expansion are not interpreted;
- comments and formatting are not included in the unsupported-line ratio;
- vendor detection uses tested marker evidence, not file extensions.
