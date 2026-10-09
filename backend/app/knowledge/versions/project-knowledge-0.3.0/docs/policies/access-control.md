# Access-control policy

These controls evaluate normalized ACL and JunOS firewall-filter rules. The
engine reports configured facts only; it does not claim that an ACL protects a
particular interface or control-plane service unless attachment data is
available in a future parser version.

## ACLs must not be empty

Policy ID: `acl.empty`

Severity: high

An ACL with no supported permit or deny action is incomplete or ineffective.
Add the intended restrictive rules or remove the unused object.

## Unrestricted permits are forbidden

Policy ID: `acl.unrestricted_permit`

Severity: critical

A permit without source, destination, or port constraints grants the selected
protocol unrestricted passage. Replace it with explicit least-privilege
matches.

## Telnet must not be permitted

Policy ID: `acl.telnet_permitted`

Severity: high

ACLs must not explicitly permit TCP port 23. Administrative access must use SSH
from approved source networks.

## Management sources must be restricted

Policy ID: `acl.management_access_from_any`

Severity: critical

Rules that explicitly permit SSH or SNMP must restrict their source addresses
to approved management networks. This rule evaluates ports represented as
service names, raw numbers, or an equality operator.
