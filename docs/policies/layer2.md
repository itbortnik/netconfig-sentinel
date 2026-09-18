# Layer 2 interface policy

These controls evaluate normalized access/trunk mode and VLAN membership. They
report only explicit interface facts and do not infer the intended topology.

## Access VLANs must be explicit

Policy ID: `interface.access_vlan_missing`

Severity: high

Every access interface must declare its intended VLAN explicitly. Reliance on a
vendor default can place endpoints in an unintended broadcast domain.

## Trunk VLANs must be restricted

Policy ID: `interface.trunk_vlans_unrestricted`

Severity: high

Every trunk must declare a least-privilege allowed VLAN set. A missing list or
an explicit all-VLAN selection is a violation.

## Switchport mode must be consistent

Policy ID: `interface.switchport_mode_conflict`

Severity: high

An access interface must not retain trunk-only native or allowed-VLAN settings,
and a trunk must not retain an access VLAN. Conflicting parameters should be
removed before deployment.
