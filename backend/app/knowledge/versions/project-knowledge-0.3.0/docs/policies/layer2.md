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

## Referenced VLANs must have local definitions

Policy ID: `interface.vlan_reference_undefined`

Severity: medium. Platforms: Cisco IOS/IOS-XE and JunOS parser slices.

The internal policy requires an explicit local definition for every supported
numeric/named access, native or finite allowed-VLAN reference. Report missing
IDs/names once per interface with the referencing statements. An unrestricted
all-VLAN selector does not invent thousands of references. Dynamic provisioning,
inherited groups and actual VLAN availability are not verified; unsupported
configuration still reduces parser coverage and suppresses aggregate risk.

## Native VLAN filtering must be reviewed

Policy ID: `interface.native_vlan_excluded`

Severity: medium. Platform: Cisco IOS/IOS-XE parser slice only.

Report an explicit native VLAN excluded from an explicit finite trunk allowed
set. Missing sets or native IDs are not guessed. Intentional filtering may be
valid, so this is an engineering-review requirement, not proof of a forwarding
failure or security exposure. JunOS native-VLAN behavior varies by platform and
configuration style; this rule is not applied to JunOS.

## Duplicate interface addresses must be reviewed

Policy ID: `interface.duplicate_address`

Severity: high. Platforms: Cisco IOS/IOS-XE and JunOS parser slices.

Report a host IP configured on different supported physical/logical interfaces;
the prefix length does not hide host-address equality. Repeated entries on the
same interface are not separate interface collisions. Explicitly disabled
interfaces are excluded. Review intended anycast, VRFs and ownership before
changing addresses. Actual operational state, VRF assignment and real network
impact are not verified, and legitimate exceptions require engineering review.
