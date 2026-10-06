# Routing policy

These controls evaluate explicit BGP, OSPF, interface-address, and static-route
facts. They do not infer an intended topology or expected peer inventory; those
comparisons belong to the baseline and formal-verification stages.

## BGP router ID must be explicit

Policy ID: `bgp.router_id_missing`

Severity: medium

Every BGP process must use an explicitly configured, stable IPv4 router ID so a
change in interface state cannot silently change protocol identity.

## BGP neighbors must be remote

Policy ID: `bgp.neighbor_is_local_address`

Severity: critical

A BGP neighbor address must not equal an address assigned to the same device.
The finding cites both the neighbor statement and local interface address.

## OSPF router ID must be explicit

Policy ID: `ospf.router_id_missing`

Severity: medium

Every OSPF process must use an explicitly configured, stable IPv4 router ID.
This avoids identity changes caused by interface or address selection.

## Default routes must not be discarded

Policy ID: `routing.default_route_discarded`

Severity: critical

An IPv4 or IPv6 default static route must not point to a discard action. More
specific discard routes used for aggregation are outside this rule.
