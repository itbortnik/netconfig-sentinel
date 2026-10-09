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

## Static next hops must not be local addresses

Policy ID: `routing.static_next_hop_is_local`

Severity: high. Platforms: Cisco IOS/IOS-XE and JunOS parser slices.

Report an explicit non-discard static next hop equal to a supported interface host
address on the same supplied configuration. Cite the route and matching address
statements. Review target/VRF intent before changing it. This checks local declared
facts, not route recursion, forwarding state, full inventory or reachability.

## Static next hops must be unicast

Policy ID: `routing.static_next_hop_non_unicast`

Severity: high. Platforms: Cisco IOS/IOS-XE and JunOS parser slices.

Report explicit multicast, unspecified or IPv4 limited-broadcast next hops on
non-discard static routes. Private, documentation and IPv6 link-local addresses
are not treated as violations by this rule. Require the intended unicast neighbor
or an explicit supported discard action. Interface-only/discard routes are not
guessed to have a next hop; runtime forwarding and reachability are not verified.
