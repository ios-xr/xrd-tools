# OSPF + BGP Route Reflector Lab

## Introduction

This lab demonstrates a service-provider-style network with OSPF as the IGP underlay
and iBGP with redundant route reflectors carrying service prefixes. It replaces the
previous `bgp-ospf-triangle` and `bgp-route-reflector` samples by combining their
features into a single topology.

Two route reflectors (rr1, rr2) share `cluster-id 1`, meaning either can independently
reflect the full set of client routes. If one RR fails, every PE still has an active
BGP session to the surviving RR, so route reflection — and therefore host reachability —
continues without interruption. This is the standard SP redundancy pattern: the shared
cluster-id ensures both RRs consider the same routes eligible for reflection and
prevents duplicate advertisements when both are healthy.

The key architectural point: host-facing interfaces are deliberately excluded from
OSPF. Host subnets are advertised into BGP and reach remote PEs only through route
reflection. This means every layer of the stack — OSPF adjacencies, iBGP sessions,
and route reflection — must be working for the end-to-end smoke test to pass. Removing
*both* route reflectors would break host-to-host connectivity, while losing one
leaves the network fully operational.

## Topology Diagram

```
     [host1]                     [host2]
        |                           |
       pe1 -------- pe2 --------- pe3
        |                           |
       rr1 ---------------------- rr2
```

- **PE mesh**: pe1–pe2, pe1–pe3, pe2–pe3 (full mesh of inter-router links)
- **PE to RR**: pe1–rr1, pe3–rr2 (each edge PE connects to one RR)
- **RR interconnect**: rr1–rr2
- **Host links**: host1–pe1, host2–pe3

7 containers total: 5 XRd routers + 2 Alpine hosts.

## Roles and Intent

| Router | Role | Key Responsibilities |
|--------|------|---------------------|
| pe1 | Provider Edge | Connects host1; originates 172.30.1.0/24 and 192.168.1.0/24 into BGP; OSPF adjacencies with pe2, pe3, rr1 |
| pe2 | Provider Edge | Transit PE with no host; originates 192.168.2.0/24 into BGP; OSPF adjacencies with pe1, pe3 |
| pe3 | Provider Edge | Connects host2; originates 172.30.2.0/24 and 192.168.3.0/24 into BGP; OSPF adjacencies with pe1, pe2, rr2 |
| rr1 | Route Reflector | Redundant RR (shared cluster-id 1 with rr2); reflects all PE routes; OSPF adjacencies with pe1, rr2 |
| rr2 | Route Reflector | Redundant RR (shared cluster-id 1 with rr1); reflects all PE routes; OSPF adjacencies with pe3, rr1 |
| host1 | End host | Alpine container on pe1; static route to reach host2 and PE loopback space |
| host2 | End host | Alpine container on pe3; static route to reach host1 and PE loopback space |

## Addressing Scheme

### Loopbacks

| Router | Loopback0 (router-id, iBGP) | Loopback1 (advertised /24) |
|--------|----------------------------|---------------------------|
| pe1 | 10.0.0.1/32 | 192.168.1.1/24 |
| pe2 | 10.0.0.2/32 | 192.168.2.1/24 |
| pe3 | 10.0.0.3/32 | 192.168.3.1/24 |
| rr1 | 10.0.0.11/32 | — |
| rr2 | 10.0.0.12/32 | — |

### Inter-Router Links (OSPF Area 0, point-to-point)

| Link | Subnet | A side | B side |
|------|--------|--------|--------|
| pe1–pe2 | 10.1.1.0/24 | pe1 Gi0/0/0/0: .1 | pe2 Gi0/0/0/0: .2 |
| pe1–pe3 | 10.1.2.0/24 | pe1 Gi0/0/0/1: .1 | pe3 Gi0/0/0/0: .2 |
| pe2–pe3 | 10.1.3.0/24 | pe2 Gi0/0/0/1: .1 | pe3 Gi0/0/0/1: .2 |
| pe1–rr1 | 10.1.4.0/24 | pe1 Gi0/0/0/3: .1 | rr1 Gi0/0/0/0: .2 |
| pe3–rr2 | 10.1.5.0/24 | pe3 Gi0/0/0/3: .1 | rr2 Gi0/0/0/0: .2 |
| rr1–rr2 | 10.1.6.0/24 | rr1 Gi0/0/0/1: .1 | rr2 Gi0/0/0/1: .2 |

### Host Links (NOT in OSPF — carried via BGP)

| Link | Subnet | Router side | Host side |
|------|--------|-------------|-----------|
| host1–pe1 | 172.30.1.0/24 | pe1 Gi0/0/0/2: .1 | host1: .100 |
| host2–pe3 | 172.30.2.0/24 | pe3 Gi0/0/0/2: .1 | host2: .100 |

### Management Network (VRF MGMT)

All routers have MgmtEth0/RP0/CPU0/0 under VRF MGMT on the shared 172.28.0.0/24
management subnet. This isolates management traffic from the data plane.

| Router | MgmtEth0/RP0/CPU0/0 |
|--------|---------------------|
| pe1 | 172.28.0.1/24 |
| pe2 | 172.28.0.2/24 |
| pe3 | 172.28.0.3/24 |
| rr1 | 172.28.0.11/24 |
| rr2 | 172.28.0.12/24 |

## Protocol/Feature Plan

### OSPF (Process 1, Area 0)

All inter-router GigE links run OSPF with `network point-to-point`. Loopback0 is
passive. Host-facing interfaces (Gi0/0/0/2 on pe1 and pe3) are deliberately excluded
so that host subnets are not learned via OSPF.

Expected OSPF adjacencies (all FULL):

| Router | Neighbor | Interface |
|--------|----------|-----------|
| pe1 | pe2 (10.0.0.2) | Gi0/0/0/0 |
| pe1 | pe3 (10.0.0.3) | Gi0/0/0/1 |
| pe1 | rr1 (10.0.0.11) | Gi0/0/0/3 |
| pe2 | pe1 (10.0.0.1) | Gi0/0/0/0 |
| pe2 | pe3 (10.0.0.3) | Gi0/0/0/1 |
| pe3 | pe1 (10.0.0.1) | Gi0/0/0/0 |
| pe3 | pe2 (10.0.0.2) | Gi0/0/0/1 |
| pe3 | rr2 (10.0.0.12) | Gi0/0/0/3 |
| rr1 | pe1 (10.0.0.1) | Gi0/0/0/0 |
| rr1 | rr2 (10.0.0.12) | Gi0/0/0/1 |
| rr2 | pe3 (10.0.0.3) | Gi0/0/0/0 |
| rr2 | rr1 (10.0.0.11) | Gi0/0/0/1 |

### BGP (AS 65000, iBGP)

Redundant route reflectors (rr1, rr2) with a shared `bgp cluster-id 1`. The shared
cluster-id is what makes them a redundancy pair: each RR independently reflects
the full route set, and the matching cluster-id prevents duplicate advertisements
when both are healthy. Every PE peers with *both* RRs, so the loss of one RR is
a non-event — the surviving RR continues reflecting all routes. rr1 and rr2 also
peer with each other as non-client peers to synchronize routes. All sessions use
`update-source Loopback0`.

Expected BGP sessions (7 total):

| From | To | Relationship |
|------|----|-------------|
| pe1 | rr1 (10.0.0.11) | client → RR |
| pe1 | rr2 (10.0.0.12) | client → RR |
| pe2 | rr1 (10.0.0.11) | client → RR |
| pe2 | rr2 (10.0.0.12) | client → RR |
| pe3 | rr1 (10.0.0.11) | client → RR |
| pe3 | rr2 (10.0.0.12) | client → RR |
| rr1 | rr2 (10.0.0.12) | non-client peer |

BGP prefixes advertised via `network` statements:

| Router | Prefix | Source |
|--------|--------|--------|
| pe1 | 192.168.1.0/24 | Loopback1 |
| pe1 | 172.30.1.0/24 | host1 link (Gi0/0/0/2) |
| pe2 | 192.168.2.0/24 | Loopback1 |
| pe3 | 192.168.3.0/24 | Loopback1 |
| pe3 | 172.30.2.0/24 | host2 link (Gi0/0/0/2) |

### VRF MGMT

All five routers have MgmtEth0/RP0/CPU0/0 under VRF MGMT with SSH server enabled
in the VRF. This is SP best practice: management traffic stays isolated from the
data plane and does not appear in the default routing table.

## Key Show Commands

```
show ospf neighbor                     # Verify all OSPF adjacencies are FULL
show ospf route                        # Verify OSPF routes for inter-router links + loopbacks
show bgp ipv4 unicast summary          # Verify BGP sessions established with non-zero PfxRcd
show bgp ipv4 unicast                  # View all BGP routes (host subnets + PE prefixes)
show bgp ipv4 unicast 172.30.2.0/24   # Trace host2 subnet path through RR
show route                             # Full RIB showing both OSPF and BGP routes
show route 172.30.2.0/24              # Verify host2 subnet resolved via BGP next-hop
```

## Smoke Tests

These tests validate the full dependency chain: OSPF → iBGP sessions → route
reflection → BGP next-hop resolution → forwarding.

1. **host1 → host2**: From host1, run `ping 172.30.2.100`
2. **host2 → host1**: From host2, run `ping 172.30.1.100`

Both pings must succeed. If either fails, it indicates a problem at one or more
layers of the stack (OSPF adjacency, BGP session, route reflection, or forwarding).

## Evolutions

- **RR failover**: Stop one RR container and verify host-to-host ping continues — validates the redundancy design; then restart and confirm both RRs re-sync
- **BFD**: Add BFD on OSPF and BGP sessions for sub-second failure detection
- **VPNv4**: Extend BGP to carry VPNv4 routes; add per-PE customer VRFs
- **IS-IS migration**: Replace OSPF with IS-IS to compare IGP behavior
- **Traffic engineering**: Add MPLS or SR-MPLS labels for TE tunnels between PEs
- **Graceful restart**: Configure BGP graceful restart on RRs and test PE failure
