# segment-routing

## Introduction

This lab demonstrates SR-MPLS (Segment Routing over MPLS) with a Path Computation Element (PCE) in a meshed 8-router topology. Six routers (xrd-1 through xrd-6) form a core with two edge PEs (xrd-1, xrd-2) connecting source and dest Alpine containers. xrd-7 is the PCE and xrd-8 is a BGP VPNv4 route reflector (vRR). The PEs use MPLS VPN (VRF 100) with color-based SR Policy computed by the PCE via PCEP. ISIS with two-level hierarchy (Level 1 for PEs and core, Level 2 for core and infrastructure) provides IGP underlay. Flex-Algo 128 and 129 and TI-LFA fast-reroute illustrate advanced SR features. Traffic from source to dest is carried over an SR Policy with color 100, computed on-demand by the PCE.

## Topology diagram

```
                         xrd-7 (PCE)
                        /            \
                   GE0 /              \ GE1
                      /   xrd-3 --- xrd-4   \
                     /     |  \     /  |     \
               GE2  /      |   \   /   |      \  GE2
         source --- xrd-1  |    \ /    |  xrd-2 --- dest
               GE2  \      |   xrd-5   |     /
                     \     |   /   \   |    /
                      \    |  /     \  |   /
                   GE1 \   | /       \ |  / GE1
                        \ xrd-6 ----- /
                         \    |    /
                          \   |   /
                           GE0  GE0
                                |
                         xrd-8 (vRR)
```

Link details:

- **source** (10.1.1.2) → xrd-1 GE2 (10.1.1.3)
- **xrd-1** GE0 ↔ xrd-3 GE2, GE1 ↔ xrd-5 GE2
- **xrd-2** GE0 ↔ xrd-4 GE2, GE1 ↔ xrd-6 GE2
- **xrd-3** GE0 ↔ xrd-4 GE0, GE1 ↔ xrd-5 GE1, GE2 ↔ xrd-1 GE0, GE3 ↔ xrd-7 GE0
- **xrd-4** GE3 ↔ xrd-7 GE1
- **xrd-5** GE0 ↔ xrd-6 GE0, GE3 ↔ xrd-8 GE0
- **xrd-6** GE3 ↔ xrd-8 GE1
- **dest** (10.3.1.3) ← xrd-2 GE2 (10.3.1.2)

## Roles and intent

| Node   | Role                    | Key features                                           | Responsibility                                      |
|--------|-------------------------|--------------------------------------------------------|-----------------------------------------------------|
| **source** | Linux host            | Static default route                                   | Sends traffic via 10.1.1.3                           |
| **xrd-1** | PE (ingress)          | VRF 100, ISIS L1, BGP VPNv4+LSPE, SR-TE, PCEP client   | CE attach; originates SR Policy; sends to PCE       |
| **xrd-2** | PE (egress)           | VRF 100, ISIS L1, BGP VPNv4+LSPE, SR-TE, PCEP client   | CE attach; receives SR Policy; exchanges VPN routes via vRR |
| **xrd-3..6** | P (core)            | ISIS L1/L2, SR-MPLS, TI-LFA, Flex-Algo                 | Transit; propagate link-state to PCE; forward MPLS    |
| **xrd-7** | PCE                   | ISIS L2, BGP-LS, PCEP server                           | Compute SR Policies for PEs; TED from BGP-LS         |
| **xrd-8** | vRR                   | ISIS L2, BGP VPNv4 RR                                  | Reflect VPNv4 between xrd-1 and xrd-2                |
| **dest** | Linux host            | Static default route                                   | Receives traffic via 10.3.1.2                         |

## Addressing scheme

### Loopbacks (Global)

| Router | Loopback0        | Loopback1 (anycast)   |
|--------|------------------|------------------------|
| xrd-1  | 100.100.100.101  | —                      |
| xrd-2  | 100.100.100.102  | —                      |
| xrd-3  | 100.100.100.103  | 101.103.105.255        |
| xrd-4  | 100.100.100.104  | 101.104.106.255        |
| xrd-5  | 100.100.100.105  | 101.103.105.255        |
| xrd-6  | 100.100.100.106  | 101.104.106.255        |
| xrd-7  | 100.100.100.107  | —                      |
| xrd-8  | 100.100.100.108  | —                      |

### Data links (selected)

| Link       | xrd-A if | xrd-B if | Subnet           |
|------------|----------|----------|------------------|
| xrd-1–xrd-3 | GE0      | GE2      | 100.101.103.0/24 |
| xrd-1–xrd-5 | GE1      | GE2      | 100.101.105.0/24 |
| xrd-2–xrd-4 | GE0      | GE2      | 100.102.104.0/24 |
| xrd-2–xrd-6 | GE1      | GE2      | 100.102.106.0/24 |
| xrd-3–xrd-4 | GE0      | GE0      | 100.103.104.0/24 |
| xrd-3–xrd-5 | GE1      | GE1      | 100.103.105.0/24 |
| xrd-4–xrd-6 | GE1      | GE1      | 100.104.106.0/24 |
| xrd-5–xrd-6 | GE0      | GE0      | 100.105.106.0/24 |
| xrd-3–xrd-7 | GE3      | GE0      | 100.103.107.0/24 |
| xrd-4–xrd-7 | GE3      | GE1      | 100.104.107.0/24 |
| xrd-5–xrd-8 | GE3      | GE0      | 100.105.108.0/24 |
| xrd-6–xrd-8 | GE3      | GE1      | 100.106.108.0/24 |

### VRF 100 (PE–CE)

| Node   | Interface | IPv4      | Subnet     |
|--------|-----------|-----------|------------|
| xrd-1  | GE2 (VRF 100) | 10.1.1.3  | 10.1.1.0/24 |
| xrd-2  | GE2 (VRF 100) | 10.3.1.2  | 10.3.1.0/24 |
| source | eth0      | 10.1.1.2  | 10.1.1.0/24 |
| dest   | eth0      | 10.3.1.3  | 10.3.1.0/24 |

### Mgmt

All routers: MgmtEth0 172.40.0.10x/24 (x = 1..8). Note: docker-compose may use 172.30.0.0/24; align if needed.

## Protocol/feature plan

- **ISIS 1**: NET 49.0100.0100.0100.0XX.00 (XX = 01..08).
  - L1: xrd-1, xrd-2 (PEs); xrd-3..6 (core interfaces to PEs).
  - L2: xrd-3..8 (core and infra). L2→L1 propagation filtered by route-policy INFRA (only 100.100.100.107, 108).
- **SR-MPLS**: Global block 16000–18000. Prefix-SIDs: index 101–108 (default), 201–208 (Flex-Algo 128), 301–308 (Flex-Algo 129). Anycast Loopback1 on xrd-3/5 and xrd-4/6 with indexes 1001/1101.
- **Flex-Algo 128, 129**: Defined with affinity red/blue; used for constraint-based path computation.
- **SR-TE + PCEP**: xrd-1 and xrd-2 as PCCs; xrd-7 as PCE. On-demand color 100, dynamic candidate path via PCEP, IGP metric.
- **BGP**: VPNv4 via xrd-8 (RR) between xrd-1 and xrd-2. BGP-LS from xrd-1, xrd-2 to xrd-7 for TED.
- **VRF 100**: RT 100:100; export route-policy sets extcommunity color 100. Connected redistribution into VPNv4.
- **TI-LFA**: Enabled on ISIS interfaces for fast-reroute.

## Key show commands

```bash
# ISIS
show isis adjacency
show isis database
show isis segment-routing flex-algo

# SR
show segment-routing traffic-eng policy
show segment-routing traffic-eng pcc ipv4 peer   # On PCC (xrd-1, xrd-2): PCEP session to PCE
show segment-routing prefix-sid-map

# BGP
show bgp vpnv4 unicast summary
show bgp vrf 100 ipv4 unicast

# PCE (xrd-7)
show pce peer
show pce topology
```

## Smoke tests

1. **PCEP session**: On xrd-1, run `show segment-routing traffic-eng pcc ipv4 peer` — the peer 100.100.100.107 should be in **State up** with Stateful/Update/Segment-Routing capabilities. This confirms the PCC↔PCE control channel is established and the PCE can compute and push SR Policies. Allow up to ~120s after boot for the session to establish.
2. **SR-TE policy operational**: On xrd-1, run `show segment-routing traffic-eng policy color 100` — status should be **Operational: up**. This confirms the PCE has computed a valid path for the on-demand color 100 policy toward xrd-2.
3. **End-to-end ping**: From `source`, `ping 10.3.1.3` — should succeed. This exercises the full stack: ISIS underlay, PCEP-computed SR Policy (color 100), MPLS label switching through the core, and VPNv4 route exchange via the vRR.
4. **Bidirectional reachability**: From `dest`, `ping 10.1.1.2` — should succeed. Proves the L3VPN service delivers reachability in both directions across the SR-TE overlay.

## Optional: PCE REST API

xrd-7 supports an XTC northbound REST API for external visibility into the PCE topology and policies. It is not enabled in the startup config to avoid embedding credentials. To enable post-boot:

```cisco
pce
 api
  user <username>
   password <password>
```
