# IS-IS TI-LFA with SR-MPLS Lab

## Introduction

This lab demonstrates **Topology-Independent Loop-Free Alternate (TI-LFA)** fast-reroute using **Segment Routing MPLS (SR-MPLS)** over an IS-IS backbone.

TI-LFA pre-computes backup paths for every prefix before any failure occurs. When a link fails, the Point of Local Repair (PLR) immediately switches to the backup path using a pre-computed SR label stack — achieving sub-50ms convergence without waiting for the IGP to reconverge.

The topology is specifically designed so that the TI-LFA backup path must traverse **nodes earlier in the original shortest path**. When the R3–R4 link fails, R3 (the PLR) must steer traffic backwards through R2 and R1 to reach R4 via the bottom path. This requires a label stack (not just a simple next-hop swap), making it a compelling demonstration of TI-LFA's power over traditional LFA.

**Protocols and technologies:**
- **IS-IS** (level-2-only, metric-style wide) — IGP for reachability
- **SR-MPLS** — segment routing data plane with per-node prefix SIDs
- **TI-LFA** — topology-independent fast-reroute computed per-prefix

## Topology diagram

```
         metric 10      metric 10      metric 10
    R1 ========== R2 ========== R3 ========== R4
    ||                                        ||
    || metric 20      metric 20      metric 20||
    R5 ========== R6 =========================+
```

All links are point-to-point. The top path (R1–R2–R3–R4) has IS-IS metric 10 per hop, while the bottom path (R1–R5–R6–R4) has metric 20 per hop. This ensures the primary shortest path for east-west traffic uses the top path, with the bottom path serving as the backup.

## Roles and intent

| Router | Role | Description |
|--------|------|-------------|
| R1 | West edge / junction | Connects top path (to R2) and bottom path (to R5). Serves as the pivot point where TI-LFA backup traffic re-enters the bottom path. |
| R2 | Top-path transit | Forwards traffic between R1 and R3 along the primary path. Part of the TI-LFA backup path when R3–R4 fails. |
| R3 | PLR (Point of Local Repair) | When R3–R4 fails, R3 is the PLR that activates TI-LFA. It pushes an SR label stack to steer traffic back through R2→R1→R5→R6→R4. |
| R4 | East edge / destination | The destination for the primary traffic flow. Reachable via top path (R3) or bottom path (R6). |
| R5 | Bottom-path transit | Part of the alternate path R1→R5→R6→R4 used when the top path fails. |
| R6 | Bottom-path transit | Part of the alternate path, connects R5 to R4 via the bottom path. |

## Addressing scheme

### Loopback Addresses

| Router | Loopback0 | Prefix-SID Index | Label |
|--------|-----------|-----------------|-------|
| R1 | 10.0.0.1/32 | 1 | 16001 |
| R2 | 10.0.0.2/32 | 2 | 16002 |
| R3 | 10.0.0.3/32 | 3 | 16003 |
| R4 | 10.0.0.4/32 | 4 | 16004 |
| R5 | 10.0.0.5/32 | 5 | 16005 |
| R6 | 10.0.0.6/32 | 6 | 16006 |

### Point-to-Point Links

| Link | Subnet | R1 Side | R2 Side | IS-IS Metric |
|------|--------|---------|---------|--------------|
| R1–R2 | 10.1.12.0/24 | 10.1.12.1 (Gi0/0/0/0) | 10.1.12.2 (Gi0/0/0/0) | 10 |
| R2–R3 | 10.1.23.0/24 | 10.1.23.2 (Gi0/0/0/1) | 10.1.23.3 (Gi0/0/0/0) | 10 |
| R3–R4 | 10.1.34.0/24 | 10.1.34.3 (Gi0/0/0/1) | 10.1.34.4 (Gi0/0/0/0) | 10 |
| R1–R5 | 10.1.15.0/24 | 10.1.15.1 (Gi0/0/0/1) | 10.1.15.5 (Gi0/0/0/0) | 20 |
| R5–R6 | 10.1.56.0/24 | 10.1.56.5 (Gi0/0/0/1) | 10.1.56.6 (Gi0/0/0/0) | 20 |
| R6–R4 | 10.1.64.0/24 | 10.1.64.6 (Gi0/0/0/1) | 10.1.64.4 (Gi0/0/0/1) | 20 |

## Protocol/feature plan

### IS-IS

- **Instance**: LAB
- **Type**: level-2-only (single-area flat network)
- **Metric style**: wide (required for segment routing)
- **NET format**: 49.0001.0000.0000.000X.00 (X = router number)

All routers should form IS-IS level-2 adjacencies on every point-to-point link. Expected adjacencies:

| Router | Neighbors |
|--------|-----------|
| R1 | R2 (Gi0/0/0/0), R5 (Gi0/0/0/1) |
| R2 | R1 (Gi0/0/0/0), R3 (Gi0/0/0/1) |
| R3 | R2 (Gi0/0/0/0), R4 (Gi0/0/0/1) |
| R4 | R3 (Gi0/0/0/0), R6 (Gi0/0/0/1) |
| R5 | R1 (Gi0/0/0/0), R6 (Gi0/0/0/1) |
| R6 | R5 (Gi0/0/0/0), R4 (Gi0/0/0/1) |

### Segment Routing MPLS

- **SRGB**: 16000–23999 (default)
- **Prefix-SID assignment**: index = router number (labels 16001–16006)
- Enabled under `router isis LAB` → `address-family ipv4 unicast` → `segment-routing mpls`
- Each router advertises its Loopback0 prefix-SID

### TI-LFA

- Enabled per-interface under IS-IS with `fast-reroute per-prefix` and `fast-reroute per-prefix ti-lfa`
- All IS-IS interfaces have TI-LFA enabled
- Backup paths are pre-computed using the post-convergence SPF

**Expected TI-LFA behavior at R3 for prefix 10.0.0.4/32:**
- Primary: via Gi0/0/0/1 (R3→R4), metric 10
- Backup: label stack pushing R1's prefix-SID (16001), forwarding via Gi0/0/0/0 (towards R2)
- The backup path traverses: R3→R2→R1→R5→R6→R4

## Key show commands

```
! Verify IS-IS neighbors are up
show isis neighbors

! Verify IS-IS routes including SR prefix-SIDs
show isis route

! Check segment routing label table
show isis segment-routing label table

! Verify TI-LFA backup paths
show isis fast-reroute 10.0.0.4/32 detail

! Check the MPLS forwarding table for SR labels
show mpls forwarding

! Verify SR prefix-SID bindings
show isis segment-routing prefix-sid-map active-policy
```

## Smoke tests

1. **End-to-end reachability**: Ping R4 loopback from R1:
   ```
   ping 10.0.0.4 source 10.0.0.1
   ```
   Expected: Success (5/5 replies)

2. **TI-LFA backup computed on R3**: Verify R3 has a TI-LFA backup for R4's prefix:
   ```
   show isis fast-reroute 10.0.0.4/32 detail
   ```
   Expected: Backup path present via R2 (Gi0/0/0/0) with an SR label stack
