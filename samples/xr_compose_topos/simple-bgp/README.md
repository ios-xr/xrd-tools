# simple-bgp

## Introduction

This lab demonstrates basic BGP connectivity between two IOS-XR routers with a single linear path. Two Alpine containers act as source and destination endpoints; traffic flows source → xrd-1 → xrd-2 → dest. The routers form an iBGP session and redistribute connected routes, so each router learns the prefixes on the other side of the network. This topology is ideal for learning BGP basics and verifying end-to-end reachability through a minimal control-plane setup.

## Topology diagram

```
    [source]          [xrd-1]          [xrd-2]          [dest]
    10.1.1.2  --------  10.1.1.3   GE1  10.2.1.2
                 GE0       |                |
                    10.2.1.0/24 (L2 link)   |
                                           GE1  10.3.1.2 -------- 10.3.1.3
                                                      GE0
```

- **source** (Alpine): Attached to xrd-1 GE0. Default route via 10.1.1.3.
- **xrd-1**: GE0 to source (10.1.1.0/24), GE1 to xrd-2 (10.2.1.0/24).
- **xrd-2**: GE0 to xrd-1 (10.2.1.0/24), GE1 to dest (10.3.1.0/24).
- **dest** (Alpine): Attached to xrd-2 GE1. Default route via 10.3.1.2.

## Roles and intent

| Node      | Role                         | Key features                     | Responsibility                                    |
|-----------|------------------------------|----------------------------------|---------------------------------------------------|
| **source**| Linux host                   | Static default route             | Sends traffic toward 10.0.0.0/8 via xrd-1         |
| **xrd-1** | Edge PE (left)               | iBGP, redistribute connected     | Connects source subnet, advertises to xrd-2       |
| **xrd-2** | Edge PE (right)              | iBGP, redistribute connected     | Connects dest subnet, advertises to xrd-1        |
| **dest**  | Linux host                   | Static default route             | Receives traffic from 10.0.0.0/8 via xrd-2        |

Both routers use BGP AS 100, advertise their connected interfaces (including source and dest subnets) via `redistribute connected`, and peer directly over the 10.2.1.0/24 link. No loopbacks or OSPF/ISIS; iBGP runs directly on physical interfaces.

## Addressing scheme

| Node   | Interface   | IPv4 address  | Subnet        |
|--------|-------------|---------------|---------------|
| source | eth0        | 10.1.1.2      | 10.1.1.0/24   |
| xrd-1  | GE0/0/0/0   | 10.1.1.3      | 10.1.1.0/24   |
| xrd-1  | GE0/0/0/1   | 10.2.1.2      | 10.2.1.0/24   |
| xrd-2  | GE0/0/0/0   | 10.2.1.3      | 10.2.1.0/24   |
| xrd-2  | GE0/0/0/1   | 10.3.1.2      | 10.3.1.0/24   |
| dest   | eth0        | 10.3.1.3      | 10.3.1.0/24   |

| Node   | Interface  | IPv4 address  | Purpose |
|--------|------------|---------------|---------|
| xrd-1  | MgmtEth0   | 172.30.0.2    | Mgmt    |
| xrd-2  | MgmtEth0   | 172.30.0.3    | Mgmt    |

No loopbacks. All data links use 24-bit masks.

## Protocol/feature plan

- **BGP AS 100**: xrd-1 and xrd-2 form a single iBGP session 10.2.1.2 ↔ 10.2.1.3.
- **Redistribution**: Both routers redistribute connected into BGP, so 10.1.1.0/24 and 10.3.1.0/24 are exchanged.
- **Adjacencies**: One iBGP peer per router; no additional protocols.
- **VRFs / policies**: None.

## Key show commands

```bash
# On xrd-1 and xrd-2
show bgp summary
show bgp ipv4 unicast
show route

# Verify interfaces
show ipv4 interface brief
```

## Smoke tests

1. **End-to-end ping**: From `source` run `ping 10.3.1.3` — should succeed, proving traffic traverses both routers via BGP-learned routes. A successful ping confirms BGP sessions are up and routes have been exchanged, so no separate protocol checks are needed.
