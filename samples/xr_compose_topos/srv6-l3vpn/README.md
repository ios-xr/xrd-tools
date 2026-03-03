# SRv6 L3VPN Lab

## Introduction

This lab demonstrates a simple Segment Routing over IPv6 (SRv6) Layer 3 VPN service. Two customer edge routers (CE1 and CE2) are connected to provider edge routers (PE1 and PE2) via eBGP, with a provider core router (P1) providing transit. The PE routers use SRv6 as the data-plane encapsulation for L3VPN traffic, replacing traditional MPLS labels with IPv6 SRv6 SIDs.

**Key technologies:**
- **IS-IS** provides IPv6 reachability across the provider core (PE1, P1, PE2)
- **SRv6** with micro-segment (uSID) behavior provides the transport layer — each core router has a locator prefix advertised via IS-IS
- **MP-BGP VPNv4** between PE1 and PE2 carries customer IPv4 prefixes with SRv6 encapsulation
- **eBGP** on CE-PE links allows customer routers to advertise their loopbacks into the VPN

## Topology diagram

```
  AS 65001        AS 100                              AS 100        AS 65002
  ┌─────┐       ┌─────┐       ┌─────┐       ┌─────┐       ┌─────┐
  │ CE1 ├───────┤ PE1 ├───────┤  P1 ├───────┤ PE2 ├───────┤ CE2 │
  └─────┘       └─────┘       └─────┘       └─────┘       └─────┘
         Gi0/0/0/0   Gi0/0/0/1   Gi0/0/0/0   Gi0/0/0/0   Gi0/0/0/1
         10.1.1.0/31 2001:db8:1::/127  2001:db8:2::/127  10.1.4.0/31
         (VRF CUSTOMER)   (IS-IS + SRv6)  (IS-IS + SRv6)  (VRF CUSTOMER)

         PE1 ◄──────── iBGP VPNv4 (SRv6) ────────► PE2
```

## Roles and intent

| Router | Role | Description |
|--------|------|-------------|
| **CE1** | Customer Edge | Originates customer prefix 192.168.1.1/32 via eBGP to PE1. Represents a customer site on the left side of the network. |
| **PE1** | Provider Edge | Terminates the customer VRF, peers with CE1 via eBGP and with PE2 via iBGP VPNv4. Encapsulates customer traffic in SRv6 for transport across the core. |
| **P1** | Provider Core | Pure transit router. Runs IS-IS and has an SRv6 locator so it can participate in the SRv6 domain, but does not terminate any VPN services. |
| **PE2** | Provider Edge | Mirror of PE1 on the right side. Terminates VRF CUSTOMER, peers with CE2 via eBGP and with PE1 via iBGP VPNv4 with SRv6 encapsulation. |
| **CE2** | Customer Edge | Originates customer prefix 192.168.2.1/32 via eBGP to PE2. Represents a customer site on the right side of the network. |

## Addressing scheme

### Loopbacks

| Router | Loopback0 | Purpose |
|--------|-----------|---------|
| PE1 | fc00::1/128 | IS-IS router-ID, BGP update-source, SRv6 origination |
| P1 | fc00::2/128 | IS-IS router-ID |
| PE2 | fc00::3/128 | IS-IS router-ID, BGP update-source, SRv6 origination |
| CE1 | 192.168.1.1/32 | Customer prefix advertised via eBGP |
| CE2 | 192.168.2.1/32 | Customer prefix advertised via eBGP |

### Point-to-Point Links

| Link | Interface (Left) | Address (Left) | Interface (Right) | Address (Right) | Context |
|------|-------------------|----------------|-------------------|-----------------|---------|
| CE1–PE1 | CE1 Gi0/0/0/0 | 10.1.1.0/31 | PE1 Gi0/0/0/0 | 10.1.1.1/31 | VRF CUSTOMER |
| PE1–P1 | PE1 Gi0/0/0/1 | 2001:db8:1::/127 | P1 Gi0/0/0/0 | 2001:db8:1::1/127 | IS-IS core |
| P1–PE2 | P1 Gi0/0/0/1 | 2001:db8:2::/127 | PE2 Gi0/0/0/0 | 2001:db8:2::1/127 | IS-IS core |
| PE2–CE2 | PE2 Gi0/0/0/1 | 10.1.4.1/31 | CE2 Gi0/0/0/0 | 10.1.4.0/31 | VRF CUSTOMER |

### SRv6 Locators

| Router | Locator Name | Prefix | Behavior |
|--------|-------------|--------|----------|
| PE1 | PE1 | fcbb:bb00:1::/48 | uNode PSP-USD |
| P1 | P1 | fcbb:bb00:2::/48 | uNode PSP-USD |
| PE2 | PE2 | fcbb:bb00:3::/48 | uNode PSP-USD |

## Protocol/feature plan

### IS-IS (core)

- Instance: `core`, level-2-only
- Area: 49.0001
- Routers: PE1, P1, PE2
- Address-family: IPv6 unicast with `metric-style wide`
- SRv6: Each router advertises its locator via IS-IS

**Expected adjacencies:**
| Router | Neighbor | Interface |
|--------|----------|-----------|
| PE1 | P1 | Gi0/0/0/1 |
| P1 | PE1 | Gi0/0/0/0 |
| P1 | PE2 | Gi0/0/0/1 |
| PE2 | P1 | Gi0/0/0/0 |

### SRv6

- Micro-segment (uSID) with `unode psp-usd` behavior on all core routers
- Locator prefixes are distributed by IS-IS, providing SRv6 reachability across the core
- PEs allocate per-VRF SIDs for L3VPN service

### BGP

**iBGP (PE1 ↔ PE2, AS 100):**
- Address-family: VPNv4 unicast
- Update-source: Loopback0
- Encapsulation: SRv6 (`encapsulation-type srv6`)
- Carries VRF CUSTOMER prefixes between PEs

**eBGP (CE–PE):**
| Session | CE AS | PE AS | Link |
|---------|-------|-------|------|
| CE1 ↔ PE1 | 65001 | 100 | 10.1.1.0/31 (VRF CUSTOMER) |
| CE2 ↔ PE2 | 65002 | 100 | 10.1.4.0/31 (VRF CUSTOMER) |

CEs advertise their Loopback0 via `network` statement. PEs redistribute connected VRF routes and import remote VPN prefixes.

### VRF CUSTOMER

- Configured on PE1 and PE2
- RD: 100:1
- RT import/export: 100:1
- SRv6 allocation: per-VRF mode using each PE's locator

## Key show commands

```
! IS-IS adjacencies (PE1, P1, PE2)
show isis neighbors

! IS-IS IPv6 routes including SRv6 locator prefixes
show isis ipv6 route

! SRv6 locator and SID table
show segment-routing srv6 locator
show segment-routing srv6 sid

! BGP VPNv4 summary (PE1, PE2)
show bgp vpnv4 unicast summary

! VRF routes on PEs — should show local and remote CE loopbacks
show bgp vrf CUSTOMER ipv4 unicast

! eBGP session on CEs
show bgp ipv4 unicast summary

! End-to-end VRF reachability
show route vrf CUSTOMER
```

## Smoke tests

These tests verify end-to-end SRv6 L3VPN connectivity:

| # | Test | Command | Router | Expected Result |
|---|------|---------|--------|-----------------|
| 1 | CE1 → CE2 loopback | `ping vrf default 192.168.2.1 source 192.168.1.1` | CE1 | Success (5/5 replies) |
| 2 | CE2 → CE1 loopback | `ping vrf default 192.168.1.1 source 192.168.2.1` | CE2 | Success (5/5 replies) |
