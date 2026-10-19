# Network Forensic Traverse & Packet Flow Deconstruction

**Case Reference:** IR-2026-CLOUD-001  
**Author:** Mark Bahaa (Lead DFIR Investigator, Inspire HUB)

---

## 1. Network Architecture Overview

The target enterprise environment employs an Azure Hub-and-Spoke topology:
- **Hub VNet (`10.50.0.0/16`):** Houses the perimeter Next-Generation Firewall (FortiGate VM running FortiOS).
  - External Interface (`port1`): `10.50.20.4` (attached to Azure Public IP `20.50.100.15`).
  - Internal Interface (`port2`): `10.50.200.4` (gateway router interface connecting to spoke subnets).
- **Spoke VNet / Subnet (`10.50.200.0/24`):** Production database tier.
  - Victim VM: `PROD-DB01.CORP.LOCAL` (`10.50.200.7`), primary NIC: `db-nic-01`.

```
[Attacker Node: 198.51.100.133]
          │
          ▼ (Public Internet)
[Azure Public IP: 20.50.100.15]
          │
          ▼ (Azure SDN Ingress / No NSG drop)
[FortiGate Hub: port1 (10.50.20.4)]
          │
          ▼ [VIP DNAT: Inbound-App-VIP (extport: ANY -> mappedip: 10.50.200.7)]
[FortiOS Kernel: Policy 28 "Inbound-Access" (srcaddr: all, service: ALL)]
          │
          ▼
[FortiGate Hub: port2 (10.50.200.4)]
          │
          ▼ (Azure VNet Peering / UDR)
[Subnet 10.50.200.0/24]
          │
          ▼
[Victim Host: PROD-DB01 (10.50.200.7:1433 / 3389)]
```

---

## 2. Step-by-Step 11-Hop Packet Flow Matrix

| Hop | Layer | Component / Entity | Source IP:Port | Destination IP:Port | Action / Kernel Translation | Forensic Artifact |
|---|---|---|---|---|---|---|
| **01** | L3/L4 | Threat Actor Host | `198.51.100.133:51944` | `20.50.100.15:1433` | Initial TCP SYN packet transmission | ISP AS60068 route table |
| **02** | L3 | Azure Edge Router | `198.51.100.133:51944` | `20.50.100.15:1433` | Public IP routed to Azure Microsoft WAN edge | Azure Front Door / Edge flow logs |
| **03** | L2/L3 | Azure SDN / SLB | `198.51.100.133:51944` | `10.50.20.4:1433` | Azure 1:1 NAT mapping Public IP to Hub NIC (`port1`) | Azure Network Interface IP config |
| **04** | L3 | Hub Inbound NSG | `198.51.100.133:51944` | `10.50.20.4:1433` | Evaluated against NSG rules. Default allow VNet / Inbound pass | Azure Network Watcher NSG Flow Log |
| **05** | L2 | FGT VM Kernel (`port1`) | `198.51.100.133:51944` | `10.50.20.4:1433` | Ingress driver packet reception on virtual network card | `diagnose sniffer packet port1` |
| **06** | L4/NAT | FortiOS DNAT Engine | `198.51.100.133:51944` | `10.50.200.7:1433` | VIP `Inbound-App-VIP` applied; destination rewritten to internal IP | `show firewall vip "Inbound-App-VIP"` |
| **07** | L4-L7 | FortiOS Policy Engine | `198.51.100.133:51944` | `10.50.200.7:1433` | Policy 28 (`Inbound-Access`) match: `srcaddr: all`, `service: ALL` -> **ACCEPT** | `diagnose firewall iprope show` |
| **08** | L3 | FortiOS Routing Table | `198.51.100.133:51944` | `10.50.200.7:1433` | Route lookup matches `10.50.200.0/24` via egress `port2` | `get router info routing-table all` |
| **09** | L2 | FGT VM Kernel (`port2`) | `198.51.100.133:51944` | `10.50.200.7:1433` | Egress packet queued onto internal interface | `diagnose sniffer packet port2` |
| **10** | L3 | Spoke Subnet UDR | `198.51.100.133:51944` | `10.50.200.7:1433` | Azure User Defined Route forwards packet across peered VNet | Effective Route Table (Azure Portal) |
| **11** | L4-L7 | Host OS (`PROD-DB01`) | `198.51.100.133:51944` | `10.50.200.7:1433` | SQL Server listening daemon receives TDS authentication request | `ERRORLOG2`, Memory Netstat table |

---

## 3. Kernel PoC & Smoking Gun Evidence

Live extraction from FortiOS kernel iprope table confirmed direct live flows through Policy 28:

```bash
Cloud-Edge-FW01 # diagnose firewall iprope show 100004 999
-- Policy 28 (Inbound-Access) Active Flow Counters --
index=28 pkts=10 bytes=460 hits=5 (in 2 seconds)
srcintf=port1 dstintf=port2 action=accept
```

This confirmed conclusively that Policy 28 was actively accepting inbound internet traffic across all ports and pushing it directly to the internal database tier.
