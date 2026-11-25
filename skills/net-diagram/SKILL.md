---
name: net-diagram
description: >-
  Generate a clean, segmented network topology diagram (Mermaid) with subnet/VLAN
  grouping, port and protocol labels, a summary table, and automatic security risk
  highlights. Use when the user asks to draw, map, or visualize a network, firewall
  architecture, VLAN layout, cloud VPC, or Docker/Terraform topology.
---

# Network Topology Diagram (`/net-diagram`)

Convert plain-language descriptions, firewall/router configs, IP plans, Terraform files, or Docker Compose files into a clear, accurate network topology diagram.

## Workflow

1. **Extract network entities**:
   - Identify external/untrusted zones (Internet, WAN, Partner VPNs, Remote Users).
   - Identify security boundaries (Firewalls, WAF, Load Balancers, NAT Gateways, Bastion/Jump hosts).
   - Identify internal segments (DMZ, Corporate LAN, Servers, Databases, Management/OOB, Guest Wi-Fi, Cloud VPCs/Subnets) with their VLAN IDs and CIDR blocks.
   - Identify traffic flows with protocols and ports (e.g., `HTTPS 443`, `IPsec IKEv2`, `SQL 1433`, `SSH 22`).

2. **Verify subnet math (when CIDRs are provided)**:
   - Call the bundled MCP tool `check_cidr_overlaps` if 2+ CIDRs are mentioned, so any accidental IP overlap is flagged immediately.
   - Call `calculate_subnet` if the user asks for host ranges or masks.

3. **Build the Mermaid diagram**:
   - Consult `references/topology-patterns.md` for clean Mermaid structure and syntax rules.
   - Use `flowchart LR` (or `flowchart TD` for deep tiered architectures).
   - Group each VLAN/Zone/VPC inside a labeled `subgraph`.
   - Always quote node labels containing parentheses, slashes, or brackets (e.g., `FW["Core Firewall (FortiGate)"]`).
   - Label every edge with protocol/port (e.g., `-->|"HTTPS 443"|`).
   - Highlight risky or unencrypted paths clearly (e.g., dashed edge `-.->|"RISK: Cleartext Telnet 23"|`).

4. **Include a concise summary & security check**:
   - Provide a **Zones & Subnets Table** (Zone, VLAN, CIDR, Purpose).
   - Provide a **Security Observations** section calling out segmentation gaps (e.g., DMZ talking directly to Management, unencrypted protocols, missing jump host, or overlapping CIDRs).
   - Respond in the user's language (Hebrew or English).
