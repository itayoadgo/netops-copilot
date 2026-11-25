---
name: subnet-plan
description: >-
  Calculate exact IPv4 CIDR details, design optimal VLSM subnet allocations from a
  supernet, and check for CIDR overlaps. Use when the user asks to split a subnet,
  plan VLAN IP addressing, calculate netmasks/host ranges, or validate an IP plan.
---

# CIDR & VLSM Subnet Planner (`/subnet-plan`)

Design accurate, conflict-free IPv4 addressing plans using deterministic MCP calculations rather than mental math.

## Workflow

1. **Always compute via bundled MCP tools**:
   - Single CIDR details -> call `calculate_subnet`.
   - Dividing a supernet across VLANs/departments -> call `split_subnet_vlsm` with `{ baseCidr, requirements: [{ name, hosts }] }`.
   - Validating an existing IP plan -> call `check_cidr_overlaps`.

2. **Add practical NetOps recommendations**:
   - Reserve room for growth (suggest ~20–30% headroom if the user gave exact current host counts).
   - Note gateway conventions (typically first usable `.1` or last usable IP) and DHCP pool vs. static reservation ranges.
   - Recommend clean VLAN ID alignment (e.g., VLAN 10 -> `10.x.10.0/24`) when feasible.

3. **Output format**:
   - Present a crisp Markdown table: **Segment / VLAN**, **CIDR**, **Subnet Mask**, **Usable Range**, **Gateway (Suggested)**, **Usable Hosts**, **Utilization %**.
   - Show remaining unallocated address space and next free IP for future expansion.
   - Respond in the user's language (Hebrew or English).
