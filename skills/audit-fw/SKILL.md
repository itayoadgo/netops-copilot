---
name: audit-fw
description: >-
  Audit firewall rules, ACLs, and cloud security groups (FortiGate, Palo Alto,
  Cisco, AWS SG, Azure NSG, Terraform, CSV/JSON) for Any-Any exposures, high-risk
  public ports, cleartext protocols, and duplicate/shadowed rules. Use when the user
  shares firewall policies or asks for a firewall or security group review.
---

# Firewall & Security Group Audit (`/audit-fw`)

Perform a structured, deterministic security audit on firewall rules or cloud security groups.

## Workflow

1. **Parse the input rules**:
   - Accept pasted CLI configs (FortiGate `config firewall policy`, Palo Alto, Cisco ASA/IOS ACLs, `iptables`), Terraform (`aws_security_group`, `azurerm_network_security_group`), JSON, or CSV/Markdown tables.
   - Normalize each rule into `{ id, action, source, destination, protocol, port }`.

2. **Run deterministic analysis via MCP**:
   - Call the bundled MCP tool `audit_firewall_rules` with the normalized rule list.
   - If the rules include CIDR ranges, also call `check_cidr_overlaps` when relevant.
   - Cross-reference findings with `references/risky-ports.md`.

3. **Check architectural & policy hygiene**:
   - Verify whether an explicit or implicit default-deny cleanup rule exists at the bottom.
   - Flag missing logging on allow/deny rules.
   - Flag overly broad egress (`LAN -> Any` on all ports) that enables C2 or data exfiltration.
   - Flag shadowed rules (a broad rule above a narrower rule that prevents the narrower rule from ever matching).

4. **Present an actionable report**:
   - **Executive Summary**: counts of Critical / High / Medium / Low findings.
   - **Prioritized Findings Table**: Rule ID, Severity, Issue, Exact Fix.
   - **Hardened Config Snippet**: concrete corrected rules ready to apply (following Least Privilege).
   - Respond in the user's language (Hebrew or English).
