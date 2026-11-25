# NetOps Copilot

**NetOps Copilot** is an offline-first Antigravity plugin built for networking, data communications, and information security workflows — with zero external API dependencies.

## What's Included

### Skills (Slash Commands)
- **`/net-diagram`** — Turn plain-language descriptions, firewall/router configs, IP plans, Terraform, or Docker Compose files into clean Mermaid network topology diagrams with zone segmentation, port labels, and risk highlights.
- **`/audit-fw`** — Audit firewall rules and cloud security groups (FortiGate, Palo Alto, Cisco, AWS SG, Azure NSG, Terraform, CSV/JSON) for `Any-Any` exposures, exposed management/DB ports, shadowed rules, and Least Privilege gaps.
- **`/subnet-plan`** — Design CIDR/VLSM IP addressing plans, verify subnet math deterministically via the bundled MCP server, and detect CIDR overlaps.

### Bundled Local MCP Server (`netops-copilot_nettools`)
Runs 100% locally via Node.js (zero npm dependencies) with 5 deterministic tools:
- `calculate_subnet` — Exact IPv4 CIDR calculations (network, broadcast, netmask, wildcard, host range, usable hosts, RFC1918/special classification).
- `check_cidr_overlaps` — Detects exact duplicates, subnet containment, and overlapping address blocks across a list of CIDRs.
- `split_subnet_vlsm` — Allocates optimal Variable Length Subnet Masks (VLSM) from a base CIDR given named host requirements.
- `audit_firewall_rules` — Deterministic analysis of structured firewall rules for `Any-Any`, high-risk ports exposed to `0.0.0.0/0`, unencrypted management protocols, and shadowed/duplicate rules.
- `defang_iocs` — Extracts and safely defangs IPv4 addresses, URLs, domains, and file hashes for SOC/IR reports.

### Custom Agent / Subagent
- **`netsec-auditor`** — Read-only network & security specialist agent (`mainAgent: true`, `subagent: true`) that audits configs, infrastructure code, and architectures without modifying files.

### Rules & Guardrails
- **`rules/AGENTS.md`** — Always-on networking & InfoSec hygiene (defang malicious IOCs, never hardcode secrets, verify CIDR math via MCP).
- **`rules/infra-security.md`** — Glob-triggered guardrails for `.tf`, `.tfvars`, `.conf`, `.cfg`, firewall, and Nginx configs.
- **`hooks.json` (`netsec-guard`)** — Synchronous `PreToolUse` hook that blocks hardcoded private keys/cloud secrets and warns on destructive shell commands.

## Local Validation & Installation

```bash
agy plugin validate --strict ./netops-copilot
agy plugin install ./netops-copilot
agy plugin list
```
