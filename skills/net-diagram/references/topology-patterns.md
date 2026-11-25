# Network Topology Mermaid Patterns

## Syntax Safety Rules
- Always use `flowchart LR` or `flowchart TD`.
- Always quote labels with special characters: `NODE["Web Server (10.10.1.10/24)"]`.
- Never use raw HTML tags inside Mermaid labels.
- Use `(["..."])` for external clouds/Internet, `["..."]` for routers/firewalls/servers, and `[("...")]` for databases.

## Pattern 1: Enterprise Perimeter + Segmented VLANs
```mermaid
flowchart LR
    INET(["Internet"]) -->|"HTTPS 443 / IPsec"| FW["Perimeter Firewall"]

    subgraph DMZ["DMZ - VLAN 10 (10.10.10.0/24)"]
        RP["Reverse Proxy / WAF"]
    end

    subgraph LAN["Corporate LAN - VLAN 20 (10.10.20.0/24)"]
        USR["User Workstations"]
    end

    subgraph SRV["App & Data - VLAN 30 (10.10.30.0/24)"]
        APP["App Server"]
        DB[("Database")]
    end

    subgraph MGMT["Management - VLAN 99 (10.10.99.0/24)"]
        BASTION["Jump Host / Bastion"]
    end

    FW -->|"HTTPS 443"| RP
    RP -->|"TLS 8443"| APP
    APP -->|"SQL 1433"| DB
    USR -->|"HTTPS 443"| FW
    BASTION -->|"SSH 22 / HTTPS"| FW
```

## Pattern 2: Hub-and-Spoke Cloud / Site-to-Site VPN
```mermaid
flowchart TD
    HQ["HQ Firewall (10.0.0.0/16)"] <-->|"IPsec VPN"| HUB["Transit / Hub VPC (10.100.0.0/16)"]
    BRANCH["Branch Office (10.1.0.0/16)"] <-->|"IPsec VPN"| HUB
    HUB -->|"Peering"| PROD["Prod Spoke (10.101.0.0/16)"]
    HUB -->|"Peering"| DEV["Dev Spoke (10.102.0.0/16)"]
```
