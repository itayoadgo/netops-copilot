# High-Risk Ports & Hardening Reference

| Port | Protocol / Service | Risk Level (if Public) | Recommended Hardening |
| --- | --- | --- | --- |
| 21 | FTP | Critical / High | Disable; replace with SFTP (22) or HTTPS |
| 22 | SSH | High | Restrict to VPN/Bastion CIDR; disable password auth |
| 23 | Telnet | Critical | Disable immediately; migrate to SSH |
| 135 / 139 / 445 | RPC / NetBIOS / SMB | Critical | Never expose to Internet; segment internally |
| 161 / 162 | SNMP v1/v2c | High | Restrict to NMS IP only; migrate to SNMPv3 |
| 1433 / 1521 / 3306 / 5432 / 27017 | Databases | Critical / High | Private subnet only; allow only App tier IPs |
| 2375 | Docker Daemon (unencrypted) | Critical | Disable TCP 2375 or enforce mTLS (2376) on management net |
| 3389 | RDP | Critical | Never expose to `0.0.0.0/0`; require VPN + MFA + Bastion |
| 5900 | VNC | Critical | Tunnel over SSH/VPN; restrict to management VLAN |
| 6379 / 9200 | Redis / Elasticsearch | Critical | Bind to localhost or private app subnet with auth + TLS |
