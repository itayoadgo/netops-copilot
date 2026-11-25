---
trigger: glob
globs: "**/*.tf, **/*.tfvars, **/*.conf, **/*.cfg, **/*firewall*, **/*nginx*"
description: Network and infrastructure security hardening standards for firewall, Terraform, and proxy configs
---

- Never allow `0.0.0.0/0` or `::/0` ingress on management or database ports (`22`, `23`, `445`, `1433`, `3306`, `3389`, `5432`, `6379`, `27017`) without an explicit documented waiver.
- Always prefer explicit least-privilege CIDR ranges and named security groups over wildcard rules.
- Enforce TLS 1.2+ and disable cleartext protocols (`Telnet`, `FTP`, unencrypted `HTTP` admin interfaces) in proxy and device configurations.
- Require explicit logging on perimeter allow and deny policies for auditability and incident response.
