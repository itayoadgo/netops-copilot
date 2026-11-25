#!/usr/bin/env node
/**
 * NetOps Copilot — Zero-Dependency Offline MCP Server (stdio JSON-RPC 2.0)
 *
 * Tools:
 *  - calculate_subnet: Exact IPv4 CIDR calculations
 *  - check_cidr_overlaps: Detects duplicates, containment, and overlaps across CIDRs
 *  - split_subnet_vlsm: Optimal VLSM subnet allocation from a base CIDR
 *  - audit_firewall_rules: Deterministic firewall rule risk & shadow audit
 *  - defang_iocs: Extracts and safely defangs IPs, URLs, domains, and hashes
 */

import readline from "node:readline";

const SERVER_INFO = {
  name: "netops-copilot-nettools",
  version: "1.0.0",
};

const PROTOCOL_VERSION = "2024-11-05";

// ---------------------------------------------------------------------------
// IPv4 / CIDR Utilities
// ---------------------------------------------------------------------------

function ipToInt(ip) {
  const parts = ip.trim().split(".");
  if (parts.length !== 4) {
    throw new Error(`Invalid IPv4 address: "${ip}"`);
  }
  let value = 0;
  for (const part of parts) {
    if (!/^\d+$/.test(part)) {
      throw new Error(`Invalid IPv4 octet "${part}" in "${ip}"`);
    }
    const num = Number(part);
    if (num < 0 || num > 255) {
      throw new Error(`IPv4 octet out of range (0-255) in "${ip}"`);
    }
    value = (value * 256) + num;
  }
  return value >>> 0;
}

function intToIp(num) {
  const n = num >>> 0;
  return [
    (n >>> 24) & 255,
    (n >>> 16) & 255,
    (n >>> 8) & 255,
    n & 255,
  ].join(".");
}

function parseCidr(cidrStr) {
  const trimmed = String(cidrStr || "").trim();
  const [ipPart, prefixPart] = trimmed.split("/");
  if (!ipPart || prefixPart === undefined || !/^\d+$/.test(prefixPart)) {
    throw new Error(`Invalid CIDR notation: "${cidrStr}" (expected e.g. 10.10.0.0/24)`);
  }
  const prefix = Number(prefixPart);
  if (prefix < 0 || prefix > 32) {
    throw new Error(`CIDR prefix out of range (0-32): "${cidrStr}"`);
  }
  const ipInt = ipToInt(ipPart);
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  const wildcard = (~mask) >>> 0;
  const network = (ipInt & mask) >>> 0;
  const broadcast = (network | wildcard) >>> 0;
  const totalAddresses = Math.pow(2, 32 - prefix);

  let usableHosts;
  let firstHost;
  let lastHost;

  if (prefix === 32) {
    usableHosts = 1;
    firstHost = intToIp(network);
    lastHost = intToIp(network);
  } else if (prefix === 31) {
    // RFC 3021 point-to-point link
    usableHosts = 2;
    firstHost = intToIp(network);
    lastHost = intToIp(broadcast);
  } else {
    usableHosts = Math.max(0, totalAddresses - 2);
    firstHost = intToIp((network + 1) >>> 0);
    lastHost = intToIp((broadcast - 1) >>> 0);
  }

  return {
    input: trimmed,
    normalizedCidr: `${intToIp(network)}/${prefix}`,
    prefix,
    networkInt: network,
    broadcastInt: broadcast,
    networkAddress: intToIp(network),
    broadcastAddress: intToIp(broadcast),
    netmask: intToIp(mask),
    wildcardMask: intToIp(wildcard),
    firstUsableHost: firstHost,
    lastUsableHost: lastHost,
    totalAddresses,
    usableHosts,
    classification: classifyIpv4(network),
  };
}

function classifyIpv4(ipInt) {
  const a = (ipInt >>> 24) & 255;
  const b = (ipInt >>> 16) & 255;
  if (a === 10) return "Private (RFC 1918 — 10.0.0.0/8)";
  if (a === 172 && b >= 16 && b <= 31) return "Private (RFC 1918 — 172.16.0.0/12)";
  if (a === 192 && b === 168) return "Private (RFC 1918 — 192.168.0.0/16)";
  if (a === 100 && b >= 64 && b <= 127) return "Shared / CGNAT (RFC 6598 — 100.64.0.0/10)";
  if (a === 127) return "Loopback (127.0.0.0/8)";
  if (a === 169 && b === 254) return "Link-Local / APIPA (169.254.0.0/16)";
  if (a >= 224 && a <= 239) return "Multicast (224.0.0.0/4)";
  if (a >= 240) return "Reserved (240.0.0.0/4)";
  if (a === 0) return "Unspecified / Default (0.0.0.0/8)";
  return "Public Routable IPv4";
}

function calculateSubnetTool({ cidr }) {
  const info = parseCidr(cidr);
  return {
    input: info.input,
    normalizedCidr: info.normalizedCidr,
    networkAddress: info.networkAddress,
    broadcastAddress: info.broadcastAddress,
    netmask: info.netmask,
    wildcardMask: info.wildcardMask,
    firstUsableHost: info.firstUsableHost,
    lastUsableHost: info.lastUsableHost,
    totalAddresses: info.totalAddresses,
    usableHosts: info.usableHosts,
    classification: info.classification,
  };
}

function checkCidrOverlapsTool({ cidrs }) {
  if (!Array.isArray(cidrs) || cidrs.length === 0) {
    throw new Error("cidrs must be a non-empty array of CIDR strings");
  }
  const parsed = cidrs.map((c, index) => ({ index, ...parseCidr(c) }));
  const conflicts = [];

  for (let i = 0; i < parsed.length; i++) {
    for (let j = i + 1; j < parsed.length; j++) {
      const a = parsed[i];
      const b = parsed[j];
      const overlaps = a.networkInt <= b.broadcastInt && b.networkInt <= a.broadcastInt;
      if (overlaps) {
        let relation = "partial_overlap";
        if (a.networkInt === b.networkInt && a.broadcastInt === b.broadcastInt) {
          relation = "exact_duplicate";
        } else if (a.networkInt <= b.networkInt && a.broadcastInt >= b.broadcastInt) {
          relation = `${a.normalizedCidr} contains ${b.normalizedCidr}`;
        } else if (b.networkInt <= a.networkInt && b.broadcastInt >= a.broadcastInt) {
          relation = `${b.normalizedCidr} contains ${a.normalizedCidr}`;
        }
        conflicts.push({
          cidrA: a.normalizedCidr,
          cidrB: b.normalizedCidr,
          relation,
        });
      }
    }
  }

  return {
    checkedCount: parsed.length,
    hasOverlaps: conflicts.length > 0,
    conflictCount: conflicts.length,
    conflicts,
  };
}

function splitSubnetVlsmTool({ baseCidr, requirements }) {
  const base = parseCidr(baseCidr);
  if (!Array.isArray(requirements) || requirements.length === 0) {
    throw new Error("requirements must be a non-empty array of { name, hosts }");
  }

  // Sort largest host requirement first (standard VLSM best practice)
  const sorted = requirements
    .map((req, idx) => {
      const hosts = Number(req.hosts);
      if (!Number.isInteger(hosts) || hosts < 1) {
        throw new Error(`Requirement #${idx + 1} (${req.name || "unnamed"}) must have hosts >= 1`);
      }
      // Determine smallest prefix that fits `hosts`
      let prefix;
      if (hosts === 1) {
        prefix = 32;
      } else if (hosts === 2) {
        // Use /30 by default for general subnets (2 usable + net + bcast)
        prefix = 30;
      } else {
        const neededAddresses = hosts + 2;
        const bits = Math.ceil(Math.log2(neededAddresses));
        prefix = 32 - bits;
      }
      const blockSize = Math.pow(2, 32 - prefix);
      return {
        name: String(req.name || `Subnet-${idx + 1}`),
        requestedHosts: hosts,
        prefix,
        blockSize,
      };
    })
    .sort((a, b) => b.blockSize - a.blockSize);

  const allocations = [];
  let cursor = base.networkInt;

  for (const item of sorted) {
    // Align cursor to item.blockSize boundary
    const remainder = cursor % item.blockSize;
    if (remainder !== 0) {
      cursor += item.blockSize - remainder;
    }
    const end = cursor + item.blockSize - 1;
    if (end > base.broadcastInt) {
      throw new Error(
        `Insufficient address space in ${base.normalizedCidr} to allocate "${item.name}" (${item.requestedHosts} hosts -> /${item.prefix})`
      );
    }
    const detail = parseCidr(`${intToIp(cursor)}/${item.prefix}`);
    allocations.push({
      name: item.name,
      requestedHosts: item.requestedHosts,
      cidr: detail.normalizedCidr,
      netmask: detail.netmask,
      firstUsableHost: detail.firstUsableHost,
      lastUsableHost: detail.lastUsableHost,
      broadcastAddress: detail.broadcastAddress,
      usableHosts: detail.usableHosts,
      utilizationPercent: Number(((item.requestedHosts / detail.usableHosts) * 100).toFixed(1)),
    });
    cursor = end + 1;
  }

  const remainingAddresses = base.broadcastInt - cursor + 1;
  return {
    baseCidr: base.normalizedCidr,
    totalBaseAddresses: base.totalAddresses,
    allocatedSubnets: allocations,
    nextFreeIp: remainingAddresses > 0 ? intToIp(cursor) : null,
    remainingAddresses,
  };
}

// ---------------------------------------------------------------------------
// Firewall Rule Auditor
// ---------------------------------------------------------------------------

const HIGH_RISK_PORTS = {
  21: { service: "FTP", risk: "Cleartext file transfer & credentials" },
  22: { service: "SSH", risk: "Remote administration exposed" },
  23: { service: "Telnet", risk: "Unencrypted remote administration" },
  25: { service: "SMTP", risk: "Open mail relay / spam abuse risk" },
  53: { service: "DNS", risk: "DNS amplification / zone transfer risk" },
  135: { service: "MS-RPC", risk: "Lateral movement / Windows RPC exposure" },
  139: { service: "NetBIOS", risk: "Legacy Windows file sharing exposure" },
  161: { service: "SNMP", risk: "Network device enumeration / amplification" },
  389: { service: "LDAP", risk: "Unencrypted directory access" },
  445: { service: "SMB", risk: "Ransomware / lateral movement primary vector" },
  1433: { service: "MSSQL", risk: "Database port exposed" },
  1521: { service: "Oracle DB", risk: "Database port exposed" },
  2375: { service: "Docker API (Unencrypted)", risk: "Full container host takeover" },
  3306: { service: "MySQL/MariaDB", risk: "Database port exposed" },
  3389: { service: "RDP", risk: "Primary brute-force & ransomware entry vector" },
  5432: { service: "PostgreSQL", risk: "Database port exposed" },
  5900: { service: "VNC", risk: "Weak/unencrypted remote desktop" },
  6379: { service: "Redis", risk: "Unauthenticated in-memory DB exposure" },
  9200: { service: "Elasticsearch", risk: "Data exfiltration / unauthenticated API" },
  27017: { service: "MongoDB", risk: "Database port exposed" },
};

function isAnyValue(val) {
  const s = String(val || "").trim().toLowerCase();
  return s === "any" || s === "*" || s === "all" || s === "0.0.0.0/0" || s === "::/0" || s === "internet";
}

function parsePorts(portField) {
  if (portField === undefined || portField === null) return { isAny: true, ports: [] };
  const s = String(portField).trim().toLowerCase();
  if (isAnyValue(s) || s === "1-65535" || s === "0-65535") {
    return { isAny: true, ports: [] };
  }
  const ports = new Set();
  for (const token of s.split(/[,\s]+/).filter(Boolean)) {
    const rangeMatch = token.match(/^(\d+)-(\d+)$/);
    if (rangeMatch) {
      const start = Number(rangeMatch[1]);
      const end = Number(rangeMatch[2]);
      if (end - start > 1000) {
        return { isAny: true, ports: [] };
      }
      for (let p = start; p <= end; p++) ports.add(p);
    } else if (/^\d+$/.test(token)) {
      ports.add(Number(token));
    }
  }
  return { isAny: false, ports: [...ports] };
}

function auditFirewallRulesTool({ rules }) {
  if (!Array.isArray(rules) || rules.length === 0) {
    throw new Error("rules must be a non-empty array of firewall rule objects");
  }

  const findings = [];
  const seenSignatures = new Map();

  rules.forEach((rule, idx) => {
    const id = String(rule.id || rule.name || `Rule-${idx + 1}`);
    const action = String(rule.action || "allow").trim().toLowerCase();
    const src = String(rule.source || "any").trim();
    const dst = String(rule.destination || "any").trim();
    const proto = String(rule.protocol || "any").trim().toLowerCase();
    const portInfo = parsePorts(rule.port ?? rule.ports ?? "any");

    if (action !== "allow" && action !== "accept" && action !== "permit") {
      return;
    }

    const srcAny = isAnyValue(src);
    const dstAny = isAnyValue(dst);

    // 1. Any-Any-Any check
    if (srcAny && dstAny && portInfo.isAny) {
      findings.push({
        ruleId: id,
        severity: "CRITICAL",
        category: "ANY_ANY_ALLOW",
        message: `Rule "${id}" allows ANY source to ANY destination on ANY port (${proto}).`,
        recommendation: "Restrict source, destination, and specific service ports following Least Privilege.",
      });
    } else if (srcAny && portInfo.isAny) {
      findings.push({
        ruleId: id,
        severity: "HIGH",
        category: "WIDE_PORT_EXPOSURE",
        message: `Rule "${id}" allows ANY source (${src}) to ${dst} on ALL ports.`,
        recommendation: "Limit exposed ports to only required application services.",
      });
    }

    // 2. High-risk ports exposed from Any / Internet
    if (srcAny && !portInfo.isAny) {
      for (const p of portInfo.ports) {
        if (HIGH_RISK_PORTS[p]) {
          const meta = HIGH_RISK_PORTS[p];
          findings.push({
            ruleId: id,
            severity: [23, 445, 2375, 3389, 6379].includes(p) ? "CRITICAL" : "HIGH",
            category: "RISKY_PUBLIC_PORT",
            message: `Rule "${id}" exposes port ${p} (${meta.service}) to ${src} -> ${dst}. Risk: ${meta.risk}.`,
            recommendation: `Restrict port ${p} to a VPN, Bastion/Jump host, or explicit management CIDR.`,
          });
        }
      }
    }

    // 3. Unencrypted legacy protocols even internally
    if (!srcAny && !portInfo.isAny) {
      for (const p of portInfo.ports) {
        if (p === 23 || p === 21 || p === 2375) {
          const meta = HIGH_RISK_PORTS[p];
          findings.push({
            ruleId: id,
            severity: "MEDIUM",
            category: "CLEARTEXT_PROTOCOL",
            message: `Rule "${id}" permits insecure protocol port ${p} (${meta.service}) internally (${src} -> ${dst}).`,
            recommendation: "Replace with encrypted alternative (SSH/SFTP/TLS).",
          });
        }
      }
    }

    // 4. Duplicate rule detection
    const sig = `${action}|${src.toLowerCase()}|${dst.toLowerCase()}|${proto}|${String(rule.port ?? rule.ports ?? "any").toLowerCase()}`;
    if (seenSignatures.has(sig)) {
      findings.push({
        ruleId: id,
        severity: "LOW",
        category: "DUPLICATE_RULE",
        message: `Rule "${id}" duplicates earlier rule "${seenSignatures.get(sig)}".`,
        recommendation: "Remove redundant rule to keep the policy table clean and maintainable.",
      });
    } else {
      seenSignatures.set(sig, id);
    }
  });

  const summary = {
    totalRulesAnalyzed: rules.length,
    critical: findings.filter((f) => f.severity === "CRITICAL").length,
    high: findings.filter((f) => f.severity === "HIGH").length,
    medium: findings.filter((f) => f.severity === "MEDIUM").length,
    low: findings.filter((f) => f.severity === "LOW").length,
  };

  return { summary, findings };
}

// ---------------------------------------------------------------------------
// IOC Extractor & Defanger
// ---------------------------------------------------------------------------

function defangIocsTool({ text }) {
  const input = String(text || "");
  const ipv4Regex = /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g;
  const urlRegex = /\bhttps?:\/\/[^\s"'<>)\]]+/gi;
  const sha256Regex = /\b[a-fA-F0-9]{64}\b/g;
  const sha1Regex = /\b[a-fA-F0-9]{40}\b/g;
  const md5Regex = /\b[a-fA-F0-9]{32}\b/g;

  const unique = (arr) => [...new Set(arr || [])];

  const rawIps = unique(input.match(ipv4Regex));
  const rawUrls = unique(input.match(urlRegex));
  const sha256 = unique(input.match(sha256Regex));
  const sha1 = unique(input.match(sha1Regex)).filter((h) => !sha256.some((s) => s.includes(h)));
  const md5 = unique(input.match(md5Regex)).filter(
    (h) => !sha256.some((s) => s.includes(h)) && !sha1.some((s) => s.includes(h))
  );

  const defangIp = (ip) => ip.replace(/\./g, "[.]");
  const defangUrl = (u) =>
    u
      .replace(/^https:\/\//i, "hxxps://")
      .replace(/^http:\/\//i, "hxxp://")
      .replace(/\./g, "[.]");

  return {
    ipv4: rawIps.map((ip) => ({
      defanged: defangIp(ip),
      classification: classifyIpv4(ipToInt(ip)),
    })),
    urls: rawUrls.map((u) => ({ defanged: defangUrl(u) })),
    hashes: { sha256, sha1, md5 },
  };
}

// ---------------------------------------------------------------------------
// MCP Tool Definitions & JSON-RPC 2.0 Transport
// ---------------------------------------------------------------------------

const TOOLS = [
  {
    name: "calculate_subnet",
    description:
      "Calculate exact IPv4 CIDR details (network, broadcast, netmask, wildcard, first/last host, usable host count, and RFC1918/public classification).",
    inputSchema: {
      type: "object",
      properties: {
        cidr: { type: "string", description: "IPv4 CIDR block, e.g. '10.10.20.0/24'" },
      },
      required: ["cidr"],
    },
  },
  {
    name: "check_cidr_overlaps",
    description:
      "Check a list of IPv4 CIDR blocks for exact duplicates, containment, or overlapping address ranges.",
    inputSchema: {
      type: "object",
      properties: {
        cidrs: {
          type: "array",
          items: { type: "string" },
          description: "Array of IPv4 CIDR strings to check for overlaps",
        },
      },
      required: ["cidrs"],
    },
  },
  {
    name: "split_subnet_vlsm",
    description:
      "Allocate optimal VLSM (Variable Length Subnet Mask) subnets from a base IPv4 CIDR given named host count requirements.",
    inputSchema: {
      type: "object",
      properties: {
        baseCidr: { type: "string", description: "Supernet CIDR to divide, e.g. '10.20.0.0/22'" },
        requirements: {
          type: "array",
          description: "List of subnet requirements with name and required usable host count",
          items: {
            type: "object",
            properties: {
              name: { type: "string" },
              hosts: { type: "integer", minimum: 1 },
            },
            required: ["name", "hosts"],
          },
        },
      },
      required: ["baseCidr", "requirements"],
    },
  },
  {
    name: "audit_firewall_rules",
    description:
      "Deterministically audit structured firewall or security group rules for Any-Any exposures, high-risk public ports (SSH/RDP/SMB/DB), cleartext protocols, and duplicates.",
    inputSchema: {
      type: "object",
      properties: {
        rules: {
          type: "array",
          items: {
            type: "object",
            properties: {
              id: { type: "string" },
              action: { type: "string", description: "allow, deny, accept, drop, etc." },
              source: { type: "string" },
              destination: { type: "string" },
              protocol: { type: "string" },
              port: { type: "string", description: "Port, comma-separated ports, range, or 'any'" },
            },
          },
        },
      },
      required: ["rules"],
    },
  },
  {
    name: "defang_iocs",
    description:
      "Extract and safely defang IPv4 addresses, URLs, and MD5/SHA1/SHA256 hashes from raw logs or text for incident reports.",
    inputSchema: {
      type: "object",
      properties: {
        text: { type: "string", description: "Raw log snippet or text containing IOCs" },
      },
      required: ["text"],
    },
  },
];

function sendMessage(msg) {
  process.stdout.write(`${JSON.stringify(msg)}\n`);
}

function handleRequest(req) {
  const { id, method, params } = req;

  if (method === "notifications/initialized") {
    return;
  }

  if (method === "initialize") {
    sendMessage({
      jsonrpc: "2.0",
      id,
      result: {
        protocolVersion: PROTOCOL_VERSION,
        capabilities: { tools: {} },
        serverInfo: SERVER_INFO,
      },
    });
    return;
  }

  if (method === "ping") {
    sendMessage({ jsonrpc: "2.0", id, result: {} });
    return;
  }

  if (method === "tools/list") {
    sendMessage({
      jsonrpc: "2.0",
      id,
      result: { tools: TOOLS },
    });
    return;
  }

  if (method === "tools/call") {
    const toolName = params?.name;
    const args = params?.arguments || {};
    try {
      let data;
      switch (toolName) {
        case "calculate_subnet":
          data = calculateSubnetTool(args);
          break;
        case "check_cidr_overlaps":
          data = checkCidrOverlapsTool(args);
          break;
        case "split_subnet_vlsm":
          data = splitSubnetVlsmTool(args);
          break;
        case "audit_firewall_rules":
          data = auditFirewallRulesTool(args);
          break;
        case "defang_iocs":
          data = defangIocsTool(args);
          break;
        default:
          sendMessage({
            jsonrpc: "2.0",
            id,
            error: { code: -32601, message: `Unknown tool: ${toolName}` },
          });
          return;
      }

      sendMessage({
        jsonrpc: "2.0",
        id,
        result: {
          content: [{ type: "text", text: JSON.stringify(data, null, 2) }],
        },
      });
    } catch (err) {
      sendMessage({
        jsonrpc: "2.0",
        id,
        result: {
          isError: true,
          content: [{ type: "text", text: `Error: ${err.message}` }],
        },
      });
    }
    return;
  }

  if (id !== undefined) {
    sendMessage({
      jsonrpc: "2.0",
      id,
      error: { code: -32601, message: `Method not found: ${method}` },
    });
  }
}

const rl = readline.createInterface({
  input: process.stdin,
  crlfDelay: Infinity,
});

rl.on("line", (line) => {
  const trimmed = line.trim();
  if (!trimmed) return;
  try {
    const msg = JSON.parse(trimmed);
    handleRequest(msg);
  } catch (err) {
    sendMessage({
      jsonrpc: "2.0",
      id: null,
      error: { code: -32700, message: `Parse error: ${err.message}` },
    });
  }
});
