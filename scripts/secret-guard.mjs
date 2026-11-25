#!/usr/bin/env node
/**
 * NetOps Copilot — PreToolUse Security Guard Hook
 *
 * Reads PreToolUse event JSON from stdin, checks for:
 *  1. Hardcoded private keys / cloud & API secrets in file edits or commands
 *  2. Catastrophic or high-risk network/filesystem commands
 *
 * Always exits 0 and prints a JSON decision to stdout.
 */

import fs from "node:fs";

const SECRET_PATTERNS = [
  { name: "Private Key Block", regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/ },
  { name: "AWS Access Key ID", regex: /\bAKIA[0-9A-Z]{16}\b/ },
  { name: "GitHub Personal Access Token", regex: /\bgh[pousr]_[A-Za-z0-9_]{36,}\b/ },
  { name: "Slack Token", regex: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/ },
  { name: "Google API Key", regex: /\bAIza[0-9A-Za-z\-_]{35}\b/ },
];

const DENY_COMMAND_PATTERNS = [
  {
    name: "Root filesystem wipe",
    regex: /\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r)\s+(\/|\*|~\/?)\s*$/,
  },
  {
    name: "Firewall flush without policy safeguard",
    regex: /\b(iptables|nft)\s+(-F|--flush|flush\s+ruleset)\b/,
  },
];

const ASK_COMMAND_PATTERNS = [
  {
    name: "Force push to main/master",
    regex: /\bgit\s+push\b.*(--force|-f)\b.*\b(main|master)\b/,
  },
  {
    name: "Pipe remote script directly to shell",
    regex: /\b(curl|wget)\b[^|]*\|\s*(ba)?sh\b/,
  },
];

function respond(obj) {
  process.stdout.write(`${JSON.stringify(obj)}\n`);
  process.exit(0);
}

try {
  const raw = fs.readFileSync(0, "utf8").trim();
  if (!raw) respond({});

  const event = JSON.parse(raw);
  const toolName = String(event.tool_name || event.toolName || event.name || "");
  const args = event.tool_input || event.toolInput || event.arguments || event.input || {};

  // Check shell commands
  if (toolName === "run_command" || typeof args.CommandLine === "string" || typeof args.command === "string") {
    const cmd = String(args.CommandLine || args.command || "");
    for (const rule of DENY_COMMAND_PATTERNS) {
      if (rule.regex.test(cmd)) {
        respond({
          decision: "deny",
          reason: `[NetOps Guard] Blocked dangerous command (${rule.name}).`,
        });
      }
    }
    for (const rule of ASK_COMMAND_PATTERNS) {
      if (rule.regex.test(cmd)) {
        respond({
          decision: "ask",
          reason: `[NetOps Guard] High-risk command detected (${rule.name}). Please confirm before executing.`,
        });
      }
    }
  }

  // Check written/edited file content for leaked secrets
  const contentToScan = [
    args.CodeContent,
    args.ReplacementContent,
    args.content,
    args.new_string,
  ]
    .filter((v) => typeof v === "string")
    .join("\n");

  if (contentToScan) {
    for (const secret of SECRET_PATTERNS) {
      if (secret.regex.test(contentToScan)) {
        respond({
          decision: "deny",
          reason: `[NetOps Guard] Detected potential hardcoded secret (${secret.name}). Use environment variables or a secret manager instead.`,
        });
      }
    }
  }

  respond({});
} catch {
  // Fail open on unexpected input format
  respond({});
}
