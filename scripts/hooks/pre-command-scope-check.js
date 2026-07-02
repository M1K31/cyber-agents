#!/usr/bin/env node
// ===========================================================================
// pre-command-scope-check.js
// ---------------------------------------------------------------------------
// Claude Code PreToolUse Hook — Scope Validator
//
// Intercepts Bash tool invocations that contain offensive commands
// (/scan, nmap, masscan, metasploit, nuclei, etc.), extracts target
// identifiers (IPs, CIDRs, domains), and validates them against
// authorized_scope.json. Aborts the command with a HARD STOP if ANY
// target falls outside the authorized scope.
//
// Integration:
//   Register in hooks/hooks.json under PreToolUse for the "Bash" tool.
//
// References:
//   - rules/safe-harbor.md (scope enforcement)
//   - rules/opsec.md (scan noise classification)
// ===========================================================================

'use strict';

const fs = require('fs');
const path = require('path');
const net = require('net');

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/** Path to the authorized scope definition (relative to project root). */
const SCOPE_FILE = path.resolve(__dirname, '..', 'authorized_scope.json');

/** Commands that trigger scope validation. */
const OFFENSIVE_COMMANDS = [
  'nmap', 'masscan', 'rustscan',               // Scanners
  'msfconsole', 'msfvenom', 'msfdb',           // Metasploit
  'nuclei', 'nikto', 'gobuster', 'ffuf',       // Web scanners
  'hydra', 'medusa', 'patator',                // Brute-forcers
  'sqlmap', 'wpscan',                           // App-specific
  'impacket-psexec', 'impacket-wmiexec',       // Impacket
  'impacket-smbexec', 'impacket-secretsdump',
  'crackmapexec', 'netexec', 'enum4linux',     // AD/SMB
  'curl', 'wget',                               // When used offensively
  'proxychains', 'proxychains4',               // Proxied commands
];

// ---------------------------------------------------------------------------
// Scope Loading
// ---------------------------------------------------------------------------

/**
 * Loads and parses the authorized scope file.
 * @returns {object} Parsed scope config, or null on failure.
 */
function loadScope() {
  try {
    const raw = fs.readFileSync(SCOPE_FILE, 'utf-8');
    return JSON.parse(raw);
  } catch (err) {
    process.stderr.write(
      `[SCOPE-CHECK] ⛔ ABORT: Cannot read scope file: ${SCOPE_FILE}\n` +
      `  Error: ${err.message}\n` +
      `  All offensive operations are blocked until a valid scope file is provided.\n`
    );
    return null;
  }
}

// ---------------------------------------------------------------------------
// IP / CIDR Utilities
// ---------------------------------------------------------------------------

/**
 * Converts an IPv4 address string to a 32-bit integer.
 * @param {string} ip - e.g. "10.0.0.5"
 * @returns {number}
 */
function ipToInt(ip) {
  return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
}

/**
 * Parses a CIDR notation string into { network, broadcast } integers.
 * @param {string} cidr - e.g. "10.0.0.0/24"
 * @returns {{ network: number, broadcast: number }}
 */
function parseCIDR(cidr) {
  const [ip, prefixStr] = cidr.split('/');
  const prefix = parseInt(prefixStr, 10);
  const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
  const network = ipToInt(ip) & mask;
  const broadcast = network | (~mask >>> 0);
  return { network, broadcast };
}

/**
 * Checks whether an IP falls within ANY of the provided CIDR ranges.
 * @param {string} ip - IPv4 address string
 * @param {string[]} cidrList - Array of CIDR strings
 * @returns {boolean}
 */
function ipInCIDRList(ip, cidrList) {
  if (!net.isIPv4(ip)) return false;
  const ipInt = ipToInt(ip);
  for (const cidr of cidrList) {
    const { network, broadcast } = parseCIDR(cidr);
    if (ipInt >= network && ipInt <= broadcast) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Domain Matching
// ---------------------------------------------------------------------------

/**
 * Checks if a domain matches any pattern in the authorized list.
 * Supports wildcard patterns like "*.target.example.com".
 * @param {string} domain - Domain to check
 * @param {string[]} patterns - Array of domain patterns
 * @returns {boolean}
 */
function domainMatchesAny(domain, patterns) {
  const lowerDomain = domain.toLowerCase();
  for (const pattern of patterns) {
    const lowerPattern = pattern.toLowerCase();
    if (lowerPattern.startsWith('*.')) {
      // Wildcard: *.target.example.com matches sub.target.example.com
      const suffix = lowerPattern.slice(1); // ".target.example.com"
      if (lowerDomain.endsWith(suffix) || lowerDomain === lowerPattern.slice(2)) {
        return true;
      }
    } else if (lowerDomain === lowerPattern) {
      return true;
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// Target Extraction from Command Line
// ---------------------------------------------------------------------------

/** Regex to match IPv4 addresses. */
const IPV4_REGEX = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|1?\d{1,2})(?:\/\d{1,2})?\b/g;

/** Regex to match domain names (basic). */
const DOMAIN_REGEX = /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b/g;

/** Patterns to exclude from domain detection (common command flags, file ext). */
const DOMAIN_EXCLUDE = /\.(exe|dll|ps1|sh|py|rb|js|json|xml|txt|csv|md|log|conf|cfg|yar|yml|yaml|ini|bat|vbs|hta|sct|inf|war|jar|zip|gz|tar|elf|bin|raw|pcap|cap)$/i;

/**
 * Extracts target IPs and domains from a command-line string.
 * @param {string} cmdLine - The full command line
 * @returns {{ ips: string[], domains: string[] }}
 */
function extractTargets(cmdLine) {
  const ips = [];
  const domains = [];

  // Extract IPs/CIDRs
  const ipMatches = cmdLine.match(IPV4_REGEX) || [];
  for (const match of ipMatches) {
    ips.push(match);
  }

  // Extract domains (filter out file extensions and common false positives)
  const domainMatches = cmdLine.match(DOMAIN_REGEX) || [];
  for (const match of domainMatches) {
    if (!DOMAIN_EXCLUDE.test(match) && !net.isIPv4(match)) {
      domains.push(match);
    }
  }

  return { ips, domains };
}

// ---------------------------------------------------------------------------
// Engagement Window Validation
// ---------------------------------------------------------------------------

/**
 * Checks whether the current time is within the engagement window.
 * @param {object} engagement - Engagement config from scope file
 * @returns {{ valid: boolean, reason?: string }}
 */
function checkEngagementWindow(engagement) {
  if (!engagement || !engagement.start_date || !engagement.end_date) {
    return { valid: true }; // No window restriction
  }

  const now = new Date();
  const start = new Date(engagement.start_date);
  const end = new Date(engagement.end_date);

  if (now < start) {
    return {
      valid: false,
      reason: `Engagement has not started yet. Start date: ${engagement.start_date}`,
    };
  }
  if (now > end) {
    return {
      valid: false,
      reason: `Engagement has expired. End date: ${engagement.end_date}`,
    };
  }

  return { valid: true };
}

/**
 * Checks whether the current time falls within permitted testing hours.
 * @param {object} testingHours - Testing hours config from scope file
 * @returns {{ valid: boolean, reason?: string }}
 */
function checkTestingHours(testingHours) {
  if (!testingHours || !testingHours.enabled) {
    return { valid: true }; // No hour restriction
  }

  const now = new Date();
  const currentHour = now.getUTCHours();
  const { start_hour, end_hour } = testingHours;

  let inWindow;
  if (start_hour < end_hour) {
    // e.g., 09-17 (daytime)
    inWindow = currentHour >= start_hour && currentHour < end_hour;
  } else {
    // e.g., 22-06 (overnight)
    inWindow = currentHour >= start_hour || currentHour < end_hour;
  }

  if (!inWindow) {
    return {
      valid: false,
      reason: `Testing is restricted to ${start_hour}:00–${end_hour}:00 UTC. Current: ${currentHour}:00 UTC.`,
    };
  }

  return { valid: true };
}

// ---------------------------------------------------------------------------
// Main Scope Validation
// ---------------------------------------------------------------------------

/**
 * Validates all extracted targets against the authorized scope.
 * @param {string[]} ips - Extracted IPs/CIDRs from command
 * @param {string[]} domains - Extracted domains from command
 * @param {object} scope - Parsed scope config
 * @returns {{ allowed: boolean, violations: string[] }}
 */
function validateTargets(ips, domains, scope) {
  const violations = [];
  const authorizedIPs = scope.authorized_targets.ip_ranges || [];
  const excludedIPs = scope.excluded_targets.ip_ranges || [];
  const authorizedDomains = scope.authorized_targets.domains || [];
  const excludedDomains = scope.excluded_targets.domains || [];

  // --- Validate IPs ---
  for (const raw of ips) {
    const ip = raw.includes('/') ? raw.split('/')[0] : raw;

    // Check exclusion first (takes precedence)
    if (ipInCIDRList(ip, excludedIPs)) {
      violations.push(`⛔ IP ${raw} is EXPLICITLY EXCLUDED from scope`);
      continue;
    }

    // Check authorization
    if (!ipInCIDRList(ip, authorizedIPs)) {
      violations.push(`⛔ IP ${raw} is NOT in any authorized IP range`);
    }
  }

  // --- Validate domains ---
  for (const domain of domains) {
    // Check exclusion first
    if (domainMatchesAny(domain, excludedDomains)) {
      violations.push(`⛔ Domain ${domain} is EXPLICITLY EXCLUDED from scope`);
      continue;
    }

    // Check authorization
    if (!domainMatchesAny(domain, authorizedDomains)) {
      violations.push(`⛔ Domain ${domain} is NOT in any authorized domain pattern`);
    }
  }

  return {
    allowed: violations.length === 0,
    violations,
  };
}

// ---------------------------------------------------------------------------
// Hook Entry Point
// ---------------------------------------------------------------------------

/**
 * Main hook function — reads tool input from stdin (Claude Code passes
 * the tool name and input as JSON on stdin for PreToolUse hooks).
 */
async function main() {
  // Read stdin (Claude Code pipes tool invocation JSON)
  const chunks = [];
  for await (const chunk of process.stdin) {
    chunks.push(chunk);
  }
  const input = Buffer.concat(chunks).toString('utf-8').trim();

  let toolInput;
  try {
    toolInput = JSON.parse(input);
  } catch {
    // If stdin isn't valid JSON, treat the raw string as the command
    toolInput = { tool_input: { command: input } };
  }

  const command = toolInput.tool_input?.command || toolInput.command || '';

  if (!command) {
    // No command to check — allow
    process.stdout.write(JSON.stringify({ decision: 'allow' }));
    return;
  }

  // Check if this command contains an offensive tool invocation
  const cmdLower = command.toLowerCase();
  const isOffensive = OFFENSIVE_COMMANDS.some((tool) =>
    cmdLower.includes(tool.toLowerCase())
  );

  if (!isOffensive) {
    // Not an offensive command — allow without scope check
    process.stdout.write(JSON.stringify({ decision: 'allow' }));
    return;
  }

  // --- Load scope ---
  const scope = loadScope();
  if (!scope) {
    // Scope file unreadable — hard stop
    process.stdout.write(JSON.stringify({
      decision: 'block',
      message: '⛔ HARD STOP: Cannot load authorized_scope.json. All offensive operations are blocked.',
    }));
    process.exit(0);
  }

  // --- Check engagement window ---
  const windowCheck = checkEngagementWindow(scope.engagement);
  if (!windowCheck.valid) {
    process.stdout.write(JSON.stringify({
      decision: 'block',
      message: `⛔ HARD STOP: ${windowCheck.reason}`,
    }));
    process.exit(0);
  }

  // --- Check testing hours ---
  const hoursCheck = checkTestingHours(scope.testing_hours);
  if (!hoursCheck.valid) {
    process.stdout.write(JSON.stringify({
      decision: 'block',
      message: `⛔ HARD STOP: ${hoursCheck.reason}`,
    }));
    process.exit(0);
  }

  // --- Extract and validate targets ---
  const { ips, domains } = extractTargets(command);

  if (ips.length === 0 && domains.length === 0) {
    // No identifiable targets found — allow but warn
    process.stderr.write(
      `[SCOPE-CHECK] ⚠️  No targets detected in command. Allowing, but verify manually.\n` +
      `  Command: ${command.substring(0, 120)}...\n`
    );
    process.stdout.write(JSON.stringify({ decision: 'allow' }));
    return;
  }

  const result = validateTargets(ips, domains, scope);

  if (result.allowed) {
    // All targets in scope — allow
    process.stderr.write(
      `[SCOPE-CHECK] ✅ All targets in scope: ${[...ips, ...domains].join(', ')}\n`
    );
    process.stdout.write(JSON.stringify({ decision: 'allow' }));
  } else {
    // Violations found — block with detailed report
    const report = [
      '⛔ SCOPE VIOLATION — Command blocked by pre-command-scope-check.js',
      '',
      `Engagement: ${scope.engagement?.id || 'UNKNOWN'}`,
      `Command:    ${command.substring(0, 200)}`,
      '',
      'Violations:',
      ...result.violations.map((v) => `  ${v}`),
      '',
      'Authorized IP ranges:',
      ...(scope.authorized_targets.ip_ranges || []).map((r) => `  ✅ ${r}`),
      'Authorized domains:',
      ...(scope.authorized_targets.domains || []).map((d) => `  ✅ ${d}`),
      '',
      'To add targets, update scripts/authorized_scope.json',
      'Reference: rules/safe-harbor.md',
    ].join('\n');

    process.stderr.write(`[SCOPE-CHECK]\n${report}\n`);
    process.stdout.write(JSON.stringify({
      decision: 'block',
      message: report,
    }));
  }
}

main().catch((err) => {
  process.stderr.write(`[SCOPE-CHECK] Fatal error: ${err.message}\n`);
  // On error, fail closed (block)
  process.stdout.write(JSON.stringify({
    decision: 'block',
    message: `⛔ Scope check failed with error: ${err.message}. Blocking for safety.`,
  }));
  process.exit(1);
});
