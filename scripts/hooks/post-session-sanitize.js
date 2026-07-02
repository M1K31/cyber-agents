#!/usr/bin/env node
// ===========================================================================
// post-session-sanitize.js
// ---------------------------------------------------------------------------
// Claude Code Stop Hook — Session Context Sanitizer
//
// Runs when the Claude Code session ends (or is compacted). Scans the
// session context/output for patterns resembling private keys
// (RSA, EC, DSA, Ed25519, OpenSSH), passwords, API tokens, and other
// credentials. Replaces them with [REDACTED_CREDENTIAL] placeholders.
//
// Also produces a sanitization summary log in vault/sanitization-log.json.
//
// Integration:
//   Register in hooks/hooks.json under Stop hook.
//
// References:
//   - rules/data-handling.md (Tier 1 — auto-redact immediately)
//   - rules/opsec.md (credential handling)
// ===========================================================================

'use strict';

const fs = require('fs');
const path = require('path');

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/** Sanitization log output path. */
const SANITIZE_LOG = path.resolve(
  process.env.CYBER_AGENTS_ROOT || path.resolve(__dirname, '..', '..'),
  'vault',
  'sanitization-log.json'
);

// ---------------------------------------------------------------------------
// Credential Detection Patterns
// ---------------------------------------------------------------------------

/**
 * Each pattern: { name, regex, replacement, severity, description }
 *
 * Patterns are ordered from most specific (low FP) to least specific.
 * The regex MUST use the global and multiline flags where needed.
 */
const CREDENTIAL_PATTERNS = [
  // === Private Keys ===
  {
    name: 'RSA_PRIVATE_KEY',
    regex: /-----BEGIN RSA PRIVATE KEY-----[\s\S]*?-----END RSA PRIVATE KEY-----/gm,
    replacement: '[REDACTED_CREDENTIAL type=RSA_PRIVATE_KEY]',
    severity: 'critical',
    description: 'RSA private key (PKCS#1 format)',
  },
  {
    name: 'EC_PRIVATE_KEY',
    regex: /-----BEGIN EC PRIVATE KEY-----[\s\S]*?-----END EC PRIVATE KEY-----/gm,
    replacement: '[REDACTED_CREDENTIAL type=EC_PRIVATE_KEY]',
    severity: 'critical',
    description: 'Elliptic Curve private key',
  },
  {
    name: 'DSA_PRIVATE_KEY',
    regex: /-----BEGIN DSA PRIVATE KEY-----[\s\S]*?-----END DSA PRIVATE KEY-----/gm,
    replacement: '[REDACTED_CREDENTIAL type=DSA_PRIVATE_KEY]',
    severity: 'critical',
    description: 'DSA private key',
  },
  {
    name: 'OPENSSH_PRIVATE_KEY',
    regex: /-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]*?-----END OPENSSH PRIVATE KEY-----/gm,
    replacement: '[REDACTED_CREDENTIAL type=OPENSSH_PRIVATE_KEY]',
    severity: 'critical',
    description: 'OpenSSH private key (Ed25519, ECDSA, or RSA)',
  },
  {
    name: 'GENERIC_PRIVATE_KEY',
    regex: /-----BEGIN PRIVATE KEY-----[\s\S]*?-----END PRIVATE KEY-----/gm,
    replacement: '[REDACTED_CREDENTIAL type=PRIVATE_KEY]',
    severity: 'critical',
    description: 'Generic PKCS#8 private key',
  },
  {
    name: 'ENCRYPTED_PRIVATE_KEY',
    regex: /-----BEGIN ENCRYPTED PRIVATE KEY-----[\s\S]*?-----END ENCRYPTED PRIVATE KEY-----/gm,
    replacement: '[REDACTED_CREDENTIAL type=ENCRYPTED_PRIVATE_KEY]',
    severity: 'critical',
    description: 'Encrypted PKCS#8 private key',
  },
  {
    name: 'PGP_PRIVATE_KEY',
    regex: /-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]*?-----END PGP PRIVATE KEY BLOCK-----/gm,
    replacement: '[REDACTED_CREDENTIAL type=PGP_PRIVATE_KEY]',
    severity: 'critical',
    description: 'PGP/GPG private key block',
  },

  // === API Keys & Tokens ===
  {
    name: 'AWS_ACCESS_KEY',
    regex: /\b(AKIA[A-Z0-9]{16})\b/g,
    replacement: '[REDACTED_CREDENTIAL type=AWS_ACCESS_KEY]',
    severity: 'critical',
    description: 'AWS Access Key ID',
  },
  {
    name: 'AWS_SECRET_KEY',
    regex: /(?:aws_secret_access_key|secret_access_key|aws_secret)\s*[=:]\s*["']?([A-Za-z0-9/+=]{40})["']?/gi,
    replacement: '[REDACTED_CREDENTIAL type=AWS_SECRET_KEY]',
    severity: 'critical',
    description: 'AWS Secret Access Key',
  },
  {
    name: 'GITHUB_TOKEN',
    regex: /\b(ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36}|ghu_[a-zA-Z0-9]{36}|ghs_[a-zA-Z0-9]{36}|ghr_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{22,})\b/g,
    replacement: '[REDACTED_CREDENTIAL type=GITHUB_TOKEN]',
    severity: 'critical',
    description: 'GitHub personal access token or OAuth token',
  },
  {
    name: 'OPENAI_API_KEY',
    regex: /\b(sk-[a-zA-Z0-9]{20,}T3BlbkFJ[a-zA-Z0-9]{20,}|sk-proj-[a-zA-Z0-9_-]{40,})\b/g,
    replacement: '[REDACTED_CREDENTIAL type=OPENAI_API_KEY]',
    severity: 'critical',
    description: 'OpenAI API key',
  },
  {
    name: 'SLACK_TOKEN',
    regex: /\b(xox[baprs]-[0-9]{10,}-[a-zA-Z0-9-]+)\b/g,
    replacement: '[REDACTED_CREDENTIAL type=SLACK_TOKEN]',
    severity: 'critical',
    description: 'Slack bot/app/user token',
  },
  {
    name: 'GENERIC_BEARER_TOKEN',
    regex: /(?:Bearer\s+)([a-zA-Z0-9._~+/=-]{20,})/gi,
    replacement: 'Bearer [REDACTED_CREDENTIAL type=BEARER_TOKEN]',
    severity: 'high',
    description: 'HTTP Bearer authentication token',
  },

  // === Connection Strings ===
  {
    name: 'DATABASE_URL',
    regex: /(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql):\/\/[^\s"'<>]+/gi,
    replacement: '[REDACTED_CREDENTIAL type=DATABASE_CONNECTION_STRING]',
    severity: 'critical',
    description: 'Database connection string with potential embedded credentials',
  },

  // === Passwords ===
  {
    name: 'PASSWORD_ASSIGNMENT',
    regex: /(?:password|passwd|pass|pwd|secret|token|api_key|apikey|auth_token|access_token|secret_key)\s*[=:]\s*["']?([^\s"']{8,})["']?/gi,
    replacement: (match, ...groups) => {
      // Preserve the key name but redact the value
      const keyMatch = match.match(/^([^=:]+[=:])\s*/);
      const key = keyMatch ? keyMatch[1] : 'password=';
      return `${key} [REDACTED_CREDENTIAL type=PASSWORD]`;
    },
    severity: 'high',
    description: 'Password or secret in key=value format',
  },

  // === Windows Credential Dumps ===
  {
    name: 'NTLM_HASH',
    regex: /\b([a-zA-Z0-9._-]+):(\d+):([a-fA-F0-9]{32}):([a-fA-F0-9]{32}):::\s*$/gm,
    replacement: (match, user, rid) => {
      return `${user}:${rid}:[REDACTED_CREDENTIAL type=NTLM_HASH]:[REDACTED_CREDENTIAL type=NTLM_HASH]:::`;
    },
    severity: 'critical',
    description: 'NTLM hash dump (SAM/secretsdump format)',
  },
  {
    name: 'KERBEROS_TICKET',
    regex: /\$krb5tgs\$[0-9]+\$\*[^\s]+/gi,
    replacement: '[REDACTED_CREDENTIAL type=KERBEROS_TGS_HASH]',
    severity: 'critical',
    description: 'Kerberos TGS hash (Kerberoasting output)',
  },
  {
    name: 'KERBEROS_ASREP',
    regex: /\$krb5asrep\$[0-9]+\$[^\s]+/gi,
    replacement: '[REDACTED_CREDENTIAL type=KERBEROS_ASREP_HASH]',
    severity: 'critical',
    description: 'Kerberos AS-REP hash (ASREPRoasting output)',
  },

  // === SSH Credentials in Commands ===
  {
    name: 'SSH_PASS_IN_COMMAND',
    regex: /sshpass\s+-p\s+["']?([^\s"']+)["']?/gi,
    replacement: 'sshpass -p [REDACTED_CREDENTIAL type=SSH_PASSWORD]',
    severity: 'critical',
    description: 'SSH password passed via sshpass command',
  },
];

// ---------------------------------------------------------------------------
// Sanitization Engine
// ---------------------------------------------------------------------------

/**
 * Sanitizes a text block by applying all credential patterns.
 * @param {string} text - The text to sanitize
 * @returns {{ sanitized: string, redactions: object[] }}
 */
function sanitize(text) {
  let result = text;
  const redactions = [];

  for (const pattern of CREDENTIAL_PATTERNS) {
    // Reset regex state
    pattern.regex.lastIndex = 0;

    // Count matches before replacing
    const matches = result.match(pattern.regex) || [];
    if (matches.length === 0) continue;

    // Replace all matches
    result = result.replace(pattern.regex, pattern.replacement);

    redactions.push({
      pattern_name: pattern.name,
      severity: pattern.severity,
      description: pattern.description,
      count: matches.length,
      timestamp: new Date().toISOString(),
    });
  }

  return { sanitized: result, redactions };
}

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

/**
 * Appends sanitization results to the log file.
 * @param {object[]} redactions - Array of redaction records
 * @param {object} metadata - Session metadata
 */
function writeSanitizationLog(redactions, metadata) {
  const dir = path.dirname(SANITIZE_LOG);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  // Load existing log or start fresh
  let log = [];
  try {
    const existing = fs.readFileSync(SANITIZE_LOG, 'utf-8');
    log = JSON.parse(existing);
    if (!Array.isArray(log)) log = [];
  } catch {
    log = [];
  }

  log.push({
    session_end: new Date().toISOString(),
    total_redactions: redactions.reduce((sum, r) => sum + r.count, 0),
    patterns_triggered: redactions.length,
    details: redactions,
    metadata,
  });

  // Keep only last 100 entries to avoid unbounded growth
  if (log.length > 100) {
    log = log.slice(-100);
  }

  fs.writeFileSync(SANITIZE_LOG, JSON.stringify(log, null, 2), 'utf-8');
}

// ---------------------------------------------------------------------------
// Hook Entry Point
// ---------------------------------------------------------------------------

/**
 * Main hook function — reads session context from stdin.
 * Claude Code passes session data as JSON on stdin for Stop hooks.
 * The sanitized output is written to stdout.
 */
async function main() {
  const chunks = [];
  for await (const chunk of process.stdin) {
    chunks.push(chunk);
  }
  const input = Buffer.concat(chunks).toString('utf-8').trim();

  if (!input) {
    process.exit(0);
  }

  let sessionData;
  try {
    sessionData = JSON.parse(input);
  } catch {
    // If not JSON, treat entire input as text to sanitize
    sessionData = { content: input };
  }

  // Extract text content to sanitize from various possible structures
  const textFields = [];
  const extractText = (obj, prefix = '') => {
    if (typeof obj === 'string') {
      textFields.push({ path: prefix, value: obj });
    } else if (Array.isArray(obj)) {
      obj.forEach((item, i) => extractText(item, `${prefix}[${i}]`));
    } else if (obj && typeof obj === 'object') {
      for (const [key, val] of Object.entries(obj)) {
        extractText(val, prefix ? `${prefix}.${key}` : key);
      }
    }
  };
  extractText(sessionData);

  // --- Sanitize all text fields ---
  let totalRedactions = [];
  let sanitizedData = JSON.stringify(sessionData);

  for (const field of textFields) {
    const { sanitized, redactions } = sanitize(field.value);
    if (redactions.length > 0) {
      // Replace the original value in the serialized JSON
      // Use a stable replacement approach for the full value
      sanitizedData = sanitizedData.split(JSON.stringify(field.value).slice(1, -1))
        .join(JSON.stringify(sanitized).slice(1, -1));
      totalRedactions = totalRedactions.concat(redactions);
    }
  }

  // --- Write sanitization log ---
  if (totalRedactions.length > 0) {
    const totalCount = totalRedactions.reduce((sum, r) => sum + r.count, 0);

    writeSanitizationLog(totalRedactions, {
      fields_scanned: textFields.length,
      patterns_available: CREDENTIAL_PATTERNS.length,
    });

    process.stderr.write(
      `[SESSION-SANITIZE] 🔒 Sanitization complete:\n` +
      `  ${totalCount} credential(s) redacted across ${totalRedactions.length} pattern(s)\n`
    );
    for (const r of totalRedactions) {
      process.stderr.write(
        `  ${r.severity === 'critical' ? '🔴' : '🟡'} ${r.pattern_name}: ${r.count} instance(s) — ${r.description}\n`
      );
    }
    process.stderr.write(`  → Log written to ${SANITIZE_LOG}\n`);
  } else {
    process.stderr.write(
      `[SESSION-SANITIZE] ✅ No credentials detected in session context (${textFields.length} fields scanned).\n`
    );
  }

  // Output sanitized data to stdout (Claude Code reads this back)
  process.stdout.write(sanitizedData);
}

main().catch((err) => {
  process.stderr.write(`[SESSION-SANITIZE] Error: ${err.message}\n`);
  // On error, pass through original data — don't block session end
  process.exit(0);
});
