#!/usr/bin/env node
// ===========================================================================
// ioc-extractor.js
// ---------------------------------------------------------------------------
// Claude Code PostToolUse Hook — IOC (Indicator of Compromise) Extractor
//
// Automatically parses tool output for IP addresses, domains, file hashes
// (MD5, SHA-1, SHA-256), URLs, and email addresses. Deduplicates against
// existing entries and appends new IOCs to a local iocs.csv tracker.
//
// Integration:
//   Register in hooks/hooks.json under PostToolUse for all tools.
//
// References:
//   - agents/threat-hunter.md (IOC enrichment SOP-4)
//   - rules/data-handling.md (Tier 3 — operational data handling)
// ===========================================================================

'use strict';

const fs = require('fs');
const path = require('path');

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/** Output CSV file for extracted IOCs. */
const IOC_FILE = path.resolve(
  process.env.CYBER_AGENTS_ROOT || path.resolve(__dirname, '..', '..'),
  'vault',
  'iocs.csv'
);

/** CSV header row. */
const CSV_HEADER = 'timestamp,type,value,source_tool,context,confidence\n';

// ---------------------------------------------------------------------------
// IOC Detection Patterns
// ---------------------------------------------------------------------------

/**
 * Regex patterns for each IOC type.
 * Each entry: { type, regex, validate?, confidence }
 *   - type:       IOC classification string for the CSV
 *   - regex:      RegExp with global flag
 *   - validate:   optional function(match) => boolean for extra filtering
 *   - confidence: default confidence score (1-100)
 */
const IOC_PATTERNS = [
  // --- IPv4 Addresses ---
  {
    type: 'ipv4',
    regex: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|1?\d{1,2})\b/g,
    validate: (ip) => {
      // Filter out common non-IOC IPs
      const exclude = [
        /^127\./,           // Loopback
        /^0\./,             // Invalid
        /^255\./,           // Broadcast-adjacent
        /^224\./,           // Multicast
        /^169\.254\./,      // Link-local
      ];
      return !exclude.some((re) => re.test(ip));
    },
    confidence: 60,
  },

  // --- Domain Names ---
  {
    type: 'domain',
    regex: /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|info|biz|xyz|top|ru|cn|tk|ml|ga|cf|gq|cc|pw|ws|co|me|tv|de|uk|fr|nl|br|in|jp|kr|au|za)\b/gi,
    validate: (domain) => {
      // Exclude known benign domains and file-like patterns
      const exclude = [
        /^(www\.)?google\.com$/i,
        /^(www\.)?github\.com$/i,
        /^(www\.)?microsoft\.com$/i,
        /^(www\.)?anthropic\.com$/i,
        /^localhost$/i,
        /\.(exe|dll|py|js|sh|md|txt|json|xml|yml|yaml|csv|log)$/i,
      ];
      return !exclude.some((re) => re.test(domain));
    },
    confidence: 50,
  },

  // --- SHA-256 Hashes ---
  {
    type: 'sha256',
    regex: /\b[a-fA-F0-9]{64}\b/g,
    validate: (hash) => {
      // Ensure it's not all zeros or all same character
      return !/^(.)\1+$/.test(hash);
    },
    confidence: 90,
  },

  // --- SHA-1 Hashes ---
  {
    type: 'sha1',
    regex: /\b[a-fA-F0-9]{40}\b/g,
    validate: (hash) => {
      return !/^(.)\1+$/.test(hash) && !/^[a-fA-F0-9]{64}/.test(hash);
    },
    confidence: 85,
  },

  // --- MD5 Hashes ---
  {
    type: 'md5',
    regex: /\b[a-fA-F0-9]{32}\b/g,
    validate: (hash) => {
      // Exclude patterns that are likely UUIDs (with hyphens removed) or
      // other hex strings. MD5 detection has higher FP rate.
      return !/^(.)\1+$/.test(hash) && !/^[a-fA-F0-9]{40}/.test(hash);
    },
    confidence: 70,
  },

  // --- URLs ---
  {
    type: 'url',
    regex: /https?:\/\/[^\s"'<>\]|)]+/gi,
    validate: (url) => {
      const exclude = [
        /^https?:\/\/(www\.)?google\.com/i,
        /^https?:\/\/(www\.)?github\.com/i,
        /^https?:\/\/localhost/i,
        /^https?:\/\/127\./,
        /^https?:\/\/nvd\.nist\.gov/i,        // NVD lookups are not IOCs
        /^https?:\/\/attack\.mitre\.org/i,     // MITRE references
        /^https?:\/\/cve\.mitre\.org/i,
      ];
      return !exclude.some((re) => re.test(url));
    },
    confidence: 65,
  },

  // --- Email Addresses ---
  {
    type: 'email',
    regex: /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g,
    validate: (email) => {
      const exclude = [
        /@example\.com$/i,
        /@localhost$/i,
        /@test\.com$/i,
      ];
      return !exclude.some((re) => re.test(email));
    },
    confidence: 55,
  },
];

// ---------------------------------------------------------------------------
// CSV Management
// ---------------------------------------------------------------------------

/**
 * Ensures the IOC CSV file exists with a header row.
 * Creates parent directories if needed.
 */
function ensureCSVFile() {
  const dir = path.dirname(IOC_FILE);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  if (!fs.existsSync(IOC_FILE)) {
    fs.writeFileSync(IOC_FILE, CSV_HEADER, 'utf-8');
  }
}

/**
 * Loads existing IOC values from the CSV to enable deduplication.
 * Returns a Set of "type:value" strings for fast lookup.
 * @returns {Set<string>}
 */
function loadExistingIOCs() {
  const existing = new Set();
  try {
    const content = fs.readFileSync(IOC_FILE, 'utf-8');
    const lines = content.split('\n').slice(1); // Skip header
    for (const line of lines) {
      if (!line.trim()) continue;
      const parts = line.split(',');
      if (parts.length >= 3) {
        // Key on type:value for dedup
        existing.add(`${parts[1]}:${parts[2]}`);
      }
    }
  } catch {
    // File doesn't exist yet — will be created
  }
  return existing;
}

/**
 * Escapes a CSV field value (handles commas, quotes, newlines).
 * @param {string} value
 * @returns {string}
 */
function csvEscape(value) {
  if (/[,"\n\r]/.test(value)) {
    return `"${value.replace(/"/g, '""')}"`;
  }
  return value;
}

/**
 * Appends new IOC rows to the CSV file.
 * @param {{ type: string, value: string, source: string, context: string, confidence: number }[]} iocs
 */
function appendIOCs(iocs) {
  const timestamp = new Date().toISOString();
  const lines = iocs.map((ioc) =>
    [
      timestamp,
      ioc.type,
      csvEscape(ioc.value),
      csvEscape(ioc.source),
      csvEscape(ioc.context.substring(0, 200)),  // Truncate context
      ioc.confidence,
    ].join(',')
  );
  fs.appendFileSync(IOC_FILE, lines.join('\n') + '\n', 'utf-8');
}

// ---------------------------------------------------------------------------
// IOC Extraction Engine
// ---------------------------------------------------------------------------

/**
 * Extracts IOCs from a text block.
 * @param {string} text - Text to scan (tool output, chat message, etc.)
 * @param {string} sourceTool - Name of the tool that produced this output
 * @returns {{ type: string, value: string, source: string, context: string, confidence: number }[]}
 */
function extractIOCs(text, sourceTool) {
  const results = [];
  const seen = new Set(); // Dedup within this extraction

  for (const pattern of IOC_PATTERNS) {
    // Reset regex lastIndex for global patterns
    pattern.regex.lastIndex = 0;
    let match;

    while ((match = pattern.regex.exec(text)) !== null) {
      const value = match[0];
      const dedupKey = `${pattern.type}:${value.toLowerCase()}`;

      // Skip duplicates within this extraction
      if (seen.has(dedupKey)) continue;

      // Apply validation filter
      if (pattern.validate && !pattern.validate(value)) continue;

      // For hash types, avoid double-counting (sha1 inside sha256, md5 inside sha1)
      if (pattern.type === 'sha1' && seen.has(`sha256:${value.toLowerCase()}`)) continue;
      if (pattern.type === 'md5' && (seen.has(`sha256:${value.toLowerCase()}`) || seen.has(`sha1:${value.toLowerCase()}`))) continue;

      seen.add(dedupKey);

      // Extract surrounding context (±40 chars around the match)
      const start = Math.max(0, match.index - 40);
      const end = Math.min(text.length, match.index + value.length + 40);
      const context = text.substring(start, end).replace(/[\n\r]+/g, ' ').trim();

      results.push({
        type: pattern.type,
        value: value,
        source: sourceTool || 'unknown',
        context: context,
        confidence: pattern.confidence,
      });
    }
  }

  return results;
}

// ---------------------------------------------------------------------------
// Hook Entry Point
// ---------------------------------------------------------------------------

/**
 * Main hook function — reads tool output from stdin.
 * Claude Code passes PostToolUse data as JSON on stdin.
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

  let toolData;
  try {
    toolData = JSON.parse(input);
  } catch {
    // If not JSON, treat raw text as tool output
    toolData = { tool_name: 'unknown', tool_output: input };
  }

  const toolName = toolData.tool_name || toolData.tool || 'unknown';
  const toolOutput = toolData.tool_output || toolData.output || toolData.result || '';

  if (!toolOutput || typeof toolOutput !== 'string') {
    process.exit(0);
  }

  // --- Extract IOCs ---
  const newIOCs = extractIOCs(toolOutput, toolName);

  if (newIOCs.length === 0) {
    process.exit(0);
  }

  // --- Deduplicate against existing CSV ---
  ensureCSVFile();
  const existing = loadExistingIOCs();
  const unique = newIOCs.filter(
    (ioc) => !existing.has(`${ioc.type}:${ioc.value.toLowerCase()}`)
  );

  if (unique.length === 0) {
    process.stderr.write(
      `[IOC-EXTRACTOR] Found ${newIOCs.length} IOCs but all are already tracked.\n`
    );
    process.exit(0);
  }

  // --- Append to CSV ---
  appendIOCs(unique);

  // --- Report to stderr (visible in Claude Code logs) ---
  process.stderr.write(
    `[IOC-EXTRACTOR] ✅ Extracted ${unique.length} new IOC(s) from ${toolName} output:\n`
  );
  for (const ioc of unique) {
    process.stderr.write(
      `  ${ioc.type.padEnd(8)} ${ioc.value.substring(0, 64)} (confidence: ${ioc.confidence})\n`
    );
  }
  process.stderr.write(`  → Appended to ${IOC_FILE}\n`);
}

main().catch((err) => {
  process.stderr.write(`[IOC-EXTRACTOR] Error: ${err.message}\n`);
  // IOC extraction is non-blocking — don't fail the tool
  process.exit(0);
});
