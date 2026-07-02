#!/usr/bin/env node
'use strict';

/**
 * Threat Data Watcher Hook
 * Event: PreToolUse (any tool)
 *
 * Checks vault/threat-data/ for new high-severity threats written by the
 * AegisSIEM daemon. If found, injects a warning into the agent context.
 */

const fs = require('fs');
const path = require('path');

const VAULT_DIR = path.join(__dirname, '..', '..', 'vault', 'threat-data');
const LOOKBACK_MS = 5 * 60 * 1000; // 5 minutes

function getRecentThreats() {
    if (!fs.existsSync(VAULT_DIR)) return [];

    const now = Date.now();
    const threats = [];

    try {
        const files = fs.readdirSync(VAULT_DIR)
            .filter(f => f.endsWith('.json') && f.startsWith('threat-'))
            .sort()
            .reverse()
            .slice(0, 10);

        for (const file of files) {
            const filepath = path.join(VAULT_DIR, file);
            const stat = fs.statSync(filepath);

            if (now - stat.mtimeMs > LOOKBACK_MS) continue;

            try {
                const data = JSON.parse(fs.readFileSync(filepath, 'utf8'));
                if (data.severity === 'CRITICAL' || data.severity === 'HIGH') {
                    threats.push({
                        ip: data.source_ip || data.ip,
                        type: data.threat_type || data.type,
                        severity: data.severity,
                        timestamp: data.timestamp,
                    });
                }
            } catch (e) {
                // Skip malformed files
            }
        }
    } catch (e) {
        // Vault directory read error
    }

    return threats;
}

async function main() {
    let input = '';
    for await (const chunk of process.stdin) {
        input += chunk;
    }

    const threats = getRecentThreats();

    if (threats.length > 0) {
        const summary = threats.map(t =>
            `  [${t.severity}] ${t.type} from ${t.ip} at ${t.timestamp}`
        ).join('\n');

        // Output context injection (non-blocking — exit 0 allows tool to proceed)
        process.stderr.write(
            `[threat-watcher] ${threats.length} active high-severity threat(s):\n${summary}\n`
        );
    }

    // Always allow the tool to proceed
    process.exit(0);
}

main().catch(() => process.exit(0));
