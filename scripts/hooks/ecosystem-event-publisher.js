#!/usr/bin/env node
'use strict';

/**
 * Ecosystem Event Publisher Hook
 * Event: PostToolUse (Bash)
 *
 * Detects SSH iptables commands and threat status changes,
 * then publishes corresponding events to the ecosystem registry.
 */

const http = require('http');

const REGISTRY_URL = 'http://localhost:8500';

function publishEvent(eventType, data) {
    const payload = JSON.stringify({
        event_type: eventType,
        source: 'aegissiem_daemon',
        data: data,
    });

    const url = new URL(`${REGISTRY_URL}/events/publish`);
    const options = {
        hostname: url.hostname,
        port: url.port,
        path: url.pathname,
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(payload),
        },
        timeout: 5000,
    };

    return new Promise((resolve) => {
        const req = http.request(options, (res) => {
            resolve(res.statusCode === 200);
        });
        req.on('error', () => resolve(false));
        req.on('timeout', () => { req.destroy(); resolve(false); });
        req.write(payload);
        req.end();
    });
}

async function main() {
    let input = '';
    for await (const chunk of process.stdin) {
        input += chunk;
    }

    let toolResult;
    try {
        toolResult = JSON.parse(input);
    } catch {
        process.exit(0);
    }

    const command = toolResult?.tool_input?.command || '';
    const output = toolResult?.tool_result || '';

    // Detect iptables block command
    const blockMatch = command.match(/iptables\s+-I\s+INPUT\s+-s\s+(\d+\.\d+\.\d+\.\d+)\s+-j\s+DROP/);
    if (blockMatch) {
        const ip = blockMatch[1];
        await publishEvent('security.threat_blocked', {
            ip: ip,
            action: 'block',
            method: 'ssh_iptables',
            timestamp: new Date().toISOString(),
        });
        process.stderr.write(`[ecosystem] Published security.threat_blocked for ${ip}\n`);
    }

    // Detect iptables unblock command
    const unblockMatch = command.match(/iptables\s+-D\s+INPUT\s+-s\s+(\d+\.\d+\.\d+\.\d+)\s+-j\s+DROP/);
    if (unblockMatch) {
        const ip = unblockMatch[1];
        await publishEvent('security.threat_unblocked', {
            ip: ip,
            action: 'unblock',
            timestamp: new Date().toISOString(),
        });
        process.stderr.write(`[ecosystem] Published security.threat_unblocked for ${ip}\n`);
    }

    process.exit(0);
}

main().catch(() => process.exit(0));
