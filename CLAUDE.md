# CLAUDE.md — Cyber Claude Agents

## Project Context

This is a cybersecurity-focused Claude Code agent harness. It provides specialized agents for Red Team (offensive) and Blue Team (defensive) security operations, with skills and commands aligned to MITRE ATT&CK, OWASP, and NIST frameworks.

## Available Agents

| Agent | File | Purpose |
|-------|------|---------|
| Red Team Lead | `agents/red-team-lead.md` | Campaign planning, MITRE ATT&CK mapping, sub-agent orchestration |
| Exploit Researcher | `agents/exploit-researcher.md` | CVE analysis, PoC development, mitigation bypass |
| Threat Hunter | `agents/threat-hunter.md` | Proactive log analysis, anomaly detection, YARA/Sigma rules |
| Incident Responder | `agents/incident-responder.md` | PICERL methodology, containment, root cause analysis |
| Log Analyst | `agents/log-analyst.md` | Router log analysis, threat detection, attacker profiling |
| Network Guardian | `agents/network-guardian.md` | IP blocking, honeypot management, automated response |
| Knowledge Agent | `agents/knowledge-agent.md` | Knowledge base search and retrieval-augmented answers |

## Available Skills

- `skills/kali-linux-tooling.md` — Kali Linux pentesting suite workflows
- `skills/macos-tooling.md` — macOS/Linux security tooling
- `skills/defense-evasion.md` — Evasion techniques (LOLBins, obfuscation, AV/EDR bypass)
- `skills/yara-rule-creation.md` — YARA rule syntax, best practices, performance
- `skills/ollama-inference.md` — Ollama qwen2.5-coder API patterns for LLM analysis
- `skills/syslog-analysis.md` — ASUS router syslog patterns and detection thresholds
- `skills/router-management.md` — SSH-based router iptables and syslog management

## Available Commands

- `/scan` — Network reconnaissance (IP/CIDR → Nmap → parsed results)
- `/hunt` — Threat hunting (log/PCAP → anomaly detection → IOCs + Sigma rules)
- `/analyze` — Threat, log, IP, or CVE analysis via log-analyst agent and Ollama
- `/block` — Block or unblock IP addresses on router via SSH
- `/status` — Security posture dashboard: threats, blocks, honeypots, profiles
- `/triage` — Multi-step incident triage with playbook workflows

## Rules

All agents MUST comply with the enforceable rules in `rules/`:

| Rule | File | Enforcement |
|------|------|-------------|
| Operational Security | `rules/opsec.md` | Mandatory — scan noise, payload safety, credential handling |
| Safe Harbor (ROE) | `rules/safe-harbor.md` | Mandatory — scope validation, hard/soft stops, adjacent discovery |
| Data Handling | `rules/data-handling.md` | Mandatory — PII/credential redaction, retention lifecycle |
| Reporting Standards | `rules/reporting-standards.md` | Mandatory — CVSS, ATT&CK, templates for all report types |

### Core Principles

1. **Authorization First**: Never execute offensive tools or techniques without confirmed written authorization (see `rules/safe-harbor.md`).
2. **Scope Enforcement**: All operations must stay within the defined engagement scope. Hard stop on out-of-scope targets.
3. **Data Protection**: Auto-redact PII, credentials, and private keys from all output (see `rules/data-handling.md`).
4. **OPSEC Compliance**: Use proxychains/VPNs, respect scan noise levels, generate OPSEC-safe payloads (see `rules/opsec.md`).
5. **Framework Alignment**: Map all findings to MITRE ATT&CK technique IDs. Compute CVSS v3.1 scores. Reference NIST and OWASP.
6. **Report Quality**: All reports must follow mandatory templates with no omitted fields (see `rules/reporting-standards.md`).

## Hooks (Automation Scripts)

Registered in `hooks/hooks.json`. These Node.js scripts fire automatically during Claude Code lifecycle events:

| Hook | Event | Script | Purpose |
|------|-------|--------|---------|
| Scope Check | PreToolUse (Bash) | `scripts/hooks/pre-command-scope-check.js` | Blocks out-of-scope offensive commands against `scripts/authorized_scope.json` |
| IOC Extractor | PostToolUse (Bash, Read, Grep) | `scripts/hooks/ioc-extractor.js` | Parses tool output for IPs, domains, hashes → appends to `vault/iocs.csv` |
| Session Sanitizer | Stop | `scripts/hooks/post-session-sanitize.js` | Redacts private keys, passwords, API tokens from session context |
| Threat Watcher | PreToolUse (any) | `scripts/hooks/threat-data-watcher.js` | Injects recent high-severity threats as agent context |
| Ecosystem Publisher | PostToolUse (Bash) | `scripts/hooks/ecosystem-event-publisher.js` | Publishes block/unblock events to ecosystem registry |

## MCP Servers (External API Integration)

Configurations in `mcp-configs/` enable agents to interface with external security APIs:

| Server | Config | Tools | Team | Required Env Var |
|--------|--------|-------|------|------------------|
| Shodan | `mcp-configs/shodan-mcp.json` | 5 (host lookup, search, DNS resolve/reverse, exploit search) | 🔴 Red | `SHODAN_API_KEY` |
| VirusTotal | `mcp-configs/virustotal-mcp.json` | 6 (file/URL/domain/IP reports, URL scan, file behavior) | 🔵 Blue | `VIRUSTOTAL_API_KEY` |
| Splunk/SIEM | `mcp-configs/splunk-mcp.json` | 5 (sync/async search, job status, results, notable events) | 🔵 Blue | `SPLUNK_BASE_URL`, `SPLUNK_AUTH_TOKEN` |
| AegisSIEM | `mcp-configs/aegissiem-mcp.json` | 9 (threats, blocks, profiles, honeypot, approvals, knowledge) | 🔵 Blue | (none - local SQLite) |
| Ecosystem | `mcp-configs/ecosystem-mcp.json` | 3 (publish event, discover service, registry status) | Both | `ECOSYSTEM_REGISTRY_URL` |

## AegisSIEM Daemon

The AegisSIEM daemon (`daemon/aegissiem_daemon.py`) runs continuously alongside Claude Code, handling operations that require 24/7 monitoring:

- **Syslog ingestion**: Parses ASUS router syslog in real-time
- **Threat detection**: Brute force, deauth flood, DNS rebinding detection
- **Auto-blocking**: Automatically blocks IPs past their deadline via SSH iptables
- **Honeypot management**: SSH (2222), HTTP (8443), Telnet (2323) listeners with tarpit mode
- **Dashboard API**: Serves web dashboard on port 8088
- **Ecosystem integration**: Registers with appEcosystem, publishes security events

Start: `python -m daemon.aegissiem_daemon` (from cyber-claude-agents/)
Config: `~/.aegissiem-daemon/config.yml`
Database: `~/.aegissiem-daemon/aegissiem.db`
Dashboard: `http://localhost:8088`

## Dynamic Contexts

Switch operational modes by loading a context. Each overrides agent behavior to match the operational tempo.

| Context | File | Behavior |
|---------|------|----------|
| Research | `contexts/research.md` | Academic tone, mandatory citations, active tool prohibition, structured CVE/YARA workflows |
| Active Engagement | `contexts/active-engagement.md` | Tactical tone, command-first output, phase-aware behavior, engagement state tracking |

## Example Configuration

See `examples/cyber-CLAUDE.md` for a complete root-level project configuration that ties the entire harness together. Copy it to your project root to enable all agents, skills, commands, hooks, and MCP servers.

## Ollama Integration

This harness uses qwen2.5-coder via Ollama for offline LLM inference. Before starting:

1. Ensure Ollama is running: `scripts/ensure-ollama.sh`
2. Source environment: `source scripts/ollama-env.sh`
3. Start Claude Code: `claude`

The `skills/ollama-inference.md` skill provides curl patterns for all agents to call the model.

## Coding Conventions

- Shell scripts: POSIX-compatible where possible, Bash when necessary
- Python: 3.10+, type hints, `black` formatting
- Node.js hooks: ES2020+, `'use strict'`, async stdin handling
- YARA rules: Follow the naming convention `<malware_family>_<variant>_<author>.yar`
- Sigma rules: Follow SigmaHQ schema v2

## Obsidian Vault

Project documentation lives in `vault/`. Notes use standard Obsidian wiki-link syntax (`[[note-name]]`). Key files:

- `vault/progress-log.md` — Timestamped project progress
- `vault/known-issues.md` — Limitations and open questions
- `vault/iocs.csv` — Auto-populated IOC tracker (via `ioc-extractor.js` hook)
- `vault/sanitization-log.json` — Credential redaction audit log (via `post-session-sanitize.js` hook)
