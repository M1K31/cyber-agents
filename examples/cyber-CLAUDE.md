# CLAUDE.md — Cyber Claude Agents (Example Project Configuration)

> **Copy this file to the root of any project where you want Claude Code to load the cybersecurity agent harness.** Adjust the paths to match your `cyber-agents` installation directory.

---

## Project Context

This project is configured with the **cyber-agents** security harness — a specialized Claude Code extension providing Red Team (offensive) and Blue Team (defensive) cybersecurity agents, skills, slash commands, hooks, and MCP server integrations. All operations are governed by enforceable rules and aligned with industry frameworks (MITRE ATT&CK, OWASP, NIST).

**Harness location**: `./cyber-agents/` (adjust if installed elsewhere)

---

## Agents

Load specialized sub-agents for specific security tasks. Each agent has its own system prompt, tools, SOPs, and constraints.

| Agent | File | Role | Team |
|-------|------|------|------|
| Red Team Lead | `cyber-agents/agents/red-team-lead.md` | Campaign planning, MITRE ATT&CK mapping, kill-chain orchestration | 🔴 Offensive |
| Exploit Researcher | `cyber-agents/agents/exploit-researcher.md` | CVE analysis, PoC development, mitigation bypass | 🔴 Offensive |
| Threat Hunter | `cyber-agents/agents/threat-hunter.md` | Proactive log analysis, detection engineering (YARA/Sigma) | 🔵 Defensive |
| Incident Responder | `cyber-agents/agents/incident-responder.md` | PICERL methodology, containment, root cause analysis | 🔵 Defensive |

### Agent Delegation

When the current agent encounters a task better suited to another specialist, it should delegate:

```
Exploitable CVE found       → Exploit Researcher
Campaign needs planning     → Red Team Lead
Suspicious logs detected    → Threat Hunter
Active incident confirmed   → Incident Responder
```

---

## Skills

Domain knowledge guides that agents reference for detailed procedures. Load the relevant skill when performing specialized work.

- `cyber-agents/skills/kali-linux-tooling.md` — Nmap, Metasploit, Burp Suite best practices
- `cyber-agents/skills/macos-tooling.md` — Homebrew security toolkit, macOS forensics
- `cyber-agents/skills/defense-evasion.md` — LOLBins, obfuscation, AV/EDR bypass + detection indicators
- `cyber-agents/skills/yara-rule-creation.md` — YARA rule syntax, performance, testing methodology

---

## Commands

Slash commands for common security workflows. These define the full execution pipeline from input to structured output.

| Command | Trigger | Description |
|---------|---------|-------------|
| Scan | `/scan <target>` | Network reconnaissance: profile selection → Nmap execution → parsed results → next-step recommendations |
| Hunt | `/hunt <input>` | Threat hunting: log/PCAP ingestion → anomaly detection → IOC extraction → Sigma/YARA rule generation |

---

## Rules (Mandatory)

**ALL agents MUST comply with these rules at all times.** Violations trigger hard stops.

| Rule | File | What It Enforces |
|------|------|-----------------|
| OPSEC | `cyber-agents/rules/opsec.md` | Proxychains/VPN usage, scan noise levels (1-4), OPSEC-safe payloads, credential encryption |
| Safe Harbor (ROE) | `cyber-agents/rules/safe-harbor.md` | Scope validation against authorized targets, hard/soft stops, engagement window, adjacent discovery protocol |
| Data Handling | `cyber-agents/rules/data-handling.md` | Auto-redaction of PII/credentials/keys (3-tier classification), proof-of-access patterns, retention lifecycle |
| Reporting Standards | `cyber-agents/rules/reporting-standards.md` | CVSS v3.1 scoring, ATT&CK mapping, mandatory templates for vulnerability/engagement/incident reports |

### Core Principles

1. **Authorization First** — Never execute offensive tools without confirmed written authorization
2. **Scope Enforcement** — Hard stop on any target not in `cyber-agents/scripts/authorized_scope.json`
3. **Data Protection** — Auto-redact passwords, private keys, PII, and API tokens from all output
4. **OPSEC Compliance** — Respect scan noise classification; use anonymization layers
5. **Framework Alignment** — Map all findings to MITRE ATT&CK; compute CVSS v3.1 scores
6. **Report Quality** — Use mandatory templates with no omitted fields

---

## Dynamic Contexts

Switch between operational modes using context injection. Each context overrides agent behavior to match the operational tempo.

| Context | File | When to Use |
|---------|------|------------|
| Research | `cyber-agents/contexts/research.md` | CVE analysis, YARA/Sigma development, advisory review — academic tone, passive only, mandatory citations |
| Active Engagement | `cyber-agents/contexts/active-engagement.md` | Live pentests, red team ops, active hunts, IR — tactical tone, command-first, phase-aware |

**Switching contexts:**
```
Operator: "Switch to research mode"    → Load contexts/research.md
Operator: "Go active" / "Engage"       → Load contexts/active-engagement.md
Operator: "Default mode"               → Unload context, return to standard behavior
```

---

## Hooks (Automation)

Hooks fire automatically on Claude Code lifecycle events. Configured in `cyber-agents/hooks/hooks.json`.

| Hook | Event | Script | Function |
|------|-------|--------|----------|
| Scope Check | PreToolUse (Bash) | `cyber-agents/scripts/hooks/pre-command-scope-check.js` | Blocks out-of-scope offensive commands |
| IOC Extractor | PostToolUse | `cyber-agents/scripts/hooks/ioc-extractor.js` | Parses IPs, domains, hashes → `vault/iocs.csv` |
| Session Sanitizer | Stop | `cyber-agents/scripts/hooks/post-session-sanitize.js` | Redacts credentials from session context |

---

## MCP Servers (External APIs)

External security intelligence APIs accessible via MCP. Set the required environment variables before use.

| Server | Config | Tools | Required Env Var |
|--------|--------|-------|-----------------|
| Shodan | `cyber-agents/mcp-configs/shodan-mcp.json` | 5 (host, search, DNS, exploits) | `SHODAN_API_KEY` |
| VirusTotal | `cyber-agents/mcp-configs/virustotal-mcp.json` | 6 (file, URL, domain, IP, behavior) | `VIRUSTOTAL_API_KEY` |
| Splunk/SIEM | `cyber-agents/mcp-configs/splunk-mcp.json` | 5 (search, async, results, notables) | `SPLUNK_BASE_URL`, `SPLUNK_AUTH_TOKEN` |

### Environment Setup

```bash
# Copy to your .env or export in your shell profile
export SHODAN_API_KEY="your-shodan-api-key"
export VIRUSTOTAL_API_KEY="your-virustotal-api-key"
export SPLUNK_BASE_URL="https://splunk.corp.example.com:8089"
export SPLUNK_AUTH_TOKEN="your-splunk-auth-token"
```

---

## Terminal Output Formatting

When displaying results in the terminal, follow these conventions:

### Severity Markers

```
🔴 CRITICAL — Requires immediate action (CVSS 9.0-10.0)
🟠 HIGH     — Act within current phase (CVSS 7.0-8.9)
🟡 MEDIUM   — Document for report (CVSS 4.0-6.9)
🔵 LOW      — Log and continue (CVSS 0.1-3.9)
⚪ INFO     — Context only, no action required
```

### Command Prefixes

```
[NMAP]    Network scanning commands
[MSF]     Metasploit framework commands
[CURL]    HTTP request commands
[YARA]    YARA rule scanning
[SIGMA]   Sigma rule compilation
[SPLUNK]  SPL queries
[SHODAN]  Shodan API lookups
[VT]      VirusTotal API lookups
[SCOPE]   Scope validation results
[IOC]     IOC extraction results
[OPSEC]   Operational security check
```

### Structured Finding Format

```markdown
## [FINDING-NNN] Title
| Field    | Value                          |
|----------|--------------------------------|
| Target   | IP:port or URL                 |
| Severity | 🔴 CRITICAL (CVSS 9.8)         |
| ATT&CK   | T1190 — Exploit Public-Facing  |
| CVE      | CVE-YYYY-NNNNN                 |

**Impact**: [one line]
**Exploit**: `[ready-to-paste command]`
**Remediation**: [one line]
```

---

## Coding Conventions

- **Shell scripts**: POSIX-compatible where possible, Bash when necessary
- **Python**: 3.10+, type hints, `black` formatting, `mypy` clean
- **Node.js**: ES2020+, `'use strict'`, async/await for stdin processing
- **YARA rules**: `<malware_family>_<variant>_<author>.yar` naming convention
- **Sigma rules**: SigmaHQ schema v2
- **Reports**: Markdown format per `rules/reporting-standards.md`

---

## Vault (Project Documentation)

All project documentation, IOC tracking, and audit logs live in `cyber-agents/vault/`:

| File | Purpose | Updated By |
|------|---------|-----------|
| `progress-log.md` | Timestamped project progress | Manual |
| `known-issues.md` | Limitations and open questions | Manual |
| `iocs.csv` | IOC tracker (IPs, domains, hashes) | `ioc-extractor.js` hook |
| `sanitization-log.json` | Credential redaction audit trail | `post-session-sanitize.js` hook |

---

## Quick Reference

```
# Start a pentest campaign
"Use the red-team-lead agent to plan a campaign for the 10.0.0.0/24 network"

# Scan a target
/scan 10.0.0.50 --profile standard

# Hunt for lateral movement
/hunt sysmon --data /path/to/logs.json --hypothesis "PsExec lateral movement"

# Research a CVE (research mode)
"Switch to research mode and analyze CVE-2024-3094"

# Switch to live engagement
"Go active — we're starting the internal pentest"

# Check IOC reputation
"Use VirusTotal to check hash abc123... and Shodan to look up 203.0.113.42"
```
