# 📖 Usage Guide

> How to set up, configure, and use the cyber-claude-agents harness in your security workflows.

---

## Prerequisites

| Requirement | Version | Purpose |
|-------------|---------|---------|
| Claude Code CLI | Latest | Agent execution environment |
| Node.js | 18+ | Hook scripts (scope check, IOC extractor, session sanitizer) |
| Python | 3.10+ | AegisSIEM daemon, MCP servers |
| Ollama | Latest | Local `qwen2.5-coder` inference for log analysis |
| Nmap | 7.80+ | Network scanning (`/scan` command) |
| YARA | 4.0+ | Rule testing (`skills/yara-rule-creation.md`) |
| Git | Any | Repository management |

### Optional Tools

| Tool | Purpose | Install |
|------|---------|---------|
| Metasploit | Exploitation framework | `curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb \| bash` |
| Burp Suite | Web app testing | Download from PortSwigger |
| Nuclei | Vulnerability scanning | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| osquery | Endpoint querying | `brew install osquery` |
| Sigma CLI | Rule validation | `pip install sigma-cli` |

---

## Installation

The harness is globally installed into Claude Code. Skills, agents, and commands are symlinked from this repo into `~/.claude/` so changes here are reflected immediately — no re-installation needed.

### What's installed globally

| Location | Contents |
|----------|---------|
| `~/.claude/agents/` | 7 agents (red-team-lead, exploit-researcher, threat-hunter, incident-responder, log-analyst, network-guardian, knowledge-agent) |
| `~/.claude/skills/` | 7 skills (kali-linux-tooling, macos-tooling, defense-evasion, yara-rule-creation, syslog-analysis, ollama-inference, router-management) |
| `~/.claude/commands/` | 6 commands (/scan, /hunt, /analyze, /block, /status, /triage) |
| `~/.claude/settings.json` | 5 hooks (scope-check, threat-watcher, ioc-extractor, ecosystem-publisher, session-sanitizer) |
| `~/.claude.json` | 2 MCP servers (aegissiem, ecosystem) |

### To re-install or update symlinks

```bash
cd /Volumes/Locker2/GitHub/CybersecurityTeam/cyber-claude-agents

BASE=$(pwd)
for f in agents/*.md; do ln -sf "$BASE/$f" ~/.claude/agents/; done
for f in skills/*.md; do ln -sf "$BASE/$f" ~/.claude/skills/; done
for f in commands/*.md; do ln -sf "$BASE/$f" ~/.claude/commands/; done
```

---

## Configuration

### 1. API Keys (for external MCP servers)

```bash
# Add to ~/.zshrc or ~/.bashrc
export SHODAN_API_KEY="your-key-here"
export VIRUSTOTAL_API_KEY="your-key-here"
export SPLUNK_BASE_URL="https://splunk.corp.example.com:8089"
export SPLUNK_AUTH_TOKEN="your-token-here"
export ECOSYSTEM_REGISTRY_URL="http://localhost:8500"
```

### 2. Configure Engagement Scope

Edit `scripts/authorized_scope.json` with your authorized targets before any offensive use:

```json
{
  "authorized_targets": {
    "ip_ranges": ["10.0.0.0/24", "192.168.1.0/24"],
    "domains": ["*.target.example.com"]
  },
  "excluded_targets": {
    "ip_ranges": ["10.0.0.1/32"],
    "domains": ["mail.target.example.com"]
  },
  "engagement_window": {
    "start": "2026-04-01T09:00:00",
    "end": "2026-04-05T17:00:00"
  }
}
```

### 3. Configure Router Access

Create `~/.aegissiem-daemon/config.yml`:

```yaml
router:
  host: "192.168.1.1"        # Your ASUS router IP
  ssh_user: "admin"
  ssh_key: "~/.ssh/router_rsa"
  syslog_port: 514           # UDP port router sends logs to

daemon:
  api_port: 8088
  db_path: "~/.aegissiem-daemon/aegissiem.db"

honeypot:
  ssh_port: 2222
  http_port: 8443
  telnet_port: 2323
```

### 4. Start the AegisSIEM Daemon

The daemon provides real-time threat data that the `/analyze`, `/status`, and `/triage` commands depend on:

```bash
cd /Volumes/Locker2/GitHub/CybersecurityTeam/cyber-claude-agents
python3 -m daemon.aegissiem_daemon
```

Check it's running: `curl http://localhost:8088/api/status`

Dashboard: `http://localhost:8088`

### 5. Start Ollama

Required for `/analyze` deep analysis and Log Analyst agent:

```bash
ollama serve
ollama pull qwen2.5-coder
```

Verify: `curl http://localhost:11434/api/tags`

### 6. Verify Hooks

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"ls"}}' \
  | node /Volumes/Locker2/GitHub/CybersecurityTeam/cyber-claude-agents/scripts/hooks/pre-command-scope-check.js
# Expected: {"decision":"allow"}
```

---

## Command Reference

### `/scan` — Network Reconnaissance

```
/scan <TARGET> [--profile quick|stealth|full|vuln|udp|os|version]
```

**Examples:**
```
/scan 192.168.1.0/24
/scan 10.0.0.50 --profile vuln
/scan target.example.com --profile full
```

**Output:** Host matrix with open ports, service banners, OS guesses, CVE matches, and next-step recommendations.

---

### `/hunt` — Threat Hunting

```
/hunt <LOG_TYPE> --data <PATH> --hypothesis "<HYPOTHESIS>"
/hunt <LOG_TYPE> --data <PATH> --ioc <IP_OR_HASH>
```

**Examples:**
```
/hunt sysmon --data /tmp/sysmon.json --hypothesis "lateral movement via PsExec"
/hunt pcap --data /captures/traffic.pcap --ioc 185.220.101.45
/hunt auth --data /var/log/auth.log --hypothesis "brute force SSH"
```

**Output:** ATT&CK-mapped findings table, extracted IOCs, auto-generated Sigma/YARA/Snort rules.

---

### `/analyze` — Threat Analysis

```
/analyze <INPUT> [--type threat|log|ip|cve] [--depth quick|full]
```

**Examples:**
```
/analyze 185.220.101.45
/analyze 185.220.101.45 --type ip --depth full
/analyze CVE-2024-3094
/analyze "Nov  4 03:21:15 admin: from 185.220.101.45" --type log
/analyze "multiple failed SSH logins" --type threat --depth quick
```

**Quick depth:** Checks local threat data, AegisSIEM database, and log patterns.
**Full depth:** Adds WHOIS, rDNS, GeoIP, and Ollama `qwen2.5-coder` LLM analysis.

---

### `/block` — IP Blocking

```
/block <IP> [--router <NAME>] [--unblock] [--reason "<TEXT>"] [--duration <HOURS>]
```

**Examples:**
```
/block 185.220.101.45
/block 185.220.101.45 --reason "Brute force SSH" --duration 48
/block 185.220.101.45 --unblock
```

**What it does:**
1. Validates IP is external (not RFC1918)
2. SSHs to router and runs `iptables -I INPUT -s <IP> -j DROP`
3. Records the block in `~/.aegissiem-daemon/aegissiem.db`
4. Publishes event to ecosystem registry

---

### `/status` — Security Dashboard

```
/status [--threats] [--blocked] [--honeypot] [--profiles] [--all]
```

**Examples:**
```
/status
/status --all
/status --threats
/status --blocked
/status --honeypot
```

**Output:** Live snapshot of:
- Active threats with severity, source IP, and escalation level
- Currently blocked IPs with block reason and expiry
- Recent honeypot events (SSH, HTTP, Telnet connections)
- Top attacker profiles with confidence scores

---

### `/triage` — Incident Triage

```
/triage <IP> [--playbook incident_triage|log_analysis|security_scan]
```

**Examples:**
```
/triage 185.220.101.45
/triage 185.220.101.45 --playbook incident_triage
/triage 10.0.0.50 --playbook security_scan
```

**Incident triage playbook steps:**
1. Collect all events for the IP from the database
2. WHOIS, rDNS, GeoIP enrichment
3. LLM risk assessment via Ollama
4. Cross-reference against IOC databases
5. Generate recommended response action with confidence score

---

## Common Workflows

### 🔵 Responding to a Live Threat

```
# Check current threat posture
/status --all

# Deep-dive on a suspicious IP
/analyze 185.220.101.45 --depth full

# Run full triage
/triage 185.220.101.45

# Block if confirmed malicious
/block 185.220.101.45 --reason "Confirmed brute force" --duration 72

# Verify it's blocked
/status --blocked
```

---

### 🔵 Daily Security Review

```
# Morning posture check
/status

# Analyze anything high-severity from overnight
/analyze <HIGH_SEVERITY_IP> --depth quick

# Check what the threat watcher found
# (Run any command — the threat-watcher hook auto-injects recent threats as context)
```

---

### 🔴 Penetration Test Campaign

```
1. "Use the red-team-lead agent to plan a campaign for 10.0.0.0/24"
   → Agent produces campaign plan with kill chain phases

2. /scan 10.0.0.0/24 --profile quick
   → Discovers hosts, open ports, services

3. "Analyze CVE-2021-41773 for the Apache 2.4.41 on 10.0.0.50"
   → Exploit researcher produces technical analysis

4. "Exploit the path traversal on 10.0.0.50:80"
   → Agent provides exploit commands (scope-checked by hook)

5. "Generate the engagement report"
   → Report per rules/reporting-standards.md
```

---

### 🔵 Threat Hunt

```
1. "Switch to active engagement mode"
   → Loads contexts/active-engagement.md

2. /hunt sysmon --data /path/to/sysmon.json --hypothesis "lateral movement via PsExec"
   → Parses logs, identifies suspicious events, extracts IOCs

3. "Search Splunk for related events in the last 24 hours"
   → Agent constructs and runs SPL query via MCP

4. "Check the found IPs against VirusTotal"
   → Agent queries vt_ip_report for each IOC

5. "Generate Sigma rules for these findings"
   → Agent produces SigmaHQ-compliant YAML rules
```

---

### 📋 CVE Research

```
1. "Switch to research mode"
   → Loads contexts/research.md

2. "Research CVE-2024-3094 (XZ Utils backdoor)"
   → Academic analysis with citations, no active tools

3. "Write a YARA rule to detect the XZ backdoor"
   → Following skills/yara-rule-creation.md patterns

4. "Check if any of our systems run affected versions"
   → Agent queries Shodan MCP for passive recon
```

---

### 🚨 Incident Response

```
1. "We have a confirmed breach on SRV-DB03. Start IR."
   → Incident responder activates PICERL methodology

2. "Here are the Sysmon logs from SRV-DB03" (paste logs)
   → Agent parses, builds timeline, extracts IOCs

3. "Contain the affected system"
   → Agent provides containment checklist

4. "Generate the incident report"
   → Report per rules/reporting-standards.md incident template
```

---

## Context Switching

| Command | Effect |
|---------|--------|
| "Switch to research mode" | Load `contexts/research.md` — academic, passive, citation-required |
| "Go active" or "Engage" | Load `contexts/active-engagement.md` — tactical, command-first |
| "Default mode" | Unload any context — standard Claude Code behavior |

---

## Using Agents Directly

Address agents by name in any prompt. They are available globally in all Claude Code sessions:

```
"Use the log-analyst agent to analyze this syslog dump"
"Ask the network-guardian agent to block this IP"
"Use the knowledge-agent to find documentation on Kerberoasting"
"Have the exploit-researcher assess CVE-2024-3094"
"Use the threat-hunter to write a YARA rule for this malware sample"
```

---

## Vault File Reference

| File | Purpose | How It's Updated |
|------|---------|-----------------|
| `vault/progress-log.md` | Project build progress | Manually by developers |
| `vault/known-issues.md` | Known issues and open questions | Manually by developers |
| `vault/capabilities.md` | What the harness can do | Manually, this file |
| `vault/limitations.md` | Known constraints and gaps | Manually, this file |
| `vault/usage.md` | Setup and workflow guide | Manually, this file |
| `vault/iocs.csv` | IOC tracker | Auto — `ioc-extractor.js` hook |
| `vault/sanitization-log.json` | Credential redaction audit | Auto — `post-session-sanitize.js` hook |
| `vault/threat-data/*.json` | Live threat feed from daemon | Auto — AegisSIEM daemon |

---

## Troubleshooting

| Issue | Cause | Fix |
|-------|-------|-----|
| `/analyze` returns no data | AegisSIEM daemon not running | `cd cyber-claude-agents && python3 -m daemon.aegissiem_daemon` |
| `/block` fails with SSH error | No SSH key or wrong router IP | Check `~/.aegissiem-daemon/config.yml` and `~/.ssh/router_rsa` |
| Ollama analysis unavailable | Ollama not running or model missing | `ollama serve` then `ollama pull qwen2.5-coder` |
| Scope check blocks legitimate targets | Target not in `authorized_targets` | Add IP/domain to `scripts/authorized_scope.json` |
| "Cannot load authorized_scope.json" | Missing or invalid scope file | Create/fix `scripts/authorized_scope.json` |
| IOC extractor not running | Hook not registered | Open `/hooks` in Claude Code UI to reload config |
| MCP server returns 401 | Invalid or expired API key | Update the environment variable with a valid key |
| Port 8088 conflict | Legacy Flask dashboard also on 8088 | Stop the legacy dashboard; daemon uses 8088 exclusively |
| Nmap requires sudo | SYN scans need root | Run with `sudo` or use `-sT` for TCP connect scan |
| YARA rule syntax error | Rule doesn't compile | Run `yara -C rule.yar` to check syntax |
| Splunk search timeout | Query too broad | Add time bounds: `earliest=-24h` and index filter |
| PEP 668 pip install error | Homebrew Python blocks global installs | Use `python3 -m venv .venv && .venv/bin/pip install -e .` |
