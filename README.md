# 🛡️ Cyber Claude Agents

> A cybersecurity-focused agent harness for [Claude Code](https://docs.anthropic.com/en/docs/claude-code), designed to assist security researchers with **Red Team** (offensive) and **Blue Team** (defensive) operations.

Inspired by [everything-claude-code](https://github.com/affaan-m/everything-claude-code), this repository provides specialized agents, skills, and slash commands tailored entirely for infosec workflows — aligned with **MITRE ATT&CK**, **OWASP**, and **NIST** frameworks.

---

## 📦 What's Inside

```
cyber-agents/
├── agents/                        # Specialized subagents
│   ├── red-team-lead.md           # Campaign planning & MITRE ATT&CK orchestration
│   ├── exploit-researcher.md      # CVE analysis & PoC development
│   ├── threat-hunter.md           # Proactive hunting & detection engineering
│   └── incident-responder.md      # PICERL methodology & root cause analysis
├── skills/                        # Domain knowledge & workflow guides
│   ├── kali-linux-tooling.md      # Kali suite best practices (Nmap, MSF, Burp)
│   ├── macos-tooling.md           # macOS/Linux security tooling
│   ├── defense-evasion.md         # LOLBins, obfuscation, AV/EDR bypass
│   └── yara-rule-creation.md      # YARA rule syntax & performance patterns
├── commands/                      # Slash commands for workflow execution
│   ├── scan.md                    # /scan — Network reconnaissance
│   └── hunt.md                    # /hunt — Threat hunting from logs/PCAPs
├── rules/                         # Mandatory operational rules & guardrails
│   ├── opsec.md                   # Operational security directives
│   ├── safe-harbor.md             # Rules of Engagement (ROE) enforcement
│   ├── data-handling.md           # Sensitive data redaction & handling
│   └── reporting-standards.md     # Report templates (CVSS, ATT&CK, NIST)
├── hooks/                         # Hook registration
│   └── hooks.json                 # PreToolUse, PostToolUse, Stop config
├── scripts/                       # Automation scripts
│   ├── authorized_scope.json      # Engagement scope definition
│   └── hooks/                     # Node.js hook implementations
│       ├── pre-command-scope-check.js  # Scope validation (PreToolUse)
│       ├── ioc-extractor.js            # IOC parsing to CSV (PostToolUse)
│       └── post-session-sanitize.js    # Credential redaction (Stop)
├── mcp-configs/                   # MCP server configurations
│   ├── shodan-mcp.json            # Shodan API (5 tools — recon)
│   ├── virustotal-mcp.json        # VirusTotal API (6 tools — reputation)
│   └── splunk-mcp.json            # Splunk/SIEM API (5 tools — log hunting)
├── contexts/                      # Dynamic system prompt contexts
│   ├── research.md                # Academic/passive research mode
│   └── active-engagement.md       # Tactical active engagement mode
├── examples/                      # Example configurations
│   └── cyber-CLAUDE.md            # Root-level project config template
├── vault/                         # Obsidian vault for project documentation
│   ├── progress-log.md            # Timestamped progress tracker
│   ├── known-issues.md            # Limitations & open questions
│   ├── iocs.csv                   # Auto-populated IOC tracker (hook)
│   └── sanitization-log.json      # Credential redaction audit (hook)
├── CLAUDE.md                      # Project-level Claude Code config
└── README.md                      # This file
```

---

## 🚀 Quick Start

### Step 1: Clone the Repository

```bash
git clone https://github.com/your-org/cyber-agents.git
cd cyber-agents
```

### Step 2: Configure Claude Code

Copy the `CLAUDE.md` file to your project root or merge its contents into your existing `CLAUDE.md`:

```bash
cp CLAUDE.md /path/to/your/project/CLAUDE.md
```

### Step 3: Start Using

In Claude Code, invoke any slash command:

```
/scan 192.168.1.0/24
/hunt <paste log snippet>
```

Or delegate directly to an agent:

```
Use the red-team-lead agent to plan a penetration test for the 10.0.0.0/8 internal network.
```

---

## 🎯 Agent Overview

| Agent | Role | Team | Key Frameworks |
|-------|------|------|----------------|
| **Red Team Lead** | Campaign planning, kill-chain orchestration | 🔴 Offensive | MITRE ATT&CK, Lockheed Kill Chain |
| **Exploit Researcher** | CVE analysis, PoC development | 🔴 Offensive | NVD, CVSS, CWE |
| **Threat Hunter** | Proactive detection, rule authoring | 🔵 Defensive | MITRE ATT&CK, Sigma, YARA |
| **Incident Responder** | Triage, containment, root cause analysis | 🔵 Defensive | NIST SP 800-61, PICERL |

---

## 🛠️ Skills

| Skill | Domain | Platform |
|-------|--------|----------|
| **Kali Linux Tooling** | Pentesting suite operation & output parsing | Kali Linux |
| **macOS Tooling** | Security tools via Homebrew & native utils | macOS / Linux |
| **Defense Evasion** | Evasion techniques mapped to MITRE | Cross-platform |
| **YARA Rule Creation** | Malware detection rule engineering | Cross-platform |

---

## ⚡ Commands

| Command | Purpose |
|---------|---------|
| `/scan` | Network reconnaissance — Nmap profile selection, scan execution, output parsing |
| `/hunt` | Threat hunting — Log/PCAP ingestion, anomaly detection, IOC extraction |

---

## 🔒 Rules & Guardrails

| Rule | Purpose |
|------|---------|
| **OPSEC** | Proxychains/VPN mandates, scan noise classification, OPSEC-safe payload generation |
| **Safe Harbor** | Rules of Engagement enforcement — scope validation, hard/soft stops, adjacent discovery |
| **Data Handling** | Auto-redaction of PII, credentials, private keys with 3-tier classification |
| **Reporting Standards** | Mandatory templates for vulnerability reports, engagement summaries, incident reports |

---

## 🌐 MCP Servers

| Server | Tools | Team | Env Variable |
|--------|-------|------|-------------|
| **Shodan** | Host lookup, search (dorks), DNS resolve/reverse, exploit search | 🔴 Red | `SHODAN_API_KEY` |
| **VirusTotal** | File/URL/domain/IP reports, URL scanning, sandbox behavior | 🔵 Blue | `VIRUSTOTAL_API_KEY` |
| **Splunk/SIEM** | Sync/async SPL search, notable events, 8 pre-built hunt queries | 🔵 Blue | `SPLUNK_BASE_URL` + `SPLUNK_AUTH_TOKEN` |

---

## 📋 Requirements

- **Claude Code** CLI (latest version recommended)
- **Node.js** 18+ (for hook scripts)
- **Nmap**, **Metasploit Framework**, and other tools referenced in skills
- For Kali-specific workflows, a Kali Linux environment (VM, WSL, or bare metal)
- For macOS workflows, Homebrew with relevant security packages
- For MCP servers, set the required environment variables with valid API keys

---

## ⚠️ Important Notes

> [!CAUTION]
> **Legal & Ethical Use Only.** All tools, techniques, and procedures documented here are intended for **authorized security testing** and **defensive operations only**. Unauthorized access to computer systems is illegal. Always obtain proper written authorization before conducting any offensive security testing.

> [!NOTE]
> This project is designed for use with Claude Code's agent delegation system. Agents, skills, and commands are Markdown-based configurations — there is no executable code to install.

---

## 🤝 Contributing

Contributions are welcome. Potential areas:
- Additional agents (e.g., `malware-analyst.md`, `cloud-security.md`, `forensics-examiner.md`)
- Additional skills (e.g., `sigma-rule-creation.md`, `osint-methodology.md`)
- Additional commands (e.g., `/exploit`, `/respond`, `/report`)
- Integration with MCP servers for live tool execution

---

## 📄 License

MIT License. See [LICENSE](LICENSE) for details.
