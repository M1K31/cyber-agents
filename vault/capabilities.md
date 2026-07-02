# 🎯 Capabilities

> Complete inventory of what the cyber-claude-agents harness can do.

---

## Agent Capabilities

### 🔴 Red Team Lead
- **Campaign Planning** — Design multi-phase penetration tests mapped to the Lockheed Martin Cyber Kill Chain
- **MITRE ATT&CK Mapping** — Map all tactics, techniques, and procedures to ATT&CK framework IDs
- **Sub-Agent Orchestration** — Delegate specialized tasks to exploit-researcher and other agents
- **Scope Management** — Enforce ROE boundaries and track engagement state
- **Report Generation** — Produce engagement summaries per `rules/reporting-standards.md`

### 🔴 Exploit Researcher
- **CVE Analysis** — Research vulnerabilities using NVD, vendor advisories, and exploit databases
- **PoC Development** — Build proof-of-concept exploits with safety constraints
- **Mitigation Bypass Research** — Analyze WAFs, AV, EDR, and ASLR/DEP bypass techniques
- **CVSS Scoring** — Compute accurate CVSS v3.1 base, temporal, and environmental scores
- **Exploit Chain Construction** — Combine vulnerabilities into multi-step attack paths

### 🔵 Threat Hunter
- **Hypothesis-Driven Hunting** — Formulate and test threat hypotheses against log data
- **Detection Engineering** — Author YARA rules, Sigma rules, and Snort/Suricata signatures
- **Beaconing Detection** — Statistical analysis of connection intervals (jitter ratio calculation)
- **Lateral Movement Detection** — Identify PsExec, WMI, SMB, and RDP-based movement patterns
- **IOC Extraction** — Parse and categorize indicators of compromise from any data source

### 🔵 Incident Responder
- **PICERL Methodology** — Full incident lifecycle: Preparation, Identification, Containment, Eradication, Recovery, Lessons Learned
- **Evidence Collection** — Forensically sound evidence handling with chain-of-custody tracking
- **Containment Strategies** — Network isolation, host quarantine, account lockout recommendations
- **Root Cause Analysis** — Trace attack path from initial access to current state
- **Timeline Generation** — Chronological event reconstruction with ATT&CK mapping

### 🔵 Log Analyst
- **Router Syslog Parsing** — Classify ASUS router syslog events: login attempts, deauth floods, DNS rebinding, firewall drops
- **Threat Detection** — Identify brute force attacks, port scans, suspicious DNS queries, ARP poisoning
- **Attacker Profiling** — Build behavioral profiles: attack windows, techniques, confidence scores
- **Ollama-Powered Analysis** — Delegate deep pattern analysis to the local `qwen2.5-coder` model via `skills/ollama-inference.md`
- **Report Generation** — Produce structured threat reports with severity ratings and recommended responses
- **Data Source Integration** — Reads from `vault/threat-data/*.json`, `~/.aegissiem-daemon/aegissiem.db`, and live syslog files

### 🔵 Network Guardian
- **IP Blocking/Unblocking** — Apply and remove iptables rules on ASUS routers via SSH using `skills/router-management.md`
- **Honeypot Management** — Manage SSH (2222), HTTP (8443), and Telnet (2323) listener deployment decisions
- **Approval Workflows** — Orchestrate the PROCEED/STOP decision flow for automated response actions
- **Block Record Management** — Track blocked IPs with timestamps, reasons, and deadlines in AegisSIEM database
- **Auto-Unblock Scheduling** — Honor block expiry deadlines and trigger removal via daemon
- **Ecosystem Integration** — Publish block/unblock events to the appEcosystem registry

### 🔵 Knowledge Agent
- **Knowledge Base Search** — Full-text search across `knowledge/` directory using `Grep` and `Glob`
- **Retrieval-Augmented Answers** — Synthesize answers from multiple source documents with file citations
- **Category Navigation** — Browse by topic: cybersecurity, engineering, medical, agriculture, chemistry, system
- **Offline Operation** — Pure file-based RAG — no ChromaDB or sentence-transformers required
- **Source Attribution** — Every answer includes references to the specific knowledge base files consulted

---

## Skill Capabilities

| Skill | Key Abilities |
|-------|--------------|
| **Kali Linux Tooling** | Nmap profiles (7 scan types), Metasploit database workflows, Burp Suite automation, output parsing patterns |
| **macOS Tooling** | Homebrew security toolkit, Nuclei/Impacket cross-platform workflows, macOS-specific forensic artifacts (FSEvents, TCC.db, unified log), osquery patterns |
| **Defense Evasion** | LOLBins/GTFOBins catalog, payload obfuscation (AES/XOR encoding, string manipulation, API hashing), AV/EDR bypass (AMSI, ETW, unhooking) — with corresponding detection indicators |
| **YARA Rule Creation** | Full YARA syntax, string types (hex/text/regex), condition patterns, PE/ELF module usage, performance optimization, naming conventions, testing methodology |
| **Syslog Analysis** | ASUS router log format patterns, event classification rules, detection thresholds for brute force/deauth/DNS rebinding, escalation criteria, SPL/grep query patterns |
| **Ollama Inference** | `curl` patterns for chat completion and embeddings against local `qwen2.5-coder` via `http://localhost:11434`, system/user prompt construction, streaming output handling |
| **Router Management** | SSH key authentication to ASUS routers, `iptables` block/unblock commands, `logread` syslog retrieval, connection health checks, config loading from `~/.aegissiem-daemon/config.yml` |

---

## Command Capabilities

| Command | Input | Output |
|---------|-------|--------|
| `/scan` | IP, CIDR, hostname + profile flag | Host matrix, open ports, service versions, CVE matches, next-step tool recommendations |
| `/hunt` | Logs, PCAPs, Sysmon, DNS, auth data + hypothesis | Findings table with ATT&CK mapping, IOC list, auto-generated Sigma/YARA/Snort rules |
| `/analyze` | IP, log snippet, CVE ID, or threat description + `--type` + `--depth` | Structured analysis with severity, ATT&CK mapping, recommended actions — full depth adds WHOIS/rDNS/GeoIP and Ollama LLM analysis |
| `/block` | IP address + optional `--router` + `--unblock` flag | Applies or removes iptables rules via SSH, records action in AegisSIEM database |
| `/status` | Optional filter flags (`--threats`, `--blocked`, `--honeypot`, `--profiles`, `--all`) | Live security posture dashboard: active threats, blocked IPs, honeypot events, attacker profiles |
| `/triage` | IP address + optional `--playbook` (incident_triage, log_analysis, security_scan) | Multi-step enriched triage report: event history, WHOIS/GeoIP, LLM risk assessment, recommended response |

---

## Hook Capabilities

| Hook | Trigger | Capability |
|------|---------|-----------|
| **Scope Check** | `PreToolUse(Bash)` | CIDR matching, domain wildcard validation, exclusion list check, engagement window enforcement, testing hour validation — hard blocks out-of-scope commands |
| **Threat Watcher** | `PreToolUse(any)` — async | Reads `vault/threat-data/` for recent high-severity threats and injects them as context before each tool use |
| **IOC Extractor** | `PostToolUse(Bash\|Read\|Grep)` — async | Extracts IPv4, domains, SHA-256/SHA-1/MD5, URLs, emails — deduplicates and appends to `vault/iocs.csv` |
| **Ecosystem Publisher** | `PostToolUse(Bash)` — async | Detects `iptables` block/unblock commands and publishes events to the appEcosystem registry |
| **Session Sanitizer** | `Stop` | Detects 16 credential types (private keys, API tokens, hashes, passwords) — redacts and logs to `vault/sanitization-log.json` |

---

## MCP Server Capabilities

| Server | Scope | Queries Available | Requires |
|--------|-------|------------------|----------|
| **AegisSIEM** | 🔵 Blue (local) | `get_threats`, `get_blocked_ips`, `get_profiles`, `get_honeypot_events`, `get_status`, `get_approvals`, `resolve_threat`, `get_threat_summary`, `search_knowledge` | Daemon running at `http://localhost:8088` |
| **Ecosystem** | Both | `publish_event`, `discover_service`, `registry_status` | `ECOSYSTEM_REGISTRY_URL` env var |
| **Shodan** | 🔴 Red | Host lookup (ports/banners/CVEs), internet search (dorks), DNS resolve/reverse, exploit database search | `SHODAN_API_KEY` |
| **VirusTotal** | 🔵 Blue | File hash reputation, URL scanning, domain WHOIS/DNS/reputation, IP reputation/passive DNS, sandbox behavioral analysis | `VIRUSTOTAL_API_KEY` |
| **Splunk/SIEM** | 🔵 Blue | Synchronous SPL search, async long-running jobs, job status polling, result retrieval, Splunk ES notable events | `SPLUNK_BASE_URL`, `SPLUNK_AUTH_TOKEN` |

---

## Context Modes

| Mode | Behavior |
|------|----------|
| **Research** | Academic tone, mandatory source citations, active tool prohibition, structured CVE/YARA research templates |
| **Active Engagement** | Command-first output, phase-aware kill chain behavior, engagement state tracking, auto-delegation between agents |

---

## AegisSIEM Daemon

The daemon runs independently of Claude Code sessions and provides continuous monitoring:

| Capability | Detail |
|-----------|--------|
| **Syslog Ingestion** | Real-time parsing of ASUS router UDP syslog stream |
| **Threat Detection** | Brute force (>5 failures/min), deauth floods (>10 events/5s), DNS rebinding detection |
| **Auto-Blocking** | Applies iptables rules for threats past their escalation deadline |
| **Honeypot Listeners** | SSH (2222), HTTP (8443), Telnet (2323) with tarpit mode |
| **REST API** | Dashboard + MCP server endpoint at `http://localhost:8088` |
| **Ecosystem Registration** | Announces itself to appEcosystem registry on startup |
