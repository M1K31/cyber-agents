---
name: analyze
description: Analyze threats, logs, IPs, or CVEs using the log-analyst agent and Ollama
userInvocable: true
---

# /analyze Command

Analyze a threat, log snippet, IP address, or CVE using the log-analyst agent with qwen2.5-coder.

## Usage
```
/analyze <INPUT> [--type threat|log|ip|cve] [--depth quick|full]
```

## Workflow

1. **Parse input**: Detect if input is an IP address, log snippet, CVE ID, or threat description
2. **Gather context**:
   - For IPs: Check `vault/threat-data/` for existing data, query AegisSIEM database
   - For logs: Parse using syslog patterns from `skills/syslog-analysis.md`
   - For CVEs: Search knowledge base and external references
3. **Delegate to log-analyst agent** for analysis
4. **If --depth full**: Also run recon (WHOIS, rDNS, GeoIP) and LLM analysis via Ollama
5. **Output**: Structured analysis with severity, MITRE ATT&CK mapping, and recommended actions
